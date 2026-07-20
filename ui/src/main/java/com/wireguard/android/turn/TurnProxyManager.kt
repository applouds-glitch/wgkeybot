/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.util.Log
import com.wireguard.android.R
import com.wireguard.android.backend.TurnBackend
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap

/**
 * Lightweight manager for per-tunnel TURN client processes and logs.
 *
 * Uses PhysicalNetworkMonitor to track stable internet connections and 
 * triggers restarts when the underlying network or IP changes.
 */
class TurnProxyManager(private val context: Context) {
    private val scope = CoroutineScope(Dispatchers.IO)
    
    // State
    @Volatile private var activeTunnelName: String? = null
    @Volatile private var activeSettings: TurnSettings? = null
    @Volatile private var userInitiatedStop: Boolean = false
    
    // Network tracking
    private val networkMonitor = PhysicalNetworkMonitor(context)
    @Volatile private var lastKnownNetwork: Network? = null
    
    init {
        networkMonitor.start()

        scope.launch {
            networkMonitor.validated.collectLatest { validated ->
                // A capability flicker must not tear down healthy TURN streams.
                // Native combines this hint with fresh proof from authenticated
                // TURN traffic, so false cannot park reconnects on a working
                // corporate network that blocks Android validation probes.
                if (activeTunnelName != null && activeSettings?.enabled == true) {
                    TurnBackend.wgSetNetworkAvailable(if (validated) 1 else 0)
                }
            }
        }
        
        scope.launch {
            networkMonitor.bestNetwork.collectLatest { network ->
                if (network != null) {
                    handleNetworkChange(network)
                }
            }
        }
    }

    /**
     * Central handler for network changes from PhysicalNetworkMonitor.
     * The monitor already provides debounced stable networks.
     */
    private suspend fun handleNetworkChange(network: Network) {
        if (userInitiatedStop || activeTunnelName == null) return

        // 1. Initial baseline setting
        if (lastKnownNetwork == null) {
            Log.d(TAG, "Setting initial network baseline: $network")
            lastKnownNetwork = network
            return
        }

        // 2. Stability check
        if (lastKnownNetwork == network) {
            Log.d(TAG, "Network state stable for $network")
            return
        }

        // 3. Real change confirmed
        Log.d(TAG, "Network change confirmed: $network. Restarting TURN.")
        lastKnownNetwork = network
        performRestartSequence()
    }

    private suspend fun performRestartSequence() {
        if (userInitiatedStop || activeTunnelName == null) return

        Log.d(TAG, "Stopping TURN proxy for restart...")
        TurnBackend.wgTurnProxyStop()
        
        // Critical: Notify Go backend to clear internal socket states/DNS cache
        Log.d(TAG, "Notifying Go layer of network change...")
        TurnBackend.wgNotifyNetworkChange()
        
        delay(500) // Brief pause for Go goroutines to stop; server evicts old conns via AddConn

        val name = activeTunnelName ?: return
        val settings = activeSettings ?: return

        var attempts = 0
        while (currentCoroutineContext().isActive && !userInitiatedStop) {
            // Always probe a newly selected physical network once. Android can
            // legitimately withhold VALIDATED on corporate/probe-blocking networks,
            // while TURN itself is fully reachable. After a failed bootstrap, wait
            // for validation or a slow timeout before spending on another full start.
            // A genuinely new network cancels this collectLatest branch immediately.
            if (attempts > 0 && !networkMonitor.validated.value) {
                Log.w(TAG, "Network is not VALIDATED — waiting before controlled TURN retry")
                withTimeoutOrNull(UNVALIDATED_RETRY_INTERVAL_MS) {
                    networkMonitor.validated.first { it }
                }
                if (userInitiatedStop || !currentCoroutineContext().isActive) return
            }

            // The selected physical network may have changed while validation
            // was pending. Use the monitor's current, non-debounced winner.
            lastKnownNetwork = networkMonitor.currentNetwork

            attempts++
            Log.d(TAG, "Starting TURN for $name (Attempt $attempts)")

            val success = startForTunnelInternal(name, settings)
            if (success) {
                Log.d(TAG, "TURN restarted successfully on attempt $attempts")
                return // Exit loop on success
            }

            // A user stop that landed during the attempt makes this failure
            // expected, not retryable. Bail out now instead of logging a
            // misleading "retrying" line and sleeping before the loop condition
            // would catch it — that retry is exactly the post-disconnect
            // "keeps connecting" the user sees.
            if (userInitiatedStop || !currentCoroutineContext().isActive) return

            // Exponential backoff logic
            val delayMs = when {
                attempts <= 2 -> 2000L
                attempts <= 5 -> 5000L
                else -> 15000L
            }
            Log.w(TAG, "Restart failed, retrying in ${delayMs}ms...")
            delay(delayMs)
        }
    }

    private data class Instance(
        val log: StringBuilder = StringBuilder(),
        @Volatile var running: Boolean = false,
    )

    private val instances = ConcurrentHashMap<String, Instance>()
    // Remember the stream count that last succeeded, so the next connect
    // can start with it instead of waiting for the primary count to time out.
    private val lastSuccessfulStreams = ConcurrentHashMap<String, Int>()
    // Mutex to serialize start/stop operations and prevent race conditions between
    // onTunnelEstablished and handleNetworkChange
    private val operationMutex = kotlinx.coroutines.sync.Mutex()

    /**
     * Called from TurnManager when the tunnel is established.
     */
    suspend fun onTunnelEstablished(tunnelName: String, turnSettings: TurnSettings?): Boolean {
        Log.d(TAG, "onTunnelEstablished called for tunnel: $tunnelName")

        // Reset state for new session
        activeTunnelName = tunnelName
        activeSettings = turnSettings
        userInitiatedStop = false
        
        // Initialize network baseline for the new session
        lastKnownNetwork = networkMonitor.currentNetwork
        Log.d(TAG, "Initial network for tunnel session: $lastKnownNetwork")

        if (turnSettings == null || !turnSettings.enabled) {
            Log.d(TAG, "TURN not enabled, skipping")
            return true
        }

        val success = try {
            startForTunnelInternal(tunnelName, turnSettings)
        } catch (e: Exception) {
            Log.w(TAG, "TURN start threw exception — clearing session state")
            activeTunnelName = null
            activeSettings = null
            lastKnownNetwork = null
            userInitiatedStop = true
            throw e
        }

        if (!success) {
            // Start failed: clear session state so PhysicalNetworkMonitor does not
            // try to "restart" a tunnel that never came up — which would otherwise
            // hammer the TURN server on every network change.
            Log.w(TAG, "TURN start failed — clearing session state")
            activeTunnelName = null
            activeSettings = null
            lastKnownNetwork = null
            userInitiatedStop = true
            return false
        }

        // After initial start, allow network changes to trigger restarts
        // We delay slightly to ensure we don't catch the immediate network fluctuation caused by VPN itself
        scope.launch {
            delay(2000)
            Log.d(TAG, "Initialization phase complete, network monitoring active")
        }

        return true
    }

    private suspend fun startForTunnelInternal(tunnelName: String, settings: TurnSettings): Boolean =
        withContext(Dispatchers.IO) {
            operationMutex.lock()
            try {
                if (!currentCoroutineContext().isActive) {
                    Log.d(TAG, "startForTunnelInternal cancelled before execution")
                    return@withContext false
                }

                val instance = instances.getOrPut(tunnelName) { Instance() }

                Log.d(TAG, "Stopping any existing TURN proxy...")
                TurnBackend.wgTurnProxyStop()
                // Give Go runtime a moment to fully clean up goroutines
                delay(100)

                // Wait for JNI to be registered
                val jniReady = TurnBackend.waitForVpnServiceRegistered(2000)
                if (!jniReady) {
                    Log.e(TAG, "TIMEOUT waiting for JNI registration!")
                    return@withContext false
                }

                lastKnownNetwork = networkMonitor.currentNetwork
                // Preserve the historical manual-start behavior: allow one
                // normal startup attempt even before Android publishes
                // VALIDATED. Afterward native combines the actual capability
                // with proof from the TURN handshake and strict RX path.
                TurnBackend.wgSetNetworkAvailable(1)

                // If network is still null, try one quick re-poll from monitor
                if (lastKnownNetwork == null) {
                    lastKnownNetwork = networkMonitor.currentNetwork
                    if (lastKnownNetwork == null) {
                        Log.w(TAG, "Network still null, waiting 500ms for PhysicalNetworkMonitor...")
                        delay(500)
                        lastKnownNetwork = networkMonitor.currentNetwork
                    }
                }

                val networkHandle = lastKnownNetwork?.getNetworkHandle() ?: 0L
                val networkType = getNetworkTypeString(lastKnownNetwork)
                Log.d(TAG, "Starting TURN proxy for $tunnelName with network: $lastKnownNetwork (type=$networkType, handle=$networkHandle)")

                val stability = isStabilityMode()
                val effectiveVkLink = if (stability) {
                    settings.vkLink.split(",", "|").map { it.trim() }
                        .firstOrNull { it.isNotEmpty() } ?: settings.vkLink
                } else {
                    settings.vkLink
                }
                val effectivePeerType = if (stability) "proxy_v2" else settings.peerType
                val effectiveWrapKey = if (stability) "" else settings.wrapKey
                Log.d(TAG, "Mode: ${if (stability) "Stability (proxy_v2, 1 link, no WRAP)" else "Speed (${settings.peerType}, ${settings.vkLink.split(",","|").count { it.isNotBlank() }} links, WRAP=${settings.wrapKey.isNotBlank()})"}")

                // Build list of stream counts to try.
                // 1. Last successful count (fast path on reconnect)
                // 2. Primary configured count
                // 3. Explicit fallback (if configured)
                val streamCountsToTry = mutableListOf<Int>()
                val remembered = lastSuccessfulStreams[tunnelName]
                if (remembered != null && remembered != settings.streams) {
                    streamCountsToTry.add(remembered)
                }
                streamCountsToTry.add(settings.streams)
                val fallback = settings.fallbackStreams
                if (fallback > 0 && fallback != settings.streams && fallback != remembered) {
                    streamCountsToTry.add(fallback)
                }

                val listenAddr = "127.0.0.1:${settings.localPort}"
                var ret = -1
                for ((attempt, streamsToTry) in streamCountsToTry.withIndex()) {
                    // A user-initiated stop (stopForTunnel) may have landed while a
                    // previous attempt was in flight. Don't start another proxy — that
                    // would just re-bind the listener the user already asked to tear down.
                    if (userInitiatedStop) {
                        Log.d(TAG, "Stop requested — abandoning TURN start")
                        break
                    }
                    if (attempt > 0) {
                        val label = when {
                            remembered != null && attempt == 1 && streamsToTry == settings.streams -> "remembered count failed, trying primary $streamsToTry"
                            else -> "falling back to $streamsToTry streams"
                        }
                        Log.d(TAG, label)
                        appendLogLine(tunnelName, "Retrying with $streamsToTry streams...")
                        TurnBackend.wgTurnProxyStop()
                        delay(100)
                    }

                    ret = TurnBackend.wgTurnProxyStart(
                        settings.peer, effectiveVkLink, settings.mode, streamsToTry,
                        if (settings.useUdp) 1 else 0,
                        listenAddr,
                        settings.turnIp,
                        settings.turnPort,
                        effectivePeerType,
                        settings.streamsPerCred,
                        settings.watchdogTimeout,
                        effectiveWrapKey,
                        networkHandle
                    )

                    if (ret == -2) {
                        val msg = context.getString(R.string.turn_call_requires_auth)
                        Log.e(TAG, "TURN: $msg")
                        appendLogLine(tunnelName, msg)
                        throw Exception(msg)
                    }

                    if (ret == -4) {
                        // Dead call: the VK call ended/was deleted or the join link is
                        // invalid. No captcha, credential rotation or stream count can
                        // revive a call that no longer exists — abort without retrying.
                        val msg = context.getString(R.string.turn_call_unavailable)
                        Log.e(TAG, "TURN: $msg")
                        appendLogLine(tunnelName, msg)
                        throw Exception(msg)
                    }

                    if (ret == -3) {
                        // Captcha lockout: every credential pre-fetch failed because the
                        // captcha could not be solved. Stream count is irrelevant to a
                        // captcha challenge, so trying the next count would only reset the
                        // native lockout and re-trigger the captcha flow. Abort the start.
                        val msg = "TURN start aborted: captcha unsolved, not retrying other stream counts"
                        Log.e(TAG, msg)
                        appendLogLine(tunnelName, msg)
                        break
                    }

                    if (ret == 0) {
                        // The native stop in stopForTunnel runs without operationMutex so
                        // it can interrupt an in-flight start. If it raced ahead of this
                        // wgTurnProxyStart — before the proxy registered its cancel hook —
                        // it missed the listener and left UDP :9000 bound. Now that the
                        // proxy is up (and cancellable), honor that stop by tearing it down.
                        if (userInitiatedStop) {
                            Log.w(TAG, "Stop requested during startup — stopping freshly started proxy")
                            TurnBackend.wgTurnProxyStop()
                            instance.running = false
                            return@withContext false
                        }
                        instance.running = true
                        lastSuccessfulStreams[tunnelName] = streamsToTry
                        val streamInfo = when {
                            attempt > 0 && streamsToTry == settings.streams -> " (primary after fallback)"
                            attempt > 0 -> " (via fallback $streamsToTry streams)"
                            remembered != null -> " (remembered)"
                            else -> ""
                        }
                        val msg = "TURN started for tunnel \"$tunnelName\" listening on $listenAddr$streamInfo"
                        Log.d(TAG, msg)
                        appendLogLine(tunnelName, msg)
                        return@withContext true
                    }

                    Log.e(TAG, "Failed to start TURN proxy with $streamsToTry streams (error $ret)")
                }

                val msg = "Failed to start TURN proxy (error $ret)"
                Log.e(TAG, msg)
                appendLogLine(tunnelName, msg)
                false
            } finally {
                // End the bounded bootstrap override. Native keeps the effective gate
                // open when the just-established TURN path has fresh transport proof.
                TurnBackend.wgSetNetworkAvailable(if (networkMonitor.validated.value) 1 else 0)
                operationMutex.unlock()
            }
        }

    /**
     * Signal an imminent user-initiated stop without touching the native proxy.
     * Setting userInitiatedStop / clearing the active session here lets callers
     * inhibit the network monitor BEFORE the WireGuard backend is torn down:
     * bringing the tunnel down re-evaluates the physical network, and otherwise
     * PhysicalNetworkMonitor would restart the proxy in the gap before
     * stopForTunnel runs — leaving it reconnecting after the user disconnected.
     */
    fun beginUserStop() {
        userInitiatedStop = true
        activeTunnelName = null
        activeSettings = null
        lastKnownNetwork = null
    }

    suspend fun stopForTunnel(tunnelName: String) =
        withContext(Dispatchers.IO) {
            beginUserStop()

            // Clear remembered stream count so next manual connect starts fresh
            lastSuccessfulStreams.remove(tunnelName)

            // Reset VpnService reference
            TurnBackend.onVpnServiceCreated(null)

            // Stop the proxy BEFORE acquiring the mutex so an in-flight start
            // (which holds the mutex for the whole native call) is interrupted
            // immediately instead of after its 30s startup window.
            TurnBackend.wgTurnProxyStop()

            operationMutex.lock()
            try {
                // Authoritative stop, serialized strictly after any in-flight
                // start. If a start raced ahead and armed its cancel only after
                // the pre-mutex stop ran, that proxy is still torn down here.
                TurnBackend.wgTurnProxyStop()
                instances[tunnelName]?.running = false
                val msg = "TURN stopped for tunnel \"$tunnelName\""
                Log.d(TAG, msg)
                appendLogLine(tunnelName, msg)
            } finally {
                operationMutex.unlock()
            }
        }

    fun isRunning(tunnelName: String): Boolean {
        return instances[tunnelName]?.running == true
    }

    fun getLog(tunnelName: String): String {
        return instances[tunnelName]?.log?.toString() ?: ""
    }

    fun clearLog(tunnelName: String) {
        instances[tunnelName]?.log?.setLength(0)
    }

    fun appendLogLine(tunnelName: String, line: String) {
        val instance = instances.getOrPut(tunnelName) { Instance() }
        val builder = instance.log
        synchronized(builder) {
            if (builder.isNotEmpty()) {
                builder.append('\n')
            }
            builder.append(line)
            if (builder.length > MAX_LOG_CHARS) builder.delete(0, builder.length - MAX_LOG_CHARS)
        }
    }

    /**
     * Returns a string representation of the network type (wifi, cellular, lan, unknown).
     */
    private fun getNetworkTypeString(network: Network?): String {
        if (network == null) return "unknown"

        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.getNetworkCapabilities(network)

        return when {
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> "wifi"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> "cellular"
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> "lan"
            else -> "unknown"
        }
    }

    private fun isStabilityMode(): Boolean =
        context.getSharedPreferences("turn_mode", Context.MODE_PRIVATE)
            .getBoolean("stability_mode", false)

    companion object {
        private const val TAG = "WireGuard/TurnProxyManager"
        private const val MAX_LOG_CHARS = 128 * 1024
        private const val UNVALIDATED_RETRY_INTERVAL_MS = 60_000L
    }
}
