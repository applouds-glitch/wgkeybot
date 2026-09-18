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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Lightweight manager for per-tunnel TURN client processes and logs.
 *
 * Tells native which physical network to use (PhysicalNetworkMonitor →
 * wgSetNetwork) and whether Android validates it. It does not restart the proxy
 * when the network changes: native follows the network itself — rebinding its
 * dials, parking the workers while there is none, moving the sessions left on
 * the old network (network_switch.go). The restart that used to run here landed
 * after the workers had already recovered on the new network, tore those fresh
 * sessions down and redialed the relay before VK had freed them: a 486 after
 * every network drop.
 */
class TurnProxyManager(private val context: Context) {
    // SupervisorJob + handler: этот scope живёт весь процесс и держит оба
    // сетевых коллектора. С обычным Job() любое необработанное исключение в
    // одном из них отменяло родителя — реакция на смену сети пропадала
    // навсегда, а само исключение уходило в uncaughtExceptionHandler и роняло
    // приложение. Теперь падает только сбойная ветка, и та под логом.
    private val scope = CoroutineScope(
        SupervisorJob() + Dispatchers.IO +
            CoroutineExceptionHandler { _, e -> Log.e(TAG, "Unhandled exception in TurnProxyManager scope", e) }
    )

    // State
    @Volatile private var activeTunnelName: String? = null

    /** Name of the tunnel the TURN proxy is currently running for, or null. */
    val activeTunnel: String?
        get() = activeTunnelName

    /**
     * Whether Android has any physical network at all right now — the same fact
     * that parks the native workers (wgSetNetwork(null)). The handshake watchdog
     * reads it so that "no network" is not mistaken for "dead route".
     */
    val hasPhysicalNetwork: Boolean
        get() = networkMonitor.currentPath != null

    @Volatile private var activeSettings: TurnSettings? = null
    @Volatile private var userInitiatedStop: Boolean = false

    // Network tracking
    private val networkMonitor = PhysicalNetworkMonitor(context)

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

        // Keep the native dialer's network current. Every socket the dialer creates
        // is bound to the Network cached in JNI, and that cache used to move only
        // when the proxy (re)started — so every dial during the up-to-27s connect grace, and every
        // retry inside a start still working through the captcha ladder, bound to
        // the network the session began on. By then a dead one: the bind threw,
        // protect() left the socket unbound, and the dial failed with "network is
        // unreachable" until the restart finally landed.
        //
        // Pushed unconditionally; the comparison belongs to native, which is the
        // only writer of that state. A "already pushed this one" cache here would
        // never let a correction through, because a StateFlow does not re-emit an
        // unchanged path. The push is one JNI call per actual path change, and
        // native only takes a global ref — the Network goes over as the object we
        // already hold, so nothing has to look it up. The resolvers travel with it
        // for the same reason: a handover that moved the binding but not the DNS
        // list left every lookup starting at the dead network's servers.
        scope.launch {
            networkMonitor.rawPath.collect { path ->
                val network = path?.network
                TurnBackend.wgSetNetwork(
                    network,
                    network?.getNetworkHandle() ?: 0L,
                    networkMonitor.dnsServersOf(network),
                )
            }
        }
    }

    /** What [rebuildTransport] did. */
    sealed interface Rebuild {
        /** The proxy was restarted, or the attempt ended; the watchdog judges the result. */
        data object Done : Rebuild

        /** No TURN session for this tunnel, or a stop is under way: nothing to rebuild. */
        data object NotApplicable : Rebuild

        /** A start code no retry can fix ([START_CALL_REQUIRES_AUTH], [START_CALL_UNAVAILABLE]). */
        data class Fatal(val code: Int, val message: String) : Rebuild
    }

    /**
     * Rebuilds the TURN proxy under a tunnel that stays up: the background
     * watchdog's step before it gives up on a session that has not handshaken for
     * minutes (see WatchdogCourse). The workers retry on their own all along;
     * what a rebuild adds is a clean start — new sessions on the server, relay
     * health and the election forgotten — and, with [newCredentials], a new VK
     * identity, at the cost of one VK request.
     *
     * Not the restart this class used to run on every network change: that one
     * tore down sessions that had just recovered. This runs only after minutes
     * without a single handshake, when there is nothing left to break.
     */
    suspend fun rebuildTransport(tunnelName: String, newCredentials: Boolean): Rebuild {
        val settings = activeSettings
        if (userInitiatedStop || activeTunnelName != tunnelName || settings == null || !settings.enabled)
            return Rebuild.NotApplicable
        val line = "No WireGuard handshake for minutes — rebuilding the TURN transport" +
            if (newCredentials) " on new credentials" else ""
        Log.w(TAG, line)
        appendLogLine(tunnelName, line)
        if (newCredentials) TurnBackend.wgTurnDropCredentials()
        return try {
            if (!startForTunnelInternal(tunnelName, settings))
                Log.w(TAG, "TURN rebuild did not start — the watchdog's next step decides")
            Rebuild.Done
        } catch (e: CancellationException) {
            throw e
        } catch (e: TurnStartFatal) {
            endSession()
            Rebuild.Fatal(e.code, e.message.orEmpty())
        } catch (e: Exception) {
            Log.w(TAG, "TURN rebuild failed", e)
            Rebuild.Done
        }
    }

    /**
     * Drops the session, so a start still in flight abandons itself instead of
     * bringing a proxy up for it. Mirrors what [beginUserStop] does, but for a
     * failure rather than a user request.
     */
    private fun endSession() {
        activeTunnelName = null
        activeSettings = null
        userInitiatedStop = true
    }

    private data class Instance(
        val log: StringBuilder = StringBuilder(),
        @Volatile var running: Boolean = false,
    )

    private val instances = ConcurrentHashMap<String, Instance>()
    // Remember the stream count that last succeeded, so the next connect
    // can start with it instead of waiting for the primary count to time out.
    private val lastSuccessfulStreams = ConcurrentHashMap<String, Int>()
    // Mutex to serialize start/stop operations: a stop must not interleave with a
    // start still working through its stream-count fallbacks
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

        if (turnSettings == null || !turnSettings.enabled) {
            Log.d(TAG, "TURN not enabled, skipping")
            return true
        }

        val success = try {
            startForTunnelInternal(tunnelName, turnSettings)
        } catch (e: Exception) {
            Log.w(TAG, "TURN start threw exception — clearing session state")
            endSession()
            throw e
        }

        if (!success) {
            Log.w(TAG, "TURN start failed — clearing session state")
            endSession()
            return false
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

                // Preserve the historical manual-start behavior: allow one
                // normal startup attempt even before Android publishes
                // VALIDATED. Afterward native combines the actual capability
                // with proof from the TURN handshake and strict RX path.
                TurnBackend.wgSetNetworkAvailable(1)

                // If there is no network yet, give the monitor one quick moment. Only
                // for the log line: native binds to whatever wgSetNetwork last pushed.
                var network = networkMonitor.currentPath?.network
                if (network == null) {
                    Log.w(TAG, "Network still null, waiting 500ms for PhysicalNetworkMonitor...")
                    delay(500)
                    network = networkMonitor.currentPath?.network
                }

                val networkHandle = network?.getNetworkHandle() ?: 0L
                val networkType = getNetworkTypeString(network)
                Log.d(TAG, "Starting TURN proxy for $tunnelName with network: $network (type=$networkType, handle=$networkHandle)")

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
                        effectiveWrapKey
                    )

                    if (ret == START_CALL_REQUIRES_AUTH) {
                        val msg = context.getString(R.string.turn_call_requires_auth)
                        Log.e(TAG, "TURN: $msg")
                        appendLogLine(tunnelName, msg)
                        throw TurnStartFatal(ret, msg)
                    }

                    if (ret == START_CALL_UNAVAILABLE) {
                        // Dead call: the VK call ended/was deleted or the join link is
                        // invalid. No captcha, credential rotation or stream count can
                        // revive a call that no longer exists — abort without retrying.
                        val msg = context.getString(R.string.turn_call_unavailable)
                        Log.e(TAG, "TURN: $msg")
                        appendLogLine(tunnelName, msg)
                        throw TurnStartFatal(ret, msg)
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
     * Setting userInitiatedStop / clearing the active session here, BEFORE the
     * WireGuard backend is torn down, makes a start still in flight abandon
     * itself instead of bringing a proxy up after the user disconnected.
     */
    fun beginUserStop() {
        endSession()
    }

    suspend fun stopForTunnel(tunnelName: String) =
        withContext(Dispatchers.IO) {
            beginUserStop()

            // Clear remembered stream count so next manual connect starts fresh
            lastSuccessfulStreams.remove(tunnelName)

            // Stop the proxy BEFORE acquiring the mutex so an in-flight start
            // (which holds the mutex for the whole native call) is interrupted
            // immediately instead of after its 30s startup window.
            TurnBackend.wgTurnProxyStop()

            // Only now drop the VpnService reference. Clearing it first pulled the
            // protect()/bindSocket globals out from under workers that were still
            // dialing for the whole drain window.
            TurnBackend.onVpnServiceCreated(null)

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

        /** wgTurnProxyStart: the call refuses anonymous joins (CALL_REQUIRES_AUTH). */
        const val START_CALL_REQUIRES_AUTH = -2

        /** wgTurnProxyStart: the call has ended or the link is wrong. */
        const val START_CALL_UNAVAILABLE = -4
    }
}

/**
 * A TURN start refused with a code no retry can fix — [TurnProxyManager.START_CALL_REQUIRES_AUTH]
 * or [TurnProxyManager.START_CALL_UNAVAILABLE]. The message is the user-facing text.
 */
class TurnStartFatal(val code: Int, message: String) : Exception(message)
