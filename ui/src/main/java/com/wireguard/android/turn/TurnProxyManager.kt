/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.SystemClock
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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Lightweight manager for per-tunnel TURN client processes and logs.
 *
 * Uses PhysicalNetworkMonitor to track stable internet connections and 
 * triggers restarts when the underlying network or IP changes.
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

    @Volatile private var activeSettings: TurnSettings? = null
    @Volatile private var userInitiatedStop: Boolean = false

    /**
     * Reports a TURN session that cannot be restored by retrying, so the caller can
     * tell the user and take the tunnel down. Wired to TunnelManager in Application.
     *
     * This is the Java-side counterpart of the native terminal-failure report
     * (TurnBackend.onTurnFatal): the native accounting only fires once workers have
     * been launched and have all given up, so a proxy that never starts at all —
     * JNI registration timeout, a failing wgTurnProxyStart, a captcha lockout during
     * startup — would otherwise leave the VPN UP over a dead 127.0.0.1 route with
     * nothing to report it.
     */
    @Volatile var onUnrecoverableFailure: ((tunnelName: String, reason: String) -> Unit)? = null

    /** One report per session; native and Java paths can both reach the same failure. */
    private val failureReported = AtomicBoolean(false)

    // Network tracking
    private val networkMonitor = PhysicalNetworkMonitor(context)

    /**
     * The path TURN is currently running over: the physical network plus the
     * identity of its addresses. Comparing the whole path rather than just the
     * [Network] catches a re-addressing that keeps the same Network object — a
     * DHCP renewal, or roaming between access points — which kills every socket
     * the proxy holds while looking like "nothing changed".
     */
    @Volatile private var lastKnownPath: PhysicalNetworkMonitor.NetworkPath? = null

    private val lastKnownNetwork: Network?
        get() = lastKnownPath?.network

    /**
     * Wall-clock (elapsedRealtime) instant until which a network change only defers
     * the restart instead of running it. See [NETWORK_MONITOR_GRACE_MS].
     */
    @Volatile private var networkGraceUntilMs: Long = 0L

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
            networkMonitor.bestPath.collectLatest { path ->
                if (path != null) {
                    handleNetworkChange(path)
                }
            }
        }
    }

    /**
     * Central handler for network changes from PhysicalNetworkMonitor.
     * The monitor already provides debounced stable paths.
     */
    private suspend fun handleNetworkChange(path: PhysicalNetworkMonitor.NetworkPath) {
        if (userInitiatedStop || activeTunnelName == null) return

        // 1. Initial baseline setting
        if (lastKnownPath == null) {
            Log.d(TAG, "Setting initial network baseline: $path")
            lastKnownPath = path
            return
        }

        // 2. Stability check — the network AND the addresses it carries.
        if (lastKnownPath == path) {
            Log.d(TAG, "Network state stable for ${path.network}")
            return
        }
        if (lastKnownPath?.network == path.network) {
            Log.d(TAG, "Same network ${path.network} re-addressed — treating as a change")
        }

        // 3. Real change confirmed — but not necessarily worth acting on yet.
        // Restarting TURN takes the proxy down for at least 600ms plus a full
        // startup, and while the tunnel is still waiting for its first WireGuard
        // handshake that gap is the difference between a connect that lands and one
        // that fails. Inside the grace window, wait it out and re-decide against the
        // network that is actually current by then: a validation flap that moved the
        // monitor's winner to cellular and back resolves to "nothing changed", while
        // a genuine handover is still honoured — just after the handshake window.
        // A newer network cancels this branch outright (collectLatest).
        val graceRemaining = networkGraceUntilMs - SystemClock.elapsedRealtime()
        if (graceRemaining > 0) {
            Log.d(TAG, "Network change during connect grace — deferring ${graceRemaining}ms")
            delay(graceRemaining)
            if (userInitiatedStop || activeTunnelName == null) return
            val settled = networkMonitor.currentPath
            if (settled == null || settled == lastKnownPath) {
                Log.d(TAG, "Network settled back to $lastKnownPath — no restart needed")
                return
            }
            Log.d(TAG, "Network change confirmed after grace: $settled. Restarting TURN.")
            lastKnownPath = settled
        } else {
            Log.d(TAG, "Network change confirmed: $path. Restarting TURN.")
            lastKnownPath = path
        }
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
        // Attempts that actually got to talk to the network, counted separately from
        // [attempts] (which only drives the backoff). Being offline is not a TURN
        // failure: a lift or a tunnel would otherwise burn through the budget and
        // disconnect a user whose network is simply about to come back.
        var validatedFailures = 0
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

            // The selected physical path may have changed while validation
            // was pending. Use the monitor's current, non-debounced winner.
            lastKnownPath = networkMonitor.currentPath

            attempts++
            val onValidatedNetwork = networkMonitor.validated.value
            Log.d(TAG, "Starting TURN for $name (Attempt $attempts)")

            // startForTunnelInternal бросает на фатальных кодах старта: -2
            // (нужна авторизация) и -4 (звонок удалён / ссылка мертва). Ни
            // одно из них не лечится повтором, а раньше исключение улетало из
            // collectLatest и убивало весь scope. Гасим сессию так же, как
            // делает onTunnelEstablished, и выходим из цикла ретраев.
            val success = try {
                startForTunnelInternal(name, settings)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.w(TAG, "TURN restart failed fatally — clearing session state", e)
                endSession()
                reportUnrecoverable(name, e.message ?: "TURN restart failed")
                return
            }
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

            // Give up once the network has had a fair chance and TURN still will not
            // come up. Retrying forever kept the tunnel UP over a proxy that was never
            // going to bind, so the only thing that ever ended it was the handshake
            // watchdog — three to nine minutes of "connected" with a dead route.
            if (onValidatedNetwork && ++validatedFailures >= MAX_VALIDATED_RESTART_FAILURES) {
                Log.e(TAG, "TURN restart failed $validatedFailures times on a validated network — giving up")
                endSession()
                reportUnrecoverable(name, "restart failed $validatedFailures times")
                return
            }

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

    /**
     * Drops the session so the network monitor stops treating this tunnel as
     * something to restart. Mirrors what [beginUserStop] does, but for a failure
     * rather than a user request.
     */
    private fun endSession() {
        activeTunnelName = null
        activeSettings = null
        lastKnownPath = null
        networkGraceUntilMs = 0L
        userInitiatedStop = true
    }

    /**
     * Reports a session that retrying cannot save, at most once per session. The
     * native layer may reach the same conclusion independently (every worker gave
     * up), and a second teardown would post a second notification for one failure.
     */
    private fun reportUnrecoverable(tunnelName: String, reason: String) {
        if (!failureReported.compareAndSet(false, true)) {
            Log.d(TAG, "Unrecoverable TURN failure already reported — skipping: $reason")
            return
        }
        appendLogLine(tunnelName, "TURN unrecoverable ($reason) — disconnecting")
        val handler = onUnrecoverableFailure
        if (handler == null) {
            Log.e(TAG, "No unrecoverable-failure handler registered! ($reason)")
            return
        }
        try {
            handler(tunnelName, reason)
        } catch (e: Exception) {
            Log.e(TAG, "Unrecoverable-failure handler threw", e)
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
        failureReported.set(false)

        // Initialize network baseline for the new session
        lastKnownPath = networkMonitor.currentPath
        Log.d(TAG, "Initial network for tunnel session: $lastKnownPath")

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
            // Start failed: clear session state so PhysicalNetworkMonitor does not
            // try to "restart" a tunnel that never came up — which would otherwise
            // hammer the TURN server on every network change.
            Log.w(TAG, "TURN start failed — clearing session state")
            endSession()
            return false
        }

        // Open the grace window. The caller now waits for the first WireGuard
        // handshake, and a TURN restart inside that wait is what breaks the connect;
        // a network change arriving now is deferred to the end of the window rather
        // than acted on (see handleNetworkChange). The previous code launched a
        // coroutine that slept 2s and logged — it gated nothing at all.
        networkGraceUntilMs = SystemClock.elapsedRealtime() + NETWORK_MONITOR_GRACE_MS
        Log.d(TAG, "Network monitoring gated for ${NETWORK_MONITOR_GRACE_MS}ms (handshake window)")

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

                lastKnownPath = networkMonitor.currentPath
                // Preserve the historical manual-start behavior: allow one
                // normal startup attempt even before Android publishes
                // VALIDATED. Afterward native combines the actual capability
                // with proof from the TURN handshake and strict RX path.
                TurnBackend.wgSetNetworkAvailable(1)

                // If network is still null, try one quick re-poll from monitor
                if (lastKnownPath == null) {
                    lastKnownPath = networkMonitor.currentPath
                    if (lastKnownPath == null) {
                        Log.w(TAG, "Network still null, waiting 500ms for PhysicalNetworkMonitor...")
                        delay(500)
                        lastKnownPath = networkMonitor.currentPath
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
        private const val UNVALIDATED_RETRY_INTERVAL_MS = 60_000L

        // Consecutive restart failures on a validated network before the session is
        // declared unrecoverable. Failures while the network is unvalidated do not
        // count — those are handled by the UNVALIDATED_RETRY_INTERVAL_MS wait above.
        private const val MAX_VALIDATED_RESTART_FAILURES = 5

        // How long after a successful start a network change is deferred instead of
        // acted on. Covers TunnelManager's first-handshake wait (HANDSHAKE_TIMEOUT_MS,
        // 25s) with a small margin, so a restart can no longer land in the middle of
        // the handshake the connect is being judged by.
        private const val NETWORK_MONITOR_GRACE_MS = 27_000L
    }
}
