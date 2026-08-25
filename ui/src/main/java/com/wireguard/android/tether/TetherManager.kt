/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tether

import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.util.Log
import androidx.annotation.ChecksSdkIntAtLeast
import com.wireguard.android.Application
import com.wireguard.android.backend.TurnBackend
import com.wireguard.android.fragment.TunnelState
import com.wireguard.android.util.ScreenStateMonitor
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import org.json.JSONObject

sealed interface TetherState {
    data object Idle : TetherState
    data object Starting : TetherState
    data class Active(
        val ssid: String,
        val passphrase: String,
        val host: String,
        val port: Int,
        /**
         * Devices seen within the native side's client TTL (five minutes) — a
         * device that walked away is still counted for a while, which is why
         * [connections] is shown next to it rather than instead of it.
         */
        val clients: Int,
        /** Connections open right now: the one number that moves in real time. */
        val connections: Long,
        val bytesUp: Long,
        val bytesDown: Long,
    ) : TetherState

    data class Failed(val reason: TetherError) : TetherState
}

/**
 * Owns internet sharing: the access point, the native proxy and the state the UI
 * renders.
 *
 * The tie to the tunnel is deliberately one-way. Sharing dies the moment the
 * tunnel does — a client left on an access point whose door leads nowhere is
 * confusing — but a tunnel coming back up never revives sharing on its own.
 */
class TetherManager(private val context: Context) {

    private val _state = MutableStateFlow<TetherState>(TetherState.Idle)
    val state: StateFlow<TetherState> = _state.asStateFlow()

    private val lock = Mutex()
    private var accessPoint: TetherAccessPoint? = null

    /**
     * What the user last asked for, written before anything suspends.
     *
     * Turning sharing on is not instantaneous and never was: the caller reads the
     * tunnel's config (a suspending call) before [start] is even entered, and
     * raising the access point takes up to [AP_START_TIMEOUT_MS] after it. An
     * "off" can land anywhere in there. Queueing it behind the lock is no answer —
     * by the time it ran, the hotspot the user had just switched off was already
     * up. So the intent is recorded up front and [start] re-reads it at every
     * point where it has just given up the thread.
     */
    @Volatile
    private var wanted = false

    /**
     * The coroutine currently inside [start], or null.
     *
     * Cancelling it is how a stop that lands mid-start gets its answer without
     * waiting out a lock [start] can hold for twenty seconds — which is what made
     * the tunnel teardown (it calls [stopAndAwait] first) sit there looking hung.
     * [start]'s CancellationException branch already gives the access point back
     * and clears the Starting state, which is exactly what a stop wants.
     */
    @Volatile
    private var startJob: Job? = null

    /**
     * Consecutive stats reads that found no proxy. One is not a verdict: readStats
     * also reports a zero port when the JNI call or the JSON parse failed, and a
     * single hiccup there must not take a working session down.
     */
    private var statsMisses = 0

    /**
     * When the current run of "nothing is using sharing" began, on the
     * elapsed-realtime clock, or zero while something is.
     *
     * A timestamp rather than a countdown of ticks, because the ticks are not a
     * clock: the poll drops to [IDLE_POLL_MS] with the screen off, and a dozing
     * device suspends the delay altogether. Measuring elapsed time means a tick
     * that arrives late still reports the real span — the auto-off can fire late,
     * which nobody minds, and never early, which would take an access point away
     * from under a user who was about to connect. elapsedRealtime and not
     * currentTimeMillis: it counts through sleep and cannot be moved by NTP.
     */
    private var idleSince = 0L

    /** Total bytes at the previous tick; see [checkIdleLocked]. */
    private var lastTraffic = 0L

    // Lets lint treat this property as a NewApi gate for the LocalOnlyHotspotAp
    // construction below — without the annotation lint can't follow a named
    // boolean property as an SDK check, so don't delete it as noise.
    @get:ChecksSdkIntAtLeast(api = Build.VERSION_CODES.O)
    val isSupported: Boolean get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O

    init {
        applicationScope.launch {
            Application.getTunnelStateTracker().uiState.collect { ui ->
                val sharing = _state.value is TetherState.Active || _state.value is TetherState.Starting
                if (!sharing) return@collect
                if (ui.state == TunnelState.Disconnected || ui.state == TunnelState.Failed) {
                    Log.d(TAG, "tunnel is ${ui.state}; tearing sharing down")
                    shutdown(TetherState.Failed(TetherError.TUNNEL_DOWN))
                }
            }
        }

        // The shade entry follows the state and nothing else, so a session that
        // dies on its own takes its notification with it.
        applicationScope.launch {
            state.collect { s ->
                if (s is TetherState.Active) TetherNotification.show(context, s)
                else TetherNotification.hide(context)
            }
        }

        // Counters used to be polled by the sharing sheet, which meant they were
        // only read while someone was looking at them — and so was the one check
        // that notices the native proxy retiring itself (see refreshStats). Polling
        // belongs to the session, not to a screen; the sheet and the notification
        // now just render what lands in the flow.
        //
        // collectLatest, so the loop exists exactly while the session does: every
        // counter update re-enters it (delay first, so this never spins) and
        // leaving Active cancels it outright.
        applicationScope.launch {
            state.collectLatest { s ->
                if (s !is TetherState.Active) return@collectLatest
                while (true) {
                    // Screen off means nobody is reading the counters; the tick is
                    // kept, at a fraction of the rate, because it is also the
                    // liveness check on the native proxy.
                    delay(if (ScreenStateMonitor.screenOn.value) ACTIVE_POLL_MS else IDLE_POLL_MS)
                    refreshStats()
                }
            }
        }
    }

    /**
     * Records that the user has asked for sharing, synchronously.
     *
     * Callers reach [start] only through a suspending read of the tunnel's config,
     * so this is the last moment still ordered with respect to the tap that asked
     * for it. See [wanted].
     */
    fun requestStart() {
        wanted = true
    }

    suspend fun start(dnsServers: List<String>, tunnelAddresses: List<String>) {
        // LocalOnlyHotspotAp requires API 26 — it is the floor of startLocalOnlyHotspot.
        if (!isSupported) {
            _state.value = TetherState.Failed(TetherError.AP_UNAVAILABLE)
            return
        }
        val job = currentCoroutineContext()[Job]
        lock.withLock {
            if (_state.value is TetherState.Active) return
            // Published first, so that a stop landing anywhere from here on has
            // something to cancel. Left in place on the early returns below:
            // cancelling a coroutine that already finished does nothing, so a stale
            // entry costs one dead reference and no correctness.
            startJob = job
            if (!wanted) {
                // Switched off again — either while the caller was still reading the
                // tunnel's config, which suspends before start() is even entered, or
                // in the instant before the line above gave that stop something to
                // cancel. Nothing has been raised yet, so the whole job here is not
                // to raise it: without this check the "off" ran against a session
                // that did not exist and this coroutine went on to bring up an access
                // point the user had already dismissed.
                Log.d(TAG, "sharing was switched off before the access point was raised")
                return
            }
            // The collector below only reacts to a change, so a tunnel that is
            // already down would leave an access point standing with nothing
            // behind it. Refuse up front instead.
            if (Application.getTunnelStateTracker().uiState.value.state != TunnelState.Connected) {
                _state.value = TetherState.Failed(TetherError.TUNNEL_DOWN)
                return
            }
            _state.value = TetherState.Starting

            val ap = LocalOnlyHotspotAp(context)
            val info = try {
                // startLocalOnlyHotspot is flaky on vendor firmware, and its
                // contract offers no deadline: some builds never call back at all.
                // Unbounded, that pins the state at Starting forever and deadlocks
                // stop() on this very mutex — only killing the app recovers.
                withTimeout(AP_START_TIMEOUT_MS) {
                    ap.start(onSystemStop = { onAccessPointStopped(ap) })
                }
            } catch (e: TimeoutCancellationException) {
                // Must precede the CancellationException branch: this IS one, and
                // that branch rethrows, which would report a firmware timeout to
                // the caller as if the caller had cancelled. withTimeout has
                // already cancelled ap.start(), so its invokeOnCancellation closed
                // any reservation that arrived late; ap.stop() is the belt to that
                // pair of braces.
                Log.w(TAG, "startLocalOnlyHotspot did not call back within $AP_START_TIMEOUT_MS ms")
                ap.stop()
                _state.value = TetherState.Failed(TetherError.AP_UNAVAILABLE)
                return
            } catch (e: CancellationException) {
                // The real trigger here: the caller's scope (the sharing sheet's
                // lifecycle scope) dying while the access point is still coming
                // up — e.g. the user closes the sheet mid-start. ap.start() tears
                // its own reservation down on cancellation, but this call is what
                // set _state to Starting, so it must not leave that behind for a
                // future connect attempt to inherit. Never swallow the
                // cancellation — rethrow so structured concurrency still sees it.
                ap.stop()
                _state.value = TetherState.Idle
                throw e
            } catch (e: TetherApException) {
                Log.w(TAG, "access point failed", e)
                _state.value = TetherState.Failed(e.reason)
                return
            }
            accessPoint = ap
            if (!wanted) {
                // Switched off while the access point was coming up. Cancellation
                // normally gets here first (see cancelPendingStart), but a stop that
                // arrived before this coroutine ever reached the lock had no job to
                // cancel — the intent flag is what carries that one.
                Log.d(TAG, "sharing was switched off while the access point was coming up")
                ap.stop()
                accessPoint = null
                _state.value = TetherState.Idle
                return
            }

            // applicationScope runs on Dispatchers.Main.immediate, so every native
            // call here would otherwise block the UI thread. wgTetherStart binds a
            // socket and wgTetherStop waits out the connection drain — an ANR at
            // exactly the moment the tunnel is coming down. The Go side serialises
            // itself with its own mutex, so nothing is lost by leaving the main
            // thread.
            val rc = withContext(Dispatchers.IO) {
                TurnBackend.wgTetherStart(
                    info.bindIp,
                    DEFAULT_PORT,
                    dnsServers.joinToString(","),
                    tunnelAddresses.joinToString(","),
                )
            }
            if (rc != 0) {
                // -4 is the native side refusing to share without the tunnel's own
                // addresses to check egress against. It is reported as a plain
                // failure rather than its own wording: the user cannot act on it,
                // and it only happens when the config could not be read at all.
                Log.w(TAG, "wgTetherStart returned $rc")
                ap.stop()
                accessPoint = null
                _state.value = TetherState.Failed(
                    if (rc == -2 || rc == -3) TetherError.BIND_FAILED else TetherError.NATIVE_ERROR
                )
                return
            }

            val stats = readStats()
            idleSince = 0L
            lastTraffic = stats.up + stats.down
            _state.value = TetherState.Active(
                ssid = info.ssid,
                passphrase = info.passphrase,
                host = info.bindIp,
                port = stats.port,
                clients = stats.clients,
                connections = stats.conns,
                bytesUp = stats.up,
                bytesDown = stats.down,
            )
            Log.d(TAG, "sharing on ${info.ssid} via ${info.bindIp}:${stats.port}")
        }
    }

    fun stop() {
        // Both of these are synchronous with the tap on purpose. A stop has to be
        // able to overtake a start that has not reached the lock yet, and it cannot
        // do that from inside the coroutine below. See [wanted].
        wanted = false
        cancelPendingStart()
        applicationScope.launch { shutdown(TetherState.Idle) }
    }

    /**
     * Cancels a start still in flight instead of queueing behind it.
     *
     * [start] holds the lock for as long as the access point takes to come up, and
     * on vendor firmware that is the full [AP_START_TIMEOUT_MS]. A teardown that
     * merely waited for the lock made the user's "disconnect" — which goes through
     * [stopAndAwait] before WireGuard comes down at all — sit there looking hung
     * for twenty seconds. Cancelling lands in [start]'s CancellationException
     * branch, which gives the access point back and clears the Starting state.
     */
    private fun cancelPendingStart() {
        startJob?.cancel()
    }

    /**
     * Stops sharing and does not return until it is actually down.
     *
     * The tunnel teardown path needs this shape. The state collector above only
     * learns the tunnel is gone once WireGuard is already down, and in that
     * window a tethered client's next request dials a deliberately unprotected
     * upstream socket with no VPN left to catch it — straight out of the carrier
     * with the user's real IP. Called first on the way down, this closes the
     * window; the collector stays as the backstop it was always meant to be.
     */
    suspend fun stopAndAwait() {
        wanted = false
        cancelPendingStart()
        shutdown(TetherState.Idle)
    }

    /**
     * The user refused the runtime permission the access point cannot start
     * without.
     *
     * It lands as state rather than being handled inside the sheet because the
     * switch renders from this flow: a refusal that only printed a status line
     * left the switch sitting in the ON position with nothing behind it.
     *
     * A refusal can only arrive before sharing was ever started, so an Active or
     * Starting session here belongs to something else and is left alone.
     */
    suspend fun onPermissionDenied() {
        wanted = false
        lock.withLock {
            if (_state.value is TetherState.Active || _state.value is TetherState.Starting) return@withLock
            _state.value = TetherState.Failed(TetherError.PERMISSION_DENIED)
        }
    }

    /**
     * Refreshes the counters of an already active session; a no-op otherwise.
     *
     * Takes the same lock shutdown() uses. Without it, a tunnel-down teardown
     * landing between this reading the old Active and writing the new one would
     * get silently overwritten back to a stale Active — the proxy and access
     * point are genuinely gone, but the poll loop in init (which runs every
     * couple of seconds for as long as a session lasts) would keep reporting
     * sharing as alive. The check is re-done under the lock rather than trusted
     * from whatever the caller last observed, since that observation is exactly
     * what shutdown() may have invalidated.
     */
    private suspend fun refreshStats() {
        lock.withLock {
            val stats = readStats()
            val active = _state.value as? TetherState.Active ?: return@withLock
            // A zero port means the native side is holding no proxy at all: its
            // accept loop hit an error no retry could fix and retired itself. But
            // readStats reports the same zero when the JNI call threw or the JSON
            // would not parse, and a single hiccup there must not take a working
            // session down — so it takes two in a row to count as a verdict.
            if (stats.port == 0) {
                statsMisses++
                if (statsMisses < STATS_MISSES_BEFORE_TEARDOWN) {
                    Log.w(TAG, "stats read reported no proxy ($statsMisses); waiting for the next tick")
                    return@withLock
                }
                Log.w(TAG, "sharing proxy is gone on the native side; tearing sharing down")
                shutdownLocked(TetherState.Failed(TetherError.NATIVE_ERROR))
                return@withLock
            }
            statsMisses = 0
            checkIdleLocked(stats)
            if (_state.value !is TetherState.Active) return@withLock
            _state.value = active.copy(
                // The port is refreshed too, and that is not redundant: start()
                // publishes whatever the very first read said, so a read that failed
                // there left the session carrying port 0 for the rest of its life —
                // the sheet, the notification and the PAC URL all offering ":0"
                // while every later poll knew better.
                port = stats.port,
                clients = stats.clients,
                connections = stats.conns,
                bytesUp = stats.up,
                bytesDown = stats.down,
            )
        }
    }

    /**
     * Switches an unused session off after [AUTO_OFF_IDLE_MS].
     *
     * "Unused" means no traffic, not no associated stations. Asking the platform
     * who is joined to the access point is not an option: the only API that answers
     * that for a local-only hotspot is WifiManager.registerLocalOnlyHotspotSoftApCallback,
     * which lives in system-current.txt and is unreachable from a normal app, and
     * /proc/net/arp has been closed since Android 10. Traffic is a fair stand-in
     * here precisely because sharing runs without NAT: our proxy is the client's
     * only way out, so a client that sends nothing through it is a client that is
     * not using the hotspot. What it cannot distinguish is a device joined and
     * merely quiet, which is why AUTO_OFF_IDLE_MS is measured in hours.
     *
     * The three conditions are deliberate. clients is the count of devices the
     * native side saw within its five-minute TTL, so a laptop joined to the access
     * point but sitting quiet reads as zero — on its own it would pull the hotspot
     * out from under someone still using it. conns covers the device holding an
     * idle connection open, and the byte totals cover the short request that began
     * and ended entirely between two ticks, which with the screen off are thirty
     * seconds apart.
     *
     * Called with the lock held and only from [refreshStats], so it may tear the
     * session down in place.
     */
    private suspend fun checkIdleLocked(stats: Stats) {
        if (!TetherSettings.isAutoOffEnabled(context)) {
            idleSince = 0L
            return
        }
        val traffic = stats.up + stats.down
        val busy = stats.clients > 0 || stats.conns > 0L || traffic != lastTraffic
        lastTraffic = traffic
        if (busy) {
            idleSince = 0L
            return
        }
        val now = SystemClock.elapsedRealtime()
        if (idleSince == 0L) {
            idleSince = now
            return
        }
        val idleFor = now - idleSince
        if (idleFor < AUTO_OFF_IDLE_MS) return
        Log.d(TAG, "nothing used sharing for ${idleFor / 60_000} min; switching it off")
        shutdownLocked(TetherState.Failed(TetherError.AUTO_OFF))
        // After the teardown, so the state collector's hide() — which cancels the
        // ongoing notification — cannot race ahead of the notice that replaces it.
        TetherNotification.showAutoOff(context)
    }

    /**
     * The platform took the access point away from us — the user toggled Wi-Fi,
     * system tethering claimed the radio, the firmware restarted. Sharing is over
     * whether we like it or not, so publish that instead of leaving the sheet
     * advertising a network that no longer exists.
     *
     * The identity check matters: this fires from a platform callback thread and
     * can land after a newer start() has already replaced the access point, in
     * which case tearing down would kill a session this event knows nothing about.
     */
    private fun onAccessPointStopped(ap: TetherAccessPoint) {
        applicationScope.launch {
            lock.withLock {
                if (accessPoint !== ap) return@withLock
                Log.w(TAG, "access point stopped by the system; tearing sharing down")
                shutdownLocked(TetherState.Failed(TetherError.AP_UNAVAILABLE))
            }
        }
    }

    private suspend fun shutdown(next: TetherState) {
        // Every teardown is also an answer to "is sharing still wanted?", including
        // the ones that do not come from the switch — a tunnel that fell over, an
        // access point the system took back.
        wanted = false
        cancelPendingStart()
        lock.withLock { shutdownLocked(next) }
    }

    private suspend fun shutdownLocked(next: TetherState) {
        wanted = false
        startJob = null
        statsMisses = 0
        idleSince = 0L
        lastTraffic = 0L
        // Off the main thread: this one can block for the proxy's drain grace.
        withContext(Dispatchers.IO) { TurnBackend.wgTetherStop() }
        accessPoint?.stop()
        accessPoint = null
        _state.value = next
    }

    /**
     * The native proxy took itself down: a fatal accept error, or the egress guard
     * catching traffic that would have left outside the tunnel.
     *
     * Pushed up from Go rather than waited for. The stats poll below finds it too,
     * but a poll is two seconds apart with the screen on and thirty with it off,
     * and every one of those seconds is spent advertising an SSID, a password and
     * a QR for a proxy that will never serve another client.
     */
    fun onNativeStopped(reason: String) {
        applicationScope.launch {
            lock.withLock {
                val sharing = _state.value is TetherState.Active || _state.value is TetherState.Starting
                if (!sharing) return@withLock
                Log.w(TAG, "native sharing proxy retired itself ($reason); tearing sharing down")
                shutdownLocked(TetherState.Failed(TetherError.NATIVE_ERROR))
            }
        }
    }

    private data class Stats(
        val port: Int,
        val clients: Int,
        val conns: Long,
        val up: Long,
        val down: Long,
    )

    private suspend fun readStats(): Stats {
        val raw = try {
            withContext(Dispatchers.IO) { TurnBackend.wgTetherStats() }
        } catch (e: Throwable) {
            Log.w(TAG, "wgTetherStats failed", e)
            null
        } ?: return EMPTY_STATS
        return try {
            val json = JSONObject(raw)
            Stats(
                port = json.optInt("port"),
                clients = json.optInt("clients"),
                conns = json.optLong("conns"),
                up = json.optLong("up"),
                down = json.optLong("down"),
            )
        } catch (e: Exception) {
            Log.w(TAG, "cannot parse stats: $raw", e)
            EMPTY_STATS
        }
    }

    companion object {
        private const val TAG = "WireGuard/TetherManager"

        // A zero port reads as "the native side holds no proxy", which is exactly
        // what an unreadable stats call means; see refreshStats.
        private val EMPTY_STATS = Stats(port = 0, clients = 0, conns = 0, up = 0, down = 0)

        private const val AP_START_TIMEOUT_MS = 20_000L

        // Consecutive empty stats reads before a session is declared dead. Two, so
        // that one unreadable poll is a hiccup and not a teardown.
        private const val STATS_MISSES_BEFORE_TEARDOWN = 2

        // Matches TunnelStateTracker's cadence, so the sheet's counters move at the
        // rate the rest of the app's numbers do.
        private const val ACTIVE_POLL_MS = 2_000L
        private const val IDLE_POLL_MS = 30_000L

        // How long a session may go unused before it switches itself off. Two hours
        // rather than the half hour this started at, because "unused" is measured in
        // traffic and not in associated stations — see checkIdleLocked. A window that
        // short cut off a device that was joined and merely quiet; two hours is long
        // enough that anything actually using the hotspot has emitted something, and
        // still short enough that one forgotten at bedtime is not burning the radio
        // in the morning. Only consulted while TetherSettings.isAutoOffEnabled(),
        // which defaults to on.
        private const val AUTO_OFF_IDLE_MS = 2 * 60 * 60 * 1000L

        const val DEFAULT_PORT = 8888
    }
}
