/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.model

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.databinding.BaseObservable
import androidx.databinding.Bindable
import com.wireguard.android.Application.Companion.get
import com.wireguard.android.Application.Companion.getBackend
import com.wireguard.android.Application.Companion.getTunnelManager
import com.wireguard.android.Application.Companion.getTunnelStateTracker
import com.wireguard.android.Application.Companion.getTurnProxyManager
import com.wireguard.android.BR
import com.wireguard.android.R
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Statistics
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.configStore.ConfigStore
import com.wireguard.android.databinding.ObservableSortedKeyedArrayList
import com.wireguard.android.turn.TurnConfigProcessor
import com.wireguard.android.turn.TurnSettings
import com.wireguard.android.turn.TurnSettingsStore
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.util.UserKnobs
import com.wireguard.android.util.applicationScope
import com.wireguard.config.Config
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Maintains and mediates changes to the set of available WireGuard tunnels,
 */
class TunnelManager(
    private val configStore: ConfigStore,
    private val turnSettingsStore: TurnSettingsStore,
) : BaseObservable() {
    private val tunnels = CompletableDeferred<ObservableSortedKeyedArrayList<String, ObservableTunnel>>()
    private val context: Context = get()
    private val tunnelMap: ObservableSortedKeyedArrayList<String, ObservableTunnel> = ObservableSortedKeyedArrayList(TunnelComparator)
    private var haveLoaded = false

    // Per-tunnel background watchdog jobs. A watchdog tears the tunnel down if it
    // stays UP without a working WireGuard handshake (mid-session DPI/network death).
    private val handshakeWatchdogs = ConcurrentHashMap<String, Job>()

    private fun addToList(name: String, config: Config?, state: Tunnel.State): ObservableTunnel {
        val tunnel = ObservableTunnel(this, name, config, state)
        var turnSettings = turnSettingsStore.load(name)
        if (turnSettings == null && config != null) {
            turnSettings = TurnConfigProcessor.extractTurnSettings(config)
            if (turnSettings != null) {
                turnSettingsStore.save(name, turnSettings)
            }
        }
        tunnel.onTurnSettingsChanged(turnSettings)
        tunnelMap.add(tunnel)
        return tunnel
    }

    suspend fun getTunnels(): ObservableSortedKeyedArrayList<String, ObservableTunnel> = tunnels.await()

    suspend fun create(
        name: String,
        config: Config?,
        turnSettings: TurnSettings? = null,
    ): ObservableTunnel = withContext(Dispatchers.Main.immediate) {
        if (Tunnel.isNameInvalid(name))
            throw IllegalArgumentException(context.getString(R.string.tunnel_error_invalid_name))
        if (tunnelMap.containsKey(name))
            throw IllegalArgumentException(context.getString(R.string.tunnel_error_already_exists, name))
        
        val configWithTurn = TurnConfigProcessor.injectTurnSettings(config!!, turnSettings)
        val savedConfig = withContext(Dispatchers.IO) { configStore.create(name, configWithTurn) }
        withContext(Dispatchers.IO) { turnSettingsStore.save(name, turnSettings) }
        addToList(name, savedConfig, Tunnel.State.DOWN)
    }

    suspend fun delete(tunnel: ObservableTunnel) = withContext(Dispatchers.Main.immediate) {
        val originalState = tunnel.state
        val wasLastUsed = tunnel == lastUsedTunnel
        // Make sure nothing touches the tunnel.
        if (wasLastUsed)
            lastUsedTunnel = null
        tunnelMap.remove(tunnel)
        try {
            if (originalState == Tunnel.State.UP)
                withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.DOWN, null) }
            try {
                withContext(Dispatchers.IO) {
                    configStore.delete(tunnel.name)
                    turnSettingsStore.delete(tunnel.name)
                }
            } catch (e: Throwable) {
                if (originalState == Tunnel.State.UP)
                    withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.UP, tunnel.config) }
                throw e
            }
        } catch (e: Throwable) {
            // Failure, put the tunnel back.
            tunnelMap.add(tunnel)
            if (wasLastUsed)
                lastUsedTunnel = tunnel
            throw e
        }
    }

    @get:Bindable
    var lastUsedTunnel: ObservableTunnel? = null
        private set(value) {
            if (value == field) return
            field = value
            notifyPropertyChanged(BR.lastUsedTunnel)
            applicationScope.launch { UserKnobs.setLastUsedTunnel(value?.name) }
        }

    suspend fun getTunnelConfig(tunnel: ObservableTunnel): Config = withContext(Dispatchers.Main.immediate) {
        val config = withContext(Dispatchers.IO) { configStore.load(tunnel.name) }
        val extractedTurn = TurnConfigProcessor.extractTurnSettings(config)
        if (extractedTurn != null) {
            withContext(Dispatchers.IO) {
                turnSettingsStore.save(tunnel.name, extractedTurn)
            }
            tunnel.onTurnSettingsChanged(extractedTurn)
        }
        tunnel.onConfigChanged(config)!!
    }

    fun onCreate() {
        applicationScope.launch {
            try {
                onTunnelsLoaded(
                    withContext(Dispatchers.IO) { configStore.enumerate() },
                    withContext(Dispatchers.IO) { getBackend().runningTunnelNames },
                )
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }
    }

    private fun onTunnelsLoaded(present: Iterable<String>, running: Collection<String>) {
        for (name in present)
            addToList(name, null, if (running.contains(name)) Tunnel.State.UP else Tunnel.State.DOWN)
        applicationScope.launch {
            val lastUsedName = UserKnobs.lastUsedTunnel.first()
            if (lastUsedName != null)
                lastUsedTunnel = tunnelMap[lastUsedName]
            haveLoaded = true
            restoreState(true)
            tunnels.complete(tunnelMap)
        }
    }

    private fun refreshTunnelStates() {
        applicationScope.launch {
            try {
                val running = withContext(Dispatchers.IO) { getBackend().runningTunnelNames }
                for (tunnel in tunnelMap)
                    tunnel.onStateChanged(if (running.contains(tunnel.name)) Tunnel.State.UP else Tunnel.State.DOWN)
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }
    }

    suspend fun restoreState(force: Boolean) {
        if (!haveLoaded || (!force && !UserKnobs.restoreOnBoot.first()))
            return
        val previouslyRunning = UserKnobs.runningTunnels.first()
        if (previouslyRunning.isEmpty()) return
        withContext(Dispatchers.IO) {
            try {
                tunnelMap.filter { previouslyRunning.contains(it.name) }.map { async(Dispatchers.IO + SupervisorJob()) { setTunnelState(it, Tunnel.State.UP, restore = true) } }
                    .awaitAll()
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }
    }

    suspend fun saveState() {
        UserKnobs.setRunningTunnels(tunnelMap.filter { it.state == Tunnel.State.UP }.map { it.name }.toSet())
    }

    /** Names of currently-UP tunnels minus [excludedName] — used to persist a "going DOWN" state pre-emptively. */
    private fun runningTunnelNamesExcluding(excludedName: String): Set<String> =
        tunnelMap.filter { it.state == Tunnel.State.UP && it.name != excludedName }
            .map { it.name }.toSet()

    suspend fun setTunnelConfig(
        tunnel: ObservableTunnel,
        config: Config,
        turnSettings: TurnSettings? = null,
        reconnect: Boolean = true,
    ): Config = withContext(Dispatchers.Main.immediate) {
        // When reconnect is false, persist the new config (disk + in-memory) but leave
        // a running tunnel untouched — it applies on the next connect via getConfigAsync.
        val bounce = reconnect && tunnel.state == Tunnel.State.UP
        if (bounce) {
            setTunnelState(tunnel, Tunnel.State.DOWN)
        }

        val configWithTurn = TurnConfigProcessor.injectTurnSettings(config, turnSettings)
        val result = tunnel.onConfigChanged(
            withContext(Dispatchers.IO) {
                configStore.save(tunnel.name, configWithTurn)
                configWithTurn
            },
        )!!
            .also {
                withContext(Dispatchers.IO) {
                    turnSettingsStore.save(tunnel.name, turnSettings)
                    tunnel.onTurnSettingsChanged(turnSettingsStore.load(tunnel.name))
                }
            }
        
        if (bounce) {
            setTunnelState(tunnel, Tunnel.State.UP)
        }

        result
    }

    suspend fun setTunnelName(tunnel: ObservableTunnel, name: String): String = withContext(Dispatchers.Main.immediate) {
        if (Tunnel.isNameInvalid(name))
            throw IllegalArgumentException(context.getString(R.string.tunnel_error_invalid_name))
        if (tunnelMap.containsKey(name)) {
            throw IllegalArgumentException(context.getString(R.string.tunnel_error_already_exists, name))
        }
        val originalState = tunnel.state
        val wasLastUsed = tunnel == lastUsedTunnel
        // Make sure nothing touches the tunnel.
        if (wasLastUsed)
            lastUsedTunnel = null
        tunnelMap.remove(tunnel)
        var throwable: Throwable? = null
        var newName: String? = null
        try {
            if (originalState == Tunnel.State.UP)
                withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.DOWN, null) }
            withContext(Dispatchers.IO) {
                configStore.rename(tunnel.name, name)
                turnSettingsStore.rename(tunnel.name, name)
            }
            newName = tunnel.onNameChanged(name)
            if (originalState == Tunnel.State.UP)
                withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.UP, tunnel.config) }
        } catch (e: Throwable) {
            throwable = e
            // On failure, we don't know what state the tunnel might be in. Fix that.
            getTunnelState(tunnel)
        }
        // Add the tunnel back to the manager, under whatever name it thinks it has.
        tunnelMap.add(tunnel)
        if (wasLastUsed)
            lastUsedTunnel = tunnel
        if (throwable != null)
            throw throwable
        newName!!
    }

    suspend fun setTunnelState(
        tunnel: ObservableTunnel,
        state: Tunnel.State,
        restore: Boolean = false,
    ): Tunnel.State = withContext(Dispatchers.Main.immediate) {
        if (state == tunnel.state) return@withContext state
        
        // If we are already UP and someone (like AlwaysOnCallback) requests UP again,
        // double check with backend if it is really running.
        if (state == Tunnel.State.UP && tunnel.state == Tunnel.State.UP) {
            val runningNames = withContext(Dispatchers.IO) { getBackend().runningTunnelNames }
            if (runningNames.contains(tunnel.name)) {
                Log.d(TAG, "Skip redundant UP call for ${tunnel.name}, already running")
                return@withContext state
            }
        }

        // Hoisted above the try so the post-failure cleanup block can read them.
        val turn = tunnel.turnSettings
        val turnEnabled = turn != null && turn.enabled
        // TURN starts when explicitly requesting UP, or on TOGGLE from DOWN.
        val shouldStartTurn = state == Tunnel.State.UP || (state == Tunnel.State.TOGGLE && tunnel.state == Tunnel.State.DOWN)

        var newState = tunnel.state
        var throwable: Throwable? = null
        try {
            var configToUse = tunnel.getConfigAsync()

            // Stop TURN when tunnel goes DOWN
            val shouldStopTurn = state == Tunnel.State.DOWN || (state == Tunnel.State.TOGGLE && tunnel.state == Tunnel.State.UP)

            // Pre-emptively persist "tunnel going DOWN" before backend teardown.
            // getBackend().setState(DOWN) calls stopSelf() asynchronously — if Android
            // restarts the VPN service (AlwaysOn) before saveState() runs at the end,
            // restoreState() would read stale runningTunnels and auto-reconnect.
            // Writing {} here (after DataStore edit() commits) eliminates that race window.
            if (shouldStopTurn) {
                UserKnobs.setRunningTunnels(runningTunnelNamesExcluding(tunnel.name))
            }

            if (turnEnabled && shouldStartTurn) {
                configToUse = TurnConfigProcessor.modifyConfigForActiveTurn(configToUse, turn)

                // Start VpnService early so TURN sockets can be protected before WireGuard starts
                if (getBackend() is GoBackend) {
                    get().startService(Intent(get(), GoBackend.VpnService::class.java))
                }

                // Start TURN proxy BEFORE WireGuard so the first WG handshake has a working proxy
                Log.d(TAG, "Starting TURN proxy before WireGuard...")
                val turnStarted = withContext(Dispatchers.IO) {
                    getTurnProxyManager().onTunnelEstablished(tunnel.name, turn)
                }
                if (!turnStarted) {
                    // TURN failed — stop VpnService so VPN icon doesn't stay active with no traffic.
                    if (getBackend() is GoBackend) {
                        get().stopService(Intent(get(), GoBackend.VpnService::class.java))
                    }
                    throw Exception(context.getString(R.string.turn_start_failed))
                }
            }

            // WireGuard stops first, then TURN — mirror image of connect order
            newState = withContext(Dispatchers.IO) { getBackend().setState(tunnel, state, configToUse) }

            // Atomic connect: the backend reports UP the moment the TUN interface is
            // created, before any WireGuard handshake. If DPI blocks the TURN path the
            // handshake never completes, leaving a "connected" VPN with a dead route.
            // Wait for the first real handshake; if none arrives, tear everything down
            // so the attempt fails cleanly instead of staying UP forever.
            // Skipped for restore (auto-reconnect): there the tunnel comes up
            // optimistically and the handshake watchdog handles a dead connection —
            // tearing down here would clear runningTunnels and disable auto-reconnect.
            if (newState == Tunnel.State.UP && shouldStartTurn && !restore) {
                val handshakeOk = withContext(Dispatchers.IO) { awaitFirstHandshake(tunnel) }
                if (!handshakeOk) {
                    val stillUp = withContext(Dispatchers.IO) { getBackend().getState(tunnel) } == Tunnel.State.UP
                    if (stillUp) {
                        Log.w(TAG, "No WireGuard handshake within ${HANDSHAKE_TIMEOUT_MS}ms — aborting ${tunnel.name}")
                        // Persist DOWN before teardown so an AlwaysOn restart can't read
                        // stale runningTunnels and immediately reconnect into the same fail.
                        UserKnobs.setRunningTunnels(runningTunnelNamesExcluding(tunnel.name))
                        newState = withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.DOWN, null) }
                        if (turnEnabled)
                            withContext(Dispatchers.IO) { getTurnProxyManager().stopForTunnel(tunnel.name) }
                        throw Exception(context.getString(R.string.turn_start_failed))
                    } else {
                        // Tunnel was torn down concurrently (e.g. the user tapped cancel).
                        newState = Tunnel.State.DOWN
                    }
                }
            }

            if (turnEnabled && shouldStopTurn) {
                Log.d(TAG, "Stopping TURN proxy after WireGuard...")
                withContext(Dispatchers.IO) {
                    getTurnProxyManager().stopForTunnel(tunnel.name)
                }
            }

            if (newState == Tunnel.State.UP) {
                lastUsedTunnel = tunnel
            }
        } catch (e: Throwable) {
            throwable = e
        }
        // Cleanup + state persistence must complete even if the connect coroutine
        // was cancelled mid-wait (e.g. the fragment was destroyed during the 25s
        // handshake wait) — otherwise a half-started tunnel/TURN/VpnService leaks.
        withContext(NonCancellable) {
            // A connect attempt that did not reach UP must not leave a TURN proxy or
            // a foreground VpnService running in the background.
            if (throwable != null && shouldStartTurn && newState != Tunnel.State.UP) {
                try {
                    if (turnEnabled)
                        withContext(Dispatchers.IO) { getTurnProxyManager().stopForTunnel(tunnel.name) }
                    if (getBackend() is GoBackend)
                        get().stopService(Intent(get(), GoBackend.VpnService::class.java))
                } catch (cleanupError: Throwable) {
                    Log.w(TAG, "Post-failure cleanup error: ${Log.getStackTraceString(cleanupError)}")
                }
            }
            tunnel.onStateChanged(newState)
            saveState()
            // Run a background watchdog while UP; stop it once the tunnel is DOWN.
            if (newState == Tunnel.State.UP)
                startHandshakeWatchdog(tunnel)
            else
                cancelHandshakeWatchdog(tunnel.name)
        }
        if (throwable != null)
            throw throwable
        newState
    }

    /**
     * Polls backend statistics until a peer reports a non-zero handshake timestamp,
     * or the timeout elapses. Returns false if no handshake is observed, or if the
     * tunnel is brought DOWN concurrently while waiting (caller re-checks real state).
     */
    private suspend fun awaitFirstHandshake(tunnel: ObservableTunnel): Boolean {
        val deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            delay(HANDSHAKE_POLL_INTERVAL_MS)
            // Tunnel torn down concurrently — stop waiting.
            if (getBackend().getState(tunnel) != Tunnel.State.UP)
                return false
            val stats = try {
                getBackend().getStatistics(tunnel)
            } catch (e: Throwable) {
                Log.w(TAG, "getStatistics during handshake wait failed: $e")
                continue
            }
            val latestHandshake = stats.peers()
                .mapNotNull { stats.peer(it)?.latestHandshakeEpochMillis }
                .maxOrNull() ?: 0L
            if (latestHandshake > 0L)
                return true
        }
        return false
    }

    /**
     * Starts a background watchdog that tears the tunnel down if it stays UP without
     * a working connection — no WireGuard handshake ever completes, or a previously
     * healthy one goes stale while traffic is still being sent. This catches
     * mid-session death (DPI/network) that the connect-time [awaitFirstHandshake]
     * check cannot see. App-scoped so it survives the UI being closed.
     */
    private fun startHandshakeWatchdog(tunnel: ObservableTunnel) {
        handshakeWatchdogs.remove(tunnel.name)?.cancel()
        handshakeWatchdogs[tunnel.name] = applicationScope.launch(Dispatchers.IO) {
            val upSince = System.currentTimeMillis()
            var prevTx = -1L
            var deadChecks = 0
            while (isActive) {
                delay(WATCHDOG_POLL_MS)
                if (getBackend().getState(tunnel) != Tunnel.State.UP)
                    return@launch
                val stats = try {
                    getBackend().getStatistics(tunnel)
                } catch (e: Throwable) {
                    continue
                }
                val now = System.currentTimeMillis()
                val latestHandshake = stats.peers()
                    .mapNotNull { stats.peer(it)?.latestHandshakeEpochMillis }
                    .maxOrNull() ?: 0L
                val tx = stats.totalTx()
                val dead = when {
                    // Never completed a single handshake since coming up.
                    latestHandshake == 0L -> now - upSince > WATCHDOG_NEVER_CONNECTED_MS
                    // Handshake went stale while the app is still pushing traffic into
                    // the tunnel (tx growing) — packets are going into a dead route.
                    now - latestHandshake > WATCHDOG_STALE_MS -> prevTx >= 0L && tx > prevTx
                    else -> false
                }
                prevTx = tx
                if (!dead) {
                    deadChecks = 0
                    continue
                }
                deadChecks++
                if (deadChecks >= WATCHDOG_DEAD_CHECKS) {
                    Log.w(TAG, "Handshake watchdog: ${tunnel.name} has no working connection — tearing down")
                    notifyConnectionLost()
                    // Tear down on a fresh job so returning here doesn't abort it.
                    applicationScope.launch {
                        try {
                            setTunnelState(tunnel, Tunnel.State.DOWN)
                        } catch (e: Throwable) {
                            Log.w(TAG, "Watchdog teardown failed: ${Log.getStackTraceString(e)}")
                        }
                    }
                    return@launch
                }
            }
        }
    }

    private fun cancelHandshakeWatchdog(name: String) {
        handshakeWatchdogs.remove(name)?.cancel()
    }

    /** Posts a user-visible notification that the VPN was disconnected due to a dead connection. */
    private fun notifyConnectionLost() {
        try {
            val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as? NotificationManager ?: return
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                nm.createNotificationChannel(
                    NotificationChannel(
                        ALERT_CHANNEL_ID,
                        context.getString(R.string.vpn_alert_channel_name),
                        NotificationManager.IMPORTANCE_DEFAULT,
                    )
                )
            }
            val launchIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)
            val contentIntent = PendingIntent.getActivity(
                context, 0, launchIntent ?: Intent(),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
            val notification = NotificationCompat.Builder(context, ALERT_CHANNEL_ID)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentTitle(context.getString(R.string.tunnel_connection_lost_title))
                .setContentText(context.getString(R.string.tunnel_connection_lost_text))
                .setAutoCancel(true)
                .setContentIntent(contentIntent)
                .build()
            nm.notify(ALERT_NOTIFICATION_ID, notification)
        } catch (e: Throwable) {
            Log.w(TAG, "Failed to post connection-lost notification: $e")
        }
    }

    class IntentReceiver : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent?) {
            applicationScope.launch {
                val manager = getTunnelManager()
                if (intent == null) return@launch
                val action = intent.action ?: return@launch
                if ("com.wireguard.android.action.REFRESH_TUNNEL_STATES" == action) {
                    manager.refreshTunnelStates()
                    return@launch
                }
                val isInternal = intent.getBooleanExtra("internal", false)
                if (!isInternal && !UserKnobs.allowRemoteControlIntents.first())
                    return@launch
                val state = when (action) {
                    "com.wireguard.android.action.SET_TUNNEL_UP" -> Tunnel.State.UP
                    "com.wireguard.android.action.SET_TUNNEL_DOWN" -> Tunnel.State.DOWN
                    else -> return@launch
                }
                val tunnelName = intent.getStringExtra("tunnel") ?: return@launch
                val tunnels = manager.getTunnels()
                val tunnel = tunnels[tunnelName] ?: return@launch
                // Pre-signal the tracker so the widget/UI switches to Disconnected
                // immediately — same as pressing the button in the app.
                if (isInternal && state == Tunnel.State.DOWN) {
                    getTunnelStateTracker().signalUserDisconnect()
                }
                try {
                    manager.setTunnelState(tunnel, state)
                } catch (e: Throwable) {
                    Toast.makeText(context, ErrorMessages[e], Toast.LENGTH_LONG).show()
                } finally {
                    // For internal disconnect requests, always persist state — setTunnelState
                    // may return early (tunnel already DOWN) without calling saveState(), leaving
                    // runningTunnels DataStore stale and causing auto-reconnect on resume.
                    if (isInternal && state == Tunnel.State.DOWN) {
                        manager.saveState()
                    }
                }
            }
        }
    }

    suspend fun getTunnelState(tunnel: ObservableTunnel): Tunnel.State = withContext(Dispatchers.Main.immediate) {
        tunnel.onStateChanged(withContext(Dispatchers.IO) { getBackend().getState(tunnel) })
    }

    suspend fun getTunnelStatistics(tunnel: ObservableTunnel): Statistics = withContext(Dispatchers.Main.immediate) {
        tunnel.onStatisticsChanged(withContext(Dispatchers.IO) { getBackend().getStatistics(tunnel) })!!
    }

    companion object {
        private const val TAG = "WireGuard/TunnelManager"
        // How long to wait for the first WireGuard handshake after the interface
        // comes up before declaring the connection failed and tearing it down.
        private const val HANDSHAKE_TIMEOUT_MS = 25_000L
        private const val HANDSHAKE_POLL_INTERVAL_MS = 1_000L

        // Background watchdog: tears the tunnel down on prolonged loss of handshake.
        private const val WATCHDOG_POLL_MS = 30_000L
        // Handshake age beyond which an in-use connection is considered broken.
        private const val WATCHDOG_STALE_MS = 180_000L
        // Grace period for a tunnel that has never completed a single handshake.
        private const val WATCHDOG_NEVER_CONNECTED_MS = 150_000L
        // Consecutive bad polls required before tearing down (debounce).
        private const val WATCHDOG_DEAD_CHECKS = 2

        private const val ALERT_CHANNEL_ID = "vpn_alerts"
        private const val ALERT_NOTIFICATION_ID = 2
    }
}
