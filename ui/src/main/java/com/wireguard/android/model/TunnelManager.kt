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
import android.content.IntentFilter
import android.os.Build
import android.util.Log
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import androidx.databinding.BaseObservable
import androidx.databinding.Bindable
import com.wireguard.android.Application.Companion.get
import com.wireguard.android.Application.Companion.getBackend
import com.wireguard.android.Application.Companion.getTunnelManager
import com.wireguard.android.Application.Companion.getTetherManager
import com.wireguard.android.Application.Companion.getTunnelStateTracker
import com.wireguard.android.Application.Companion.getTurnProxyManager
import com.wireguard.android.BR
import com.wireguard.android.R
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Statistics
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.configStore.ConfigStore
import com.wireguard.android.databinding.ObservableSortedKeyedArrayList
import com.wireguard.android.fragment.TunnelFailure
import com.wireguard.android.turn.TurnConfigProcessor
import com.wireguard.android.turn.TurnSettings
import com.wireguard.android.turn.TurnSettingsStore
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.util.ScreenStateMonitor
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
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
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

    // Serializes the whole connect/disconnect path. tunnel.state is only updated at
    // the very end, so a request arriving during the ~25s handshake window used to
    // see a stale DOWN and run a second full connect — restarting TURN under the
    // first attempt's feet (widget/tile TOGGLE, AlwaysOn restoreState).
    private val stateMutex = Mutex()

    /** Name of the tunnel whose connect is currently in flight, or null. */
    @Volatile private var connectInFlight: String? = null

    /**
     * How many user-requested connects are outstanding — queued on [stateMutex] as well
     * as in flight. An automatic restore is not counted: it never paints Connecting, so
     * the user is looking at a disconnected tunnel and their tap means "connect".
     */
    private var userConnects = 0

    /**
     * Bumped by every stop request. A connect that queued before the bump is stale by the
     * time it reaches the lock and drops itself instead of running. Global rather than
     * per-tunnel, like [connectInFlight] and [abortConnect] beside it — this client ships
     * a single tunnel.
     */
    private var stopGeneration = 0

    /** Set when a queued request wants the in-flight connect to stop waiting. */
    @Volatile private var abortConnect = false

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

    /**
     * The tunnel this client acts on from everywhere but the main screen: the tile, the
     * widget, the state tracker and internet sharing. It is the one shipped under
     * [PRIMARY_TUNNEL_NAME]; the last one that reached UP is the fallback for a config
     * imported under some other name. Suspends until the list is loaded.
     */
    suspend fun primaryTunnel(): ObservableTunnel? {
        getTunnels()
        return primaryTunnelOrNull()
    }

    /**
     * [primaryTunnel] for callers that cannot suspend — the QS tile renders its label from
     * the main thread. Null until [onTunnelsLoaded] has filled the map.
     */
    fun primaryTunnelOrNull(): ObservableTunnel? = tunnelMap[PRIMARY_TUNNEL_NAME] ?: lastUsedTunnel

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
        registerPackageInstallReceiver()
    }

    // ── Split tunneling vs. newly installed apps ───────────────────────────────
    //
    // The per-app rules are baked into the VPN interface by VpnService.Builder at
    // establish() time and cannot be changed on a live interface. An app installed
    // afterwards is therefore absent from those rules, which breaks "only these apps"
    // mode: everything outside the include list is disallowed by enumerating the
    // installed packages (see GoBackend), so a package that did not exist at connect
    // time is not disallowed and its traffic silently goes through the tunnel.
    // The only fix is to re-establish the interface, which is what this does.

    /** Packages installed since the last re-apply, drained by [reapplySplitTunnel]. */
    private val pendingInstalledPackages = mutableSetOf<String>()

    /** Debounce for [pendingInstalledPackages]; a device restore installs apps in bulk. */
    private var splitTunnelReapplyJob: Job? = null

    private fun registerPackageInstallReceiver() {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                // An update keeps both the package name and the UID, so the rules of a
                // running tunnel still apply — only genuinely new packages matter here.
                if (intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return
                val packageName = intent.data?.schemeSpecificPart ?: return
                if (packageName == context.packageName) return
                onPackageInstalled(packageName)
            }
        }
        val filter = IntentFilter(Intent.ACTION_PACKAGE_ADDED).apply { addDataScheme("package") }
        ContextCompat.registerReceiver(
            context.applicationContext, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED,
        )
    }

    private fun onPackageInstalled(packageName: String) {
        pendingInstalledPackages.add(packageName)
        scheduleSplitTunnelReapply()
    }

    private fun scheduleSplitTunnelReapply() {
        splitTunnelReapplyJob?.cancel()
        splitTunnelReapplyJob = applicationScope.launch {
            delay(PACKAGE_INSTALL_DEBOUNCE_MS)
            try {
                reapplySplitTunnel()
            } catch (e: Throwable) {
                Log.e(TAG, Log.getStackTraceString(e))
            }
        }
    }

    private suspend fun reapplySplitTunnel() = withContext(Dispatchers.Main.immediate) {
        // Keep the packages queued while a connect is in flight. Its VpnService
        // rules may already have been built, and the connect completion path below
        // schedules this work again once it is safe to bounce the interface.
        if (connectInFlight != null) return@withContext
        val installed = pendingInstalledPackages.toSet()
        pendingInstalledPackages.clear()
        if (installed.isEmpty()) return@withContext
        for (tunnel in tunnelMap.filter { it.state == Tunnel.State.UP }) {
            val iface = getTunnelConfig(tunnel).`interface`
            // Include mode: any new package is missing from the disallow list. Exclude
            // mode: only a reinstall of an excluded app matters — same package name, but
            // a new UID that the live interface's rules were never built against.
            val stale = iface.includedApplications.isNotEmpty() ||
                    installed.any { iface.excludedApplications.contains(it) }
            if (!stale) continue
            Log.i(TAG, "Re-applying split tunneling on ${tunnel.name} after install of $installed")
            setTunnelState(tunnel, Tunnel.State.DOWN)
            setTunnelState(tunnel, Tunnel.State.UP)
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
            // Publish the list before restoring, not after. Upstream completes it last,
            // which is harmless there because restoreState() is a couple of ioctls; here
            // it is a full connect — TURN allocation, a trip to VK for credentials, maybe
            // the whole captcha ladder, then the 25s handshake wait. Everything that
            // resolves a tunnel goes through getTunnels(), so completing last froze the
            // QS tile, the widget and the state tracker for the entire restore: on a cold
            // start the tile's tap parked on getTunnels() and the tile looked dead.
            // The states already in the map come from the backend's own
            // runningTunnelNames, so they are accurate as of now; restoreState() repairs
            // tunnels the backend lost, it is not what makes the list valid.
            tunnels.complete(tunnelMap)
            restoreState(true)
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

    /**
     * What a TOGGLE on [tunnel] resolves to right now.
     *
     * Not the model state: during a connect tunnel.state is still DOWN, so a widget/tile
     * toggle meant as "cancel" would be read as "connect" and start a second attempt. And
     * [userConnects] rather than [connectInFlight], because the request being cancelled
     * may still be queued on [stateMutex] behind an automatic restore, with nothing in
     * flight yet that carries the user's intent.
     *
     * A restore on its own is deliberately not cancellable this way: it never calls
     * signalUserConnect, so the UI reads Disconnected, and on a cold start it runs at the
     * very moment of the tap that revived the process — reading that first tap as "cancel"
     * would kill the connect the user just asked for. So the first tap adopts the restore
     * (queues its own UP behind it, which comes out of setTunnelStateSerialized on the
     * first line if the restore got there), and every tap after that cancels like any
     * other.
     *
     * Public because the tile and the widget paint Connecting/Disconnected before this
     * (slow) work starts, and guessing from tunnel.state alone leaves them claiming
     * "Connecting" on a tap that is actually a cancel.
     */
    fun resolveToggle(tunnel: ObservableTunnel): Tunnel.State = when {
        tunnel.state == Tunnel.State.UP -> Tunnel.State.DOWN
        userConnects > 0 -> Tunnel.State.DOWN
        else -> Tunnel.State.UP
    }

    suspend fun setTunnelState(
        tunnel: ObservableTunnel,
        state: Tunnel.State,
        restore: Boolean = false,
    ): Tunnel.State = withContext(Dispatchers.Main.immediate) {
        val requested = if (state != Tunnel.State.TOGGLE) state else resolveToggle(tunnel)

        val userConnect = requested == Tunnel.State.UP && !restore
        if (userConnect) userConnects++
        // Snapshot before queueing. Aborting what is in flight is not enough on its own:
        // a connect already queued behind it would take the lock next and start a fresh
        // 25s attempt, so the stop has to invalidate the queue too.
        val generation = stopGeneration

        if (requested == Tunnel.State.DOWN) {
            stopGeneration++
            // Don't make the user wait out a 25s handshake to cancel: tell the in-flight
            // connect to give up and inhibit the TURN auto-restart before queueing.
            if (connectInFlight == tunnel.name) {
                Log.d(TAG, "Disconnect requested during connect — aborting ${tunnel.name}")
                abortConnect = true
                getTurnProxyManager().beginUserStop()
            }
        }

        try {
            stateMutex.withLock {
                if (requested == Tunnel.State.UP && stopGeneration != generation) {
                    Log.d(TAG, "Connect for ${tunnel.name} superseded by a stop, dropping it")
                    return@withLock tunnel.state
                }
                if (requested == Tunnel.State.UP) {
                    connectInFlight = tunnel.name
                    abortConnect = false
                }
                try {
                    setTunnelStateSerialized(tunnel, requested, restore)
                } finally {
                    if (requested == Tunnel.State.UP) {
                        connectInFlight = null
                        if (pendingInstalledPackages.isNotEmpty()) {
                            scheduleSplitTunnelReapply()
                        }
                    }
                }
            }
        } finally {
            if (userConnect) userConnects--
        }
    }

    private suspend fun setTunnelStateSerialized(
        tunnel: ObservableTunnel,
        state: Tunnel.State,
        restore: Boolean,
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
        // TOGGLE is resolved by the caller, so state is UP or DOWN here.
        val shouldStartTurn = state == Tunnel.State.UP

        var newState = tunnel.state
        var throwable: Throwable? = null
        try {
            var configToUse = tunnel.getConfigAsync()

            // Stop TURN when tunnel goes DOWN
            val shouldStopTurn = state == Tunnel.State.DOWN

            if (shouldStopTurn) {
                // ADDED step, not a reordering: everything below keeps the exact
                // sequence documented for this method. Sharing simply has to be
                // torn down before WireGuard, because its upstream sockets are
                // deliberately unprotected — after the tunnel is gone a tethered
                // client's next request would egress straight out of the carrier
                // with the user's real IP. TetherManager also watches the tunnel
                // state flow, but that only fires once WireGuard is already down,
                // which is exactly the window this closes; the collector remains
                // the backstop for teardowns that do not come through here.
                // Bounded wait: TetherManager.start() now times its access point
                // out, so this cannot park the teardown indefinitely.
                getTetherManager().stopAndAwait()

                // Pre-emptively persist "tunnel going DOWN" before backend teardown.
                // getBackend().setState(DOWN) calls stopSelf() asynchronously — if Android
                // restarts the VPN service (AlwaysOn) before saveState() runs at the end,
                // restoreState() would read stale runningTunnels and auto-reconnect.
                // Writing {} here (after DataStore edit() commits) eliminates that race window.
                UserKnobs.setRunningTunnels(runningTunnelNamesExcluding(tunnel.name))
                // Inhibit TURN auto-restart before backend teardown. Bringing
                // WireGuard down re-evaluates the physical network, which can
                // otherwise trip PhysicalNetworkMonitor into restarting the
                // proxy in the window before stopForTunnel runs — leaving it
                // endlessly reconnecting after the user pressed disconnect.
                if (turnEnabled) getTurnProxyManager().beginUserStop()
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
                    if (stillUp && abortConnect) {
                        // A disconnect is queued behind this connect. Tear the
                        // half-connected tunnel down quietly and let it run — the user
                        // asked for this, so it must not surface as a connect error.
                        Log.d(TAG, "Connect aborted — bringing ${tunnel.name} down for the queued request")
                        UserKnobs.setRunningTunnels(runningTunnelNamesExcluding(tunnel.name))
                        newState = withContext(Dispatchers.IO) { getBackend().setState(tunnel, Tunnel.State.DOWN, null) }
                        if (turnEnabled)
                            withContext(Dispatchers.IO) { getTurnProxyManager().stopForTunnel(tunnel.name) }
                    } else if (stillUp) {
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
            // A disconnect request is waiting behind this connect — stop waiting.
            if (abortConnect)
                return false
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
                awaitNextWatchdogPoll()
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

    /**
     * Waits until the next handshake-watchdog poll is due. With the screen on the
     * cadence is unchanged, so a user staring at a dead tunnel still gets a fast
     * teardown. With the screen off nobody is looking, so the watchdog stops
     * burning a JNI stats call (which parses the whole uapi config) every 30s all
     * night and instead sleeps until the screen comes back on — or for
     * [WATCHDOG_POLL_IDLE_MS], whichever happens first, so a tunnel that died in
     * the dark is still caught. The tunnel itself, its keepalives and the native
     * dead-stream detector are untouched.
     */
    private suspend fun awaitNextWatchdogPoll() {
        if (ScreenStateMonitor.screenOn.value) {
            delay(WATCHDOG_POLL_MS)
            return
        }
        withTimeoutOrNull(WATCHDOG_POLL_IDLE_MS) { ScreenStateMonitor.screenOn.first { it } }
    }

    private fun cancelHandshakeWatchdog(name: String) {
        handshakeWatchdogs.remove(name)?.cancel()
    }

    /**
     * Called from the native TURN layer when the session has failed terminally:
     * every worker gave up because retrying cannot fix the cause (an unsolvable
     * captcha, a call that has ended). Nothing will restore the transport, so the
     * tunnel is taken down with a user-visible reason instead of being left UP
     * over a dead route while the native side retries forever.
     */
    fun onTurnFatal(reason: String) {
        Log.e(TAG, "TURN reported terminal failure: $reason")
        val activeName = getTurnProxyManager().activeTunnel
        if (activeName != null)
            getTurnProxyManager().appendLogLine(activeName, "TURN terminal failure ($reason) — disconnecting")
        tearDownForTurnFailure(
            activeName,
            context.getString(R.string.turn_fatal_text),
            // Every give-up on this path is a credential one; the reason string
            // only says which kind.
            TunnelFailure.fromTurnReason(reason) ?: TunnelFailure.Credentials,
        )
    }

    /**
     * Called from [com.wireguard.android.turn.TurnProxyManager] when its own restart
     * loop concludes the proxy cannot be brought back: a fatal start code, or repeated
     * failures on a network the system reports as validated.
     *
     * This is the Android-side twin of [onTurnFatal]. The native terminal-failure
     * accounting only fires once workers have been launched and have all given up, so
     * a proxy that never starts — JNI registration timeout, a failing wgTurnProxyStart,
     * a captcha lockout during startup — reaches no worker and would otherwise leave
     * the tunnel UP over a dead 127.0.0.1 route until the handshake watchdog noticed,
     * three to nine minutes later.
     */
    fun onTurnUnrecoverable(tunnelName: String, reason: String) {
        Log.e(TAG, "TURN proxy unrecoverable on $tunnelName: $reason")
        tearDownForTurnFailure(
            tunnelName,
            context.getString(R.string.turn_restart_failed_text),
            // The restart loop can also lose to a credential failure it saw on the
            // way, so let an explicit reason win over the generic restart verdict.
            TunnelFailure.fromTurnReason(reason) ?: TunnelFailure.ProxyRestart,
        )
    }

    /**
     * Notifies the user and brings down the tunnel TURN was carrying. [tunnelName]
     * narrows the choice when known; the session may already have been cleared by the
     * reporter, in which case the single UP tunnel is the one that lost its transport.
     */
    private fun tearDownForTurnFailure(tunnelName: String?, text: String, failure: TunnelFailure) {
        applicationScope.launch {
            notifyAlert(context.getString(R.string.tunnel_connection_lost_title), text)
            val tunnel = withContext(Dispatchers.Main.immediate) {
                tunnelMap.firstOrNull {
                    it.state == Tunnel.State.UP && (tunnelName == null || it.name == tunnelName)
                }
            } ?: return@launch
            // After the lookup, and before the teardown. After, because a report
            // that finds nothing to take down must not leave a failure sitting on a
            // screen the user had already stopped themselves; before, because the
            // tracker has to be holding the reason by the time the tunnel flips to
            // DOWN, or the down edge emits a plain Disconnected over it.
            getTunnelStateTracker().signalFatalFailure(failure)
            try {
                setTunnelState(tunnel, Tunnel.State.DOWN)
            } catch (e: Throwable) {
                Log.w(TAG, "Teardown after TURN failure failed: ${Log.getStackTraceString(e)}")
            }
        }
    }

    /** Posts a user-visible notification that the VPN was disconnected due to a dead connection. */
    private fun notifyConnectionLost() = notifyAlert(
        context.getString(R.string.tunnel_connection_lost_title),
        context.getString(R.string.tunnel_connection_lost_text),
    )

    /** Posts a VPN-alert notification with the given title and text. */
    private fun notifyAlert(title: String, text: String) {
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
                .setContentTitle(title)
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
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

        /**
         * The one tunnel this client ships, created by the import flow under this name.
         * Every surface outside the main screen resolves it through [primaryTunnel];
         * the literal lives here and nowhere else.
         */
        const val PRIMARY_TUNNEL_NAME = "wgkeybot"

        // How long to wait for the first WireGuard handshake after the interface
        // comes up before declaring the connection failed and tearing it down.
        private const val HANDSHAKE_TIMEOUT_MS = 25_000L
        private const val HANDSHAKE_POLL_INTERVAL_MS = 1_000L

        // Background watchdog: tears the tunnel down on prolonged loss of handshake.
        private const val WATCHDOG_POLL_MS = 30_000L
        // Poll cadence with the screen off, where a slower verdict costs nothing.
        private const val WATCHDOG_POLL_IDLE_MS = 180_000L
        // Handshake age beyond which an in-use connection is considered broken.
        private const val WATCHDOG_STALE_MS = 180_000L
        // Grace period for a tunnel that has never completed a single handshake.
        private const val WATCHDOG_NEVER_CONNECTED_MS = 150_000L
        // Consecutive bad polls required before tearing down (debounce).
        private const val WATCHDOG_DEAD_CHECKS = 2

        // Coalescing window for package installs, so a device restore that installs
        // dozens of apps back to back costs one reconnect instead of dozens.
        private const val PACKAGE_INSTALL_DEBOUNCE_MS = 5_000L

        private const val ALERT_CHANNEL_ID = "vpn_alerts"
        private const val ALERT_NOTIFICATION_ID = 2
    }
}
