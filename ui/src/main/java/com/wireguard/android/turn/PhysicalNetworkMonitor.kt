/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.util.Log
import androidx.annotation.RequiresApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.NetworkInterface
import java.util.concurrent.ConcurrentHashMap

/**
 * Tells the rest of the app which physical network the TURN sockets bind to.
 * Ignores VPN interfaces to avoid tracking our own tunnel.
 *
 * The choice is Android's, not ours — see [PhysicalNetworkChoice] for why. On
 * API 31+ the platform reports its pick directly (the best network matching
 * "internet, not a VPN", which is the one every app outside the tunnel uses);
 * before that, and until its first report, the networks are ranked by transport.
 */
class PhysicalNetworkMonitor(context: Context) {
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    
    private val _bestPath = MutableStateFlow<NetworkPath?>(null)
    private val _validated = MutableStateFlow(false)

    /**
     * A physical network together with the identity of the addresses it carries.
     *
     * The [Network] object alone does not show every change: a DHCP renewal onto a
     * different lease, or roaming between access points of the same network,
     * replaces the local IP while Android keeps handing out the same Network.
     * Native sees the same network handle then, and needs nothing more: a
     * connected socket whose source address is gone fails its next write, and its
     * worker reconnects from the new one.
     */
    data class NetworkPath(val network: Network, val addresses: String)

    /**
     * The best available physical path — the network and the addresses it carries
     * — as the monitor believes it right now, undebounced.
     *
     * It goes straight into native (wgSetNetwork), which owns every decision made
     * from it. There used to be a 1500ms-debounced twin that drove a TURN restart;
     * the settle was the right trade for tearing a proxy down, and the wrong one
     * for telling the dialer which network to bind to — a reconnect attempted
     * mid-handover bound to a dead Network. The restart is gone (native moves the
     * sessions itself, network_switch.go), and so is the twin.
     */
    val rawPath: StateFlow<NetworkPath?> = _bestPath.asStateFlow()

    /**
     * Whether Android reports [currentPath] as validated. For the log and nothing
     * else: no decision is made from it, here or in native. It stays because "was
     * the network validated" is the first question about any field log — a
     * cellular network that never validates is what a mobile whitelist looks like.
     */
    val validated = _validated.asStateFlow()

    /**
     * A snapshot of [rawPath], for callers that want the value rather than the
     * flow. Reads through [rawPath] so there is one undebounced view of the path
     * and not two independent ones over the same MutableStateFlow.
     */
    val currentPath: NetworkPath?
        get() = rawPath.value

    /**
     * The DNS servers [network] advertises, comma-separated, or "" when Android
     * names none (or there is no network).
     *
     * Read on demand rather than folded into [NetworkPath], whose equality decides
     * when the path is pushed to native again; the resolvers ride along with each
     * push of the network they belong to.
     */
    fun dnsServersOf(network: Network?): String {
        if (network == null) return ""
        val lp = cm.getLinkProperties(network) ?: return ""
        return lp.dnsServers.mapNotNull { it.hostAddress }.joinToString(",")
    }

    /**
     * The MTU of [network], for the log: the one set on its interface, followed by
     * the one the network advertised (LinkProperties, API 29+) when that differs —
     * a carrier's value that did not make it onto the interface is worth seeing.
     * "unknown" when neither can be read.
     *
     * Every TURN packet leaves through this interface wrapped several times over
     * (see TurnConfigProcessor.TURN_DEFAULT_MTU), so this is the number to compare with
     * the tunnel MTU when big transfers stall while handshakes still pass.
     */
    fun mtuOf(network: Network?): String {
        if (network == null) return "none"
        val lp = cm.getLinkProperties(network) ?: return "unknown"
        val advertised = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) lp.mtu else 0
        val onInterface = lp.interfaceName?.let { name ->
            try {
                NetworkInterface.getByName(name)?.mtu?.takeIf { it > 0 }
            } catch (_: Exception) {
                null
            }
        }
        return when {
            onInterface == null && advertised > 0 -> "$advertised (advertised)"
            onInterface == null -> "unknown"
            advertised > 0 && advertised != onInterface -> "$onInterface (network advertises $advertised)"
            else -> "$onInterface"
        }
    }

    private val networks = ConcurrentHashMap<Network, NetworkCapabilities>()
    private val links = ConcurrentHashMap<Network, String>()

    private val request = NetworkRequest.Builder()
        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        .build()

    // Android's pick, once it has told us (API 31+); null until then, and for
    // good on older platforms. SystemPick(null) is "Android has no network".
    @Volatile private var systemPick: PhysicalNetworkChoice.SystemPick<Network>? = null
    private var systemCallbackThread: HandlerThread? = null

    // The registration that follows Android's pick, and the handler it runs on;
    // both null when the platform does not report its pick. reask() replaces
    // the registration, and a callback that is no longer this one is ignored.
    @Volatile private var systemCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var systemHandler: Handler? = null

    // For the log, under the monitor's lock: the default network last announced
    // as standing in for "no network", and how often and when the current
    // stretch of "no network" has been re-asked.
    private var announcedDefault: Network? = null
    private var reasks = 0
    private var lastReaskAt = 0L

    private val reaskTick = Runnable {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) reask()
    }

    /**
     * Follows the best network matching the request, the way a network *request*
     * does but without holding one: when the pick moves from A to B there is an
     * onAvailable(B) and no onLost(A); onLost means there is nothing left at all.
     * Capabilities and link properties come for the pick only.
     */
    private fun newSystemCallback() = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (this !== systemCallback) return
            networks.keys.retainAll(setOf(network))
            links.keys.retainAll(setOf(network))
            systemPick = PhysicalNetworkChoice.SystemPick(network)
            update()
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            if (this !== systemCallback || systemPick?.network != network) return
            networks[network] = caps
            update()
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            if (this !== systemCallback || systemPick?.network != network) return
            links[network] = addressIdentity(linkProperties)
            update()
        }

        override fun onLost(network: Network) {
            if (this !== systemCallback) return
            networks.remove(network)
            links.remove(network)
            if (systemPick?.network == network) systemPick = PhysicalNetworkChoice.SystemPick(null)
            update()
        }
    }

    /**
     * Asks Android for its pick again while it says there is no network, in case
     * that answer is stale. A new registration is told the best network at once,
     * so a pick the old one missed shows up within milliseconds.
     *
     * Field logs 2026-10-09/10 (Pixel 9, Android 17): the callback said "no
     * network" and then stayed silent — 22 minutes once — while the phone was on
     * cellular (see PhysicalNetworkChoice for the evidence). In two of the five
     * cases the "none" landed within milliseconds of the app coming back to the
     * screen with the tunnel off, so after a stretch in the cached state. Where
     * the cellular network did show up in the end, its number was lower than
     * the Wi-Fi's that had gone (113 against 115), so it had been up in the
     * background all along, and it showed up a second before a new Wi-Fi did,
     * as if only the next network event got the pick recomputed. A wifi →
     * cellular move onto a newly connected cellular network (19:19, 129 after
     * Wi-Fi 117) came through as it should. Whatever the cause, a fresh registration
     * gets a fresh answer. It runs every [REASK_EVERY_MS] while "no network"
     * lasts. A tick that falls due while the process is frozen runs as soon as
     * it thaws, which is when the app comes back to the screen. A connect asks
     * straight away ([reaskNow]).
     */
    @RequiresApi(Build.VERSION_CODES.S)
    private fun reask() {
        val handler = systemHandler ?: return
        val old = systemCallback ?: return
        if (systemPick?.network != null) return
        val fresh = newSystemCallback()
        systemCallback = fresh
        try {
            cm.registerBestMatchingNetworkCallback(request, fresh, handler)
        } catch (e: RuntimeException) {
            systemCallback = old
            Log.w(TAG, "Asking Android again for its pick failed: $e")
            update()
            return
        }
        try {
            cm.unregisterNetworkCallback(old)
        } catch (e: RuntimeException) {
            // Already gone; nothing of it is listened to any more either way.
        }
        synchronized(this) {
            if (reasks++ == 0) Log.i(TAG, "Android reports no physical network — asking it again every ${REASK_EVERY_MS / 1000}s while that lasts")
            lastReaskAt = SystemClock.elapsedRealtime()
        }
        update()
    }

    /**
     * Asks Android for its pick straight away if it says there is no network. For
     * a connect, which otherwise starts with the workers parked and fails ~30s
     * later on a network the phone is using. The answer arrives on [rawPath].
     */
    fun reaskNow() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return
        systemHandler?.post(reaskTick)
    }

    /**
     * The physical network Android has for this app, asked for directly rather
     * than through a callback. Before the tunnel is up that is the default
     * network, the one every app uses. Once it is up, the app rides its own
     * tunnel and the default is the VPN, which says nothing about the physical
     * side; then [current], the network the sockets are on, stands for as long
     * as Android still knows it. Without that, a connect brought up on the
     * default network would lose it to the next re-ask once the tunnel was up,
     * and the workers would be parked under a live tunnel.
     */
    private fun physicalDefault(current: Network?): Network? {
        val active = cm.activeNetwork ?: return null
        if (isPhysicalWithInternet(active)) return active
        return current?.takeIf { isPhysicalWithInternet(it) }
    }

    // getNetworkCapabilities answers null for a network that is gone.
    private fun isPhysicalWithInternet(network: Network): Boolean {
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
    }

    // The ranking of our own, for platforms that do not report theirs.
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            // Ignore VPNs to avoid feedback loops with our own tunnel
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return

            // We only care about networks with internet
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                networks.remove(network)
            } else {
                networks[network] = caps
            }
            update()
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            links[network] = addressIdentity(linkProperties)
            update()
        }

        override fun onLost(network: Network) {
            networks.remove(network)
            links.remove(network)
            update()
        }
    }

    /**
     * A stable identity for the addresses a link carries, used to tell a real
     * re-addressing apart from normal churn.
     *
     * IPv4 addresses are compared in full. IPv6 is reduced to its /64 prefixes on
     * purpose: privacy extensions rotate temporary IPv6 addresses on their own
     * schedule, and comparing them in full would keep declaring a network change
     * on a link that never moved. A genuine handover changes
     * the prefix. Loopback and link-local addresses carry no information here and
     * are dropped.
     */
    /**
     * The cached address identity for [network], falling back to a direct query.
     *
     * onCapabilitiesChanged can arrive before onLinkPropertiesChanged for a newly
     * appeared network, which would briefly publish a path with no addresses and
     * then "change" it a moment later — a re-addressing that never happened.
     * Querying directly removes the window instead of relying on the timing.
     */
    private fun identityFor(network: Network): String {
        links[network]?.let { return it }
        val identity = cm.getLinkProperties(network)?.let { addressIdentity(it) } ?: return ""
        links[network] = identity
        return identity
    }

    private fun addressIdentity(lp: LinkProperties): String {
        val parts = lp.linkAddresses.mapNotNull { linkAddress ->
            val address = linkAddress.address
            if (address.isLoopbackAddress || address.isLinkLocalAddress) return@mapNotNull null
            when (address) {
                is Inet4Address -> address.hostAddress
                is Inet6Address -> address.address.take(8)
                    .joinToString("") { "%02x".format(it) }
                else -> null
            }
        }.distinct().sorted()
        return "${lp.interfaceName.orEmpty()}|${parts.joinToString(",")}"
    }

    // Called from the callback thread and, once, from start().
    @Synchronized
    private fun update() {
        val candidates = networks.entries.map { (network, caps) ->
            PhysicalNetworkChoice.Candidate(
                id = network,
                transport = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> PhysicalNetworkChoice.Transport.WIFI
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> PhysicalNetworkChoice.Transport.CELLULAR
                    else -> PhysicalNetworkChoice.Transport.OTHER
                },
            )
        }
        val pick = systemPick
        // While Android's pick says "no network" — or has not been given — its
        // answer may be stale: check it against what Android says when asked
        // directly, and keep re-asking (reask). Only where the platform reports
        // its pick at all.
        val handler = systemHandler
        val unsure = pick?.network == null
        val systemDefault = if (handler != null && unsure) physicalDefault(_bestPath.value?.network) else null
        val best = PhysicalNetworkChoice.pick(pick, candidates, systemDefault)

        // Logged only against an actual "none": before the first report the
        // default stands in silently, as the ranking does.
        val standIn = if (pick != null && pick.network == null) systemDefault else null
        if (standIn != announcedDefault) {
            if (standIn != null) {
                Log.w(TAG, "Android's pick says no physical network, but asked directly it has $standIn — following that")
            }
            announcedDefault = standIn
        }
        if (unsure && handler != null) {
            handler.removeCallbacks(reaskTick)
            handler.postDelayed(reaskTick, REASK_EVERY_MS)
        } else {
            handler?.removeCallbacks(reaskTick)
            if (reasks > 0 && pick?.network != null) {
                Log.i(TAG, "Android picks ${pick.network} ${SystemClock.elapsedRealtime() - lastReaskAt}ms after it was last asked again ($reasks time(s))")
            }
            reasks = 0
        }

        _bestPath.value = best?.let { network -> NetworkPath(network, identityFor(network)) }
        // onAvailable comes ahead of the pick's capabilities, hence the direct query.
        val caps = best?.let { networks[it] ?: cm.getNetworkCapabilities(it) }
        _validated.value = caps != null &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    fun start() {
        // Initial state: rank what is there before any callback has fired, so that a
        // connect started right after the process came up has a network to bind to.
        // We look through all networks because activeNetwork might be the VPN itself.
        //
        // Foreground networks only, which is what the callbacks below report: without
        // CHANGE_NETWORK_STATE every listen is implicitly foreground. allNetworks
        // also returns the ones the system keeps in the background (cellular under
        // a Wi-Fi default, "mobile data always active"), and an entry taken from
        // there is never reported lost — it outlived its network for as long as the
        // process ran, a dead Network that the transport order could still pick, and
        // next to a live one of the same transport the pick between the two was the
        // map's iteration order. Before API 28 the capability is not public; the
        // callback delivers the existing networks within milliseconds anyway.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            @Suppress("DEPRECATION")
            cm.allNetworks.forEach { network ->
                val caps = cm.getNetworkCapabilities(network)
                if (caps != null &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_FOREGROUND)) {
                    networks[network] = caps
                    cm.getLinkProperties(network)?.let { links[network] = addressIdentity(it) }
                }
            }
        }
        update()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && followSystemPick()) return
        Log.i(TAG, "Ranking the physical networks by transport (API ${Build.VERSION.SDK_INT})")
        cm.registerNetworkCallback(request, callback)
    }

    /**
     * Asks Android for its own pick. False if the platform refuses (it limits the
     * callbacks one app may hold), in which case the caller ranks the networks
     * itself, as it does before API 31.
     */
    @RequiresApi(Build.VERSION_CODES.S)
    private fun followSystemPick(): Boolean {
        val thread = HandlerThread("wgk-netmon").apply { start() }
        val handler = Handler(thread.looper)
        val cb = newSystemCallback()
        // Set before registering: the first report may come before the call returns.
        systemCallback = cb
        systemHandler = handler
        return try {
            cm.registerBestMatchingNetworkCallback(request, cb, handler)
            systemCallbackThread = thread
            Log.i(TAG, "Following Android's pick of the physical network")
            // If Android has no network to report, nothing else would start the re-asking.
            update()
            true
        } catch (e: RuntimeException) {
            Log.w(TAG, "registerBestMatchingNetworkCallback refused: $e")
            systemCallback = null
            systemHandler = null
            thread.quitSafely()
            false
        }
    }

    fun stop() {
        systemHandler?.removeCallbacks(reaskTick)
        for (cb in listOfNotNull(callback, systemCallback)) {
            try {
                cm.unregisterNetworkCallback(cb)
            } catch (e: Exception) {
                // Ignore: only one of the two was ever registered.
            }
        }
        systemCallback = null
        systemHandler = null
        systemCallbackThread?.quitSafely()
        systemCallbackThread = null
        systemPick = null
        networks.clear()
        links.clear()
        synchronized(this) {
            announcedDefault = null
            reasks = 0
        }
        _bestPath.value = null
        _validated.value = false
    }

    private companion object {
        const val TAG = "WireGuard/PhysicalNetworkMonitor"

        // How often a "no network" from Android is asked again (see reask).
        const val REASK_EVERY_MS = 10_000L
    }
}
