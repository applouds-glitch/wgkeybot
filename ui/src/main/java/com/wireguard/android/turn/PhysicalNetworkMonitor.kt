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
import android.util.Log
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
     * (see TurnConfigProcessor.TURN_MAX_MTU), so this is the number to compare with
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

    // Android's pick, once it has told us (API 31+); null until then, and for
    // good on older platforms. SystemPick(null) is "Android has no network".
    @Volatile private var systemPick: PhysicalNetworkChoice.SystemPick<Network>? = null
    private var systemCallbackThread: HandlerThread? = null

    /**
     * Follows the best network matching the request, the way a network *request*
     * does but without holding one: when the pick moves from A to B there is an
     * onAvailable(B) and no onLost(A); onLost means there is nothing left at all.
     * Capabilities and link properties come for the pick only.
     */
    private val systemCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            networks.keys.retainAll(setOf(network))
            links.keys.retainAll(setOf(network))
            systemPick = PhysicalNetworkChoice.SystemPick(network)
            update()
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            if (systemPick?.network != network) return
            networks[network] = caps
            update()
        }

        override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
            if (systemPick?.network != network) return
            links[network] = addressIdentity(linkProperties)
            update()
        }

        override fun onLost(network: Network) {
            networks.remove(network)
            links.remove(network)
            if (systemPick?.network == network) systemPick = PhysicalNetworkChoice.SystemPick(null)
            update()
        }
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
        val best = PhysicalNetworkChoice.pick(systemPick, candidates)

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

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && followSystemPick(request)) return
        Log.i(TAG, "Ranking the physical networks by transport (API ${Build.VERSION.SDK_INT})")
        cm.registerNetworkCallback(request, callback)
    }

    /**
     * Asks Android for its own pick. False if the platform refuses (it limits the
     * callbacks one app may hold), in which case the caller ranks the networks
     * itself, as it does before API 31.
     */
    @androidx.annotation.RequiresApi(Build.VERSION_CODES.S)
    private fun followSystemPick(request: NetworkRequest): Boolean {
        val thread = HandlerThread("wgk-netmon").apply { start() }
        return try {
            cm.registerBestMatchingNetworkCallback(request, systemCallback, Handler(thread.looper))
            systemCallbackThread = thread
            Log.i(TAG, "Following Android's pick of the physical network")
            true
        } catch (e: RuntimeException) {
            Log.w(TAG, "registerBestMatchingNetworkCallback refused: $e")
            thread.quitSafely()
            false
        }
    }

    fun stop() {
        for (cb in listOf(callback, systemCallback)) {
            try {
                cm.unregisterNetworkCallback(cb)
            } catch (e: Exception) {
                // Ignore: only one of the two was ever registered.
            }
        }
        systemCallbackThread?.quitSafely()
        systemCallbackThread = null
        systemPick = null
        networks.clear()
        links.clear()
        _bestPath.value = null
        _validated.value = false
    }

    private companion object {
        const val TAG = "WireGuard/PhysicalNetworkMonitor"
    }
}
