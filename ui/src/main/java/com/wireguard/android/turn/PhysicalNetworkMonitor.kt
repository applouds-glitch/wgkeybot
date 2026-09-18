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
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.Inet4Address
import java.net.Inet6Address
import java.util.concurrent.ConcurrentHashMap

/**
 * Monitors physical networks (WiFi, Cellular) and provides the "best" available one.
 * Ignores VPN interfaces to avoid tracking our own tunnel.
 * Priority: WiFi > Cellular.
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
     * Whether [currentPath] currently has validated upstream connectivity.
     * This is separate from [rawPath] because Android can add or remove
     * NET_CAPABILITY_VALIDATED without changing the Network object.
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
     * True if [network] currently reports validated internet connectivity
     * (NET_CAPABILITY_VALIDATED) — the system confirmed a real upstream, not
     * just an associated link. A captive portal, associated-but-dead Wi-Fi or
     * no-signal cell reports INTERNET but not VALIDATED. Native combines this
     * hint with observed TURN reachability and a rate-limited recovery probe, so
     * probe-blocking corporate networks are not treated as permanently offline.
     */
    fun isValidated(network: Network?): Boolean {
        if (network == null) return false
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    private val networks = ConcurrentHashMap<Network, NetworkCapabilities>()
    private val links = ConcurrentHashMap<Network, String>()

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

    private fun update() {
        val candidates = networks.entries.toList()
        val validatedCandidates = candidates.filter { (_, caps) ->
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        }

        fun bestFrom(entries: List<Map.Entry<Network, NetworkCapabilities>>): Map.Entry<Network, NetworkCapabilities>? =
            entries.firstOrNull { it.value.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) }
                ?: entries.firstOrNull { it.value.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) }
                ?: entries.firstOrNull()

        // Prefer a usable validated path over associated-but-dead Wi-Fi. If no
        // path is validated yet, retain the old priority as a passive baseline.
        val bestEntry = bestFrom(validatedCandidates) ?: bestFrom(candidates)
        _bestPath.value = bestEntry?.key?.let { network ->
            NetworkPath(network, identityFor(network))
        }
        _validated.value = bestEntry?.value?.let { caps ->
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        } == true
    }

    fun start() {
        // Initial state: identify current best physical network before registering callback
        // We look through all networks because activeNetwork might be the VPN itself
        @Suppress("DEPRECATION")
        cm.allNetworks.forEach { network ->
            val caps = cm.getNetworkCapabilities(network)
            if (caps != null &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
                networks[network] = caps
                cm.getLinkProperties(network)?.let { links[network] = addressIdentity(it) }
            }
        }
        update()

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        cm.registerNetworkCallback(request, callback)
    }

    fun stop() {
        try {
            cm.unregisterNetworkCallback(callback)
        } catch (e: Exception) {
            // Ignore
        }
        networks.clear()
        links.clear()
        _bestPath.value = null
        _validated.value = false
    }
}
