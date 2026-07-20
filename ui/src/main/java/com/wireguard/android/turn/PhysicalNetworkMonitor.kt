/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import java.util.concurrent.ConcurrentHashMap

/**
 * Monitors physical networks (WiFi, Cellular) and provides the "best" available one.
 * Ignores VPN interfaces to avoid tracking our own tunnel.
 * Priority: WiFi > Cellular.
 */
class PhysicalNetworkMonitor(context: Context) {
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    
    private val _bestNetwork = MutableStateFlow<Network?>(null)
    private val _validated = MutableStateFlow(false)
    
    /**
     * Flow of the best available physical network.
     * Includes a 1500ms debounce to filter out rapid transitions and flickering.
     */
    @OptIn(kotlinx.coroutines.FlowPreview::class)
    val bestNetwork = _bestNetwork.asStateFlow()
        .debounce(1500)
        .distinctUntilChanged()

    /**
     * Whether [currentNetwork] currently has validated upstream connectivity.
     * This is separate from [bestNetwork] because Android can add or remove
     * NET_CAPABILITY_VALIDATED without changing the Network object.
     */
    val validated = _validated.asStateFlow()

    /**
     * Synchronously get the current best network without debounce.
     */
    val currentNetwork: Network?
        get() = _bestNetwork.value

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

        override fun onLost(network: Network) {
            networks.remove(network)
            update()
        }
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
        _bestNetwork.value = bestEntry?.key
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
        _bestNetwork.value = null
        _validated.value = false
    }
}
