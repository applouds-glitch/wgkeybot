/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.captcha

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.util.Log
import com.wireguard.android.Application
import com.wireguard.android.turn.PhysicalNetworkChoice

/**
 * Takes the process out from under the tunnel while a captcha WebView is up.
 *
 * This app is kept inside its own VPN, and a WebView cannot be given a socket
 * factory, so the only way to load the captcha over the physical network is to
 * bind the whole process to it for the duration. Which network is the point of
 * this class: the one the TURN sockets are on — see
 * [PhysicalNetworkChoice.bindOrder] for what went wrong before.
 *
 * Both captcha surfaces (the invisible WebView and the dialog activity) come
 * through here, so the binding is counted: whoever binds first saves what was
 * there, and it is put back when the last holder lets go. Before, each kept its
 * own copy of "the previous binding", and a tunnel stop restored one of them
 * underneath a dialog that was still on screen.
 */
object CaptchaNetworkBinding {
    private const val TAG = "WireGuard/CaptchaNetwork"

    private var holders = 0
    private var previous: Network? = null

    /**
     * Binds the process to a physical network. False if there was none to bind
     * to — the caller then holds nothing and must not [release].
     */
    @Synchronized
    fun bind(context: Context): Boolean {
        if (holders > 0) {
            holders++
            return true
        }
        return try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val inUse = Application.getTurnProxyManager().physicalNetwork
            val saved = cm.boundNetworkForProcess
            for (network in PhysicalNetworkChoice.bindOrder(inUse, candidates(cm))) {
                // Refused for a network that has gone away, or one kept in the
                // background that this app may not use: try the next.
                if (!cm.bindProcessToNetwork(network)) {
                    Log.w(TAG, "Binding to $network refused")
                    continue
                }
                previous = saved
                holders = 1
                Log.i(TAG, "Process bound to $network" +
                    if (network == inUse) " — the network TURN is on" else " — TURN is on $inUse")
                return true
            }
            Log.w(TAG, "No physical network to bind to: the captcha goes wherever the process does")
            false
        } catch (e: Exception) {
            Log.e(TAG, "Binding failed", e)
            false
        }
    }

    /** Lets go of one [bind]; the last one puts the previous binding back. */
    @Synchronized
    fun release(context: Context) {
        if (holders == 0) return
        if (--holders == 0) restore(context)
    }

    /**
     * The tunnel is going down: nothing may be left bound, whoever was holding.
     * A holder that lets go after this finds nothing to release.
     */
    @Synchronized
    fun reset(context: Context) {
        if (holders == 0) return
        holders = 0
        restore(context)
    }

    private fun restore(context: Context) {
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.bindProcessToNetwork(previous)
            Log.i(TAG, "Process binding restored")
        } catch (e: Exception) {
            Log.e(TAG, "Restoring the binding failed", e)
        }
        previous = null
    }

    // What the monitor ranks when Android has not told it its pick: non-VPN
    // networks with internet that this app can actually use (foreground).
    private fun candidates(cm: ConnectivityManager): List<PhysicalNetworkChoice.Candidate<Network>> {
        @Suppress("DEPRECATION")
        return cm.allNetworks.mapNotNull { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_FOREGROUND)) return@mapNotNull null
            PhysicalNetworkChoice.Candidate(
                network,
                when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> PhysicalNetworkChoice.Transport.WIFI
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> PhysicalNetworkChoice.Transport.CELLULAR
                    else -> PhysicalNetworkChoice.Transport.OTHER
                },
            )
        }
    }
}
