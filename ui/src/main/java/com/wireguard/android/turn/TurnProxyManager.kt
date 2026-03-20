/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.content.Intent
import android.util.Log
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.TurnBackend
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Lightweight manager for per-tunnel TURN client processes and logs.
 * 
 * TURN streams automatically reconnect on network changes (WiFi <-> Cellular)
 * via NetworkCallback and native notification.
 */
class TurnProxyManager(private val context: Context) {
    private val scope = CoroutineScope(Dispatchers.IO)
    private var activeTunnelName: String? = null
    private var activeSettings: TurnSettings? = null
    @Volatile private var userInitiatedStop: Boolean = false
    private val networkChangeLock = AtomicBoolean(false)
    private var restartFailureCount: Int = 0
    
    // Fields for network event filtering (Android 14 fix)
    @Volatile private var lastTransportType: Int? = null
    @Volatile private var lastRestartTime: Long = 0

    init {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        
        // Initialize lastTransportType with current active network to avoid false restart on app launch
        val activeNetwork = connectivityManager.activeNetwork
        if (activeNetwork != null) {
            val capabilities = connectivityManager.getNetworkCapabilities(activeNetwork)
            if (capabilities != null) {
                lastTransportType = when {
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkCapabilities.TRANSPORT_WIFI
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkCapabilities.TRANSPORT_CELLULAR
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkCapabilities.TRANSPORT_ETHERNET
                    else -> null
                }
                Log.d(TAG, "Initialized with active transport: ${transportName(lastTransportType ?: -1)}")
            }
        }
        
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
            .build()
        connectivityManager.registerNetworkCallback(request, object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                Log.d(TAG, "onAvailable: network=${network}")
            }
            override fun onLost(network: Network) {
                super.onLost(network)
                Log.d(TAG, "onLost: network=${network}")
            }
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                super.onCapabilitiesChanged(network, capabilities)

                // Determine current transport type
                val currentTransportType = when {
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkCapabilities.TRANSPORT_WIFI
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkCapabilities.TRANSPORT_CELLULAR
                    capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkCapabilities.TRANSPORT_ETHERNET
                    else -> {
                        Log.d(TAG, "onCapabilitiesChanged: unknown transport, skipping")
                        return
                    }
                }

                // Ignore networks without internet
                if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                    Log.d(TAG, "Skipping: no INTERNET capability")
                    return
                }

                // Ignore non-default networks (MMS, IMS, VPN)
                val NOT_DEFAULT_CAPABILITY = 23
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                    if (capabilities.hasCapability(NOT_DEFAULT_CAPABILITY)) {
                        Log.d(TAG, "Skipping: NOT_DEFAULT network")
                        return
                    }
                }

                // Compare with previous state
                val lastType = lastTransportType
                if (lastType != null && lastType == currentTransportType) {
                    // Skip minor changes within same transport type
                    return
                }

                // Check lock
                if (!networkChangeLock.compareAndSet(false, true)) {
                    Log.d(TAG, "Skipping: network change lock is held")
                    return
                }
                if (userInitiatedStop || activeTunnelName == null) {
                    Log.d(TAG, "Skipping: user initiated stop or no active tunnel")
                    networkChangeLock.set(false)
                    return
                }

                // Save current type
                lastTransportType = currentTransportType

                // Check restart frequency (10 seconds debounce)
                val now = System.currentTimeMillis()
                if (now - lastRestartTime < 10000) {
                    Log.w(TAG, "Skipping restart: too soon (${now - lastRestartTime}ms)")
                    networkChangeLock.set(false)
                    return
                }
                lastRestartTime = now

                Log.d(TAG, "Network change detected: transport=${transportName(currentTransportType)}, restarting TURN for $activeTunnelName")
                scope.launch {
                    try {
                        Log.d(TAG, "Stopping TURN proxy...")
                        TurnBackend.wgTurnProxyStop()
                        delay(1000)
                        
                        // Call wgNotifyNetworkChange() to reset DNS/HTTP in Go layer
                        Log.d(TAG, "Notifying Go layer of network change...")
                        TurnBackend.wgNotifyNetworkChange()
                        delay(500)
                        
                        val name = activeTunnelName ?: return@launch
                        val settings = activeSettings ?: return@launch
                        
                        Log.d(TAG, "Starting TURN for $name")
                        val success = startForTunnel(name, settings)
                        if (success) {
                            restartFailureCount = 0
                            Log.d(TAG, "TURN restarted successfully")
                        } else {
                            restartFailureCount++
                            val delayMs = when (restartFailureCount) {
                                1 -> 5000L
                                2 -> 10000L
                                else -> 20000L
                            }
                            Log.w(TAG, "Restart failed (attempt $restartFailureCount), retry in $delayMs ms")
                            delay(delayMs)
                        }
                    } finally {
                        delay(5000)
                        networkChangeLock.set(false)
                    }
                }
            }
        })
    }

    private data class Instance(
        val log: StringBuilder = StringBuilder(),
        @Volatile var running: Boolean = false,
    )

    private val instances = ConcurrentHashMap<String, Instance>()

    suspend fun startForTunnel(tunnelName: String, settings: TurnSettings): Boolean =
        withContext(Dispatchers.IO) {
            userInitiatedStop = false
            activeTunnelName = tunnelName
            activeSettings = settings
            restartFailureCount = 0
            val instance = instances.getOrPut(tunnelName) { Instance() }
            
            // Force stop any existing proxy before starting a new one
            TurnBackend.wgTurnProxyStop()
            TurnBackend.onVpnServiceCreated(null)

            // Pre-start VpnService to ensure native layer can protect sockets.
            // This is required because VpnService must exist to call protect().
            var vpnServiceReady = false
            try {
                val intent = Intent(context, GoBackend.VpnService::class.java).apply { setPackage(context.packageName) }
                context.startService(intent)
                for (attempt in 1..50) {
                    try {
                        TurnBackend.getVpnServiceFuture().get(200, TimeUnit.MILLISECONDS)
                        vpnServiceReady = true
                        break
                    } catch (e: Exception) { continue }
                }
            } catch (e: Exception) { Log.e(TAG, "VpnService error: ${e.message}") }

            if (vpnServiceReady) delay(500)

            val ret = TurnBackend.wgTurnProxyStart(
                settings.peer, settings.vkLink, settings.streams,
                if (settings.useUdp) 1 else 0,
                "127.0.0.1:${settings.localPort}",
                settings.turnIp,
                settings.turnPort,
                if (settings.noDtls) 1 else 0
            )

            val listenAddr = "127.0.0.1:${settings.localPort}"
            if (ret == 0) {
                instance.running = true
                val msg = "TURN started for tunnel \"$tunnelName\" listening on $listenAddr"
                Log.d(TAG, msg)
                appendLogLine(tunnelName, msg)
                true
            } else {
                val msg = "Failed to start TURN proxy (error $ret)"
                Log.e(TAG, msg)
                appendLogLine(tunnelName, msg)
                false
            }
        }

    suspend fun stopForTunnel(tunnelName: String) =
        withContext(Dispatchers.IO) {
            userInitiatedStop = true
            activeTunnelName = null
            activeSettings = null
            lastTransportType = null  // Reset for next launch
            lastRestartTime = 0
            val instance = instances[tunnelName] ?: return@withContext
            TurnBackend.wgTurnProxyStop()
            instance.running = false
            val msg = "TURN stopped for tunnel \"$tunnelName\""
            Log.d(TAG, msg)
            appendLogLine(tunnelName, msg)
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
        if (builder.isNotEmpty()) {
            builder.append('\n')
        }
        builder.append(line)
        if (builder.length > MAX_LOG_CHARS) builder.delete(0, builder.length - MAX_LOG_CHARS)
    }

    companion object {
        private const val TAG = "WireGuard/TurnProxyManager"
        private const val MAX_LOG_CHARS = 128 * 1024
        
        private fun transportName(type: Int): String = when (type) {
            NetworkCapabilities.TRANSPORT_WIFI -> "WiFi"
            NetworkCapabilities.TRANSPORT_CELLULAR -> "Cellular"
            NetworkCapabilities.TRANSPORT_ETHERNET -> "Ethernet"
            else -> "Unknown"
        }
    }
}
