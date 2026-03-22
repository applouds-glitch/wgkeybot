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
import android.os.Build
import android.util.Log
import com.wireguard.android.backend.TurnBackend
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap
import java.net.Inet4Address

/**
 * Lightweight manager for per-tunnel TURN client processes and logs.
 *
 * TURN streams automatically reconnect on network changes (WiFi <-> Cellular)
 * using the DefaultNetworkCallback to track the system's preferred internet connection.
 */
class TurnProxyManager(private val context: Context) {
    private val scope = CoroutineScope(Dispatchers.IO)
    
    // State
    private var activeTunnelName: String? = null
    private var activeSettings: TurnSettings? = null
    @Volatile private var userInitiatedStop: Boolean = false
    
    // Network tracking
	private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private var reconnectJob: Job? = null
    @Volatile private var pendingNetwork: Network? = null
    @Volatile private var lastKnownNetwork: Network? = null
	@Volatile private var lastKnownIps: Set<String> = emptySet()
    
    init {
        //val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

        // Initialize with current active network (if it's not VPN)
        // We do a quick check to avoid setting VPN as baseline
        val active = connectivityManager.activeNetwork
        val caps = connectivityManager.getNetworkCapabilities(active)
        if (active != null && caps != null && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) {
            lastKnownNetwork = active
			lastKnownIps = getIpsV4ForNetwork(active)
        }

        // Use a specific request that EXCLUDES VPNs.
        // This ensures we track the underlying physical network (WiFi/LTE), not our own tunnel.
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) // Crucial: Ignore VPN interfaces
            .build()

        connectivityManager.registerNetworkCallback(request, object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                Log.d(TAG, "onAvailable: Physical network $network")
                handleNetworkChange(network)
            }

            override fun onLost(network: Network) {
                 Log.d(TAG, "onLost: Physical network $network")
                 if (lastKnownNetwork == network) {
                     // We lost our tracking network
                     // We don't restart immediately, we wait for a new one
                 }
                 if (pendingNetwork == network) {
                     Log.d(TAG, "Cancelling pending restart check: network $network lost")
                     reconnectJob?.cancel()
                     pendingNetwork = null
                 }
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return
                // We are guaranteed NOT_VPN by the request filter
                handleNetworkChange(network)
            }
        })
    }

    /**
     * Central handler for network changes.
     * Uses Debouncing via Job Cancellation: prevents race conditions by canceling any pending
     * restart check if a new network change arrives immediately.
     *
     * The check itself (IP comparison) is delayed by 5s to ensure network stability.
     */
    private fun handleNetworkChange(network: Network) {
        if (userInitiatedStop || activeTunnelName == null) return

        // Immediate baseline setting if we don't have one yet
        if (lastKnownNetwork == null) {
            val ips = getIpsV4ForNetwork(network)
            if (ips.isNotEmpty()) {
                Log.d(TAG, "Setting initial network baseline immediately: $network with IPs: $ips")
                lastKnownNetwork = network
                lastKnownIps = ips
                return
            }
        }

        // Schedule a debounced check. If another event comes within 5s, this is cancelled.
        pendingNetwork = network
        reconnectJob?.cancel()
        reconnectJob = scope.launch {
            // Wait for network to settle (e.g. DHCP to finish)
            delay(5000)
            if (!isActive || pendingNetwork != network) return@launch

            val currentIps = getIpsV4ForNetwork(network)
            
            // 1. Check if IPs are even available
            if (currentIps.isEmpty()) {
                Log.d(TAG, "Network $network has no IPv4 after 5s. Skipping restart.")
                return@launch
            }

            // 2. Check if anything actually changed compared to what's currently running
            if (lastKnownNetwork == network && lastKnownIps == currentIps) {
                Log.d(TAG, "Network state is stable and unchanged for $network. Skipping restart.")
                return@launch
            }

            // 3. Special case: same IPs but different network handle
            if (lastKnownNetwork != network && lastKnownIps == currentIps) {
                Log.d(TAG, "Network changed ($network), but IPs remained same. Updating baseline only.")
                lastKnownNetwork = network
                return@launch
            }

            // 4. Real change confirmed
            Log.d(TAG, "Network change confirmed after 5s debounce: $lastKnownIps -> $currentIps. Restarting TURN.")
            lastKnownNetwork = network
            lastKnownIps = currentIps
            performRestartSequence()
        }
    }

    private suspend fun performRestartSequence() {
        if (userInitiatedStop || activeTunnelName == null) return

        Log.d(TAG, "Stopping TURN proxy for restart...")
        TurnBackend.wgTurnProxyStop()
        
        // Critical: Notify Go backend to clear internal socket states/DNS cache
        Log.d(TAG, "Notifying Go layer of network change...")
        TurnBackend.wgNotifyNetworkChange()
        
        delay(500) // Give Go minimal time to react

        val name = activeTunnelName ?: return
        val settings = activeSettings ?: return

        var attempts = 0
        while (currentCoroutineContext().isActive && !userInitiatedStop) {
            attempts++
            Log.d(TAG, "Starting TURN for $name (Attempt $attempts)")
            
            val success = startForTunnelInternal(name, settings)
            if (success) {
                Log.d(TAG, "TURN restarted successfully on attempt $attempts")
                return // Exit loop on success
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

    private data class Instance(
        val log: StringBuilder = StringBuilder(),
        @Volatile var running: Boolean = false,
    )

    private val instances = ConcurrentHashMap<String, Instance>()
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
        
        if (turnSettings == null || !turnSettings.enabled) {
            Log.d(TAG, "TURN not enabled, skipping")
            return true
        }

        val success = startForTunnelInternal(tunnelName, turnSettings)
        
        // After initial start, allow network changes to trigger restarts
        // We delay slightly to ensure we don't catch the immediate network fluctuation caused by VPN itself
        scope.launch {
            delay(2000)
            Log.d(TAG, "Initialization phase complete, network monitoring active")
        }
        
        return success
    }

    suspend fun startForTunnel(tunnelName: String, settings: TurnSettings): Boolean {
        return startForTunnelInternal(tunnelName, settings)
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
                delay(200)

                // Wait for JNI to be registered
                val jniReady = TurnBackend.waitForVpnServiceRegistered(2000)
                if (!jniReady) {
                    Log.e(TAG, "TIMEOUT waiting for JNI registration!")
                    return@withContext false
                }

                Log.d(TAG, "Starting TURN proxy for $tunnelName...")
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
            } finally {
                operationMutex.unlock()
            }
        }

    suspend fun stopForTunnel(tunnelName: String) =
        withContext(Dispatchers.IO) {
            userInitiatedStop = true
            activeTunnelName = null
            activeSettings = null
            lastKnownNetwork = null
			lastKnownIps = emptySet()
            
            // Cancel any pending restart jobs
            reconnectJob?.cancel()

            // Reset VpnService reference
            TurnBackend.onVpnServiceCreated(null)

            operationMutex.lock()
            try {
                val instance = instances[tunnelName] ?: return@withContext
                TurnBackend.wgTurnProxyStop()
                instance.running = false
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
	
	private fun getIpsV4ForNetwork(network: Network): Set<String> {
		val linkProperties = connectivityManager.getLinkProperties(network) ?: return emptySet()
		return linkProperties.linkAddresses
        .map { it.address }
        .filterIsInstance<Inet4Address>()
        .mapNotNull { it.hostAddress }
        .toSet()
	}

    companion object {
        private const val TAG = "WireGuard/TurnProxyManager"
        private const val MAX_LOG_CHARS = 128 * 1024
    }
}
