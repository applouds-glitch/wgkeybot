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

    init {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder().build()
        connectivityManager.registerNetworkCallback(request, object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                super.onAvailable(network)
                Log.d(TAG, "Network available")
                TurnBackend.wgNotifyNetworkChange()
            }
            override fun onLost(network: Network) {
                super.onLost(network)
                Log.d(TAG, "Network lost")
                TurnBackend.wgNotifyNetworkChange()
            }
            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                super.onCapabilitiesChanged(network, capabilities)
                if (!networkChangeLock.compareAndSet(false, true)) return
                if (userInitiatedStop || activeTunnelName == null) {
                    networkChangeLock.set(false)
                    return
                }

                Log.d(TAG, "Network change detected, restarting TURN for $activeTunnelName")
                scope.launch {
                    try {
                        Log.d(TAG, "Stopping TURN proxy...")
                        TurnBackend.wgTurnProxyStop()
                        delay(1000)
                        Log.d(TAG, "Notifying Go layer...")
                        TurnBackend.wgNotifyNetworkChange()

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
                "127.0.0.1:${settings.localPort}"
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
    }
}
