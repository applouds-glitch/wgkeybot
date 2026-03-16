/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.util.Log
import com.wireguard.android.backend.TurnBackend
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * Lightweight manager for per-tunnel TURN client processes and logs.
 */
class TurnProxyManager(private val context: Context) {
    private data class Instance(
        val log: StringBuilder = StringBuilder(),
        @Volatile var running: Boolean = false,
    )

    private val instances = ConcurrentHashMap<String, Instance>()

    suspend fun startForTunnel(tunnelName: String, settings: TurnSettings): Boolean =
        withContext(Dispatchers.IO) {
            val instance = instances.getOrPut(tunnelName) { Instance() }
            
            // Force stop any existing proxy before starting a new one
            TurnBackend.wgTurnProxyStop()
            
            val listenAddr = "127.0.0.1:${settings.localPort}"
            val ret = TurnBackend.wgTurnProxyStart(
                settings.peer,
                settings.vkLink,
                settings.streams,
                settings.useUdp,
                listenAddr
            )

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
        instances[tunnelName]?.log?.apply {
            setLength(0)
        }
    }

    fun appendLogLine(tunnelName: String, line: String) {
        val instance = instances.getOrPut(tunnelName) { Instance() }
        val builder = instance.log
        if (builder.isNotEmpty()) {
            builder.append('\n')
        }
        builder.append(line)
        if (builder.length > MAX_LOG_CHARS) {
            val overflow = builder.length - MAX_LOG_CHARS
            try {
                builder.delete(0, overflow)
            } catch (e: Throwable) {
                Log.e(TAG, "Failed to trim TURN log for $tunnelName", e)
            }
        }
    }

    companion object {
        private const val TAG = "WireGuard/TurnProxyManager"
        private const val MAX_LOG_CHARS = 128 * 1024
    }
}

