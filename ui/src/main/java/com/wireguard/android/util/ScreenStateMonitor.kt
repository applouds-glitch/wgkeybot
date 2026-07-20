/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.PowerManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * App-wide screen interactivity signal for battery-aware duty cycling.
 *
 * The stats poller ([com.wireguard.android.model.TunnelStateTracker]) only exists
 * to feed UI surfaces; with the screen off nobody is looking, so it parks on this
 * signal instead of burning a JNI stats call every 2s all night. This is purely a
 * display concern — it never touches the tunnel, keepalives, or reconnect logic,
 * and the handshake watchdog keeps running unchanged to catch a dead tunnel.
 */
object ScreenStateMonitor {
    private val _screenOn = MutableStateFlow(true)
    val screenOn: StateFlow<Boolean> = _screenOn.asStateFlow()

    fun init(context: Context) {
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        _screenOn.value = pm.isInteractive
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                when (intent.action) {
                    Intent.ACTION_SCREEN_ON -> _screenOn.value = true
                    Intent.ACTION_SCREEN_OFF -> _screenOn.value = false
                }
            }
        }
        context.applicationContext.registerReceiver(receiver, IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        })
    }
}
