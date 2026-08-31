/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.widget.TunnelToggleAppWidgetProvider
import kotlinx.coroutines.launch

/**
 * Headless activity launched from the home-screen widget to toggle the named
 * tunnel. Mirrors [TunnelToggleActivity] but resolves the tunnel by name and
 * uses [finish] instead of [finishAffinity] so it does not close the main app
 * when the user has it open.
 */
class WidgetToggleActivity : AppCompatActivity() {
    private val permissionActivityResultLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { toggleTunnel() }

    private fun toggleTunnel() {
        lifecycleScope.launch {
            val tunnel = Application.getTunnelManager().getTunnels()[TunnelToggleAppWidgetProvider.TUNNEL_NAME]
            if (tunnel == null) {
                finish()
                return@launch
            }
            val tracker = Application.getTunnelStateTracker()
            // Resolved by the manager, not guessed from tunnel.state: during a connect
            // the state is still DOWN, so the tap that cancels it would paint Connecting.
            val goingUp = Application.getTunnelManager().resolveToggle(tunnel) == Tunnel.State.UP
            if (goingUp) tracker.signalUserConnect() else tracker.signalUserDisconnect()
            try {
                tunnel.setStateAsync(Tunnel.State.TOGGLE)
            } catch (e: Throwable) {
                val error = ErrorMessages[e]
                val message = getString(R.string.toggle_error, error)
                Log.e(TAG, message, e)
                tracker.signalUserDisconnect()
                Toast.makeText(this@WidgetToggleActivity, message, Toast.LENGTH_LONG).show()
            }
            finish()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lifecycleScope.launch {
            if (Application.getBackend() is GoBackend) {
                try {
                    val intent = GoBackend.VpnService.prepare(this@WidgetToggleActivity)
                    if (intent != null) {
                        permissionActivityResultLauncher.launch(intent)
                        return@launch
                    }
                } catch (e: Exception) {
                    Toast.makeText(this@WidgetToggleActivity, ErrorMessages[e], Toast.LENGTH_LONG).show()
                }
            }
            toggleTunnel()
        }
    }

    companion object {
        private const val TAG = "WireGuard/WidgetToggleActivity"
    }
}
