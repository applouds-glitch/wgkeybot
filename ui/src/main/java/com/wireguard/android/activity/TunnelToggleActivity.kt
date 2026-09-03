/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.content.ComponentName
import android.content.Context
import android.os.Bundle
import android.service.quicksettings.TileService
import android.util.Log
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wireguard.android.Application
import com.wireguard.android.QuickTileService
import com.wireguard.android.R
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.launch

/**
 * Headless activity that toggles the primary tunnel on behalf of the quick
 * settings tile and the home-screen widget. Both toggle silently on their own;
 * they come here when the VPN consent dialog has to be shown, and only an
 * activity can host that.
 *
 * It lives in a task of its own (taskAffinity="" in the manifest) and leaves
 * with [finish], never finishAffinity: launched into the app's task it dragged
 * the main screen to the front and then closed it.
 */
class TunnelToggleActivity : AppCompatActivity() {
    private val permissionActivityResultLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { toggleTunnel() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        lifecycleScope.launch {
            if (Application.getBackend() is GoBackend) {
                try {
                    val intent = GoBackend.VpnService.prepare(this@TunnelToggleActivity)
                    if (intent != null) {
                        permissionActivityResultLauncher.launch(intent)
                        return@launch
                    }
                } catch (e: Exception) {
                    Toast.makeText(this@TunnelToggleActivity, ErrorMessages[e], Toast.LENGTH_LONG).show()
                }
            }
            toggleTunnel()
        }
    }

    /**
     * Fires the toggle and leaves at once.
     *
     * The toggle is not awaited here, and that is the point: a connect takes up
     * to 25 seconds (TURN allocation, credentials, the handshake wait), and this
     * window is full-screen and translucent, so waiting inside it left whatever
     * was underneath frozen for the duration, with Back merely cancelling the
     * wait. The work runs on the application scope instead, the tracker paints
     * Connecting/Disconnected for every surface, and the tile is told to re-read
     * its state once the toggle has settled.
     */
    private fun toggleTunnel() {
        toggleInBackground(applicationContext)
        finish()
    }

    companion object {
        private const val TAG = "WireGuard/TunnelToggleActivity"

        private fun toggleInBackground(context: Context) {
            applicationScope.launch {
                val manager = Application.getTunnelManager()
                val tunnel = manager.primaryTunnel()
                if (tunnel == null) {
                    Log.w(TAG, "No tunnel to toggle")
                    return@launch
                }
                val tracker = Application.getTunnelStateTracker()
                // Resolved by the manager, not guessed from tunnel.state: during a
                // connect the state is still DOWN, so the tap that cancels it would
                // paint Connecting.
                val goingUp = manager.resolveToggle(tunnel) == Tunnel.State.UP
                if (goingUp) tracker.signalUserConnect() else tracker.signalUserDisconnect()
                try {
                    tunnel.setStateAsync(Tunnel.State.TOGGLE)
                } catch (e: Throwable) {
                    val message = context.getString(R.string.toggle_error, ErrorMessages[e])
                    Log.e(TAG, message, e)
                    tracker.signalUserDisconnect()
                    Toast.makeText(context, message, Toast.LENGTH_LONG).show()
                } finally {
                    TileService.requestListeningState(context, ComponentName(context, QuickTileService::class.java))
                }
            }
        }
    }
}
