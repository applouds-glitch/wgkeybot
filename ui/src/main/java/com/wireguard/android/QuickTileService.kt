/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android

import android.annotation.SuppressLint
import android.app.PendingIntent
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.drawable.Icon
import android.os.Build
import android.os.IBinder
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.util.Log
import android.widget.Toast
import androidx.databinding.Observable
import androidx.databinding.Observable.OnPropertyChangedCallback
import com.wireguard.android.activity.MainActivity
import com.wireguard.android.activity.TunnelToggleActivity
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.Application.Companion.getTunnelStateTracker
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.util.applicationScope
import com.wireguard.android.widget.SlashDrawable
import kotlinx.coroutines.launch

/**
 * Service that maintains the application's custom Quick Settings tile. This service is bound by the
 * system framework as necessary to update the appearance of the tile in the system UI, and to
 * forward click events to the application.
 */
class QuickTileService : TileService() {
    private val onStateChangedCallback = OnStateChangedCallback()
    private val onTunnelChangedCallback = OnTunnelChangedCallback()
    private var iconOff: Icon? = null
    private var iconOn: Icon? = null
    private var tunnel: ObservableTunnel? = null

    /* This works around an annoying unsolved frameworks bug some people are hitting. */
    override fun onBind(intent: Intent): IBinder? {
        var ret: IBinder? = null
        try {
            ret = super.onBind(intent)
        } catch (e: Throwable) {
            Log.d(TAG, "Failed to bind to TileService", e)
        }
        return ret
    }

    override fun onClick() {
        applicationScope.launch {
            if (tunnel == null) {
                Application.getTunnelManager().getTunnels()
                updateTile()
            }
            when (val tunnel = tunnel) {
                null -> {
                    Log.d(TAG, "No tunnel set, so launching main activity")
                    launchAndCollapse(Intent(this@QuickTileService, MainActivity::class.java))
                }

                else -> {
                    // Android hands VPN consent to one app at a time: starting any other
                    // VPN revokes ours, and prepare() goes back to returning an intent.
                    // GoBackend then throws VPN_NOT_AUTHORIZED, and a tile cannot host the
                    // system consent dialog itself — so hand off to an activity that can,
                    // the way the main screen and the widget already do. The catch below is
                    // not a substitute: it starts the activity from the background after
                    // onClick() has returned, which Android 10+ blocks, and on 14+ it asks
                    // for an overlay permission instead of showing the consent dialog. The
                    // symptom was a tile that did nothing for anyone who had used another
                    // VPN in between, leaving the app itself as the only way to connect.
                    if (needsVpnConsent()) {
                        Log.d(TAG, "VPN consent missing, so handing off to TunnelToggleActivity")
                        launchAndCollapse(Intent(this@QuickTileService, TunnelToggleActivity::class.java))
                        return@launch
                    }
                    unlockAndRun {
                        applicationScope.launch {
                            val tracker = getTunnelStateTracker()
                            // Ask the manager what this toggle resolves to instead of
                            // guessing from tunnel.state: during a connect the state is
                            // still DOWN, so the tap that cancels it would paint
                            // Connecting and then stick there — nothing changes
                            // tunnel.state afterwards to correct the tracker.
                            val goingUp = Application.getTunnelManager()
                                .resolveToggle(tunnel) == Tunnel.State.UP
                            if (goingUp) tracker.signalUserConnect() else tracker.signalUserDisconnect()
                            try {
                                tunnel.setStateAsync(Tunnel.State.TOGGLE)
                                updateTile()
                            } catch (e: Throwable) {
                                // Report and stop, like the widget does. Missing consent is
                                // handled above, so anything landing here is a real connect
                                // failure that starting an activity would not fix: retrying
                                // the toggle in TunnelToggleActivity just fails again, and
                                // the overlay permission this used to ask for on API 34+ is
                                // not even declared by the app, so that was a dead end.
                                tracker.signalUserDisconnect()
                                val message = getString(R.string.toggle_error, ErrorMessages[e])
                                Log.e(TAG, message, e)
                                Toast.makeText(this@QuickTileService, message, Toast.LENGTH_LONG).show()
                            }
                        }
                    }
                }
            }
        }
    }

    private suspend fun needsVpnConsent(): Boolean = try {
        Application.getBackend() is GoBackend && GoBackend.VpnService.prepare(this) != null
    } catch (e: Throwable) {
        Log.w(TAG, "VpnService.prepare failed", e)
        false
    }

    private fun launchAndCollapse(intent: Intent) {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startActivityAndCollapse(PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE))
        } else {
            startActivityAndCollapseCompat(intent)
        }
    }

    @SuppressLint("StartActivityAndCollapseDeprecated")
    @Suppress("DEPRECATION")
    private fun startActivityAndCollapseCompat(intent: Intent) {
        startActivityAndCollapse(intent)
    }

    override fun onCreate() {
        isAdded = true
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            iconOn = Icon.createWithResource(this, R.drawable.ic_launcher_foreground)
            iconOff = iconOn
            return
        }
        val icon = SlashDrawable(resources.getDrawable(R.drawable.ic_launcher_foreground, Application.get().theme))
        icon.setAnimationEnabled(false) /* Unfortunately we can't have animations, since Icons are marshaled. */
        icon.setSlashed(false)
        var b = Bitmap.createBitmap(icon.intrinsicWidth, icon.intrinsicHeight, Bitmap.Config.ARGB_8888)
        var c = Canvas(b)
        icon.setBounds(0, 0, c.width, c.height)
        icon.draw(c)
        iconOn = Icon.createWithBitmap(b)
        icon.setSlashed(true)
        b = Bitmap.createBitmap(icon.intrinsicWidth, icon.intrinsicHeight, Bitmap.Config.ARGB_8888)
        c = Canvas(b)
        icon.setBounds(0, 0, c.width, c.height)
        icon.draw(c)
        iconOff = Icon.createWithBitmap(b)
    }

    override fun onDestroy() {
        super.onDestroy()
        isAdded = false
    }

    override fun onStartListening() {
        Application.getTunnelManager().addOnPropertyChangedCallback(onTunnelChangedCallback)
        tunnel?.addOnPropertyChangedCallback(onStateChangedCallback)
        updateTile()
    }

    override fun onStopListening() {
        tunnel?.removeOnPropertyChangedCallback(onStateChangedCallback)
        Application.getTunnelManager().removeOnPropertyChangedCallback(onTunnelChangedCallback)
    }

    override fun onTileAdded() {
        isAdded = true
    }

    override fun onTileRemoved() {
        isAdded = false
    }

    private fun updateTile() {
        // Update the tunnel. Resolve by name first — lastUsedTunnel is only set once a
        // connect has actually reached UP, so before the first successful connect the
        // tile would sit on "no tunnel" and merely open the app. Every other entry point
        // (main screen, widget, state tracker) already keys off the name.
        val manager = Application.getTunnelManager()
        val newTunnel = manager.getTunnelByName(TUNNEL_NAME) ?: manager.lastUsedTunnel
        if (newTunnel != tunnel) {
            tunnel?.removeOnPropertyChangedCallback(onStateChangedCallback)
            tunnel = newTunnel
            tunnel?.addOnPropertyChangedCallback(onStateChangedCallback)
        }
        // Update the tile contents.
        val tile = qsTile ?: return

        when (val tunnel = tunnel) {
            null -> {
                tile.label = getString(R.string.app_name)
                tile.state = Tile.STATE_INACTIVE
                tile.icon = iconOff
            }
            else -> {
                tile.label = tunnel.name
                tile.state = if (tunnel.state == Tunnel.State.UP) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
                tile.icon = if (tunnel.state == Tunnel.State.UP) iconOn else iconOff
            }
        }
        tile.updateTile()
    }

    private inner class OnStateChangedCallback : OnPropertyChangedCallback() {
        override fun onPropertyChanged(sender: Observable, propertyId: Int) {
            if (sender != tunnel) {
                sender.removeOnPropertyChangedCallback(this)
                return
            }
            if (propertyId != 0 && propertyId != BR.state)
                return
            updateTile()
        }
    }

    private inner class OnTunnelChangedCallback : OnPropertyChangedCallback() {
        override fun onPropertyChanged(sender: Observable, propertyId: Int) {
            if (propertyId != 0 && propertyId != BR.lastUsedTunnel)
                return
            updateTile()
        }
    }

    companion object {
        private const val TAG = "WireGuard/QuickTileService"
        private const val TUNNEL_NAME = "wgkeybot"
        var isAdded: Boolean = false
            private set
    }
}
