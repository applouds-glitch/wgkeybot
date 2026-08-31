/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.widget

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.RemoteViews
import android.widget.Toast
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.activity.MainActivity
import com.wireguard.android.activity.WidgetToggleActivity
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.android.fragment.TunnelState
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.util.ErrorMessages
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.launch

class TunnelToggleAppWidgetProvider : AppWidgetProvider() {

    override fun onUpdate(context: Context, appWidgetManager: AppWidgetManager, appWidgetIds: IntArray) {
        renderInto(context, appWidgetManager, appWidgetIds)
    }

    override fun onAppWidgetOptionsChanged(
        context: Context,
        appWidgetManager: AppWidgetManager,
        appWidgetId: Int,
        newOptions: Bundle
    ) {
        renderInto(context, appWidgetManager, intArrayOf(appWidgetId))
    }

    override fun onReceive(context: Context, intent: Intent) {
        super.onReceive(context, intent)
        if (intent.action != ACTION_TOGGLE) return
        applicationScope.launch {
            val tunnel = findTunnel()
            if (tunnel == null) {
                // No tunnel yet — open the app so the user can import one.
                val openApp = Intent(context, MainActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                }
                context.startActivity(openApp)
                return@launch
            }
            // VpnService.prepare() returns non-null only when the user has never
            // granted VPN permission to this app. In that case we must launch an
            // Activity to host the system consent dialog. Once the permission is
            // granted, prepare() returns null and we can toggle silently from here.
            val needsConsent = try {
                Application.getBackend() is GoBackend &&
                    GoBackend.VpnService.prepare(context) != null
            } catch (e: Throwable) {
                Log.w(TAG, "VpnService.prepare failed: $e")
                false
            }
            if (needsConsent) {
                val toggle = Intent(context, WidgetToggleActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                context.startActivity(toggle)
                return@launch
            }
            // Tell the tracker we want Connecting/Disconnected immediately —
            // the polling loop will then refine the state from real handshake
            // data as it happens.
            // Resolved by the manager, not guessed from tunnel.state: during a connect
            // the state is still DOWN, so the tap that cancels it would paint Connecting.
            val goingUp = Application.getTunnelManager().resolveToggle(tunnel) == Tunnel.State.UP
            val tracker = Application.getTunnelStateTracker()
            if (goingUp) tracker.signalUserConnect() else tracker.signalUserDisconnect()
            try {
                tunnel.setStateAsync(Tunnel.State.TOGGLE)
            } catch (e: Throwable) {
                Log.e(TAG, "Widget toggle failed", e)
                tracker.signalUserDisconnect()
                Toast.makeText(
                    context,
                    context.getString(R.string.toggle_error, ErrorMessages[e]),
                    Toast.LENGTH_LONG
                ).show()
            }
        }
    }

    private enum class LayoutMode { ICON_ONLY, COMPACT, FULL }

    companion object {
        private const val TAG = "WireGuard/WidgetProvider"
        const val TUNNEL_NAME = "wgkeybot"
        private const val ACTION_TOGGLE = "com.wgkeybot.android.action.WIDGET_TOGGLE"
        // Widget size breakpoints (dp). Below COMPACT_MIN only the round power
        // button is shown; between COMPACT_MIN and FULL_MIN the status text is
        // shown but the WGKEYBOT brand label is hidden because it does not fit.
        private const val COMPACT_MIN_WIDTH_DP = 100
        private const val FULL_MIN_WIDTH_DP = 160

        /** Re-renders all instances of this widget on the launcher. */
        fun refreshAll(context: Context) {
            val mgr = AppWidgetManager.getInstance(context) ?: return
            val component = ComponentName(context, TunnelToggleAppWidgetProvider::class.java)
            val ids = mgr.getAppWidgetIds(component) ?: return
            if (ids.isEmpty()) return
            renderInto(context, mgr, ids)
        }

        private fun renderInto(context: Context, mgr: AppWidgetManager, ids: IntArray) {
            applicationScope.launch {
                val tunnel = findTunnel()
                val state = Application.getTunnelStateTracker().uiState.value.state
                for (id in ids) {
                    val mode = layoutModeFor(mgr, id)
                    mgr.updateAppWidget(id, buildViews(context, tunnel, mode, state))
                }
            }
        }

        private fun layoutModeFor(mgr: AppWidgetManager, appWidgetId: Int): LayoutMode {
            val opts = mgr.getAppWidgetOptions(appWidgetId) ?: return LayoutMode.FULL
            val minWidth = opts.getInt(AppWidgetManager.OPTION_APPWIDGET_MIN_WIDTH, 0)
            return when {
                minWidth == 0 -> LayoutMode.FULL
                minWidth >= FULL_MIN_WIDTH_DP -> LayoutMode.FULL
                minWidth >= COMPACT_MIN_WIDTH_DP -> LayoutMode.COMPACT
                else -> LayoutMode.ICON_ONLY
            }
        }

        private suspend fun findTunnel(): ObservableTunnel? =
            Application.getTunnelManager().getTunnels()[TUNNEL_NAME]

        private fun buildViews(
            context: Context,
            tunnel: ObservableTunnel?,
            mode: LayoutMode,
            state: TunnelState
        ): RemoteViews {
            // Show the green power icon only while the link is healthy. During
            // Connecting/Handshake/Reconnecting the spinner replaces the icon.
            val showConnectedIcon = state == TunnelState.Connected
            val isBusy = state == TunnelState.Connecting ||
                state == TunnelState.Handshake ||
                state == TunnelState.Reconnecting
            val layoutRes = when (mode) {
                LayoutMode.FULL -> R.layout.appwidget_tunnel_toggle
                LayoutMode.COMPACT, LayoutMode.ICON_ONLY -> R.layout.appwidget_tunnel_toggle_compact
            }
            val views = RemoteViews(context.packageName, layoutRes)

            views.setImageViewResource(
                R.id.widget_power,
                if (showConnectedIcon) R.drawable.widget_power_on else R.drawable.widget_power_off
            )
            views.setViewVisibility(R.id.widget_power, if (isBusy) View.GONE else View.VISIBLE)
            views.setViewVisibility(R.id.widget_progress, if (isBusy) View.VISIBLE else View.GONE)
            views.setViewVisibility(
                R.id.widget_status,
                if (mode == LayoutMode.ICON_ONLY) View.GONE else View.VISIBLE
            )
            val statusText = context.getString(statusTextFor(state, tunnel))
            views.setTextViewText(R.id.widget_status, statusText)
            views.setContentDescription(R.id.widget_button, statusText)

            val intent = Intent(context, TunnelToggleAppWidgetProvider::class.java).apply {
                action = ACTION_TOGGLE
            }
            val pi = PendingIntent.getBroadcast(
                context, 0, intent,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            views.setOnClickPendingIntent(R.id.widget_button, pi)
            return views
        }

        private fun statusTextFor(state: TunnelState, tunnel: ObservableTunnel?): Int = when {
            tunnel == null -> R.string.widget_no_tunnel
            state == TunnelState.Connecting -> R.string.widget_status_connecting
            state == TunnelState.Handshake -> R.string.widget_status_handshake
            state == TunnelState.Connected -> R.string.widget_status_on
            state == TunnelState.Reconnecting -> R.string.widget_status_reconnecting
            state == TunnelState.Failed -> R.string.widget_status_failed
            else -> R.string.widget_status_off
        }
    }
}
