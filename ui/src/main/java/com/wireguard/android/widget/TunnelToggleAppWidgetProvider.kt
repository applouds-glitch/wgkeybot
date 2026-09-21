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
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.util.SizeF
import android.util.TypedValue
import android.view.View
import android.widget.RemoteViews
import android.widget.Toast
import androidx.core.os.BundleCompat
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.activity.MainActivity
import com.wireguard.android.activity.TunnelToggleActivity
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
                val toggle = Intent(context, TunnelToggleActivity::class.java).apply {
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
        private const val ACTION_TOGGLE = "com.wgkeybot.android.action.WIDGET_TOGGLE"
        // Narrow widgets keep only the bot; medium widgets put the status below it.
        // Height matters too: a landscape launcher can offer only one short row.
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
                    mgr.updateAppWidget(id, buildSizedViews(context, mgr.getAppWidgetOptions(id), tunnel, state))
                }
            }
        }

        private fun buildSizedViews(
            context: Context,
            options: Bundle,
            tunnel: ObservableTunnel?,
            state: TunnelState
        ): RemoteViews {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val sizes = BundleCompat.getParcelableArrayList(
                    options, AppWidgetManager.OPTION_APPWIDGET_SIZES, SizeF::class.java
                )?.filter { it.width > 0 && it.height > 0 }?.distinct()?.take(16)
                if (!sizes.isNullOrEmpty()) {
                    return RemoteViews(sizes.associateWith { buildViews(context, tunnel, state, it) })
                }
            }

            // The two minimums describe different orientations, not one small
            // rectangle. Pair portrait width with portrait height (and vice versa).
            val minWidth = options.getInt(AppWidgetManager.OPTION_APPWIDGET_MIN_WIDTH)
                .takeIf { it > 0 } ?: FULL_MIN_WIDTH_DP
            val minHeight = options.getInt(AppWidgetManager.OPTION_APPWIDGET_MIN_HEIGHT)
                .takeIf { it > 0 } ?: 57
            val maxWidth = options.getInt(AppWidgetManager.OPTION_APPWIDGET_MAX_WIDTH)
                .coerceAtLeast(minWidth)
            val maxHeight = options.getInt(AppWidgetManager.OPTION_APPWIDGET_MAX_HEIGHT)
                .coerceAtLeast(minHeight)
            return RemoteViews(
                buildViews(context, tunnel, state, SizeF(maxWidth.toFloat(), minHeight.toFloat())),
                buildViews(context, tunnel, state, SizeF(minWidth.toFloat(), maxHeight.toFloat()))
            )
        }

        private suspend fun findTunnel(): ObservableTunnel? =
            Application.getTunnelManager().primaryTunnel()

        private fun buildViews(
            context: Context,
            tunnel: ObservableTunnel?,
            state: TunnelState,
            size: SizeF
        ): RemoteViews {
            val fontScale = context.resources.configuration.fontScale.coerceAtLeast(1f)
            val mode = when {
                size.width >= FULL_MIN_WIDTH_DP * fontScale &&
                    size.height >= 36 * fontScale + 12 -> LayoutMode.FULL
                size.width >= COMPACT_MIN_WIDTH_DP && size.height >= 88 * fontScale -> LayoutMode.COMPACT
                else -> LayoutMode.ICON_ONLY
            }
            val showAction = mode == LayoutMode.FULL &&
                size.width >= 220 * fontScale && size.height >= 100 * fontScale
            // A removed tunnel must not retain the previous connection's green mark.
            val displayState = if (tunnel == null) TunnelState.Disconnected else state
            val showConnectedIcon = displayState == TunnelState.Connected
            val isBusy = displayState == TunnelState.Connecting ||
                displayState == TunnelState.Handshake ||
                displayState == TunnelState.Reconnecting ||
                displayState == TunnelState.WaitingForNetwork
            val layoutRes = when (mode) {
                LayoutMode.FULL -> R.layout.appwidget_tunnel_toggle
                LayoutMode.COMPACT, LayoutMode.ICON_ONLY -> R.layout.appwidget_tunnel_toggle_compact
            }
            val views = RemoteViews(context.packageName, layoutRes)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                // Grow the mark with its actual launcher cell instead of leaving
                // a fixed 44dp button floating inside a much larger card.
                val buttonSize = when (mode) {
                    LayoutMode.FULL -> minOf(size.width * 0.28f, size.height - 12, 72f)
                    LayoutMode.COMPACT -> minOf(size.width - 20, size.height - 20 * fontScale - 20, 104f)
                    LayoutMode.ICON_ONLY -> minOf(size.width - 12, size.height - 12, 104f)
                }.coerceAtLeast(24f)
                val iconSize = (buttonSize - 12).coerceAtLeast(20f)
                val progressSize = (buttonSize * 0.45f).coerceIn(20f, 40f)
                for ((viewId, side) in listOf(
                    R.id.widget_button to buttonSize,
                    R.id.widget_icon to iconSize,
                    R.id.widget_progress to progressSize
                )) {
                    views.setViewLayoutWidth(viewId, side, TypedValue.COMPLEX_UNIT_DIP)
                    views.setViewLayoutHeight(viewId, side, TypedValue.COMPLEX_UNIT_DIP)
                }
            }

            val iconColor = context.getColor(when (displayState) {
                TunnelState.Connected -> R.color.wgk_success
                TunnelState.Failed -> R.color.wgk_error
                else -> R.color.wgk_primary
            })
            val statusColor = when {
                showConnectedIcon || isBusy || displayState == TunnelState.Failed -> iconColor
                else -> context.getColor(R.color.wgk_on_surface_variant)
            }
            views.setInt(R.id.widget_icon, "setColorFilter", iconColor)
            views.setTextColor(R.id.widget_status, statusColor)
            views.setViewVisibility(R.id.widget_icon, if (isBusy) View.GONE else View.VISIBLE)
            views.setViewVisibility(R.id.widget_progress, if (isBusy) View.VISIBLE else View.GONE)
            views.setViewVisibility(
                R.id.widget_status,
                if (mode == LayoutMode.ICON_ONLY) View.GONE else View.VISIBLE
            )
            val statusText = context.getString(statusTextFor(state, tunnel))
            val actionText = context.getString(when {
                tunnel == null -> R.string.widget_action_open
                isBusy -> R.string.widget_action_cancel
                showConnectedIcon -> R.string.wgk_connect_cd_disconnect
                displayState == TunnelState.Failed -> R.string.widget_action_retry
                else -> R.string.wgk_connect_cd_connect
            })
            views.setTextViewText(R.id.widget_status, statusText)
            if (mode == LayoutMode.FULL) {
                views.setTextViewText(R.id.widget_action, actionText)
                views.setViewVisibility(R.id.widget_action, if (showAction) View.VISIBLE else View.GONE)
            }
            views.setContentDescription(
                R.id.widget_root,
                context.getString(R.string.widget_accessibility, statusText, actionText)
            )

            val intent = Intent(context, TunnelToggleAppWidgetProvider::class.java).apply {
                action = ACTION_TOGGLE
            }
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            val pi = if (tunnel == null) {
                // A launcher PendingIntent can open the app directly, including on
                // Android versions that block activity launches from a receiver.
                PendingIntent.getActivity(context, 0, Intent(context, MainActivity::class.java), flags)
            } else {
                PendingIntent.getBroadcast(context, 0, intent, flags)
            }
            views.setOnClickPendingIntent(R.id.widget_root, pi)
            return views
        }

        private fun statusTextFor(state: TunnelState, tunnel: ObservableTunnel?): Int = when {
            tunnel == null -> R.string.widget_no_tunnel
            state == TunnelState.Connecting -> R.string.widget_status_connecting
            state == TunnelState.Handshake -> R.string.widget_status_handshake
            state == TunnelState.Connected -> R.string.widget_status_on
            state == TunnelState.Reconnecting -> R.string.widget_status_reconnecting
            state == TunnelState.WaitingForNetwork -> R.string.widget_status_waiting_network
            state == TunnelState.Failed -> R.string.widget_status_failed
            else -> R.string.widget_status_off
        }
    }
}
