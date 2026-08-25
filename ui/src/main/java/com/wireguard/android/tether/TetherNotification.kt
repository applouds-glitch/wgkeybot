/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tether

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import com.wireguard.android.Application
import com.wireguard.android.R

/**
 * The shade entry for an active sharing session.
 *
 * Sharing costs the phone a Wi-Fi radio, a wake lock and its data plan, and
 * until now the only place that said so was a bottom sheet the user had to go
 * looking for: counters stopped updating when it closed, and there was no way to
 * turn sharing off without unlocking the phone and walking back into settings.
 * An ongoing notification is the standard place for both.
 *
 * Purely a display surface — it owns no state. [TetherManager] posts it while its
 * state is Active and cancels it otherwise, so a session that dies on its own
 * (tunnel down, access point taken by the system) takes the notification with it.
 */
object TetherNotification {

    internal const val TAG = "WireGuard/TetherNotification"
    private const val CHANNEL_ID = "tether_sharing"

    // 1 is the VPN foreground notification and 2 the VPN alert; this is the third.
    private const val NOTIFICATION_ID = 3

    /**
     * The "sharing switched itself off" notice, on an id of its own.
     *
     * It has to outlive the session it is reporting on, and [hide] runs the moment
     * the state stops being Active — sharing one id would have the notice
     * cancelled by the very teardown that posted it.
     */
    private const val STOPPED_NOTIFICATION_ID = 4

    const val ACTION_STOP = "com.wgkeybot.android.action.TETHER_STOP"

    fun show(context: Context, state: TetherState.Active) {
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        try {
            ensureChannel(context, nm)
            // A session is running again, so last time's "switched itself off" line
            // is stale — and sitting in the shade right next to a live one.
            nm.cancel(STOPPED_NOTIFICATION_ID)
            val text = context.getString(
                R.string.wgk_tether_counters,
                state.clients,
                state.connections,
                formatTetherBytes(state.bytesUp),
                formatTetherBytes(state.bytesDown),
            )
            // The counters carry the collapsed line on their own; the network they
            // belong to goes in the header, and the proxy address — the thing a
            // user reads off the screen to type into a client — in the expanded
            // view, where there is room for it.
            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_wifi_tethering)
                .setContentTitle(context.getString(R.string.wgk_tether_title))
                .setContentText(text)
                .setStyle(
                    NotificationCompat.BigTextStyle()
                        .bigText("${state.ssid} · ${state.host}:${state.port}\n$text")
                )
                .setSubText(state.ssid)
                // Ongoing and un-dismissable: sharing is still running behind it, and
                // a swiped-away notification would leave the radio on with nothing
                // saying so.
                .setOngoing(true)
                .setShowWhen(false)
                .setOnlyAlertOnce(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setCategory(NotificationCompat.CATEGORY_SERVICE)
                .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
                .setContentIntent(launchIntent(context))
                .addAction(
                    R.drawable.ic_wifi_tethering,
                    context.getString(R.string.wgk_tether_stop_action),
                    stopIntent(context),
                )
                .build()
            nm.notify(NOTIFICATION_ID, notification)
        } catch (e: Throwable) {
            // Posting is best-effort: without POST_NOTIFICATIONS this silently does
            // nothing, and nothing about sharing itself depends on it.
            Log.w(TAG, "cannot post the sharing notification", e)
        }
    }

    /**
     * Reports the idle auto-off, once, after the session is already down.
     *
     * The shade is the only place this can be said. The settings screen carries
     * the same wording, but a user whose hotspot went quiet is by definition not
     * looking at it — and sharing that vanishes with no explanation reads as a
     * bug, which is how the feature would get reported.
     */
    fun showAutoOff(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        try {
            ensureChannel(context, nm)
            val text = context.getString(R.string.wgk_tether_error_auto_off)
            val notification = NotificationCompat.Builder(context, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_wifi_tethering)
                .setContentTitle(context.getString(R.string.wgk_tether_auto_off_notice))
                .setContentText(text)
                .setStyle(NotificationCompat.BigTextStyle().bigText(text))
                // The opposite of the ongoing one above: nothing is running behind
                // this, so it is dismissable and goes away when tapped.
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
                .setContentIntent(launchIntent(context))
                .build()
            nm.notify(STOPPED_NOTIFICATION_ID, notification)
        } catch (e: Throwable) {
            Log.w(TAG, "cannot post the sharing auto-off notice", e)
        }
    }

    fun hide(context: Context) {
        try {
            context.getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
        } catch (e: Throwable) {
            Log.w(TAG, "cannot cancel the sharing notification", e)
        }
    }

    private fun ensureChannel(context: Context, nm: NotificationManager) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        nm.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                context.getString(R.string.wgk_tether_notification_channel),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                setShowBadge(false)
                setSound(null, null)
                enableVibration(false)
                lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
            }
        )
    }

    private fun launchIntent(context: Context): PendingIntent {
        val intent = context.packageManager.getLaunchIntentForPackage(context.packageName) ?: Intent()
        return PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
    }

    private fun stopIntent(context: Context): PendingIntent = PendingIntent.getBroadcast(
        context,
        0,
        Intent(context, TetherStopReceiver::class.java).setAction(ACTION_STOP),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
}

/** Backs the notification's Stop action. Not exported: only our own PendingIntent fires it. */
class TetherStopReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != TetherNotification.ACTION_STOP) return
        // stop() is already fire-and-forget on the application scope, which is what
        // a receiver needs: nothing here may block or outlive onReceive. Guarded
        // because an exception escaping a receiver takes the whole app with it, and
        // this one runs from a notification the user could tap at any moment.
        try {
            Application.getTetherManager().stop()
        } catch (e: Throwable) {
            Log.w(TetherNotification.TAG, "cannot stop sharing from the notification", e)
        }
    }
}
