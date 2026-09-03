/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tether

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.activity.result.ActivityResultCaller
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.StringRes
import androidx.core.content.ContextCompat
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date

private const val TAG = "WireGuard/TetherToggle"

/**
 * Everything between a switch and TetherManager.start(): the permissions the
 * access point needs, and the pieces of the tunnel's own config the native side
 * cannot start without.
 *
 * It sits apart from the settings screen that owns the switch because none of it
 * is about that screen: a missing permission, a refused one and a tunnel with no
 * config to hand over mean the same thing whoever asked.
 *
 * Construct it as a field in onCreate (or onCreateView): it registers an activity
 * result launcher, and that has to happen before the host reaches STARTED.
 */
class TetherToggle(
    caller: ActivityResultCaller,
    private val context: Context,
    /**
     * Called once TetherManager has recorded the refusal. A StateFlow does not
     * re-emit an equal value, so a second refusal in a row never reaches a
     * collector — without re-rendering here the switch would stay visually ON
     * with nothing running behind it.
     */
    private val onPermissionDenied: () -> Unit,
) {
    private val permissionLauncher =
        caller.registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { _ ->
            // The result map is not consulted: it only carries the permissions this
            // round actually asked for, and what matters is the state afterwards —
            // the access point's permission decides, the notification's does not.
            if (hasApPermission()) start() else reportPermissionDenied()
        }

    fun setEnabled(enabled: Boolean) {
        if (enabled) requestPermissionThenStart() else Application.getTetherManager().stop()
    }

    private fun requestPermissionThenStart() {
        val missing = requiredPermissions().filter {
            ContextCompat.checkSelfPermission(context, it) != PackageManager.PERMISSION_GRANTED
        }
        if (missing.isEmpty()) start() else permissionLauncher.launch(missing.toTypedArray())
    }

    /**
     * The permissions the access point cannot start without.
     *
     * Below API 33 the hotspot is location-gated. FINE and COARSE must both be
     * declared and requested: API 26..28 checks COARSE directly, while Android
     * 12/12L ignores a FINE-only runtime request. They share one permission
     * dialog, and both declarations are capped at API 32 in the manifest.
     */
    private fun apPermissions(): List<String> = buildList {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            add(Manifest.permission.NEARBY_WIFI_DEVICES)
        } else {
            add(Manifest.permission.ACCESS_COARSE_LOCATION)
            add(Manifest.permission.ACCESS_FINE_LOCATION)
        }
    }

    private fun hasApPermission(): Boolean = apPermissions().all {
        ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
    }

    private fun requiredPermissions(): List<String> = buildList {
        addAll(apPermissions())
        // POST_NOTIFICATIONS rides along because the sharing notification is the
        // only place the counters and a Stop button exist once the sheet is closed,
        // and on API 33+ a notification without it is simply never shown. Asked for
        // in the same round, never required: refusing it costs the shade entry, not
        // sharing.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            add(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    /**
     * Deliberately outlives the host: a user who flips the switch and leaves the
     * screen right away must still end up with a working access point.
     * TetherManager.stop() runs on this same scope for the same reason.
     */
    private fun start() {
        val manager = Application.getTetherManager()
        // Recorded synchronously, before anything suspends. readTunnelNetworking()
        // below is a suspending call, so an "off" tapped while it runs used to be
        // overtaken by the "on" that was still on its way: shutdown() ran against a
        // session that did not exist yet, and this coroutine then raised an access
        // point the user had already switched off.
        manager.requestStart()
        applicationScope.launch {
            val tunnel = readTunnelNetworking()
            manager.start(tunnel.dnsServers, tunnel.addresses)
        }
    }

    private fun reportPermissionDenied() {
        applicationScope.launch {
            Application.getTetherManager().onPermissionDenied()
            onPermissionDenied()
        }
    }

    /**
     * What the native side needs from the tunnel's own config.
     *
     * [dnsServers] because names for tethered clients are resolved on the phone,
     * through the tunnel's resolvers — the client never sees one. [addresses]
     * because every upstream socket's local address is checked against them: that
     * is the proof the traffic really left through the tunnel, and without it
     * sharing does not start at all.
     */
    private data class TunnelNetworking(val dnsServers: List<String>, val addresses: List<String>)

    private suspend fun readTunnelNetworking(): TunnelNetworking = try {
        val tunnel = Application.getTunnelManager().primaryTunnel()
        val iface = tunnel?.getConfigAsync()?.`interface`
        TunnelNetworking(
            dnsServers = iface?.dnsServers?.mapNotNull { it.hostAddress }.orEmpty(),
            addresses = iface?.addresses?.mapNotNull { it.address.hostAddress }.orEmpty(),
        )
    } catch (e: Exception) {
        // Empty addresses are not a soft failure: TetherManager turns them into a
        // refusal to share, which is the point — better no access point than one
        // whose egress nobody can vouch for.
        Log.w(TAG, "cannot read the tunnel's config; sharing will refuse to start", e)
        TunnelNetworking(emptyList(), emptyList())
    }
}

/**
 * Byte counters, shared by every surface that shows them — the sharing sheet and
 * the notification have to agree, down to the rounding.
 */
fun formatTetherBytes(bytes: Long): String = when {
    bytes >= 1_073_741_824 -> String.format("%.1f GB", bytes / 1_073_741_824.0)
    bytes >= 1_048_576 -> String.format("%.1f MB", bytes / 1_048_576.0)
    bytes >= 1024 -> String.format("%.1f KB", bytes / 1024.0)
    else -> "$bytes B"
}

/** Dates on the routing screens: the device's short locale format, or a dash for "never". */
fun formatRoutingDate(epochMillis: Long): String =
    if (epochMillis <= 0L) "—"
    else DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(epochMillis))

/** One wording per failure, shared by every surface that reports one. */
@StringRes
fun TetherError.messageRes(): Int = when (this) {
    TetherError.TUNNEL_DOWN -> R.string.wgk_tether_error_tunnel_down
    TetherError.PERMISSION_DENIED -> R.string.wgk_tether_error_permission
    TetherError.LOCATION_OFF -> R.string.wgk_tether_error_location
    TetherError.AP_TETHERING_DISALLOWED -> R.string.wgk_tether_error_disallowed
    TetherError.AP_UNAVAILABLE -> R.string.wgk_tether_error_ap
    TetherError.BIND_FAILED -> R.string.wgk_tether_error_bind
    TetherError.NATIVE_ERROR -> R.string.wgk_tether_error_native
    TetherError.AUTO_OFF -> R.string.wgk_tether_error_auto_off
}
