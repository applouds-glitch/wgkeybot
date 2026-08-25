/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tether

import android.annotation.SuppressLint
import android.content.Context
import android.location.LocationManager
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.core.location.LocationManagerCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.net.Inet4Address
import java.net.NetworkInterface
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

@RequiresApi(Build.VERSION_CODES.O)
class LocalOnlyHotspotAp(private val context: Context) : TetherAccessPoint {

    // Written from the platform callback thread and read from wherever stop()
    // happens to run (invokeOnCancellation, the TetherManager teardown, a
    // notification tap). Atomic rather than @Volatile because every consumer wants
    // take-and-clear in one step: a plain read-close-null lets two callers close
    // the same reservation, and the second close is a platform call whose
    // behaviour is a vendor coin flip.
    private val reservation = AtomicReference<WifiManager.LocalOnlyHotspotReservation?>(null)

    override suspend fun start(onSystemStop: () -> Unit): ApInfo {
        // Sampled before the request, so that afterwards the access point can be
        // recognised as the address that was not there a moment ago.
        val before = snapshotPrivateIpv4()
        val creds = awaitHotspot(onSystemStop)
        val address = resolveApAddress(before)
        if (address == null) {
            // An access point the proxy cannot bind to is worse than none: the user
            // would get "cannot assign requested address" and nothing pointing at
            // why. Give the hotspot back and say what was actually on the device.
            stop()
            throw TetherApException(
                TetherError.AP_UNAVAILABLE,
                "cannot tell which interface is the access point; saw ${snapshotPrivateIpv4()}"
            )
        }
        return ApInfo(creds.first, creds.second, address)
    }

    @SuppressLint("MissingPermission") // TetherManager checks the runtime permission first
    private suspend fun awaitHotspot(onSystemStop: () -> Unit): Pair<String, String> = suspendCancellableCoroutine { cont ->
        val wifi = context.getSystemService(WifiManager::class.java)
        if (wifi == null) {
            cont.resumeWithException(TetherApException(TetherError.AP_UNAVAILABLE, "no WifiManager"))
            return@suspendCancellableCoroutine
        }
        val callback = object : WifiManager.LocalOnlyHotspotCallback() {
            override fun onStarted(res: WifiManager.LocalOnlyHotspotReservation) {
                // Guarded because this runs on the platform's callback thread, where
                // an escaping exception takes the whole app with it — and reading the
                // credentials means touching the same vendor Wi-Fi APIs that already
                // throw on the start path below. A failure here is indistinguishable
                // from a hotspot that came up without credentials, so it lands in the
                // same branch.
                val creds = try {
                    reservation.set(res)
                    readCredentials(res)
                } catch (e: Throwable) {
                    Log.w(TAG, "reading the hotspot credentials failed", e)
                    null
                }
                if (creds == null) {
                    stop()
                    if (cont.isActive) cont.resumeWithException(
                        TetherApException(TetherError.AP_UNAVAILABLE, "hotspot started without credentials")
                    )
                    return
                }
                if (cont.isActive) {
                    cont.resume(creds)
                } else {
                    // The coroutine can already be cancelled by the time this fires:
                    // startLocalOnlyHotspot cannot be aborted once called, so a late
                    // success races cancellation. invokeOnCancellation's stop() ran
                    // earlier and saw no reservation yet, so nothing closed this one.
                    // Mirror the creds==null branch above: close and clear here, or
                    // the reservation is orphaned and the hotspot stays up forever.
                    stop()
                }
            }

            override fun onFailed(reason: Int) {
                if (cont.isActive) cont.resumeWithException(
                    TetherApException(mapFailure(reason), "startLocalOnlyHotspot failed with $reason")
                )
            }

            override fun onStopped() {
                // The system tears the hotspot down on its own when Wi-Fi settings
                // change or tethering takes the radio. Nobody asked us to stop, so
                // the owner has to be told: otherwise sharing stays "Active" over a
                // network that is gone, QR and password included.
                Log.d(TAG, "local-only hotspot stopped by the system")
                if (reservation.getAndSet(null) != null) onSystemStop()
            }
        }
        // startLocalOnlyHotspot reports two failures by throwing rather than
        // through the callback, and both are reachable in normal use:
        // SecurityException when the runtime permission is missing — and, on API
        // 26-30, when the system Location toggle is off, which no permission check
        // can see — and IllegalStateException when a local-only hotspot request is
        // already outstanding. Thrown here they would escape suspendCancellableCoroutine
        // into applicationScope and take the whole app with them, so they are turned
        // into the same TetherApException every other failure uses.
        try {
            wifi.startLocalOnlyHotspot(callback, null)
        } catch (e: SecurityException) {
            // Two different problems arrive as the same exception, and telling the
            // user the wrong one sends them to a settings screen where everything
            // already looks correct: on API 26..32 the platform also refuses when
            // the system location toggle is off, with the permission granted. The
            // toggle is checked here rather than guessed from the message text.
            val reason = if (isLocationEnabled()) TetherError.PERMISSION_DENIED else TetherError.LOCATION_OFF
            Log.w(TAG, "startLocalOnlyHotspot refused ($reason)", e)
            cont.resumeWithException(
                TetherApException(reason, "startLocalOnlyHotspot: ${e.message}")
            )
            return@suspendCancellableCoroutine
        } catch (e: IllegalStateException) {
            Log.w(TAG, "startLocalOnlyHotspot rejected", e)
            cont.resumeWithException(
                TetherApException(TetherError.AP_UNAVAILABLE, "startLocalOnlyHotspot: ${e.message}")
            )
            return@suspendCancellableCoroutine
        }
        cont.invokeOnCancellation { stop() }
    }

    override fun stop() {
        val res = reservation.getAndSet(null) ?: return
        try {
            res.close()
        } catch (e: Exception) {
            // Same reasoning as the start path (which has been throwing on vendor
            // firmware since day one): a failure to hand the hotspot back is
            // nothing the caller can act on, and letting it out of a teardown —
            // which runs on the tunnel's way down — would take the app with it.
            Log.w(TAG, "closing the hotspot reservation failed", e)
        }
    }

    /**
     * Whether the system location toggle is on.
     *
     * Answers true when it cannot tell: a wrong "location is off" would be a
     * confident lie, while falling back to the permission wording is merely the
     * status quo.
     */
    private fun isLocationEnabled(): Boolean = try {
        val lm = context.getSystemService(LocationManager::class.java)
        lm == null || LocationManagerCompat.isLocationEnabled(lm)
    } catch (e: Exception) {
        Log.w(TAG, "cannot read the location toggle", e)
        true
    }

    @Suppress("DEPRECATION")
    private fun readCredentials(res: WifiManager.LocalOnlyHotspotReservation): Pair<String, String>? {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val cfg = res.softApConfiguration
            val ssid = cfg.ssid ?: return null
            val passphrase = cfg.passphrase ?: return null
            return ssid to passphrase
        }
        val cfg = res.wifiConfiguration ?: return null
        val ssid = cfg.SSID?.trim('"') ?: return null
        val passphrase = cfg.preSharedKey?.trim('"') ?: return null
        return ssid to passphrase
    }

    private fun mapFailure(reason: Int): TetherError = when (reason) {
        WifiManager.LocalOnlyHotspotCallback.ERROR_TETHERING_DISALLOWED -> TetherError.AP_TETHERING_DISALLOWED
        else -> TetherError.AP_UNAVAILABLE
    }

    /**
     * On the device this was first found broken the address was already there when
     * the callback fired, but firmware differs, so this polls briefly instead of
     * reading once and concluding.
     */
    private suspend fun resolveApAddress(before: Map<String, Set<String>>): String? {
        repeat(AP_ADDRESS_ATTEMPTS) { attempt ->
            val after = snapshotPrivateIpv4()
            val picked = pickApAddress(before, after, AP_INTERFACE_HINTS)
            if (picked != null) {
                Log.d(TAG, "ap address $picked on attempt ${attempt + 1}; saw $after")
                return picked
            }
            if (attempt < AP_ADDRESS_ATTEMPTS - 1) delay(AP_ADDRESS_RETRY_MS)
        }
        Log.w(TAG, "no access-point address after $AP_ADDRESS_ATTEMPTS attempts; before=$before")
        return null
    }

    /**
     * Private IPv4 per interface. Interfaces that cannot be the access point are
     * dropped here rather than confusing the comparison: the app's own tunnel is
     * always up while sharing runs, and mobile data is usually CGNAT — both are as
     * private as the hotspot is.
     */
    private suspend fun snapshotPrivateIpv4(): Map<String, Set<String>> = withContext(Dispatchers.IO) {
        // Off the main thread: getNetworkInterfaces() walks /proc and issues an
        // ioctl per interface, and resolveApAddress calls this up to ten times in a
        // row. applicationScope runs on Dispatchers.Main.immediate, so all of that
        // was landing on the UI thread — the same reason the native tether calls
        // next door are wrapped (see TetherManager.start).
        val interfaces = try {
            NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
        } catch (e: Exception) {
            Log.w(TAG, "cannot enumerate interfaces", e)
            return@withContext emptyMap()
        }
        val snapshot = LinkedHashMap<String, Set<String>>()
        for (iface in interfaces) {
            if (!iface.isUp || iface.isLoopback) continue
            if (EXCLUDED_INTERFACES.any { iface.name.startsWith(it) }) continue
            snapshot[iface.name] = iface.inetAddresses.toList()
                .filterIsInstance<Inet4Address>()
                .filter { it.isSiteLocalAddress }
                .mapNotNull { it.hostAddress }
                .toSet()
        }
        snapshot
    }

    companion object {
        private const val TAG = "WireGuard/LocalOnlyHotspotAp"

        // Only a tie-breaker now. The list was the whole rule once, and it shipped
        // broken: a device raised its hotspot on wlan2, which no list predicted.
        private val AP_INTERFACE_HINTS = listOf("ap", "swlan", "softap", "wlan1")

        // Never the access point, and all of them can carry a private IPv4.
        private val EXCLUDED_INTERFACES = listOf("tun", "rmnet", "dummy", "ccmni")

        private const val AP_ADDRESS_ATTEMPTS = 10
        private const val AP_ADDRESS_RETRY_MS = 200L
    }
}
