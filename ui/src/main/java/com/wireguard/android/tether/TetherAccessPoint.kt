/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tether

/** Credentials and address of a running access point. */
data class ApInfo(val ssid: String, val passphrase: String, val bindIp: String)

/**
 * Why a sharing session is not running.
 *
 * [isFailure] separates "something broke" from "sharing ended the way it was
 * supposed to". Every reason here used to be the first kind, so the settings
 * screen could paint the status line in warning colour off the state alone;
 * AUTO_OFF is the first that is simply an outcome, and reporting a hotspot
 * that switched itself off on schedule in red would be a lie.
 */
enum class TetherError(val isFailure: Boolean = true) {
    TUNNEL_DOWN,
    PERMISSION_DENIED,

    /**
     * The permission is granted but the system location toggle is off, which the
     * platform reports as the same SecurityException a missing permission does.
     * Its own value because the two need opposite instructions.
     */
    LOCATION_OFF,
    AP_UNAVAILABLE,
    AP_TETHERING_DISALLOWED,
    BIND_FAILED,
    NATIVE_ERROR,

    /**
     * Nothing had used sharing for half an hour, so it switched itself off. Not a
     * failure — the access point costs a radio and a data plan, and this is the
     * feature the user armed (or left armed) precisely to be spared it.
     */
    AUTO_OFF(isFailure = false),
}

class TetherApException(val reason: TetherError, message: String) : Exception(message)

/**
 * Raises the local access point clients connect to. Local-only on purpose: with
 * no NAT of its own, the sharing proxy is the client's only way out, so nothing
 * can leak past the tunnel.
 *
 * An interface because startLocalOnlyHotspot is refused outright by some vendor
 * firmware; a Wi-Fi Direct implementation can be dropped in behind it without
 * touching anything else.
 */
interface TetherAccessPoint {
    /**
     * Raises the access point and returns its credentials.
     *
     * [onSystemStop] reports a teardown the platform performed on its own — the
     * user toggling Wi-Fi, system tethering claiming the radio, a firmware
     * restart. It is part of the contract rather than a convenience: without it
     * the sharing sheet keeps advertising the SSID, password and QR of a network
     * that no longer exists. It may fire on any thread, at most once, and never
     * after [stop].
     */
    suspend fun start(onSystemStop: () -> Unit): ApInfo
    fun stop()
}
