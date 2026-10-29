/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import com.wireguard.android.fragment.TunnelState

/**
 * When to ask for the battery-optimisation exemption.
 *
 * The request used to fire from MainActivity.onCreate, so on a fresh install the
 * system dialog landed on top of the config import and the split-tunnel wizard,
 * with nothing saying why a VPN wanted it. It now waits for the first session
 * that really carries traffic — Connected, which needs a handshake, not merely
 * tunnel UP — when the user has just seen what the exemption protects.
 */
internal object BatteryPromptPolicy {
    fun shouldOffer(state: TunnelState, alreadyShown: Boolean, exempt: Boolean): Boolean =
        state == TunnelState.Connected && !alreadyShown && !exempt
}
