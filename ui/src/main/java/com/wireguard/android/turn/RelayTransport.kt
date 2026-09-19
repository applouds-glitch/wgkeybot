/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import com.wireguard.android.backend.TurnBackend

/**
 * How the TURN relays are reached over a physical network: UDP, which is the
 * transport everywhere it works, or TCP for the networks where UDP to the relays
 * carries no session (see relay_transport.go for what that looks like and why
 * the server side is not involved).
 *
 * The one such network known is Rostelecom's mobile network behind a whitelist,
 * and the choice there cannot be "try UDP, fall back": one user of another client
 * reported minutes of blocked DNS after every failed attempt, so the first dial
 * has to go the right way. Hence two ways in, and they have to agree on one
 * preference: the operator is recognised on its own, and the settings screen can
 * force either transport — TCP for an RTK SIM this rule does not recognise or a
 * Wi-Fi router carrying one, UDP for an RTK SIM on a network that is not
 * whitelisted, where UDP works and is faster.
 *
 * The rule is pure so that it is pinned by JVM tests; reading the operator and
 * the preference is the thin Android part below it.
 */
object RelayTransport {
    enum class Mode(val pref: String) {
        /** TCP on a network known to need it, otherwise what the tunnel config says. */
        AUTO("auto"),
        UDP("udp"),
        TCP("tcp");

        companion object {
            fun fromPref(value: String?): Mode = entries.firstOrNull { it.pref == value } ?: AUTO
        }
    }

    /** What is pushed to native with the network, and the line for the log. */
    data class Choice(val wire: Int, val reason: String)

    /**
     * The mobile operator as the default data SIM reports it. Names only: the SIM's
     * service provider name and the registered network's name.
     */
    data class Operator(val names: List<String>) {
        companion object {
            val NONE = Operator(emptyList())
        }
    }

    fun choose(mode: Mode, onCellular: Boolean, operator: Operator): Choice = when {
        mode == Mode.UDP -> Choice(TurnBackend.RELAY_TRANSPORT_UDP, "UDP (set in settings)")
        mode == Mode.TCP -> Choice(TurnBackend.RELAY_TRANSPORT_TCP, "TCP (set in settings)")
        onCellular && needsTcp(operator) ->
            Choice(TurnBackend.RELAY_TRANSPORT_TCP, "TCP (mobile operator ${operator.names.joinToString("/")})")
        else -> Choice(TurnBackend.RELAY_TRANSPORT_AS_CONFIGURED, "as configured")
    }

    /**
     * By name, not by MCC-MNC. Rostelecom's mobile service is an MVNO on Tele2's
     * network and the public MNC tables disagree about 250-39 (Rostelecom in some,
     * Tele2 St. Petersburg in others), so a numeric match would either miss RTK
     * SIMs or sweep up Tele2 subscribers, for whom UDP works. The name is what the
     * field report from an RTK SIM showed: "ROSTELECOM".
     */
    fun needsTcp(operator: Operator): Boolean = operator.names.any { name ->
        val n = name.lowercase()
        TCP_OPERATOR_NAMES.any { it in n }
    }

    private val TCP_OPERATOR_NAMES = listOf("rostelecom", "ростелеком")

    // ── Android ────────────────────────────────────────────────────────────────

    private const val PREFS = "turn_mode"
    private const val KEY = "relay_transport"

    fun mode(context: Context): Mode =
        Mode.fromPref(context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, null))

    fun setMode(context: Context, mode: Mode) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY, mode.pref).apply()
    }

    /**
     * The operator of the SIM that carries mobile data. None of these getters needs
     * a permission. A device without telephony (TV, tablet) has no operator, and
     * anything the platform throws here is treated the same way: the transport
     * then stays as configured, which is what it was before this existed.
     */
    fun currentOperator(context: Context): Operator = try {
        val base = context.getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
        val dataSub = SubscriptionManager.getDefaultDataSubscriptionId()
        val tm = if (base != null && dataSub != SubscriptionManager.INVALID_SUBSCRIPTION_ID)
            base.createForSubscriptionId(dataSub) else base
        Operator(listOfNotNull(tm?.simOperatorName, tm?.networkOperatorName).filter { it.isNotBlank() }.distinct())
    } catch (_: Exception) {
        Operator.NONE
    }
}
