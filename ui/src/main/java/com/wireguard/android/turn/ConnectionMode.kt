/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.wireguard.android.R

/**
 * The transport choice, shared by the phone's settings screen and the TV footer
 * row. A TV has no settings screen, so the row there stays the only way in, and
 * both entry points have to agree on one preference.
 *
 * The keys below must stay identical to the literals read by isStabilityMode()
 * in TurnProxyManager — the connect path keeps its own copy of them.
 */
object ConnectionMode {
    private const val PREFS = "turn_mode"
    private const val KEY = "stability_mode"

    fun isReserve(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY, false)

    fun setReserve(context: Context, reserve: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY, reserve).apply()
    }

    fun showDialog(context: Context, onChanged: () -> Unit) {
        val options = arrayOf(
            context.getString(R.string.wgk_connection_mode_standard_option),
            context.getString(R.string.wgk_connection_mode_reserve_option)
        )
        MaterialAlertDialogBuilder(context)
            .setTitle(R.string.wgk_connection_mode_title)
            .setSingleChoiceItems(options, if (isReserve(context)) 1 else 0) { dialog, which ->
                dialog.dismiss()
                setReserve(context, which == 1)
                onChanged()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }
}
