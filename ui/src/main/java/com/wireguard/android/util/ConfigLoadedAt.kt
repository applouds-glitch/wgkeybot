/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.Context
import com.wireguard.android.R
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * When the config was last loaded, for the connect screen's profile card and the
 * settings summary. [compact] is the instrument form, "13.11 · 14:32"; the long
 * one is a phrase, "Загружено в 14:32" today and "Загружено 12.11 14:32" before,
 * for the TV and for TalkBack. Zero is "never".
 */
fun Context.formatConfigLoadedAt(ts: Long, compact: Boolean = false): String {
    if (ts == 0L) return getString(R.string.wgk_profile_never_loaded)
    val date = Date(ts)
    if (compact) return SimpleDateFormat("dd.MM '·' HH:mm", Locale.getDefault()).format(date)
    val day = SimpleDateFormat("yyyyMMdd", Locale.getDefault())
    return if (day.format(date) == day.format(Date())) {
        getString(R.string.wgk_profile_loaded_at, SimpleDateFormat("HH:mm", Locale.getDefault()).format(date))
    } else {
        getString(R.string.wgk_profile_loaded_on, SimpleDateFormat("dd.MM HH:mm", Locale.getDefault()).format(date))
    }
}
