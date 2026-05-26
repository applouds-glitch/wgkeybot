/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.Context
import android.content.res.Configuration
import android.os.LocaleList
import androidx.appcompat.app.AppCompatDelegate

/**
 * Returns a context pre-wrapped with the correct per-app locale.
 *
 * Call this in attachBaseContext() before super, so that AppCompat's
 * attachBaseContext2() receives a context that already carries the right
 * locale. This acts as a safety net against cases where the applicationContext
 * locale was corrupted by deprecated updateConfiguration() calls (e.g., the
 * WebView locale clobber workaround), which would otherwise cause an Activity
 * recreation triggered by setDefaultNightMode() to inherit the wrong locale.
 */
fun Context.localeWrapped(): Context {
    val appLocales = AppCompatDelegate.getApplicationLocales()
    val targetList: LocaleList = when {
        !appLocales.isEmpty -> LocaleList(appLocales[0] ?: return this)
        else -> {
            val sys = resources.configuration.locales
            if (sys.isEmpty) return this
            sys
        }
    }
    val config = Configuration(resources.configuration).apply { setLocales(targetList) }
    return createConfigurationContext(config)
}
