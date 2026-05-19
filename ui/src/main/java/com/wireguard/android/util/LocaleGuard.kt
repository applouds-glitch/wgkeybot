/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.Context
import android.content.res.Configuration
import android.content.res.Resources
import java.util.Locale

/**
 * Repairs the process-wide locale after WebView clobbers it.
 *
 * WebView initialisation (and, on some OEM builds, page loads / renderer
 * startup) has a long-standing Android bug where it resets the JVM default
 * [Locale] and the applicationContext [Configuration] locales to the system
 * default — which silently reverts the app's language until the next process
 * start. Snapshotting around the WebView constructor isn't enough because the
 * clobber can also happen later, during page load.
 *
 * The app selects its language purely from the system locale (no per-app
 * locale override), and WebView never mutates [Resources.getSystem], so the
 * system configuration is a stable source of truth we can re-apply at any
 * point — call [restore] after the WebView constructor AND after it is
 * destroyed.
 */
object LocaleGuard {

    fun restore(context: Context) {
        val systemLocales = Resources.getSystem().configuration.locales
        if (systemLocales.isEmpty) return
        val target = systemLocales[0]

        if (Locale.getDefault() != target) {
            Locale.setDefault(target)
        }

        val appRes = context.applicationContext.resources
        val appConfig = appRes.configuration
        if (appConfig.locales != systemLocales) {
            val restored = Configuration(appConfig).apply { setLocales(systemLocales) }
            @Suppress("DEPRECATION")
            appRes.updateConfiguration(restored, appRes.displayMetrics)
        }
    }
}
