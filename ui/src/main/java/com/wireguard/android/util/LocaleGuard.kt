/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.Context
import android.content.res.Resources
import androidx.appcompat.app.AppCompatDelegate
import java.util.Locale

/**
 * Repairs Locale.getDefault() after WebView clobbers it.
 *
 * WebView initialisation (and, on some OEM builds, page loads / renderer
 * startup) has a long-standing Android bug where it calls Locale.setDefault()
 * with the system locale, silently reverting String.format() and similar JVM
 * calls to the system language.
 *
 * We deliberately do NOT call the deprecated Resources.updateConfiguration()
 * here. That API mutates the shared AssetManager configuration for the whole
 * process, which corrupts AppCompat's applyDayNight() logic: when the user
 * switches theme, AppCompat reads the applicationContext configuration to build
 * the new night-mode config — if updateConfiguration() wrote the wrong locale
 * there, the recreated Activity inherits the wrong locale.
 *
 * AppCompat's attachBaseContext2() already wraps every Activity with the
 * correct per-app locale via createConfigurationContext(), so Activity-level
 * strings are unaffected by the WebView clobber. Only Locale.getDefault()
 * needs explicit repair.
 */
object LocaleGuard {

    fun restore(context: Context) {
        // Per-app locale (Android 13+ system pref or AppCompat shim on older
        // versions) survives WebView's clobber because it is stored in the OS /
        // SharedPreferences, not in the mutable Resources configuration.
        val target: Locale = if (!AppCompatDelegate.getApplicationLocales().isEmpty) {
            AppCompatDelegate.getApplicationLocales()[0] ?: return
        } else {
            val sys = Resources.getSystem().configuration.locales
            if (sys.isEmpty) return
            sys[0]
        }

        if (Locale.getDefault() != target) {
            Locale.setDefault(target)
        }
        // No updateConfiguration() — see class-level doc.
    }
}
