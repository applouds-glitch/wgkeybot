/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.app.Activity
import android.content.Context
import android.content.pm.ActivityInfo
import android.content.pm.PackageManager
import android.content.res.Configuration

/**
 * Whether this is a TV: a television UI mode, or a leanback device that reports
 * another mode (some boxes do). The main screen uses the same test to pick what
 * it shows, so a screen asked the question here agrees with it.
 */
fun Context.isTv(): Boolean {
    val uiType = resources.configuration.uiMode and Configuration.UI_MODE_TYPE_MASK
    return uiType == Configuration.UI_MODE_TYPE_TELEVISION ||
        packageManager.hasSystemFeature(PackageManager.FEATURE_LEANBACK)
}

/**
 * The portrait lock the phone screens used to carry in the manifest, applied from
 * code so a TV is left out.
 *
 * A manifest screenOrientation cannot be qualified by device, and a TV box does
 * not ignore it: the activity comes up sideways on a display that never
 * rotates, or letterboxed to a phone's shape. The phone still wants the lock —
 * its settings screens are a single column laid out for a tall window — so the
 * lock stays, but as a request made here, before the content view is set, and
 * only when the device is not a TV.
 */
fun Activity.lockPortraitOnPhone() {
    if (isTv()) return
    @Suppress("SourceLockedOrientationActivity")
    requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
}
