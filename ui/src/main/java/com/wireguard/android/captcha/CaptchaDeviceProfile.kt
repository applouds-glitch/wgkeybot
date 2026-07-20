package com.wireguard.android.captcha

import android.app.ActivityManager
import android.content.Context
import android.util.Log
import android.webkit.WebView
import org.json.JSONObject
import java.io.File
import java.security.SecureRandom
import kotlin.math.roundToInt

/**
 * Builds the device-fingerprint JSON handed to the Go captcha solver via
 * TurnBackend.getCaptchaDeviceProfile.
 *
 * It reports the device's REAL screen size, pixel ratio and core/memory counts,
 * plus a browser_fp that is generated once and persisted. Presenting one stable,
 * believable device across repeated captcha attempts avoids the bot signal of a
 * fingerprint that changes every request (which is what freshly randomized
 * synthetic values look like to VK's detector).
 */
object CaptchaDeviceProfile {
    private const val TAG = "WireGuard/CaptchaDeviceProfile"
    private const val FP_FILE = "captcha_browser_fp"

    fun initialize(context: Context) {
        CaptchaFingerprintProbe.initialize(context.applicationContext)
    }

    /** Returns the device-profile JSON, or an empty object on unexpected failure. */
    fun buildJson(context: Context): String {
        return try {
            val profile = CaptchaFingerprintProbe.getSnapshot(context) ?: fallbackProfile(context)
            profile.apply {
                put("webViewMajor", currentWebViewMajor())
                put("browserFp", stableBrowserFp(context))
            }.toString()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to build captcha device profile", e)
            "{}"
        }
    }

    private fun fallbackProfile(context: Context): JSONObject {
        val metrics = context.resources.displayMetrics
        val density = if (metrics.density > 0f) metrics.density else 1f
        // CSS pixels = physical pixels / devicePixelRatio (what a mobile browser reports).
        val screenWidth = (metrics.widthPixels / density).roundToInt()
        val screenHeight = (metrics.heightPixels / density).roundToInt()
        val cores = Runtime.getRuntime().availableProcessors().coerceIn(4, 8)
        return JSONObject().apply {
            put("screenWidth", screenWidth)
            put("screenHeight", screenHeight)
            put("devicePixelRatio", roundDpr(density))
            put("hardwareConcurrency", cores)
            put("deviceMemory", deviceMemoryGb(context))
            put("maxTouchPoints", 5)
        }
    }

    // navigator.deviceMemory is quantized and capped at 8; approximate from RAM.
    private fun deviceMemoryGb(context: Context): Int {
        return try {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val info = ActivityManager.MemoryInfo()
            am.getMemoryInfo(info)
            val gb = info.totalMem.toDouble() / (1024.0 * 1024.0 * 1024.0)
            when {
                gb >= 6.0 -> 8
                gb >= 3.0 -> 4
                else -> 2
            }
        } catch (e: Exception) {
            4
        }
    }

    // Keep a few decimals — real DPRs are values like 2.625, 2.75, 3.0.
    private fun roundDpr(density: Float): Double = Math.round(density * 1000.0) / 1000.0

    private fun currentWebViewMajor(): Int =
        WebView.getCurrentWebViewPackage()?.versionName
            ?.substringBefore('.')
            ?.toIntOrNull()
            ?: 0

    // A 32-hex-char fingerprint generated once and persisted to filesDir. Reusing
    // it across sessions is the whole point — a per-attempt fp burns the session.
    private fun stableBrowserFp(context: Context): String {
        val file = File(context.filesDir, FP_FILE)
        val existing = runCatching { if (file.exists()) file.readText().trim() else "" }.getOrDefault("")
        if (existing.length == 32 && existing.all { it.isDigit() || it in 'a'..'f' }) {
            return existing
        }
        val bytes = ByteArray(16)
        SecureRandom().nextBytes(bytes)
        val fp = bytes.joinToString("") { "%02x".format(it) }
        runCatching { file.writeText(fp) }
        return fp
    }
}
