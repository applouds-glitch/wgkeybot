package com.wireguard.android.captcha

import android.app.ActivityManager
import android.content.Context
import android.content.res.Configuration
import android.util.Log
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale
import kotlin.math.roundToInt

/**
 * Builds the device-fingerprint JSON handed to the Go captcha solver via
 * TurnBackend.getCaptchaDeviceProfile.
 *
 * Two sources are merged. Everything a real WebView would expose on its own —
 * screen size, pixel ratio, core and memory counts, languages, client hints —
 * comes from [CaptchaFingerprintProbe] and is reported truthfully: the visible
 * captcha dialog runs a real WebView that reports those values whatever we say
 * here, so faking them would only make the HTTP path disagree with the dialog.
 *
 * The correlatable identity on top of it — User-Agent, viewport and browser_fp —
 * comes from [CaptchaPersona], which keeps it fixed for the duration of one solve
 * attempt and rotates it on a budget. See CaptchaPersona for why neither a fully
 * stable nor a per-request-random identity works.
 */
object CaptchaDeviceProfile {
    private const val TAG = "WireGuard/CaptchaDeviceProfile"

    fun initialize(context: Context) {
        CaptchaFingerprintProbe.initialize(context.applicationContext)
    }

    /** Returns the device-profile JSON, or an empty object on unexpected failure. */
    fun buildJson(context: Context): String {
        return try {
            val profile = CaptchaFingerprintProbe.getSnapshot(context) ?: fallbackProfile(context)
            val persona = CaptchaPersona.current(context)
            // The page reports its viewport in CSS pixels, so the persona's
            // physical layout size is divided by the real devicePixelRatio — the
            // same arithmetic the invisible WebView's own layout produces.
            val dpr = profile.optDouble("devicePixelRatio", 0.0)
                .takeIf { it > 0.0 }
                ?: context.resources.displayMetrics.density.toDouble().coerceAtLeast(1.0)
            profile.apply {
                // Taken from the persona's own UA rather than read off the
                // WebView package a second time: Go pairs its ClientHello with
                // this major, and treats a zero as "no persona" and drops the
                // persona UA entirely. A device whose versionName does not parse
                // used to report 0 here while the persona had already fallen
                // back to a real major — two answers to one question.
                put("webViewMajor", chromeMajorOf(persona.userAgent))
                put("userAgent", persona.userAgent)
                put("innerWidth", (persona.layoutWidthPx / dpr).roundToInt())
                put("innerHeight", (persona.layoutHeightPx / dpr).roundToInt())
                put("browserFp", persona.browserFp)
                // prefers-color-scheme, which the PoW telemetry reports. The
                // visible WebView fallback runs on this same device and answers
                // the media query truthfully, so the HTTP path has to agree.
                put("prefersDark", isNightMode(context))
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
        val locale = context.resources.configuration.locales.get(0) ?: Locale.getDefault()
        val language = locale.toLanguageTag()
        // buildJson always fills in innerWidth/innerHeight from the persona, so the
        // Go solver takes its "real device" branch even on this path — every other
        // field it reads from that branch has to be present here too, or the
        // profile would go out with zeros and an empty language.
        return JSONObject().apply {
            put("screenWidth", screenWidth)
            put("screenHeight", screenHeight)
            put("screenAvailWidth", screenWidth)
            put("screenAvailHeight", screenHeight)
            put("devicePixelRatio", roundDpr(density))
            put("language", language)
            put("languages", JSONArray().put(language))
            put("hardwareConcurrency", cores)
            put("deviceMemory", deviceMemoryGb(context))
            put("maxTouchPoints", 5)
            put("connectionEffectiveType", "4g")
            put("notificationsPermission", "denied")
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

    private fun isNightMode(context: Context): Boolean =
        (context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
                Configuration.UI_MODE_NIGHT_YES

    // Keep a few decimals — real DPRs are values like 2.625, 2.75, 3.0.
    private fun roundDpr(density: Float): Double = Math.round(density * 1000.0) / 1000.0

    private val CHROME_MAJOR = Regex("""Chrome/(\d+)\.""")

    /** The Chrome major a User-Agent claims, or 0 when it states none. */
    private fun chromeMajorOf(userAgent: String): Int =
        CHROME_MAJOR.find(userAgent)?.groupValues?.get(1)?.toIntOrNull() ?: 0
}
