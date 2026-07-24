package com.wireguard.android.captcha

import android.annotation.SuppressLint
import android.content.Context
import android.hardware.display.DisplayManager
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.Display
import android.view.View
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import com.wireguard.android.util.LocaleGuard
import org.json.JSONObject
import org.json.JSONTokener
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Captures the low-entropy browser fingerprint from a local, disposable WebView.
 * It never loads VK content and never touches the WebView used to solve captchas.
 */
object CaptchaFingerprintProbe {
    private const val TAG = "CaptchaFingerprint"
    private const val PREFS = "captcha_fingerprint_probe"
    private const val KEY_CACHE_KEY = "cache_key"
    private const val KEY_SNAPSHOT = "snapshot"
    private const val SCHEMA_VERSION = 3
    private const val PROBE_WIDTH_PX = 360
    private const val PROBE_HEIGHT_PX = 382
    private const val PROVIDER_WAIT_TIMEOUT_MS = 1_500L
    private const val PROBE_RUN_TIMEOUT_MS = 3_000L

    // Must stay identical to the UA the real captcha solver WebView sets
    // (CaptchaActivity), so the mirrored fingerprint matches what VK actually
    // sees during the interactive captcha.
    const val USER_AGENT =
        "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/146.0.0.0 Mobile Safari/537.36"

    private val lock = Any()
    private val mainHandler = Handler(Looper.getMainLooper())

    @Volatile private var snapshot: String? = null
    @Volatile private var activeKey: String? = null
    @Volatile private var attemptedKey: String? = null
    @Volatile private var completion = CountDownLatch(0)

    fun initialize(context: Context) {
        val appContext = context.applicationContext
        val cacheKey = buildCacheKey(appContext)
        synchronized(lock) {
            if (activeKey == cacheKey && snapshot != null) return

            val prefs = appContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val persisted = prefs.getString(KEY_SNAPSHOT, null)
            Log.d(
                TAG,
                "Fingerprint cache key=${cacheKey.take(8)} stored=${prefs.getString(KEY_CACHE_KEY, null)?.take(8)}",
            )
            if (prefs.getString(KEY_CACHE_KEY, null) == cacheKey && isValidSnapshot(persisted)) {
                activeKey = cacheKey
                attemptedKey = cacheKey
                snapshot = persisted
                completion = CountDownLatch(0)
                Log.d(TAG, "Using cached WebView fingerprint")
                return
            }

            if (attemptedKey == cacheKey && completion.count > 0) return
            attemptedKey = cacheKey
            activeKey = cacheKey
            snapshot = null
            completion = CountDownLatch(1)
            mainHandler.post { runProbe(appContext, cacheKey) }
        }
    }

    /** Returns the cached snapshot, waiting briefly only when called off-main. */
    fun getSnapshot(context: Context): JSONObject? {
        initialize(context)
        if (Looper.myLooper() != Looper.getMainLooper()) {
            runCatching { completion.await(PROVIDER_WAIT_TIMEOUT_MS, TimeUnit.MILLISECONDS) }
        }
        return snapshot?.let { runCatching { JSONObject(it) }.getOrNull() }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun runProbe(context: Context, cacheKey: String) {
        var webView: WebView? = null
        var finished = false
        val capturedHeaders = AtomicReference<Map<String, String>>(emptyMap())

        fun finish(result: JSONObject?) {
            if (finished) return
            finished = true
            if (result != null && isValidSnapshot(result.toString()) && buildCacheKey(context) == cacheKey) {
                val encoded = result.toString()
                context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                    .edit()
                    .putString(KEY_CACHE_KEY, cacheKey)
                    .putString(KEY_SNAPSHOT, encoded)
                    .apply()
                snapshot = encoded
                Log.d(TAG, "WebView fingerprint captured")
            } else {
                Log.w(TAG, "WebView fingerprint probe failed; using fallback profile")
            }
            runCatching {
                webView?.stopLoading()
                webView?.loadUrl("about:blank")
                webView?.webViewClient = WebViewClient()
                webView?.onPause()
                webView?.removeAllViews()
                webView?.destroy()
            }
            LocaleGuard.restore(context)
            completion.countDown()
        }

        mainHandler.postDelayed({ finish(null) }, PROBE_RUN_TIMEOUT_MS)

        try {
            val displayManager = context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
            val display = displayManager.getDisplay(Display.DEFAULT_DISPLAY)
            val webViewContext = if (display != null) {
                context.createDisplayContext(display)
                    .createConfigurationContext(context.resources.configuration)
            } else {
                context
            }

            webView = WebView(webViewContext).apply {
                settings.javaScriptEnabled = true
                settings.domStorageEnabled = false
                settings.cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE
                settings.userAgentString = USER_AGENT
                measure(
                    View.MeasureSpec.makeMeasureSpec(PROBE_WIDTH_PX, View.MeasureSpec.EXACTLY),
                    View.MeasureSpec.makeMeasureSpec(PROBE_HEIGHT_PX, View.MeasureSpec.EXACTLY),
                )
                layout(0, 0, PROBE_WIDTH_PX, PROBE_HEIGHT_PX)
                webViewClient = object : WebViewClient() {
                    override fun shouldInterceptRequest(
                        view: WebView,
                        request: WebResourceRequest,
                    ): WebResourceResponse? {
                        if (request.url.host == "api.vk.ru" && request.url.path == "/captcha-fingerprint-probe.js") {
                            capturedHeaders.set(request.requestHeaders)
                            return WebResourceResponse(
                                "application/javascript",
                                "UTF-8",
                                ByteArrayInputStream("window.__fingerprintProbeLoaded=true;".toByteArray()),
                            )
                        }
                        return super.shouldInterceptRequest(view, request)
                    }

                    override fun onPageFinished(view: WebView, url: String?) {
                        view.evaluateJavascript(FINGERPRINT_SCRIPT) { raw ->
                            val result = decodeJavascriptObject(raw)
                            if (result != null) {
                                val headers = capturedHeaders.get()
                                result.put("userAgent", header(headers, "User-Agent") ?: result.optString("userAgent"))
                                result.put("secChUa", header(headers, "sec-ch-ua") ?: "")
                                result.put("secChUaMobile", header(headers, "sec-ch-ua-mobile") ?: "")
                                result.put("secChUaPlatform", header(headers, "sec-ch-ua-platform") ?: "")
                            }
                            finish(result)
                        }
                    }
                }
                loadDataWithBaseURL(
                    "https://id.vk.ru/",
                    "<html><head><script src=\"https://api.vk.ru/captcha-fingerprint-probe.js\"></script></head><body></body></html>",
                    "text/html",
                    "UTF-8",
                    null,
                )
            }
            LocaleGuard.restore(context)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create fingerprint WebView", e)
            finish(null)
        }
    }

    private fun decodeJavascriptObject(raw: String?): JSONObject? {
        if (raw.isNullOrBlank() || raw == "null") return null
        return runCatching {
            val decoded = JSONTokener(raw).nextValue()
            when (decoded) {
                is String -> JSONObject(decoded)
                is JSONObject -> decoded
                else -> null
            }
        }.getOrNull()
    }

    private fun isValidSnapshot(raw: String?): Boolean =
        raw?.let {
            runCatching {
                val value = JSONObject(it)
                value.optString("userAgent").isNotBlank() &&
                    value.optString("secChUa").isNotBlank() &&
                    value.optString("secChUaPlatform").isNotBlank()
            }.getOrDefault(false)
        } == true

    private fun header(headers: Map<String, String>, name: String): String? =
        headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value

    private fun buildCacheKey(context: Context): String {
        val configuration = context.resources.configuration
        val webViewPackage = WebView.getCurrentWebViewPackage()
        val locale = configuration.locales.get(0)?.toLanguageTag()
            ?: Locale.getDefault().toLanguageTag()
        val raw = listOf(
            SCHEMA_VERSION,
            webViewPackage?.packageName.orEmpty(),
            webViewPackage?.versionName.orEmpty(),
            USER_AGENT,
            configuration.screenWidthDp,
            configuration.screenHeightDp,
            configuration.densityDpi,
            locale,
        ).joinToString("|")
        return MessageDigest.getInstance("SHA-256")
            .digest(raw.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }

    private val FINGERPRINT_SCRIPT = """
        (() => JSON.stringify({
          userAgent: navigator.userAgent || '',
          uaBrands: navigator.userAgentData ? navigator.userAgentData.brands : [],
          uaMobile: navigator.userAgentData ? navigator.userAgentData.mobile : false,
          uaPlatform: navigator.userAgentData ? navigator.userAgentData.platform : '',
          screenWidth: screen.width,
          screenHeight: screen.height,
          screenAvailWidth: screen.availWidth,
          screenAvailHeight: screen.availHeight,
          innerWidth: window.innerWidth,
          innerHeight: window.innerHeight,
          devicePixelRatio: window.devicePixelRatio,
          language: navigator.language || 'en-US',
          languages: navigator.languages || [navigator.language || 'en-US'],
          hardwareConcurrency: navigator.hardwareConcurrency || 4,
          deviceMemory: navigator.deviceMemory || 4,
          connectionEffectiveType: navigator.connection ? navigator.connection.effectiveType : '4g',
          notificationsPermission: typeof Notification !== 'undefined' ? Notification.permission : 'denied'
        }))()
    """.trimIndent()
}
