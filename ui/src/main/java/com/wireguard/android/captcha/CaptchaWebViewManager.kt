package com.wireguard.android.captcha

import android.annotation.SuppressLint
import android.content.Context
import android.hardware.display.DisplayManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.view.Display
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.util.Log
import android.view.MotionEvent
import android.view.View
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random

/**
 * Невидимый WebView для автоматического прохождения VK Smart Captcha.
 *
 * Один запрос = один свежий WebView:
 * 1. Привязывает процесс к физической сети (bypass VPN kill-switch)
 * 2. Создаёт WebView с рандомизированным fingerprint (UA, viewport)
 * 3. Загружает redirect_uri, ждёт ~2.7с загрузки
 * 4. Находит чекбокс "Я не робот" (label.vkc__Checkbox-module__Checkbox)
 * 5. Кликает в рандомную точку внутри label (1.5-3.5с "раздумий")
 * 6. JS-interceptor перехватывает captchaNotRobot.check → success_token
 * 7. Восстанавливает сетевую привязку и уничтожает WebView
 *
 * При обнаружении слайдера бросает IllegalStateException(ERROR_SLIDER_DETECTED)
 * — вызывающий код должен сделать fallback на CaptchaActivity.
 */
object CaptchaWebViewManager {

    private const val TAG = "CaptchaWV"
    private const val CAPTCHA_TIMEOUT_MS = 20_000L
    private const val WV_CREATE_TIMEOUT_MS = 3000L
    const val ERROR_SLIDER_DETECTED = "slider_detected"

    // UA и размер разметки приходят из CaptchaPersona — рандомизированные, но
    // общие для всех ступеней одной попытки. Раньше они разыгрывались прямо
    // здесь и независимо от HTTP-пути в Go, так что внутри одной лестницы
    // решения VK видел два разных устройства с одним browser_fp. Персона держит
    // набор неизменным до конца попытки и ротирует его по бюджету.
    private val mainHandler = Handler(Looper.getMainLooper())
    private val captchaMutex = Mutex()

    @Volatile private var isTunnelActive = false
    @Volatile private var appContext: Context? = null
    @Volatile private var previousNetwork: Network? = null

    private val pendingResult = AtomicReference<CompletableDeferred<Result<String>>?>(null)
    private val postClickSliderWatcher = AtomicReference<Runnable?>(null)

    @Volatile private var currentWebView: WebView? = null

    private val interceptorJSCode = """
        (function() {
            if (window.__wdtt_interceptor_installed) return;
            window.__wdtt_interceptor_installed = true;

            const origFetch = window.fetch;
            window.fetch = async function() {
                const args = arguments;
                const url = args[0] || '';
                if (typeof url === 'string' && url.includes('captchaNotRobot.check')) {
                    const response = await origFetch.apply(this, args);
                    const clone = response.clone();
                    try {
                        const data = await clone.json();
                        if (data.response && data.response.success_token) {
                            window.WdttCaptcha.onSuccess(data.response.success_token);
                        } else if (
                            data.response &&
                            data.response.show_captcha_type === 'slider'
                        ) {
                            window.WdttCaptcha.onSliderDetected('check_response');
                        } else if (data.error) {
                            window.WdttCaptcha.onError(JSON.stringify(data.error));
                        }
                    } catch(e) {}
                    return response;
                }
                return origFetch.apply(this, args);
            };

            const origXHROpen = XMLHttpRequest.prototype.open;
            const origXHRSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(method, url) {
                this._wdtt_url = url;
                return origXHROpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function() {
                const xhr = this;
                if (xhr._wdtt_url && xhr._wdtt_url.includes('captchaNotRobot.check')) {
                    xhr.addEventListener('load', function() {
                        try {
                            const data = JSON.parse(xhr.responseText);
                            if (data.response && data.response.success_token) {
                                window.WdttCaptcha.onSuccess(data.response.success_token);
                            } else if (
                                data.response &&
                                data.response.show_captcha_type === 'slider'
                            ) {
                                window.WdttCaptcha.onSliderDetected('check_response');
                            } else if (data.error) {
                                window.WdttCaptcha.onError(JSON.stringify(data.error));
                            }
                        } catch(e) {}
                    });
                }
                return origXHRSend.apply(this, arguments);
            };
        })();
    """.trimIndent()

    // ═══════════════════════════════════════════════════════════════
    // Lifecycle
    // ═══════════════════════════════════════════════════════════════

    fun onTunnelStart(context: Context) {
        appContext = context.applicationContext
        isTunnelActive = true
        Log.d(TAG, "Туннель активен")
    }

    /**
     * Прерывает решение капчи, идущее прямо сейчас: нативный слой останавливает
     * прокси, и токен уже некому отдать. Только освобождает ожидающий
     * [solveCaptchaAsync] — WebView уничтожит его собственный finally, поэтому
     * вызов не блокирует поток остановки.
     */
    fun cancelActive() {
        cancelPendingResult("captcha cancelled by proxy stop")
    }

    fun onTunnelStop() {
        isTunnelActive = false
        cancelPendingResult("tunnel stopped")
        destroyCurrentWebView()
        appContext?.let { restoreNetworkBinding(it) }
        appContext = null
        Log.d(TAG, "Туннель остановлен")
    }

    // ═══════════════════════════════════════════════════════════════
    // Публичный API
    // ═══════════════════════════════════════════════════════════════

    suspend fun solveCaptchaAsync(redirectUri: String, onStep: (String) -> Unit = {}): String {
        if (!isTunnelActive) throw IllegalStateException("WV не готов — туннель не активен")
        val ctx = appContext ?: throw IllegalStateException("WV не готов — контекст null")

        return captchaMutex.withLock {
            try {
                bindToPhysicalNetwork(ctx)
                withTimeout(CAPTCHA_TIMEOUT_MS) {
                    doSolveCaptcha(ctx, redirectUri, onStep)
                }
            } finally {
                pendingResult.set(null)
                destroyCurrentWebView()
                restoreNetworkBinding(ctx)
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Network binding — bypass VPN kill-switch для WebView
    // ═══════════════════════════════════════════════════════════════

    private fun bindToPhysicalNetwork(context: Context) {
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            previousNetwork = cm.boundNetworkForProcess
            @Suppress("DEPRECATION")
            val networks = cm.allNetworks
            for (network in networks) {
                val caps = cm.getNetworkCapabilities(network) ?: continue
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
                if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
                cm.bindProcessToNetwork(network)
                val type = when {
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WiFi"
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "Cellular"
                    else -> "Other"
                }
                Log.d(TAG, "Привязан к физической сети ($type)")
                return
            }
            Log.w(TAG, "Физическая сеть не найдена")
        } catch (e: Exception) {
            Log.e(TAG, "bindToPhysicalNetwork: ${e.message}")
        }
    }

    private fun restoreNetworkBinding(context: Context) {
        try {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            cm.bindProcessToNetwork(previousNetwork)
            previousNetwork = null
            Log.d(TAG, "Сетевая привязка восстановлена")
        } catch (e: Exception) {
            Log.e(TAG, "restoreNetworkBinding: ${e.message}")
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Внутренняя логика
    // ═══════════════════════════════════════════════════════════════

    private suspend fun doSolveCaptcha(context: Context, redirectUri: String, onStep: (String) -> Unit): String {
        val deferred = CompletableDeferred<Result<String>>()
        pendingResult.set(deferred)

        val webView = createWebViewSync(context, onStep)
            ?: throw IllegalStateException("Не удалось создать WebView")

        Log.d(TAG, "WebView создан ✓")

        withContext(Dispatchers.Main) {
            webView.evaluateJavascript(interceptorJSCode, null)
            kotlinx.coroutines.delay(80)
            webView.loadUrl(redirectUri)
        }

        return try {
            val token = deferred.await().getOrThrow()
            Log.d(TAG, "Капча решена ✓")
            token
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "Ошибка: ${e::class.simpleName} — ${e.message}")
            throw e
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Создание WebView с рандомизированным fingerprint
    // ═══════════════════════════════════════════════════════════════

    @SuppressLint("SetJavaScriptEnabled")
    private fun createWebViewSync(context: Context, onStep: (String) -> Unit): WebView? {
        val persona = CaptchaPersona.current(context)
        val vw = persona.layoutWidthPx
        val vh = persona.layoutHeightPx
        val ua = persona.userAgent

        Log.d(TAG, "Персона: ${vw}x${vh}, fp=${persona.browserFp.take(8)}")

        val latch = CountDownLatch(1)
        var webView: WebView? = null

        val createAction = Runnable {
            try {
                // Android 12+ (API 31+) StrictMode rejects WebView construction from a
                // non-UI Context. Chain createDisplayContext (gives a real Display) +
                // createConfigurationContext (gives Configuration that ViewConfiguration
                // needs); together they satisfy the IncorrectContextUseViolation check.
                val displayManager = context.getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
                val display = displayManager.getDisplay(Display.DEFAULT_DISPLAY)
                val wvContext = if (display != null) {
                    context.createDisplayContext(display)
                        .createConfigurationContext(context.resources.configuration)
                } else context

                val wv = WebView(wvContext)

                // WebView init clobbers the process locale (see LocaleGuard).
                // Repair immediately; destroyCurrentWebView() repairs again since
                // the clobber can also happen later during page load / render.
                com.wireguard.android.util.LocaleGuard.restore(context)
                wv.apply {
                    settings.apply {
                        javaScriptEnabled = true
                        domStorageEnabled = true
                        @Suppress("DEPRECATION")
                        databaseEnabled = true
                        mediaPlaybackRequiresUserGesture = false
                        loadWithOverviewMode = true
                        useWideViewPort = true
                        blockNetworkLoads = false
                        cacheMode = android.webkit.WebSettings.LOAD_NO_CACHE
                        userAgentString = ua
                    }

                    addJavascriptInterface(CaptchaJSBridge(), "WdttCaptcha")

                    webViewClient = object : WebViewClient() {
                        override fun onPageStarted(
                            view: WebView, url: String?, favicon: android.graphics.Bitmap?
                        ) {
                            super.onPageStarted(view, url, favicon)
                            view.evaluateJavascript(interceptorJSCode, null)
                        }

                        override fun onPageFinished(view: WebView, url: String?) {
                            super.onPageFinished(view, url)

                            val isCaptchaPage = url?.let {
                                it.contains("not_robot_captcha") ||
                                it.contains("id.vk.ru/captcha") ||
                                it.contains("not_robot")
                            } ?: false

                            if (isCaptchaPage) {
                                Log.d(TAG, "Страница капчи загружена")
                                view.evaluateJavascript(interceptorJSCode, null)

                                if (currentWebView === view && isTunnelActive) {
                                    val pageLoadDelay = 2500L + Random.Default.nextLong(0, 1000)
                                    mainHandler.postDelayed({
                                        if (currentWebView === view && isTunnelActive) {
                                            solveCaptchaAutomatedSync(view)
                                        }
                                    }, pageLoadDelay)
                                }
                            }
                        }

                        override fun shouldInterceptRequest(
                            view: WebView, request: WebResourceRequest
                        ): WebResourceResponse? {
                            return super.shouldInterceptRequest(view, request)
                        }

                        override fun onReceivedSslError(
                            view: WebView,
                            handler: android.webkit.SslErrorHandler,
                            error: android.net.http.SslError
                        ) {
                            val url = error.url ?: ""
                            if (url.contains("vk.ru") || url.contains("vk.com") || url.contains("okcdn.ru")) {
                                handler.proceed()
                            } else {
                                handler.cancel()
                                Log.w(TAG, "SSL error rejected for: $url")
                            }
                        }
                    }

                    webChromeClient = WebChromeClient()

                    measure(
                        View.MeasureSpec.makeMeasureSpec(vw, View.MeasureSpec.EXACTLY),
                        View.MeasureSpec.makeMeasureSpec(vh, View.MeasureSpec.EXACTLY)
                    )
                    layout(0, 0, vw, vh)
                    onResume()
                }
                webView = wv
                currentWebView = wv
            } catch (e: Exception) {
                Log.e(TAG, "Ошибка создания WebView: ${e.message}")
                webView = null
            } finally {
                latch.countDown()
            }
        }

        if (Looper.myLooper() == Looper.getMainLooper()) {
            createAction.run()
        } else {
            mainHandler.post(createAction)
        }

        val ok = latch.await(WV_CREATE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        if (!ok) {
            Log.e(TAG, "Таймаут создания WebView")
            return null
        }
        return webView
    }

    private fun destroyCurrentWebView() {
        val wv = currentWebView ?: return
        currentWebView = null
        postClickSliderWatcher.getAndSet(null)?.let { mainHandler.removeCallbacks(it) }

        val destroyAction = Runnable {
            try {
                wv.stopLoading()
                wv.loadUrl("about:blank")
                try { wv.removeJavascriptInterface("WdttCaptcha") } catch (_: Exception) {}
                wv.webViewClient = WebViewClient()
                wv.webChromeClient = null
                wv.onPause()
                wv.removeAllViews()
                wv.destroy()
                Log.d(TAG, "WebView уничтожен ✓")
            } catch (e: Exception) {
                Log.e(TAG, "Ошибка уничтожения: ${e.message}")
            } finally {
                // WebView may have clobbered the locale during its lifetime
                // (page load / render), not just at construction — repair now
                // that it's fully torn down.
                appContext?.let { com.wireguard.android.util.LocaleGuard.restore(it) }
            }
        }

        if (Looper.myLooper() == Looper.getMainLooper()) {
            destroyAction.run()
        } else {
            val latch = CountDownLatch(1)
            mainHandler.post {
                try { destroyAction.run() } finally { latch.countDown() }
            }
            latch.await(2000, TimeUnit.MILLISECONDS)
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Авто-решение: клик по чекбоксу «Я не робот»
    // ═══════════════════════════════════════════════════════════════

    private fun solveCaptchaAutomatedSync(webView: WebView) {
        if (currentWebView !== webView || !isTunnelActive) return

        val findLabelJS = """
            (function() {
                var slider = document.querySelector(
                    '[class*="SliderCaptcha"], [class*="Kaleidoscope"], ' +
                    '.vkc__SliderCaptcha-module__description, ' +
                    '.vkc__KaleidoscopeScreen-module__captchaId'
                );
                if (slider) return '${ERROR_SLIDER_DETECTED}';

                var el = document.querySelector('label.vkc__Checkbox-module__Checkbox');
                if (!el) el = document.querySelector('label[for="not-robot-captcha-checkbox"]');
                if (!el) el = document.getElementById('not-robot-captcha-checkbox');
                if (!el) return 'not_found';

                var rect = el.getBoundingClientRect();
                var style = window.getComputedStyle(el);
                if (rect.width < 5 || rect.height < 5 ||
                    style.display === 'none' || style.visibility === 'hidden') {
                    return 'not_found';
                }
                return rect.left + ',' + rect.top + ',' + rect.width + ',' + rect.height;
            })();
        """.trimIndent()

        webView.evaluateJavascript(findLabelJS) { rawValue ->
            val result = rawValue?.replace("\"", "") ?: ""
            Log.d(TAG, "Label чекбокса: $result")

            if (currentWebView !== webView || !isTunnelActive) return@evaluateJavascript

            if (result == ERROR_SLIDER_DETECTED) {
                Log.i(TAG, "Обнаружен слайдер — fallback на ручной WebView")
                notifyResult(Result.failure(IllegalStateException(ERROR_SLIDER_DETECTED)))
                return@evaluateJavascript
            }

            if (result == "not_found" || result.split(",").size < 4) {
                Log.w(TAG, "Label не найден — JS-клик (fallback)")
                val jsClick = """
                    (function() {
                        var el = document.querySelector('label.vkc__Checkbox-module__Checkbox');
                        if (!el) el = document.getElementById('not-robot-captcha-checkbox');
                        if (el) { el.click(); return 'clicked'; }
                        return 'nothing';
                    })();
                """.trimIndent()
                webView.evaluateJavascript(jsClick) { clickResult ->
                    if ((clickResult ?: "").replace("\"", "") == "clicked") {
                        startPostClickSliderWatcher(webView)
                    } else {
                        // Кликать нечего — невидимый WebView бессилен. Эскалируем
                        // сразу, чтобы не висеть до withTimeout.
                        Log.i(TAG, "Чекбокс не найден — fallback на видимый диалог")
                        notifyResult(Result.failure(
                            IllegalStateException("checkbox not found")
                        ))
                    }
                }
                return@evaluateJavascript
            }

            val parts = result.split(",")
            val left   = parts[0].toFloatOrNull() ?: return@evaluateJavascript
            val top    = parts[1].toFloatOrNull() ?: return@evaluateJavascript
            val width  = parts[2].toFloatOrNull() ?: return@evaluateJavascript
            val height = parts[3].toFloatOrNull() ?: return@evaluateJavascript

            val randX = left + width  * (0.15f + Random.Default.nextFloat() * 0.7f)
            val randY = top  + height * (0.25f + Random.Default.nextFloat() * 0.5f)

            Log.d(TAG, "Клик: (${randX.toInt()}, ${randY.toInt()}) в зоне ${width.toInt()}x${height.toInt()}")

            val thinkDelay = 1500L + Random.Default.nextLong(0, 2000)
            mainHandler.postDelayed({
                if (currentWebView === webView && isTunnelActive) {
                    simulateHumanTouch(webView, randX, randY)
                    startPostClickSliderWatcher(webView)
                }
            }, thinkDelay)
        }
    }

    private fun startPostClickSliderWatcher(webView: WebView) {
        postClickSliderWatcher.getAndSet(null)?.let { mainHandler.removeCallbacks(it) }

        var attemptsLeft = 12
        val watcher = object : Runnable {
            override fun run() {
                if (currentWebView !== webView || !isTunnelActive) return

                val detectSliderJS = """
                    (function() {
                        var slider = document.querySelector(
                            '[class*="SliderCaptcha"], [class*="Kaleidoscope"], ' +
                            '.vkc__SliderCaptcha-module__description, ' +
                            '.vkc__KaleidoscopeScreen-module__captchaId, ' +
                            '.vkc__SwipeButton-module__track'
                        );
                        if (slider) return 'slider';

                        var success = document.querySelector(
                            '[class*="success"], [class*="Success"], [class*="passed"], [class*="Passed"]'
                        );
                        if (success) return 'success_ui';

                        return 'none';
                    })();
                """.trimIndent()

                webView.evaluateJavascript(detectSliderJS) { rawValue ->
                    if (currentWebView !== webView || !isTunnelActive) return@evaluateJavascript

                    when (rawValue?.replace("\"", "") ?: "none") {
                        "slider" -> {
                            Log.i(TAG, "После checkbox появился слайдер — fallback на ручной WebView")
                            notifyResult(Result.failure(IllegalStateException(ERROR_SLIDER_DETECTED)))
                        }
                        "success_ui" -> {
                            postClickSliderWatcher.set(null)
                        }
                        else -> {
                            attemptsLeft--
                            if (attemptsLeft > 0) {
                                mainHandler.postDelayed(this, 650L)
                            } else {
                                // Попытки кончились, а ни success_token (через
                                // перехватчик), ни слайдер не появились — VK требует
                                // интерактивную капчу, которую невидимый WebView решить
                                // не может. Эскалируем сразу, чтобы не висеть до
                                // withTimeout(45s) и дать видимому диалогу открыться.
                                Log.i(TAG, "Авто-клик не прошёл — fallback на видимый диалог")
                                postClickSliderWatcher.set(null)
                                notifyResult(Result.failure(
                                    IllegalStateException("auto-click did not pass")
                                ))
                            }
                        }
                    }
                }
            }
        }

        postClickSliderWatcher.set(watcher)
        mainHandler.postDelayed(watcher, 900L)
    }

    private fun simulateHumanTouch(webView: WebView, cssX: Float, cssY: Float) {
        if (currentWebView !== webView) return

        val density = webView.resources.displayMetrics.density
        val physX = cssX * density
        val physY = cssY * density
        val downTime = SystemClock.uptimeMillis()

        val pressure = 0.5f + Random.Default.nextFloat() * 0.4f

        val downEvent = MotionEvent.obtain(
            downTime, downTime, MotionEvent.ACTION_DOWN, physX, physY, pressure, 1f, 0, 1f, 1f, 0, 0
        )
        downEvent.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
        webView.dispatchTouchEvent(downEvent)
        downEvent.recycle()

        val holdTime = 80L + Random.Default.nextLong(0, 100)
        mainHandler.postDelayed({
            if (currentWebView === webView) {
                val jitterX = physX + (-1f + Random.Default.nextFloat() * 2f) * density
                val jitterY = physY + (-0.5f + Random.Default.nextFloat() * 1f) * density

                val upEvent = MotionEvent.obtain(
                    downTime, SystemClock.uptimeMillis(), MotionEvent.ACTION_UP,
                    jitterX, jitterY, 0f, 1f, 0, 1f, 1f, 0, 0
                )
                upEvent.source = android.view.InputDevice.SOURCE_TOUCHSCREEN
                webView.dispatchTouchEvent(upEvent)
                upEvent.recycle()
            }
        }, holdTime)
    }

    // ═══════════════════════════════════════════════════════════════
    // JS Bridge
    // ═══════════════════════════════════════════════════════════════

    private class CaptchaJSBridge {
        @JavascriptInterface
        fun onSuccess(token: String) {
            Log.d(TAG, "JS: success_token получен (${token.length} символов)")
            notifyResult(Result.success(token))
        }

        @JavascriptInterface
        fun onSliderDetected(source: String) {
            Log.i(TAG, "JS: обнаружен slider после auto-step ($source)")
            notifyResult(Result.failure(IllegalStateException(ERROR_SLIDER_DETECTED)))
        }

        @JavascriptInterface
        fun onError(error: String) {
            Log.e(TAG, "JS: ошибка — $error")
            notifyResult(Result.failure(Exception("VK: $error")))
        }
    }

    private fun notifyResult(result: Result<String>) {
        val deferred = pendingResult.getAndSet(null) ?: return
        if (!deferred.isCompleted) deferred.complete(result)
    }

    private fun cancelPendingResult(reason: String) {
        val deferred = pendingResult.getAndSet(null) ?: return
        if (!deferred.isCompleted) deferred.complete(Result.failure(CancellationException(reason)))
    }
}
