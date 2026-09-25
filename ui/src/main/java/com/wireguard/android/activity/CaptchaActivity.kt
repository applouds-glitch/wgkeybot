/*
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.webkit.JavascriptInterface
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import com.wireguard.android.BuildConfig
import com.wireguard.android.captcha.CaptchaNetworkBinding
import com.wireguard.android.captcha.CaptchaPersona
import com.wireguard.android.util.LocaleGuard
import java.lang.ref.WeakReference
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/**
 * Transparent-themed activity that shows a WebView dialog for VK captcha solving.
 * The WebView loads the VK "not_robot_captcha" page and intercepts the success_token
 * via JavaScript injection.
 */
class CaptchaActivity : AppCompatActivity() {

    private var didBindNetwork = false
    private var reloadCount = 0

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        liveActivity = WeakReference(this)

        val redirectUri = intent.getStringExtra(EXTRA_REDIRECT_URI)
        if (redirectUri.isNullOrEmpty()) {
            Log.e(TAG, "No redirect URI provided")
            deliverResult("")
            finish()
            return
        }

        // Out from under the tunnel, so the WebView can actually reach id.vk.ru —
        // over the network TURN is on, see CaptchaNetworkBinding.
        didBindNetwork = CaptchaNetworkBinding.bind(this)

        Log.d(TAG, "Loading captcha page...")

        val webView = WebView(this).apply {
            settings.javaScriptEnabled = true
            settings.domStorageEnabled = true
            // One UA per solve attempt, shared with the invisible WebView and the
            // Go HTTP path through CaptchaPersona. Randomized between attempts —
            // see CaptchaPersona — but never within one, where a differing UA
            // would contradict the browser_fp the earlier steps already presented.
            settings.userAgentString = CaptchaPersona.current(this@CaptchaActivity).userAgent

            addJavascriptInterface(CaptchaBridge(), "AndroidCaptcha")

            webChromeClient = WebChromeClient()

            webViewClient = object : WebViewClient() {
                override fun onPageFinished(view: WebView?, url: String?) {
                    super.onPageFinished(view, url)
                    // Inject JS to intercept the captchaNotRobot.check response
                    view?.evaluateJavascript(INTERCEPT_SCRIPT, null)
                }

                override fun shouldOverrideUrlLoading(
                    view: WebView?,
                    request: WebResourceRequest?
                ): Boolean {
                    // Only intervene on top-level navigations. Sub-frame/iframe
                    // loads (captcha widgets, embedded resources) must be left
                    // alone — reloading the whole page on an iframe navigation
                    // would break the captcha and could spin into a loop.
                    if (request?.isForMainFrame != true) return false
                    val url = request.url?.toString() ?: return false
                    // Block navigation away from captcha/auth domains. The VK
                    // captcha page can redirect to vk.com after repeated failures;
                    // reload the original captcha URL instead so the user stays on
                    // the captcha and can keep trying — but cap the reloads so a
                    // persistent redirect can't spin forever.
                    if (!isCaptchaHost(url)) {
                        if (reloadCount < MAX_CAPTCHA_RELOADS) {
                            reloadCount++
                            Log.w(TAG, "Blocked navigation to external URL ($reloadCount/$MAX_CAPTCHA_RELOADS): $url")
                            view?.loadUrl(redirectUri)
                        } else {
                            Log.w(TAG, "Captcha reload limit reached after redirect to: $url — giving up")
                            deliverResult("")
                            finish()
                        }
                        return true
                    }
                    return false
                }
            }
        }

        // WebView construction clobbers the process locale (see LocaleGuard).
        // Repair now; onDestroy() repairs again since the clobber can also
        // happen later during page load / render.
        LocaleGuard.restore(this)

        setContentView(webView)
        if (BuildConfig.DEBUG) {
            Log.d(TAG, "Waiting ${DEBUG_INSPECTION_DELAY_MS}ms for DevTools before loading captcha")
            webView.postDelayed({
                if (!isFinishing && !isDestroyed) webView.loadUrl(redirectUri)
            }, DEBUG_INSPECTION_DELAY_MS)
        } else {
            webView.loadUrl(redirectUri)
        }
    }

    private fun deliverResult(token: String) {
        pendingResult?.complete(token)
    }

    private inner class CaptchaBridge {
        @JavascriptInterface
        fun onResult(successToken: String) {
            Log.d(TAG, "Captcha solved, got success_token (length=${successToken.length})")
            runOnUiThread {
                deliverResult(successToken)
                finish()
            }
        }
    }

    /**
     * Returns true if the URL is allowed for captcha navigation.
     * Blocks redirects to vk.com and other non-captcha domains that
     * would take the user away from the captcha page.
     */
    private fun isCaptchaHost(url: String?): Boolean {
        if (url == null) return false
        val host = try {
            android.net.Uri.parse(url).host ?: return false
        } catch (e: Exception) {
            return false
        }
        return host == "id.vk.ru" ||
            host == "login.vk.ru" ||
            host == "oauth.vk.ru" ||
            host == "api.vk.ru" ||
            host.endsWith(".id.vk.ru") ||
            host.endsWith(".login.vk.ru")
    }

    override fun onDestroy() {
        if (liveActivity?.get() === this) liveActivity = null
        if (didBindNetwork) {
            didBindNetwork = false
            CaptchaNetworkBinding.release(this)
        }
        // WebView may have clobbered the locale during its lifetime (page load /
        // render), not just at construction — repair after it's torn down.
        LocaleGuard.restore(this)
        super.onDestroy()
        // If activity destroyed without result (back button etc.), deliver empty
        deliverResult("")
    }

    companion object {
        private const val TAG = "WireGuard/CaptchaActivity"
        private const val EXTRA_REDIRECT_URI = "redirect_uri"
        private const val CAPTCHA_TIMEOUT_SECONDS = 120L
        private const val MAX_CAPTCHA_RELOADS = 5
        private const val DEBUG_INSPECTION_DELAY_MS = 15_000L

        @Volatile
        private var pendingResult: CompletableFuture<String>? = null

        /** The dialog currently on screen, so a native stop can dismiss it. */
        @Volatile
        private var liveActivity: WeakReference<CaptchaActivity>? = null

        /**
         * Aborts a captcha dialog that is still on screen because the native proxy
         * is stopping or restarting. Unblocks [solveCaptcha] with an empty token
         * right away instead of after [CAPTCHA_TIMEOUT_SECONDS], then dismisses the
         * dialog. Called from a native thread, so it must not block.
         */
        fun cancelPending() {
            // Every proxy stop calls this, with or without a dialog: only a
            // cancel that found one is worth a line.
            val unblocked = pendingResult?.complete("") == true
            val activity = liveActivity?.get()
            if (unblocked || activity != null) Log.d(TAG, "Captcha cancelled by native stop")
            activity ?: return
            activity.runOnUiThread {
                if (!activity.isFinishing && !activity.isDestroyed) activity.finish()
            }
        }

        /**
         * JavaScript that intercepts XHR/fetch calls to captchaNotRobot.check
         * and extracts the success_token from the response.
         * Also intercepts postMessage in case the page sends the result that way.
         */
        private val INTERCEPT_SCRIPT = """
            (function() {
                // Intercept XMLHttpRequest
                var origOpen = XMLHttpRequest.prototype.open;
                var origSend = XMLHttpRequest.prototype.send;
                XMLHttpRequest.prototype.open = function() {
                    this._captchaUrl = arguments[1];
                    return origOpen.apply(this, arguments);
                };
                XMLHttpRequest.prototype.send = function() {
                    var xhr = this;
                    if (xhr._captchaUrl && xhr._captchaUrl.indexOf('captchaNotRobot.check') !== -1) {
                        xhr.addEventListener('load', function() {
                            try {
                                var data = JSON.parse(xhr.responseText);
                                if (data.response && data.response.success_token) {
                                    AndroidCaptcha.onResult(data.response.success_token);
                                }
                            } catch(e) {}
                        });
                    }
                    return origSend.apply(this, arguments);
                };

                // Intercept fetch
                var origFetch = window.fetch;
                if (origFetch) {
                    window.fetch = function() {
                        var url = arguments[0];
                        if (typeof url === 'object' && url.url) url = url.url;
                        var p = origFetch.apply(this, arguments);
                        if (typeof url === 'string' && url.indexOf('captchaNotRobot.check') !== -1) {
                            p.then(function(response) {
                                return response.clone().json();
                            }).then(function(data) {
                                if (data.response && data.response.success_token) {
                                    AndroidCaptcha.onResult(data.response.success_token);
                                }
                            }).catch(function(e) {});
                        }
                        return p;
                    };
                }

                // Intercept postMessage as backup
                window.addEventListener('message', function(e) {
                    try {
                        var data = typeof e.data === 'string' ? JSON.parse(e.data) : e.data;
                        if (data && data.success_token) {
                            AndroidCaptcha.onResult(data.success_token);
                        } else if (data && data.response && data.response.success_token) {
                            AndroidCaptcha.onResult(data.response.success_token);
                        }
                    } catch(ex) {}
                });
            })();
        """.trimIndent()

        /**
         * Launches the captcha activity and blocks until result is available.
         * Called from a background thread (Go thread via JNI).
         * @param context Application context
         * @param redirectUri VK captcha redirect URI
         * @return success_token or empty string
         */
        fun solveCaptcha(context: Context, redirectUri: String): String {
            Log.d(TAG, "solveCaptcha called, launching activity...")

            val future = CompletableFuture<String>()
            pendingResult = future

            val intent = Intent(context, CaptchaActivity::class.java).apply {
                putExtra(EXTRA_REDIRECT_URI, redirectUri)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)

            return try {
                val result = future.get(CAPTCHA_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                Log.d(TAG, "solveCaptcha result: ${if (result.isNotEmpty()) "token" else "empty"}")
                result
            } catch (e: Exception) {
                Log.e(TAG, "solveCaptcha failed", e)
                ""
            } finally {
                pendingResult = null
            }
        }
    }
}
