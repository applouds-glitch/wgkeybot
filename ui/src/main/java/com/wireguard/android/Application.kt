/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.StrictMode
import android.os.StrictMode.ThreadPolicy
import android.os.StrictMode.VmPolicy
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.appcompat.app.AppCompatDelegate
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStoreFile
import com.google.android.material.color.DynamicColors
import com.wireguard.android.backend.Backend
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.TurnBackend
import com.wireguard.android.activity.CaptchaActivity
import com.wireguard.android.captcha.CaptchaWebViewManager
import com.wireguard.android.configStore.FileConfigStore
import com.wireguard.android.model.TunnelManager
import com.wireguard.android.model.TunnelStateTracker
import com.wireguard.android.turn.TurnProxyManager
import com.wireguard.android.turn.TurnSettingsStore
import com.wireguard.android.widget.WidgetStateObserver
import com.wireguard.android.util.AuthStore
import com.wireguard.android.util.UserKnobs
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.lang.ref.WeakReference
import java.util.Locale

class Application : android.app.Application() {
    private val futureBackend = CompletableDeferred<Backend>()
    private val coroutineScope = CoroutineScope(Job() + Dispatchers.Main.immediate)
    private var backend: Backend? = null
    private lateinit var preferencesDataStore: DataStore<Preferences>
    private lateinit var tunnelManager: TunnelManager
    private lateinit var turnProxyManager: TurnProxyManager
    private lateinit var tunnelStateTracker: TunnelStateTracker

    override fun attachBaseContext(context: Context) {
        super.attachBaseContext(context)
        if (BuildConfig.MIN_SDK_VERSION > Build.VERSION.SDK_INT) {
            val intent = Intent(Intent.ACTION_MAIN)
            intent.addCategory(Intent.CATEGORY_HOME)
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK)
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(intent)
            System.exit(0)
        }
    }

    private fun determineBackend(): Backend {
        val backend = GoBackend(applicationContext)
        GoBackend.setAlwaysOnCallback { get().applicationScope.launch { get().tunnelManager.restoreState(true) } }
        return backend
    }

    override fun onCreate() {
        Log.i(TAG, USER_AGENT)
        super.onCreate()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Создаём канал уведомлений сразу при старте приложения
            val channel = android.app.NotificationChannel(
                "vpn_running",
                "VPN Running",
                android.app.NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Уведомление о работе туннеля"
                setShowBadge(false)
                lockscreenVisibility = android.app.Notification.VISIBILITY_PUBLIC
                setSound(null, null)
                enableVibration(false)
            }
            val nm = getSystemService(android.app.NotificationManager::class.java)
            nm?.createNotificationChannel(channel)
        }
        DynamicColors.applyToActivitiesIfAvailable(this)
        preferencesDataStore = PreferenceDataStoreFactory.create { applicationContext.preferencesDataStoreFile("settings") }
        val isTvDevice = (resources.configuration.uiMode and android.content.res.Configuration.UI_MODE_TYPE_MASK) ==
                android.content.res.Configuration.UI_MODE_TYPE_TELEVISION
        AppCompatDelegate.setDefaultNightMode(
            if (isTvDevice) AppCompatDelegate.MODE_NIGHT_YES
            else when (AuthStore.getInstance(this).getThemeMode()) {
                "light" -> AppCompatDelegate.MODE_NIGHT_NO
                "dark"  -> AppCompatDelegate.MODE_NIGHT_YES
                else    -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
            }
        )
        tunnelManager = TunnelManager(
            FileConfigStore(applicationContext),
            TurnSettingsStore(applicationContext),
        )
        // Load wg-go library BEFORE creating TurnProxyManager to avoid UnsatisfiedLinkError
        com.wireguard.android.util.SharedLibraryLoader.loadSharedLibrary(applicationContext, "wg-go")
        turnProxyManager = TurnProxyManager(applicationContext)
        CaptchaWebViewManager.onTunnelStart(applicationContext)

        // Captcha strategy (matches Go mode order in vk.go):
        // 1. Go HTTP auto-solve (captchaSolveModeAuto)
        //    └─ if slider advertised in settings → Go slider POC (dynamic, not in queue)
        //         └─ if slider POC fails → skip invisible WebView, jump to visible dialog
        // 2. Invisible WebView auto-click (captchaSolveModeManual)  ← Kotlin call #1
        //    (skipped when slider POC failed — invisible WebView can't solve sliders)
        // 3. Visible CaptchaActivity dialog (captchaSolveModeManualVisible) ← Kotlin call #2
        var autoSolveAttempted = false
        TurnBackend.setCaptchaHandler { redirectUri ->
            Log.d(TAG, "Captcha handler invoked, autoSolveAttempted=$autoSolveAttempted")
            if (!autoSolveAttempted) {
                autoSolveAttempted = true
                try {
                    val token = kotlinx.coroutines.runBlocking {
                        CaptchaWebViewManager.solveCaptchaAsync(redirectUri)
                    }
                    Log.d(TAG, "Auto captcha solved, got token")
                    autoSolveAttempted = false
                    token
                } catch (e: Exception) {
                    val isSlider = e.message == CaptchaWebViewManager.ERROR_SLIDER_DETECTED
                    val reason = if (isSlider) "slider detected" else e.message
                    Log.d(TAG, "Captcha failed ($reason), signalling Go for next mode")
                    // On slider: return a sentinel so Go runs the slider POC before
                    // falling back to the visible dialog. Otherwise empty → next mode.
                    // autoSolveAttempted stays true so the next call goes to the dialog.
                    if (isSlider) CAPTCHA_SLIDER_SENTINEL else ""
                }
            } else {
                autoSolveAttempted = false
                CaptchaActivity.solveCaptcha(applicationContext, redirectUri)
            }
        }
        
        tunnelManager.onCreate()
        tunnelStateTracker = TunnelStateTracker(applicationContext)
        tunnelStateTracker.attach()
        WidgetStateObserver(applicationContext).attach()
        coroutineScope.launch(Dispatchers.IO) {
            backend = determineBackend()
            futureBackend.complete(backend!!)
        }
        if (BuildConfig.DEBUG) {
            StrictMode.setVmPolicy(VmPolicy.Builder().detectAll().penaltyLog().build())
            StrictMode.setThreadPolicy(ThreadPolicy.Builder().detectAll().penaltyLog().build())
        }
    }

    override fun onTerminate() {
        CaptchaWebViewManager.onTunnelStop()
        coroutineScope.cancel()
        super.onTerminate()
    }

    companion object {
        val USER_AGENT = String.format(Locale.ENGLISH, "WireGuard/%s (Android %d; %s; %s; %s %s; %s; %s)", BuildConfig.VERSION_NAME, Build.VERSION.SDK_INT, if (Build.SUPPORTED_ABIS.isNotEmpty()) Build.SUPPORTED_ABIS[0] else "unknown ABI", Build.BOARD, Build.MANUFACTURER, Build.MODEL, Build.FINGERPRINT, BuildConfig.APPLICATION_ID)
        private const val TAG = "WireGuard/Application"
        // Sentinel returned from the captcha handler when the invisible WebView
        // positively identified a slider captcha. Go recognises this exact string
        // (see captchaSliderSentinel in vk.go) and runs the slider POC before
        // escalating to the visible dialog. Must stay in sync with vk.go.
        private const val CAPTCHA_SLIDER_SENTINEL = "__WGK_SLIDER_DETECTED__"
        private lateinit var weakSelf: WeakReference<Application>

        fun get(): Application {
            return weakSelf.get()!!
        }

        suspend fun getBackend() = get().futureBackend.await()

        fun getPreferencesDataStore() = get().preferencesDataStore

        fun getTunnelManager() = get().tunnelManager

        fun getTurnProxyManager() = get().turnProxyManager

        fun getTunnelStateTracker() = get().tunnelStateTracker

        fun getCoroutineScope() = get().coroutineScope
    }

    init {
        weakSelf = WeakReference(this)
    }
}
