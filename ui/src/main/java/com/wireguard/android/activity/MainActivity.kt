/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.RelativeSizeSpan
import android.text.style.TypefaceSpan
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.addCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.ActionBar
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.graphics.drawable.DrawableCompat
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.FragmentTransaction
import androidx.fragment.app.commit
import androidx.lifecycle.lifecycleScope
import com.wireguard.android.BuildConfig
import com.wireguard.android.R
import com.wireguard.android.fragment.TunnelDetailFragment
import com.wireguard.android.fragment.TunnelListFragment
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.util.ApiClient
import com.wireguard.android.util.AuthStore
import com.wireguard.config.Config
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : BaseActivity(), FragmentManager.OnBackStackChangedListener {
    private var actionBar: ActionBar? = null
    private var isTwoPaneLayout = false
    private var backPressedCallback: OnBackPressedCallback? = null

    private val batteryOptLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { }

    private fun handleBackPressed() {
        val backStackEntries = supportFragmentManager.backStackEntryCount
        if (isTwoPaneLayout && backStackEntries <= 1) { finish(); return }
        if (backStackEntries >= 1) supportFragmentManager.popBackStack()
        if (backStackEntries == 1) selectedTunnel = null
    }

    override fun onBackStackChanged() {
        val backStackEntries = supportFragmentManager.backStackEntryCount
        backPressedCallback?.isEnabled = backStackEntries >= 1
        if (actionBar == null) return
        val minBackStackEntries = if (isTwoPaneLayout) 2 else 1
        actionBar!!.setDisplayHomeAsUpEnabled(backStackEntries >= minBackStackEntries)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.main_activity)
        actionBar = supportActionBar
        supportActionBar?.apply {
            title = SpannableString("WGKEYBOT").also {
                it.setSpan(TypefaceSpan("sans-serif-condensed"), 0, it.length, Spanned.SPAN_INCLUSIVE_INCLUSIVE)
            }
            subtitle = SpannableString("v${BuildConfig.VERSION_NAME}").also {
                it.setSpan(TypefaceSpan("monospace"), 0, it.length, Spanned.SPAN_INCLUSIVE_INCLUSIVE)
                it.setSpan(RelativeSizeSpan(0.8f), 0, it.length, Spanned.SPAN_INCLUSIVE_INCLUSIVE)
                it.setSpan(ForegroundColorSpan(Color.parseColor("#80909090")), 0, it.length, Spanned.SPAN_INCLUSIVE_INCLUSIVE)
            }
        }
        isTwoPaneLayout = findViewById<View?>(R.id.master_detail_wrapper) != null
        supportFragmentManager.addOnBackStackChangedListener(this)
        backPressedCallback = onBackPressedDispatcher.addCallback(this) { handleBackPressed() }
        onBackStackChanged()
        handleDeeplinkIntent(intent)
        checkBatteryOptimization()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_activity, menu)
        val item = menu.findItem(R.id.menu_theme_toggle) ?: return true
        val iconRes = if (isEffectivelyDark()) R.drawable.ic_theme_dark else R.drawable.ic_theme_light
        val drawable = androidx.core.content.ContextCompat.getDrawable(this, iconRes)?.mutate() ?: return true
        val tintColor = if (isEffectivelyDark()) android.graphics.Color.WHITE else android.graphics.Color.BLACK
        DrawableCompat.setTint(DrawableCompat.wrap(drawable), tintColor)
        item.icon = drawable
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                supportFragmentManager.popBackStack()
                true
            }
            R.id.menu_theme_toggle -> {
                val auth = AuthStore.getInstance(this)
                val next = if (isEffectivelyDark()) "light" else "dark"
                auth.setThemeMode(next)
                AppCompatDelegate.setDefaultNightMode(
                    if (next == "dark") AppCompatDelegate.MODE_NIGHT_YES
                    else AppCompatDelegate.MODE_NIGHT_NO
                )
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun isEffectivelyDark(): Boolean {
        return when (AuthStore.getInstance(this).getThemeMode()) {
            "dark"  -> true
            "light" -> false
            else    -> (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
                    Configuration.UI_MODE_NIGHT_YES
        }
    }

    private fun checkBatteryOptimization() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (!pm.isIgnoringBatteryOptimizations(packageName)) {
            try {
                batteryOptLauncher.launch(
                    Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                        data = Uri.parse("package:$packageName")
                    }
                )
            } catch (_: Exception) { }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDeeplinkIntent(intent)
    }

    private fun handleDeeplinkIntent(intent: Intent) {
        val uri = intent.data ?: return
        if (uri.scheme != "wgkeybot" || uri.host != "config") return

        val oneTimeToken = uri.getQueryParameter("token")?.takeIf { it.isNotBlank() } ?: run {
            Toast.makeText(this, getString(R.string.wgk_deeplink_missing_token), Toast.LENGTH_SHORT).show()
            return
        }
        // Consume the intent so a configuration change (rotation) doesn't replay
        // the same one-time token, which would fail server-side.
        intent.data = null

        val auth = AuthStore.getInstance(this)

        lifecycleScope.launch {
            try {
                val resp = withContext(Dispatchers.IO) { ApiClient.init(oneTimeToken) }

                auth.saveAccessToken(resp.accessToken)
                auth.saveSubscriptionExpiresAt(resp.subscriptionExpiresAt)

                if (!resp.config.contains("[Interface]") || !resp.config.contains("[Peer]")) {
                    throw IllegalArgumentException(getString(R.string.wgk_server_bad_config))
                }

                val config = Config.parse(resp.config.byteInputStream())

                // Pop detail/dialog screens so the list fragment is on top —
                // otherwise findFragmentById would return the detail fragment and
                // we'd drop the new config silently.
                if (supportFragmentManager.backStackEntryCount > 0) {
                    supportFragmentManager.popBackStackImmediate(null, FragmentManager.POP_BACK_STACK_INCLUSIVE)
                    selectedTunnel = null
                }
                val listFragment = supportFragmentManager.fragments
                    .filterIsInstance<TunnelListFragment>()
                    .firstOrNull()
                if (listFragment != null) {
                    listFragment.applyConfig(config)
                    listFragment.refreshState()
                }
            } catch (e: Exception) {
                Toast.makeText(this@MainActivity, getString(R.string.wgk_auth_error_format, e.message ?: ""), Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onSelectedTunnelChanged(
        oldTunnel: ObservableTunnel?,
        newTunnel: ObservableTunnel?
    ): Boolean {
        val fragmentManager = supportFragmentManager
        if (fragmentManager.isStateSaved) return false

        val backStackEntries = fragmentManager.backStackEntryCount
        if (newTunnel == null) {
            fragmentManager.popBackStackImmediate(0, FragmentManager.POP_BACK_STACK_INCLUSIVE)
            return true
        }
        if (backStackEntries == 2) {
            fragmentManager.popBackStackImmediate()
        } else if (backStackEntries == 0) {
            fragmentManager.commit {
                add(if (isTwoPaneLayout) R.id.detail_container else R.id.list_detail_container, TunnelDetailFragment())
                setTransition(FragmentTransaction.TRANSIT_FRAGMENT_FADE)
                addToBackStack(null)
            }
        }
        return true
    }
}
