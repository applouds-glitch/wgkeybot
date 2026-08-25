/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.content.Context
import android.content.Intent
import android.content.res.Configuration
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
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.addCallback
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.ActionBar
import androidx.core.content.ContextCompat
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
import com.wireguard.android.turn.ConnectionMode
import com.wireguard.android.util.ApiClient
import com.wireguard.android.util.AuthStore
import com.wireguard.android.util.TokenFormat
import com.wireguard.config.Config
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : BaseActivity(), FragmentManager.OnBackStackChangedListener {
    private var actionBar: ActionBar? = null
    private var backPressedCallback: OnBackPressedCallback? = null

    private val batteryOptLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { }

    private fun handleBackPressed() {
        val backStackEntries = supportFragmentManager.backStackEntryCount
        if (backStackEntries >= 1) supportFragmentManager.popBackStack()
        if (backStackEntries == 1) selectedTunnel = null
    }

    override fun onBackStackChanged() {
        val backStackEntries = supportFragmentManager.backStackEntryCount
        backPressedCallback?.isEnabled = backStackEntries >= 1
        if (actionBar == null) return
        actionBar!!.setDisplayHomeAsUpEnabled(backStackEntries >= 1)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.main_activity)
        actionBar = supportActionBar
        supportActionBar?.apply {
            // The build stamp rides on the title line instead of the subtitle it
            // used to have: a subtitle makes the bar two lines tall, and the
            // connect screen underneath is already height-bucketed
            // (values-h680dp / -h760dp) to survive short viewports. Monospace at
            // 0.55 of the title size and tinted a hair off the bar: a build stamp
            // riding on the wordmark, not a second piece of type. The separating
            // space sits inside the shrunk run, so the version stays tight
            // against the wordmark rather than a title-sized gap away.
            val wordmark = "WGKEYBOT"
            val stamp = " v${BuildConfig.VERSION_NAME}"
            title = SpannableString(wordmark + stamp).also {
                it.setSpan(TypefaceSpan("sans-serif-condensed"), 0, wordmark.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                it.setSpan(TypefaceSpan("monospace"), wordmark.length, it.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                it.setSpan(RelativeSizeSpan(0.55f), wordmark.length, it.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
                it.setSpan(
                    ForegroundColorSpan(ContextCompat.getColor(this@MainActivity, R.color.wgk_version_stamp)),
                    wordmark.length, it.length, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
                )
            }
        }
        supportFragmentManager.addOnBackStackChangedListener(this)
        backPressedCallback = onBackPressedDispatcher.addCallback(this) { handleBackPressed() }
        onBackStackChanged()
        handleDeeplinkIntent(intent)
        checkBatteryOptimization()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main_activity, menu)
        val barColor = if (isEffectivelyDark()) android.graphics.Color.WHITE else android.graphics.Color.BLACK

        // The reserve transport used to tint a value on the connect screen, and
        // that signal has to survive the move into the settings screen: a
        // non-default transport shows as a warning-coloured gear.
        val settingsColor =
            if (ConnectionMode.isReserve(this)) ContextCompat.getColor(this, R.color.wgk_warning)
            else barColor
        menu.findItem(R.id.menu_app_settings)?.setTintedIcon(R.drawable.ic_settings, settingsColor)
        return true
    }

    private fun MenuItem.setTintedIcon(iconRes: Int, tintColor: Int) {
        val drawable = ContextCompat.getDrawable(this@MainActivity, iconRes)?.mutate() ?: return
        DrawableCompat.setTint(DrawableCompat.wrap(drawable), tintColor)
        icon = drawable
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            android.R.id.home -> {
                supportFragmentManager.popBackStack()
                true
            }
            R.id.menu_app_settings -> {
                startActivity(Intent(this, AppSettingsActivity::class.java))
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    override fun onResume() {
        super.onResume()
        // The settings screen can flip the transport, and the gear carries that
        // state — rebuild the bar rather than let a stale tint stand.
        invalidateOptionsMenu()
    }

    /** Drives the tint of the bar's icons; the theme itself is set from the settings screen. */
    private fun isEffectivelyDark(): Boolean {
        return when (AuthStore.getInstance(this).getThemeMode()) {
            "dark"  -> true
            "light" -> false
            else    -> (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) ==
                    Configuration.UI_MODE_NIGHT_YES
        }
    }

    /**
     * Asks to be exempt from battery optimisation — once, ever. The tunnel wants
     * the exemption (a doze-killed proxy is a dead VPN), but the request is a
     * system modal that lands on top of the first frame, and asking on every cold
     * start until the user gives in is not how to earn it. A refusal is recorded
     * just like a grant; the exemption can still be given later from the system
     * settings.
     */
    private fun checkBatteryOptimization() {
        val auth = AuthStore.getInstance(this)
        if (auth.isBatteryPromptShown()) return
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        if (pm.isIgnoringBatteryOptimizations(packageName)) return
        try {
            batteryOptLauncher.launch(
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                    data = Uri.parse("package:$packageName")
                }
            )
            auth.setBatteryPromptShown()
        } catch (_: Exception) { }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDeeplinkIntent(intent)
    }

    private fun handleDeeplinkIntent(intent: Intent) {
        val uri = intent.data ?: return
        if (uri.scheme != "wgkeybot" || uri.host != "config") return

        val rawToken = uri.getQueryParameter("token")?.takeIf { it.isNotBlank() } ?: run {
            Toast.makeText(this, getString(R.string.wgk_deeplink_missing_token), Toast.LENGTH_SHORT).show()
            return
        }
        val oneTimeToken = TokenFormat.extract(rawToken) ?: run {
            Toast.makeText(this, getString(R.string.wgk_token_error_format), Toast.LENGTH_SHORT).show()
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
                add(R.id.list_detail_container, TunnelDetailFragment())
                setTransition(FragmentTransaction.TRANSIT_FRAGMENT_FADE)
                addToBackStack(null)
            }
        }
        return true
    }
}
