/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.content.Intent
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatDelegate
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.commit
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wireguard.android.R
import com.wireguard.android.fragment.TunnelListFragment
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.util.ApiClient
import com.wireguard.android.util.AuthStore
import com.wireguard.config.Config
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class TvMainActivity : AppCompatActivity() {
    private var selectedTunnel: ObservableTunnel? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        if (AppCompatDelegate.getDefaultNightMode() != AppCompatDelegate.MODE_NIGHT_YES) {
            AppCompatDelegate.setDefaultNightMode(AppCompatDelegate.MODE_NIGHT_YES)
        }
        super.onCreate(savedInstanceState)

        setContentView(R.layout.tv_main_activity)

        if (savedInstanceState == null) {
            supportFragmentManager.commit {
                replace(R.id.tv_fragment_container, TunnelListFragment(), "LIST")
            }
        }
        handleDeeplinkIntent(intent)
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
                Toast.makeText(this@TvMainActivity, getString(R.string.wgk_auth_error_format, e.message ?: ""), Toast.LENGTH_LONG).show()
            }
        }
    }
}
