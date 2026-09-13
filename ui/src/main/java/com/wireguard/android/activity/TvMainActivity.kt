/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.content.Intent
import android.os.Bundle
import android.view.KeyEvent
import android.widget.Toast
import androidx.fragment.app.FragmentManager
import androidx.fragment.app.commit
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.wireguard.android.R
import com.wireguard.android.fragment.TunnelListFragment
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.util.ConnectionImport
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class TvMainActivity : AppCompatActivity() {
    private var selectedTunnel: ObservableTunnel? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContentView(R.layout.tv_main_activity)

        if (savedInstanceState == null) {
            supportFragmentManager.commit {
                replace(R.id.tv_fragment_container, TunnelListFragment(), "LIST")
            }
        }
        handleDeeplinkIntent(intent)
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        val listFragment = supportFragmentManager.fragments
            .filterIsInstance<com.wireguard.android.fragment.TunnelListFragment>()
            .firstOrNull()
        if (listFragment?.dispatchKeyEvent(event) == true) return true
        return super.dispatchKeyEvent(event)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleDeeplinkIntent(intent)
    }

    private fun handleDeeplinkIntent(intent: Intent) {
        val uri = intent.data ?: return
        if (uri.scheme != "wgkeybot" || uri.host != "config") return

        val connectionInput = uri.toString()
        // Consume before importing, including offline links, so rotation cannot replay.
        intent.data = null

        lifecycleScope.launch {
            try {
                val prepared = withContext(Dispatchers.IO) {
                    ConnectionImport.prepare(connectionInput)
                }
                if (supportFragmentManager.backStackEntryCount > 0) {
                    supportFragmentManager.popBackStackImmediate(null, FragmentManager.POP_BACK_STACK_INCLUSIVE)
                    selectedTunnel = null
                }
                // TV installs the list asynchronously on cold start.
                supportFragmentManager.executePendingTransactions()
                val listFragment = supportFragmentManager.fragments
                    .filterIsInstance<TunnelListFragment>()
                    .firstOrNull() ?: throw IllegalStateException()
                listFragment.applyConnection(prepared)
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Toast.makeText(this@TvMainActivity, R.string.wgk_connection_import_error, Toast.LENGTH_LONG).show()
            }
        }
    }
}
