/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.widget

import android.content.Context
import androidx.databinding.ObservableList
import com.wireguard.android.Application
import com.wireguard.android.model.ObservableTunnel
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch

/**
 * Re-renders the home-screen widget on two signals:
 *  1. The shared [TunnelStateTracker] emits a new TunnelState (Connecting / Handshake /
 *     Connected / Reconnecting / Failed / Disconnected).
 *  2. The tunnel list changes — needed because a freshly imported tunnel often
 *     starts in Disconnected and the tracker would not emit a different state.
 */
class WidgetStateObserver(private val context: Context) {

    private val listCallback = object : ObservableList.OnListChangedCallback<ObservableList<ObservableTunnel>>() {
        override fun onChanged(s: ObservableList<ObservableTunnel>) = refresh()
        override fun onItemRangeChanged(s: ObservableList<ObservableTunnel>, p: Int, c: Int) = refresh()
        override fun onItemRangeInserted(s: ObservableList<ObservableTunnel>, p: Int, c: Int) = refresh()
        override fun onItemRangeMoved(s: ObservableList<ObservableTunnel>, f: Int, t: Int, c: Int) = refresh()
        override fun onItemRangeRemoved(s: ObservableList<ObservableTunnel>, p: Int, c: Int) = refresh()
        private fun refresh() = TunnelToggleAppWidgetProvider.refreshAll(context)
    }

    fun attach() {
        applicationScope.launch {
            Application.getTunnelManager().getTunnels().addOnListChangedCallback(listCallback)
            TunnelToggleAppWidgetProvider.refreshAll(context)
        }
        applicationScope.launch {
            Application.getTunnelStateTracker().uiState
                .map { it.state }
                .distinctUntilChanged()
                .onEach { TunnelToggleAppWidgetProvider.refreshAll(context) }
                .collect { }
        }
    }
}
