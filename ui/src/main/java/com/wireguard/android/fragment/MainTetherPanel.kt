/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.os.SystemClock
import android.view.View
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.isVisible
import androidx.fragment.app.Fragment
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.databinding.ViewWgkTetherPanelBinding
import com.wireguard.android.tether.TetherState
import com.wireguard.android.tether.TetherToggle
import com.wireguard.android.tether.messageRes
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/** Construct in Fragment.onCreate so the permission launcher survives view recreation. */
internal class MainTetherPanel(private val fragment: Fragment) {
    private val manager get() = Application.getTetherManager()
    private val tracker get() = Application.getTunnelStateTracker()
    private var binding: ViewWgkTetherPanelBinding? = null
    /** When the user switched sharing off here (elapsedRealtime), 0 when no stop is pending. */
    private val stopRequestedAt = MutableStateFlow(0L)

    /**
     * A pending stop only masks a live state for as long as a teardown can take.
     * Past that the manager did not follow through, and the switch has to come
     * back so the user can try again.
     *
     * The expiry needs a timer of its own (see [bind]); the sharing state cannot
     * be relied on to bring a render. A native stop that hangs holds the manager's
     * lock, which the stats poll needs too, so nothing is emitted at all — and an
     * Active whose counters did not move is equal to the last one, which a
     * StateFlow does not re-emit.
     */
    private val stopPending: Boolean
        get() = stopRequestedAt.value.let {
            it != 0L && SystemClock.elapsedRealtime() - it < STOP_PENDING_MAX_MS
        }
    private val toggle = TetherToggle(fragment, fragment.requireContext()) { renderCurrent() }

    fun bind(binding: ViewWgkTetherPanelBinding, owner: LifecycleOwner) {
        this.binding = binding
        binding.wgkSharingToggle.setOnClickListener {
            val enable = binding.wgkSharingToggle.isChecked
            // Recheck at the tap: the tunnel can go down before the UI collects it.
            if (!enable || tracker.uiState.value.state == TunnelState.Connected) {
                stopRequestedAt.value = if (enable) 0L else SystemClock.elapsedRealtime()
                toggle.setEnabled(enable)
            }
            // Permission prompts do not imply that a hotspot is already running.
            renderCurrent()
        }
        binding.wgkSharingDetails.setOnClickListener { openDetails() }
        binding.wgkSharingQr.setOnClickListener { openDetails() }
        renderCurrent()
        owner.lifecycleScope.launch {
            owner.repeatOnLifecycle(Lifecycle.State.STARTED) {
                // Re-armed from the request time on every start, so a view that comes
                // back with the deadline already behind it renders at once.
                launch {
                    stopRequestedAt.collectLatest { at ->
                        if (at == 0L) return@collectLatest
                        delay((at + STOP_PENDING_MAX_MS - SystemClock.elapsedRealtime()).coerceAtLeast(0L))
                        renderCurrent()
                    }
                }
                combine(
                    manager.state,
                    tracker.uiState.map { it.state == TunnelState.Connected }.distinctUntilChanged()
                ) { state, connected -> presentation(state, connected) }
                    // Byte counters and recently seen clients do not change this panel.
                    .distinctUntilChanged()
                    .collect { render(it) }
            }
        }
    }

    fun unbind() {
        binding = null
    }

    private fun renderCurrent() {
        if (binding == null) return
        render(presentation(manager.state.value, tracker.uiState.value.state == TunnelState.Connected))
    }

    private data class Presentation(
        val status: Int,
        val detail: String,
        val checked: Boolean,
        val switchable: Boolean,
        val active: Boolean,
    )

    private fun presentation(state: TetherState, connected: Boolean): Presentation {
        val active = state is TetherState.Active
        val starting = state == TetherState.Starting
        // Native teardown can drain connections before emitting Idle. Keep the
        // switch off during that interval rather than bouncing it back to ON.
        if (stopPending && (active || starting)) {
            return Presentation(
                R.string.wgk_sharing_stopping,
                fragment.getString(R.string.wgk_sharing_stopping_detail),
                checked = false, switchable = false, active = false,
            )
        }
        stopRequestedAt.value = 0L
        val failed = state is TetherState.Failed && state.reason.isFailure
        val status = when {
            active -> R.string.wgk_sharing_on
            starting -> R.string.wgk_sharing_starting
            failed -> R.string.wgk_sharing_error
            else -> R.string.wgk_sharing_off
        }
        val detail = when (state) {
            is TetherState.Active -> fragment.getString(R.string.wgk_sharing_connections, state.connections)
            is TetherState.Failed -> fragment.getString(state.reason.messageRes())
            TetherState.Starting -> fragment.getString(R.string.wgk_tether_starting_value)
            TetherState.Idle -> ""
        }
        return Presentation(status, detail, active || starting, connected || active || starting, active)
    }

    private fun render(ui: Presentation) {
        val b = binding ?: return
        b.wgkSharingSubtitle.setTextAppearance(
            if (ui.active) R.style.TextAppearance_WGKeyBot_InstrumentValue
            else R.style.TextAppearance_WGKeyBot_SupportingText
        )
        b.wgkSharingSubtitle.text = ui.detail
        b.wgkSharingSubtitle.isVisible = ui.detail.isNotEmpty()
        val detailColor = when (ui.status) {
            R.string.wgk_sharing_error -> R.color.wgk_error
            R.string.wgk_sharing_starting -> R.color.wgk_warning
            else -> R.color.wgk_on_surface_variant
        }
        b.wgkSharingSubtitle.setTextColor(ContextCompat.getColor(b.root.context, detailColor))
        val transitional = ui.status == R.string.wgk_sharing_starting ||
            ui.status == R.string.wgk_sharing_stopping || ui.status == R.string.wgk_sharing_error
        val stateDescription = when {
            transitional -> ui.detail
            ui.status == R.string.wgk_sharing_off && !ui.switchable ->
                fragment.getString(R.string.wgk_main_sharing_requires_vpn)
            else -> null
        }
        ViewCompat.setStateDescription(b.wgkSharingToggle, stateDescription)
        b.wgkSharingToggle.isChecked = ui.checked
        b.wgkSharingToggle.isEnabled = ui.switchable
        b.wgkSharingDetails.isClickable = ui.active
        b.wgkSharingDetails.isFocusable = ui.active
        // Reserve the space so the text does not jump when the hotspot comes up.
        b.wgkSharingQr.visibility = if (ui.active) View.VISIBLE else View.INVISIBLE
    }

    private fun openDetails() {
        if (stopPending || manager.state.value !is TetherState.Active || !fragment.isAdded) return
        val fm = fragment.childFragmentManager
        if (fm.isStateSaved || fm.findFragmentByTag(TAG_DETAILS) != null) return
        TetherSheet().showNow(fm, TAG_DETAILS)
    }

    private companion object {
        const val TAG_DETAILS = "main-sharing-details"
        const val STOP_PENDING_MAX_MS = 20_000L
    }
}
