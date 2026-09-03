/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.graphics.Bitmap
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.core.content.ContextCompat
import androidx.core.view.isVisible
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.bottomsheet.BottomSheetDialogFragment
import com.google.zxing.BarcodeFormat
import com.journeyapps.barcodescanner.BarcodeEncoder
import com.wireguard.android.Application
import com.wireguard.android.R
import com.wireguard.android.databinding.TetherSheetBinding
import com.wireguard.android.tether.TetherRoutingStatus
import com.wireguard.android.tether.TetherState
import com.wireguard.android.tether.formatTetherBytes
import kotlinx.coroutines.launch

private const val TAG = "WireGuard/TetherSheet"

/**
 * Everything the user needs to hand the phone's connection to another device:
 * the access point credentials (as a QR the camera understands), the proxy
 * address, and a plain warning that a client which ignores the proxy gets no
 * internet at all.
 *
 * It reports a live access point and never switches one on: the switch belongs
 * to the settings row that opens this sheet, and that row only exists while
 * sharing is up.
 */
class TetherSheet : BottomSheetDialogFragment() {

    private var binding: TetherSheetBinding? = null

    // What the QR currently on screen encodes, and the bitmap for it; see showWifiQr.
    private var qrPayload: String? = null
    private var qrBitmap: Bitmap? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val b = TetherSheetBinding.inflate(inflater, container, false)
        binding = b

        b.wgkTetherSsidRow.wgkCopyLabel.setText(R.string.wgk_tether_ssid_label)
        b.wgkTetherPassRow.wgkCopyLabel.setText(R.string.wgk_tether_pass_label)
        b.wgkTetherProxyRow.wgkCopyLabel.setText(R.string.wgk_tether_proxy_label)
        b.wgkTetherPacRow.wgkCopyLabel.setText(R.string.wgk_tether_pac_label)

        return b.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                Application.getTetherManager().state.collect { render(it) }
            }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        binding = null
    }

    private fun render(state: TetherState) {
        val b = binding ?: return
        // The sheet is a live access point's credentials and nothing else, so the
        // moment sharing stops it has nothing left to show — switched off on the
        // settings screen, taken down with the tunnel, or stopped from the
        // notification. Left standing it shrinks to a stub of a sheet instead of
        // going away; the reason, when there is one, is reported by the row that
        // opened this.
        if (state !is TetherState.Active) {
            dismissAllowingStateLoss()
            return
        }

        val proxy = "${state.host}:${state.port}"
        b.wgkTetherSsidRow.wgkCopyValue.text = state.ssid
        b.wgkTetherPassRow.wgkCopyValue.text = state.passphrase
        b.wgkTetherProxyRow.wgkCopyValue.text = proxy
        b.wgkTetherPacRow.wgkCopyValue.text = "http://$proxy/pac"

        bindCopy(b.wgkTetherSsidRow.wgkCopyBtn, state.ssid)
        bindCopy(b.wgkTetherPassRow.wgkCopyBtn, state.passphrase)
        bindCopy(b.wgkTetherProxyRow.wgkCopyBtn, proxy)
        bindCopy(b.wgkTetherPacRow.wgkCopyBtn, "http://$proxy/pac")

        b.wgkTetherCounters.text = getString(
            R.string.wgk_tether_counters,
            state.clients,
            state.connections,
            formatTetherBytes(state.bytesUp),
            formatTetherBytes(state.bytesDown)
        )
        showWifiQr(state.ssid, state.passphrase)
        showRoutingNote(state.routing)
    }

    /**
     * Split routing contradicts the "nothing slips past the tunnel" line right
     * above it, so while it is on the sheet says so in the same colour; when it
     * was asked for but no rules could be had, that is said too, quietly.
     */
    private fun showRoutingNote(routing: TetherRoutingStatus) {
        val b = binding ?: return
        b.wgkTetherRoutingNote.isVisible = routing != TetherRoutingStatus.OFF
        when (routing) {
            TetherRoutingStatus.ON -> {
                b.wgkTetherRoutingNote.setText(R.string.wgk_tether_routing_note_on)
                b.wgkTetherRoutingNote.setTextColor(ContextCompat.getColor(requireContext(), R.color.wgk_warning))
            }
            TetherRoutingStatus.UNAVAILABLE -> {
                b.wgkTetherRoutingNote.setText(R.string.wgk_tether_routing_note_unavailable)
                b.wgkTetherRoutingNote.setTextColor(ContextCompat.getColor(requireContext(), R.color.wgk_on_surface_variant))
            }
            TetherRoutingStatus.OFF -> Unit
        }
    }

    /**
     * Standard Wi-Fi credential QR: both the Android and the iOS camera join a
     * network straight from it, which spares the user typing a generated password.
     *
     * Cached by payload, and that is not micro-optimisation: render() runs on
     * every counter tick, so this used to encode a 480×480 bitmap on the main
     * thread every couple of seconds for a code whose content cannot change
     * within a session. The bitmap is kept rather than just the payload so that a
     * re-created view (the sheet reopening) re-applies it instead of re-encoding.
     */
    private fun showWifiQr(ssid: String, passphrase: String) {
        val b = binding ?: return
        val payload = "WIFI:S:${escapeQr(ssid)};T:WPA;P:${escapeQr(passphrase)};;"
        if (payload == qrPayload && b.wgkTetherQr.drawable != null) return

        val bitmap = qrBitmap.takeIf { payload == qrPayload } ?: try {
            BarcodeEncoder().encodeBitmap(payload, BarcodeFormat.QR_CODE, 480, 480)
        } catch (e: Exception) {
            Log.w(TAG, "cannot encode the Wi-Fi QR", e)
            null
        }
        if (bitmap == null) {
            b.wgkTetherQr.isVisible = false
            return
        }
        qrPayload = payload
        qrBitmap = bitmap
        b.wgkTetherQr.setImageBitmap(bitmap)
        b.wgkTetherQr.isVisible = true
    }

    // The Wi-Fi QR grammar uses \, ; , and : as separators, so they are escaped
    // with a backslash inside SSIDs and passwords.
    private fun escapeQr(value: String): String =
        value.replace("\\", "\\\\").replace(";", "\\;").replace(",", "\\,").replace(":", "\\:")

    private fun bindCopy(button: View, value: String) {
        button.setOnClickListener {
            val cm = requireContext().getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("wgkeybot", value))
            Toast.makeText(requireContext(), R.string.wgk_tether_copied, Toast.LENGTH_SHORT).show()
        }
    }
}
