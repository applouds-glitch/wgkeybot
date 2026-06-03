/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.fragment

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.os.bundleOf
import androidx.fragment.app.DialogFragment
import androidx.fragment.app.setFragmentResult
import com.wireguard.android.R

/**
 * One-time first-launch wizard that recommends configuring split tunneling and lets the user
 * pick one of the two modes (include / exclude) or postpone. It only reports the user's choice
 * via [setFragmentResult]; the host fragment opens the app picker / shows the hint.
 */
class SplitTunnelWizardFragment : DialogFragment() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setStyle(STYLE_NORMAL, R.style.Theme_WGKeyBot_FullScreen)
    }

    override fun onStart() {
        super.onStart()
        dialog?.window?.setLayout(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        val root = inflater.inflate(R.layout.split_tunnel_wizard_fragment, container, false)
        root.findViewById<View>(R.id.wizard_card_include).setOnClickListener { deliver(MODE_INCLUDE) }
        root.findViewById<View>(R.id.wizard_card_exclude).setOnClickListener { deliver(MODE_EXCLUDE) }
        root.findViewById<View>(R.id.wizard_btn_later).setOnClickListener { deliver(MODE_LATER) }
        return root
    }

    private fun deliver(mode: String) {
        setFragmentResult(REQUEST_WIZARD, bundleOf(KEY_MODE to mode))
        dismissAllowingStateLoss()
    }

    companion object {
        const val REQUEST_WIZARD = "split_wizard_request"
        const val KEY_MODE = "mode"
        const val MODE_INCLUDE = "include"
        const val MODE_EXCLUDE = "exclude"
        const val MODE_LATER = "later"
    }
}
