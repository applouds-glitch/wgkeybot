/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.widget

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.view.isVisible
import com.google.android.material.button.MaterialButton
import com.wireguard.android.R

class TvHexKeyboard(
    context: android.content.Context,
    private val onConnect: (token: String) -> Unit
) {
    val rootView: View
    private val display: TextView
    private var token = StringBuilder()

    init {
        rootView = LayoutInflater.from(context)
            .inflate(R.layout.view_tv_hex_keyboard, null, false)
        display = rootView.findViewById(R.id.tv_keyboard_display)

        val hexKeys = listOf(
            R.id.tv_key_1, R.id.tv_key_2, R.id.tv_key_3, R.id.tv_key_4,
            R.id.tv_key_5, R.id.tv_key_6, R.id.tv_key_7, R.id.tv_key_8,
            R.id.tv_key_9, R.id.tv_key_0, R.id.tv_key_a, R.id.tv_key_b,
            R.id.tv_key_c, R.id.tv_key_d, R.id.tv_key_e, R.id.tv_key_f
        )
        for (keyId in hexKeys) {
            rootView.findViewById<MaterialButton>(keyId)
                .setOnClickListener { appendChar((it as MaterialButton).text.first()) }
        }
        rootView.findViewById<View>(R.id.tv_key_backspace)
            .setOnClickListener { backspace() }
        rootView.findViewById<View>(R.id.tv_key_clear)
            .setOnClickListener { clear() }
        rootView.findViewById<View>(R.id.tv_key_connect)
            .setOnClickListener {
                val t = token.toString()
                if (t.length == TOKEN_LENGTH) {
                    onConnect(formatUuid(t))
                }
            }
    }

    fun attachTo(parent: ViewGroup) {
        detach()
        // Force a full-width layout regardless of the host's default params so the
        // weighted hex keys lay out correctly inside any container.
        parent.addView(
            rootView,
            ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        )
        clear()
        rootView.findViewById<View>(R.id.tv_key_1).requestFocus()
    }

    fun detach() {
        (rootView.parent as? ViewGroup)?.removeView(rootView)
    }

    fun setVisible(visible: Boolean) {
        rootView.isVisible = visible
    }

    private fun appendChar(c: Char) {
        if (token.length >= TOKEN_LENGTH) return
        token.append(c.uppercaseChar())
        display.text = formatUuid(token.toString())
    }

    private fun backspace() {
        if (token.isNotEmpty()) {
            token.deleteCharAt(token.length - 1)
            display.text = formatUuid(token.toString())
        }
    }

    private fun clear() {
        token.clear()
        display.text = ""
    }

    companion object {
        private const val TOKEN_LENGTH = 32

        fun formatUuid(raw: String): String {
            val sb = StringBuilder()
            for ((i, c) in raw.withIndex()) {
                if (i == 8 || i == 13 || i == 18 || i == 23) sb.append('-')
                sb.append(c)
            }
            return sb.toString()
        }
    }
}
