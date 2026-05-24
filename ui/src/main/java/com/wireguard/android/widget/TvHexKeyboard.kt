/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.widget

import android.content.ClipboardManager
import android.content.Context
import android.view.KeyEvent
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.core.view.isVisible
import com.google.android.material.button.MaterialButton
import com.wireguard.android.R

/**
 * D-pad hex keyboard for entering UUID tokens on Android TV.
 *
 * The raw token (32 hex chars, lowercase) is kept separately from the
 * displayed string, which is built fresh on every change as `8-4-4-4-12`
 * with a `|` cursor marker so users can see where the next character lands.
 */
class TvHexKeyboard(
    private val context: Context,
    private val onConnect: (token: String) -> Unit
) {
    val rootView: View
    private val display: TextView
    private val token = StringBuilder()
    private var cursor: Int = 0

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
        rootView.findViewById<View>(R.id.tv_key_left)
            .setOnClickListener { moveLeft() }
        rootView.findViewById<View>(R.id.tv_key_right)
            .setOnClickListener { moveRight() }
        rootView.findViewById<View>(R.id.tv_key_backspace)
            .setOnClickListener { backspace() }
        rootView.findViewById<View>(R.id.tv_key_clear)
            .setOnClickListener { clear() }
        rootView.findViewById<View>(R.id.tv_key_paste)
            .setOnClickListener { paste() }
        rootView.findViewById<View>(R.id.tv_key_connect)
            .setOnClickListener {
                val t = token.toString()
                if (t.length == TOKEN_LENGTH) onConnect(formatUuid(t))
            }
        render()
    }

    fun attachTo(parent: ViewGroup) {
        detach()
        parent.addView(
            rootView,
            ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
        )
        clear()
        // requestFocus() must run after the layout pass; calling it synchronously
        // right after addView() is a no-op on many TV devices (view not measured yet).
        val key1 = rootView.findViewById<View>(R.id.tv_key_1)
        key1.post { key1.requestFocus() }
    }

    fun detach() {
        (rootView.parent as? ViewGroup)?.removeView(rootView)
    }

    fun setVisible(visible: Boolean) {
        rootView.isVisible = visible
    }

    /**
     * Handle a physical keyboard event. Returns true if the event was consumed.
     * Call this from Activity.dispatchKeyEvent so USB/BT keyboards work alongside D-pad.
     */
    fun handleKey(event: KeyEvent): Boolean {
        if (event.action != KeyEvent.ACTION_DOWN) return false
        // Ctrl/Alt combos — don't interfere.
        if (event.isCtrlPressed || event.isAltPressed) return false

        // Backspace / Delete
        if (event.keyCode == KeyEvent.KEYCODE_DEL ||
            event.keyCode == KeyEvent.KEYCODE_FORWARD_DEL) {
            backspace(); return true
        }
        // Enter / numpad Enter → connect if complete
        if (event.keyCode == KeyEvent.KEYCODE_ENTER ||
            event.keyCode == KeyEvent.KEYCODE_NUMPAD_ENTER) {
            if (token.length == TOKEN_LENGTH) onConnect(formatUuid(token.toString()))
            return true
        }
        // Paste shortcut Ctrl+V — handled by caller (Ctrl already filtered above);
        // plain V is a hex digit, falls through to unicodeChar below.

        // Printable character: convert to unicode and check if it's a hex digit.
        val ch = event.unicodeChar.toChar()
        if (ch.isHex()) { appendChar(ch); return true }

        return false
    }

    // ── Editing operations ─────────────────────────────────────────────────────

    private fun appendChar(c: Char) {
        if (token.length >= TOKEN_LENGTH) return
        if (!c.isHex()) return
        token.insert(cursor, c.lowercaseChar())
        cursor++
        render()
    }

    private fun backspace() {
        if (cursor == 0) return
        token.deleteCharAt(cursor - 1)
        cursor--
        render()
    }

    private fun clear() {
        token.clear()
        cursor = 0
        render()
    }

    private fun moveLeft() {
        if (cursor > 0) {
            cursor--
            render()
        }
    }

    private fun moveRight() {
        if (cursor < token.length) {
            cursor++
            render()
        }
    }

    private fun paste() {
        val cm = context.getSystemService(ClipboardManager::class.java) ?: return
        val raw = cm.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString().orEmpty()
        // Accept the token with or without dashes / surrounding whitespace.
        val hex = raw.filter { it.isHex() }.lowercase()
        if (hex.length != TOKEN_LENGTH) return
        token.clear()
        token.append(hex)
        cursor = token.length
        render()
    }

    // ── Display ────────────────────────────────────────────────────────────────

    private fun render() {
        val raw = token.toString()
        if (raw.isEmpty()) {
            // Empty state: leave the field blank so the hint string ("Токен из бота") is visible.
            display.text = ""
            return
        }
        val sb = StringBuilder()
        for (i in 0..raw.length) {
            val atDash = i == 8 || i == 12 || i == 16 || i == 20
            // Only show a dash if it sits between actual characters, or at the
            // cursor when the user is parked exactly on the boundary.
            if (atDash && (i < raw.length || i == cursor)) sb.append('-')
            if (i == cursor) sb.append('|')
            if (i < raw.length) sb.append(raw[i])
        }
        display.text = sb.toString()
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private fun Char.isHex(): Boolean =
        this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

    companion object {
        private const val TOKEN_LENGTH = 32

        /** Format a raw 32-char hex string as `8-4-4-4-12`. */
        fun formatUuid(raw: String): String {
            val sb = StringBuilder()
            for ((i, c) in raw.withIndex()) {
                if (i == 8 || i == 12 || i == 16 || i == 20) sb.append('-')
                sb.append(c)
            }
            return sb.toString()
        }
    }
}
