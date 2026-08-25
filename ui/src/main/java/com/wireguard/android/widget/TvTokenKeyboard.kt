/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.widget

import android.content.ClipboardManager
import android.content.Context
import android.util.TypedValue
import android.view.KeyEvent
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.view.isVisible
import com.google.android.material.button.MaterialButton
import com.wireguard.android.R
import com.wireguard.android.util.TokenFormat

/**
 * D-pad keyboard for entering connection tokens on Android TV.
 *
 * The character grid is generated from [TokenFormat.KEYBOARD_CHARS] rather than
 * written out in XML, and the case key covers the rest of the token alphabet, so
 * anything [TokenFormat] accepts can be typed with a remote. The buffer holds
 * exactly what the user typed; a complete dashless UUID gets its dashes back on
 * connect (see [TokenFormat.fromKeyboard]) and is grouped `8-4-4-4-12` while it
 * is being typed.
 */
class TvTokenKeyboard(
    private val context: Context,
    private val onConnect: (token: String) -> Unit
) {
    val rootView: View
    private val display: TextView
    private val caseKey: MaterialButton
    private val connectKey: MaterialButton
    private val gridKeys = ArrayList<MaterialButton>(TokenFormat.KEYBOARD_CHARS.length)
    private val token = StringBuilder()
    private var cursor: Int = 0
    private var upperCase: Boolean = false

    init {
        rootView = LayoutInflater.from(context)
            .inflate(R.layout.view_tv_token_keyboard, null, false)
        display = rootView.findViewById(R.id.tv_keyboard_display)
        caseKey = rootView.findViewById(R.id.tv_key_case)
        connectKey = rootView.findViewById(R.id.tv_key_connect)

        buildGrid(rootView.findViewById(R.id.tv_keyboard_grid))

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
        caseKey.setOnClickListener { toggleCase() }
        connectKey.setOnClickListener { connect() }

        applyCase()
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
        val firstKey = gridKeys.firstOrNull() ?: return
        // The grid ids are generated, so the way back into it from the Telegram
        // button can only be wired once the keyboard is mounted.
        parent.rootView.findViewById<View>(R.id.wgk_bot_link_btn)?.nextFocusRightId = firstKey.id
        // requestFocus() must run after the layout pass; calling it synchronously
        // right after addView() is a no-op on many TV devices (view not measured yet).
        firstKey.post { firstKey.requestFocus() }
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
        // Enter / numpad Enter → connect if the token is complete
        if (event.keyCode == KeyEvent.KEYCODE_ENTER ||
            event.keyCode == KeyEvent.KEYCODE_NUMPAD_ENTER) {
            connect()
            return true
        }
        // Paste shortcut Ctrl+V — handled by caller (Ctrl already filtered above);
        // plain V is a token character, falls through to unicodeChar below.

        // Printable character: a physical keyboard carries its own case and can
        // reach `-`/`_`, so take whatever it produces if the token allows it.
        val ch = event.unicodeChar.toChar()
        if (TokenFormat.isTokenChar(ch)) { appendChar(ch); return true }

        return false
    }

    // ── Grid ───────────────────────────────────────────────────────────────────

    private fun buildGrid(host: LinearLayout) {
        val inflater = LayoutInflater.from(context)
        val chars = TokenFormat.KEYBOARD_CHARS
        val rowGap = TypedValue.applyDimension(
            TypedValue.COMPLEX_UNIT_DIP, GRID_ROW_GAP_DP, context.resources.displayMetrics
        ).toInt()

        var index = 0
        while (index < chars.length) {
            val row = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = rowGap }
            }
            host.addView(row)
            var column = 0
            while (column < GRID_COLUMNS && index < chars.length) {
                val char = chars[index]
                val key = inflater.inflate(R.layout.view_tv_token_key, row, false) as MaterialButton
                key.id = View.generateViewId()
                key.setOnClickListener { appendChar(cased(char)) }
                row.addView(key)
                gridKeys.add(key)
                column++
                index++
            }
        }
        wireGridFocus()
    }

    /**
     * The grid ids are generated, so D-pad focus order is wired here rather than
     * in XML: inside the grid by row/column, off its left edge back to the
     * Telegram button, and off its bottom edge into the nav row.
     */
    private fun wireGridFocus() {
        val navKeys = listOf(
            R.id.tv_key_left, R.id.tv_key_right, R.id.tv_key_backspace, R.id.tv_key_case
        )
        val lastRowStart = (gridKeys.size - 1) / GRID_COLUMNS * GRID_COLUMNS

        for ((index, key) in gridKeys.withIndex()) {
            val column = index % GRID_COLUMNS
            key.nextFocusLeftId =
                if (column == 0) R.id.wgk_bot_link_btn else gridKeys[index - 1].id
            val rightNeighbour =
                if (column < GRID_COLUMNS - 1) gridKeys.getOrNull(index + 1) else null
            key.nextFocusRightId = rightNeighbour?.id ?: key.id
            gridKeys.getOrNull(index - GRID_COLUMNS)?.let { key.nextFocusUpId = it.id }
            key.nextFocusDownId = if (index >= lastRowStart) {
                navKeys[column * navKeys.size / GRID_COLUMNS]
            } else {
                gridKeys.getOrNull(index + GRID_COLUMNS)?.id ?: key.id
            }
        }

        // …and back up from the nav row into the bottom grid row.
        for ((navIndex, navId) in navKeys.withIndex()) {
            val column = navIndex * GRID_COLUMNS / navKeys.size
            val target = gridKeys.getOrNull(lastRowStart + column) ?: gridKeys.lastOrNull()
            if (target != null) rootView.findViewById<View>(navId).nextFocusUpId = target.id
        }
    }

    // ── Editing operations ─────────────────────────────────────────────────────

    private fun appendChar(c: Char) {
        if (token.length >= TokenFormat.MAX_LENGTH) return
        if (!TokenFormat.isTokenChar(c)) return
        token.insert(cursor, c)
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
        // Accepts a bare token, a deeplink or a bot link; dashes are stripped off
        // a UUID so the display keeps grouping it, and case is left alone because
        // anything else may be case-sensitive.
        val pasted = TokenFormat.extract(raw) ?: return
        val dashless = pasted.replace("-", "")
        token.clear()
        token.append(if (TokenFormat.isRawUuidHex(dashless)) dashless else pasted)
        cursor = token.length
        render()
    }

    private fun toggleCase() {
        upperCase = !upperCase
        applyCase()
    }

    private fun connect() {
        val candidate = TokenFormat.fromKeyboard(token.toString())
        if (TokenFormat.isValid(candidate)) onConnect(candidate)
    }

    private fun cased(c: Char): Char = if (upperCase) c.uppercaseChar() else c

    // ── Display ────────────────────────────────────────────────────────────────

    private fun applyCase() {
        caseKey.text = if (upperCase) CASE_LABEL_UPPER else CASE_LABEL_LOWER
        for ((index, key) in gridKeys.withIndex()) {
            key.text = cased(TokenFormat.KEYBOARD_CHARS[index]).toString()
        }
    }

    private fun render() {
        display.text = TokenFormat.display(token.toString(), cursor)
        // A half-typed token would otherwise look like a dead Connect key.
        connectKey.isEnabled = TokenFormat.isValid(TokenFormat.fromKeyboard(token.toString()))
    }

    companion object {
        private const val GRID_COLUMNS = 6
        private const val GRID_ROW_GAP_DP = 4f
        private const val CASE_LABEL_LOWER = "abc"
        private const val CASE_LABEL_UPPER = "ABC"
    }
}
