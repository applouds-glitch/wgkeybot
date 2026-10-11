/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.activity

import android.content.DialogInterface
import android.text.InputType
import android.view.LayoutInflater
import androidx.annotation.StringRes
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.wireguard.android.R

/**
 * One text field under a title. OK is bound after the dialog is shown rather
 * than in the builder, so a rejected value keeps the dialog open with the
 * error under the field instead of closing on it.
 *
 * Returns the dialog it showed: a dialog left showing through a recreation is a
 * leaked window and a leaked context, and its save lambda would write into a
 * dead binding, so the caller keeps the reference and takes it down in
 * onDestroy.
 */
internal fun AppCompatActivity.showTextInputDialog(
    @StringRes title: Int,
    @StringRes hint: Int,
    current: String,
    inputType: Int = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS,
    validate: (String) -> Boolean,
    @StringRes invalid: Int,
    onSave: (String) -> Unit,
): AlertDialog {
    val view = LayoutInflater.from(this).inflate(R.layout.wgk_text_input_dialog, null)
    val layout = view.findViewById<TextInputLayout>(R.id.wgk_input_layout)
    val field = view.findViewById<TextInputEditText>(R.id.wgk_input_text)
    layout.hint = getString(hint)
    field.inputType = inputType
    field.setText(current)
    field.setSelection(current.length)
    val prompt = MaterialAlertDialogBuilder(this)
        .setTitle(title)
        .setView(view)
        .setPositiveButton(android.R.string.ok, null)
        .setNegativeButton(android.R.string.cancel, null)
        .create()
    prompt.setOnShowListener {
        prompt.getButton(DialogInterface.BUTTON_POSITIVE).setOnClickListener {
            val value = field.text?.toString()?.trim().orEmpty()
            if (!validate(value)) {
                layout.error = getString(invalid)
                return@setOnClickListener
            }
            prompt.dismiss()
            onSave(value)
        }
    }
    prompt.show()
    return prompt
}
