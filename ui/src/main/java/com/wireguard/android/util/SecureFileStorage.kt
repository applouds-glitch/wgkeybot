/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import com.wireguard.config.Config
import org.json.JSONObject
import java.io.File
import java.io.FileNotFoundException

/**
 * On-disk encryption helper for files containing tunnel secrets
 * (WireGuard PrivateKey, TURN wrap-key, etc.).
 *
 * Backed by AndroidX [EncryptedFile] (AES-256 GCM HKDF, per-file keyset)
 * with the symmetric master key in the Android Keystore — so even on rooted
 * devices the file contents are useless without the device-bound key.
 *
 * [read] transparently migrates legacy plaintext files: if decryption fails
 * but the bytes parse as a plaintext file from the previous app version, it
 * re-encrypts them in place and returns the cleartext.
 */
object SecureFileStorage {

    private const val TAG = "WireGuard/SecureFileStorage"

    @Volatile private var cachedMasterKey: MasterKey? = null

    private fun masterKey(context: Context): MasterKey =
        cachedMasterKey ?: synchronized(this) {
            cachedMasterKey ?: MasterKey.Builder(context.applicationContext)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
                .also { cachedMasterKey = it }
        }

    private fun encryptedFile(context: Context, file: File): EncryptedFile =
        EncryptedFile.Builder(
            context.applicationContext,
            file,
            masterKey(context),
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build()

    /**
     * Reads [file]. Returns decrypted bytes if the file was written by [write];
     * if the file is plaintext (legacy / migration path), reads it raw and
     * re-encrypts it before returning. Throws [FileNotFoundException] if the
     * file doesn't exist.
     */
    @Throws(Exception::class)
    @Synchronized
    fun read(context: Context, file: File): ByteArray {
        if (!file.isFile) throw FileNotFoundException(file.path)
        return try {
            encryptedFile(context, file).openFileInput().use { it.readBytes() }
        } catch (cryptoError: Exception) {
            // Either legacy plaintext or a corrupted keyset. Read raw bytes —
            // if that succeeds AND looks like usable content, re-encrypt and
            // return. If raw read also fails, surface the original error.
            val raw = try {
                file.inputStream().use { it.readBytes() }
            } catch (_: Exception) {
                throw cryptoError
            }
            // A failed decryption is not proof of legacy plaintext. Never replace
            // damaged ciphertext (or a file whose key is unavailable) with another
            // encrypted copy of those bytes.
            if (!isLegacyPlaintext(file, raw)) throw cryptoError
            Log.i(TAG, "Migrating plaintext file to encrypted: ${file.name}")
            try {
                write(context, file, raw)
            } catch (rewriteError: Exception) {
                // Atomic replacement kept the original legacy file for a retry.
                Log.e(TAG, "Migration write failed; original file preserved", rewriteError)
            }
            raw
        }
    }

    internal fun isLegacyPlaintext(file: File, bytes: ByteArray): Boolean = runCatching {
        when {
            file.name.endsWith(".conf") -> Config.parse(bytes.inputStream())
            file.name.endsWith(".turn.json") -> JSONObject(bytes.toString(Charsets.UTF_8))
            else -> error("Unknown legacy file type")
        }
    }.isSuccess

    /**
     * Writes [bytes] to [file] encrypted. Replaces existing content atomically
     * with a fully written and synced ciphertext. The staging file keeps the
     * destination's basename so EncryptedFile can decrypt it after the rename.
     */
    @Throws(Exception::class)
    @Synchronized
    fun write(context: Context, file: File, bytes: ByteArray) {
        AtomicFileReplacement.write(file) { staged ->
            encryptedFile(context, staged).openFileOutput().use { it.write(bytes) }
        }
    }
}
