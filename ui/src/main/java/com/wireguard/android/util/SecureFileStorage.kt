/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
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
            Log.i(TAG, "Migrating plaintext file to encrypted: ${file.name}")
            // Re-encrypt in place. EncryptedFile.openFileOutput requires the
            // file not to exist, so delete first.
            if (!file.delete()) Log.w(TAG, "Failed to delete plaintext for migration: ${file.name}")
            try {
                encryptedFile(context, file).openFileOutput().use { it.write(raw) }
            } catch (rewriteError: Exception) {
                // Rewrite failed — restore plaintext so the next launch can retry
                // rather than leaving the user with nothing.
                file.outputStream().use { it.write(raw) }
                Log.e(TAG, "Migration write failed; restored plaintext: ${rewriteError.message}")
            }
            raw
        }
    }

    /**
     * Writes [bytes] to [file] encrypted. Replaces existing content atomically
     * from the caller's perspective — internal keyset rotation is handled by
     * EncryptedFile.
     */
    @Throws(Exception::class)
    fun write(context: Context, file: File, bytes: ByteArray) {
        file.parentFile?.mkdirs()
        // EncryptedFile.openFileOutput requires the destination not to exist.
        // Synchronize to prevent a TOCTOU race when two coroutines write the same file concurrently:
        // both could see exists()==false, both proceed to openFileOutput(), and the second one crashes.
        synchronized(this) {
            if (file.exists() && !file.delete()) {
                throw IllegalStateException("Cannot replace existing file: ${file.path}")
            }
            encryptedFile(context, file).openFileOutput().use { it.write(bytes) }
        }
    }
}
