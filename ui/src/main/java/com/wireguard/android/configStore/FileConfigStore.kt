/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.configStore

import android.content.Context
import android.util.Log
import com.wireguard.android.R
import com.wireguard.android.util.SecureFileStorage
import com.wireguard.config.BadConfigException
import com.wireguard.config.Config
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.nio.charset.StandardCharsets

/**
 * Configuration store that uses a `wg-quick`-style file for each configured tunnel.
 *
 * Files are written via [SecureFileStorage] so the WireGuard PrivateKey is
 * encrypted at rest with a key bound to the Android Keystore. The Go backend
 * receives parsed [Config] objects in-memory, never the file path, so this is
 * transparent to the rest of the stack.
 */
class FileConfigStore(private val context: Context) : ConfigStore {
    @Throws(IOException::class)
    override fun create(name: String, config: Config): Config {
        Log.d(TAG, "Creating configuration for tunnel $name")
        val file = fileFor(name)
        if (file.exists())
            throw IOException(context.getString(R.string.config_file_exists_error, file.name))
        try {
            SecureFileStorage.write(context, file, config.toWgQuickString().toByteArray(StandardCharsets.UTF_8))
        } catch (e: Exception) {
            throw IOException("Failed to write encrypted config for $name", e)
        }
        return config
    }

    @Throws(IOException::class)
    override fun delete(name: String) {
        Log.d(TAG, "Deleting configuration for tunnel $name")
        val file = fileFor(name)
        if (!file.delete())
            throw IOException(context.getString(R.string.config_delete_error, file.name))
    }

    override fun enumerate(): Set<String> {
        return context.fileList()
            .filter { it.endsWith(".conf") }
            .map { it.substring(0, it.length - ".conf".length) }
            .toSet()
    }

    private fun fileFor(name: String): File {
        return File(context.filesDir, "$name.conf")
    }

    @Throws(BadConfigException::class, IOException::class)
    override fun load(name: String): Config {
        val file = fileFor(name)
        if (!file.isFile) throw FileNotFoundException(file.path)
        val bytes = try {
            SecureFileStorage.read(context, file)
        } catch (e: Exception) {
            throw IOException("Failed to read encrypted config for $name", e)
        }
        return ByteArrayInputStream(bytes).use { Config.parse(it) }
    }

    @Throws(IOException::class)
    override fun rename(name: String, replacement: String) {
        Log.d(TAG, "Renaming configuration for tunnel $name to $replacement")
        val file = fileFor(name)
        val replacementFile = fileFor(replacement)
        if (replacementFile.exists())
            throw IOException(context.getString(R.string.config_exists_error, replacement))
        // EncryptedFile's keyset is keyed by file path, so a renameTo would
        // orphan the keyset. Round-trip through SecureFileStorage instead.
        val bytes = try {
            SecureFileStorage.read(context, file)
        } catch (e: Exception) {
            throw IOException(context.getString(R.string.config_rename_error, file.name), e)
        }
        try {
            SecureFileStorage.write(context, replacementFile, bytes)
        } catch (e: Exception) {
            throw IOException(context.getString(R.string.config_rename_error, file.name), e)
        }
        if (!file.delete())
            Log.w(TAG, "Failed to delete original config after rename: ${file.name}")
    }

    @Throws(IOException::class)
    override fun save(name: String, config: Config): Config {
        Log.d(TAG, "Saving configuration for tunnel $name")
        val file = fileFor(name)
        if (!file.isFile)
            throw FileNotFoundException(context.getString(R.string.config_not_found_error, file.name))
        try {
            SecureFileStorage.write(context, file, config.toWgQuickString().toByteArray(StandardCharsets.UTF_8))
        } catch (e: Exception) {
            throw IOException(context.getString(R.string.config_save_error, file.name, e.message), e)
        }
        return config
    }

    companion object {
        private const val TAG = "WireGuard/FileConfigStore"
    }
}
