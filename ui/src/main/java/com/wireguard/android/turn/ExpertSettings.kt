/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Expert mode: the user's overrides of what the bot's configuration says, read
 * at every connect and applied to that connect only.
 *
 * Why a store of its own and not the `.conf`: the bot reissues the config (the
 * refresh compares hashes and rewrites the file), so anything edited into the
 * file would be gone at the next refresh, silently. Kept here, an override
 * outlives every refresh and is applied on top of whatever the bot sent last —
 * the same layer `stability_mode` already lives in (TurnProxyManager).
 *
 * Every override is inert while the mode is off: switching it off is the one
 * gesture that puts everything back the way the bot issued it, without
 * clearing the values, so switching it on again finds them as they were.
 *
 * Encrypted like AuthStore, because the VK links are what they are — a join
 * link admits anyone to the call — and the phone's backup is not the place
 * for them either.
 */
class ExpertSettings private constructor(context: Context) {

    private val prefs: SharedPreferences = try {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    } catch (_: Exception) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false)
    fun setEnabled(enabled: Boolean) = prefs.edit().putBoolean(KEY_ENABLED, enabled).apply()

    /** The MTU override, or 0 for "as in the config". */
    fun mtu(): Int = prefs.getInt(KEY_MTU, 0)
    fun setMtu(mtu: Int) = prefs.edit().putInt(KEY_MTU, mtu).apply()

    /** The resolvers inside the tunnel, comma separated, or empty for "as in the config". */
    fun dns(): String = prefs.getString(KEY_DNS, "").orEmpty()
    fun setDns(servers: String) = prefs.edit().putString(KEY_DNS, servers.trim()).apply()

    /** The user's own VK call links as typed; empty means the config's links. */
    fun vkLinksText(): String = prefs.getString(KEY_VK_LINKS, "").orEmpty()
    fun setVkLinksText(text: String) = prefs.edit().putString(KEY_VK_LINKS, text.trim()).apply()

    /**
     * What the next connect applies to the config, or null while the mode is
     * off. A stored value that no longer parses (nothing on this screen writes
     * one, but the store is not the parser's) counts as "as in the config".
     */
    fun overrides(): ExpertOverrides? {
        if (!isEnabled()) return null
        val mtu = mtu().takeIf { ExpertOverrides.isValidMtu(it) }
        val dns = ExpertOverrides.parseDns(dns())?.takeIf { it.isNotEmpty() }
        return ExpertOverrides(mtu = mtu, dns = dns)
    }

    /** The join hashes that stand in for the config's links at the next connect, or null for the config's. */
    fun vkLinksForStart(): List<String>? {
        if (!isEnabled()) return null
        return VkLinks.parse(vkLinksText()).hashes.takeIf { it.isNotEmpty() }
    }

    companion object {
        private const val PREFS_NAME = "expert_settings"
        private const val KEY_ENABLED = "enabled"
        private const val KEY_MTU = "mtu"
        private const val KEY_DNS = "dns"
        private const val KEY_VK_LINKS = "vk_links"

        @Volatile private var instance: ExpertSettings? = null

        fun getInstance(context: Context): ExpertSettings =
            instance ?: synchronized(this) {
                instance ?: ExpertSettings(context.applicationContext).also { instance = it }
            }
    }
}
