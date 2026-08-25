package com.wireguard.android.util

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.time.Instant

class AuthStore private constructor(context: Context) {

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

    fun getAccessToken(): String? = prefs.getString(KEY_ACCESS_TOKEN, null)

    fun saveAccessToken(token: String) =
        prefs.edit().putString(KEY_ACCESS_TOKEN, token).apply()

    fun getSubscriptionExpiresAt(): String? = prefs.getString(KEY_EXPIRES_AT, null)

    fun saveSubscriptionExpiresAt(date: String) =
        prefs.edit().putString(KEY_EXPIRES_AT, date).apply()

    fun hasAuth(): Boolean = getAccessToken() != null

    fun isSubscriptionExpired(): Boolean {
        val expiresAt = getSubscriptionExpiresAt() ?: return false
        return try {
            Instant.parse(expiresAt).isBefore(Instant.now())
        } catch (_: Exception) {
            false
        }
    }

    fun isAutoRefreshEnabled(): Boolean = prefs.getBoolean(KEY_AUTO_REFRESH, true)
    fun setAutoRefreshEnabled(enabled: Boolean) = prefs.edit().putBoolean(KEY_AUTO_REFRESH, enabled).apply()

    fun getLastRefreshTime(): Long = prefs.getLong(KEY_LAST_REFRESH, 0L)
    fun saveLastRefreshTime() = prefs.edit().putLong(KEY_LAST_REFRESH, System.currentTimeMillis()).apply()

    /** SHA-256 of the last applied server config; used to skip needless reconnects. */
    fun getLastConfigHash(): String? = prefs.getString(KEY_LAST_CONFIG_HASH, null)
    fun saveLastConfigHash(hash: String) = prefs.edit().putString(KEY_LAST_CONFIG_HASH, hash).apply()

    /** "system" | "light" | "dark" */
    fun getThemeMode(): String = prefs.getString(KEY_THEME, "dark") ?: "dark"
    fun setThemeMode(mode: String) = prefs.edit().putString(KEY_THEME, mode).apply()

    /** One-time first-launch split-tunneling wizard. */
    fun isSplitWizardShown(): Boolean = prefs.getBoolean(KEY_SPLIT_WIZARD_SHOWN, false)
    fun setSplitWizardShown() = prefs.edit().putBoolean(KEY_SPLIT_WIZARD_SHOWN, true).apply()

    /**
     * Whether the battery-optimisation exemption has already been asked for. The
     * request opens a system dialog, and it used to be fired from every single
     * MainActivity.onCreate until it was granted — a modal over the first frame,
     * on every cold start, for a user who had already said no.
     */
    fun isBatteryPromptShown(): Boolean = prefs.getBoolean(KEY_BATTERY_PROMPT_SHOWN, false)
    fun setBatteryPromptShown() = prefs.edit().putBoolean(KEY_BATTERY_PROMPT_SHOWN, true).apply()

    fun clear() = prefs.edit().clear().apply()

    companion object {
        private const val PREFS_NAME = "auth_store"
        private const val KEY_ACCESS_TOKEN = "access_token"
        private const val KEY_EXPIRES_AT = "subscription_expires_at"
        private const val KEY_AUTO_REFRESH = "auto_refresh_enabled"
        private const val KEY_LAST_REFRESH = "last_refresh_time"
        private const val KEY_LAST_CONFIG_HASH = "last_config_hash"
        private const val KEY_THEME = "theme_mode"
        private const val KEY_SPLIT_WIZARD_SHOWN = "split_wizard_shown"
        private const val KEY_BATTERY_PROMPT_SHOWN = "battery_prompt_shown"

        @Volatile private var instance: AuthStore? = null

        fun getInstance(context: Context): AuthStore =
            instance ?: synchronized(this) {
                instance ?: AuthStore(context.applicationContext).also { instance = it }
            }
    }
}
