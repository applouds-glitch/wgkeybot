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

    fun clear() = prefs.edit().clear().apply()

    companion object {
        private const val PREFS_NAME = "auth_store"
        private const val KEY_ACCESS_TOKEN = "access_token"
        private const val KEY_EXPIRES_AT = "subscription_expires_at"

        @Volatile private var instance: AuthStore? = null

        fun getInstance(context: Context): AuthStore =
            instance ?: synchronized(this) {
                instance ?: AuthStore(context.applicationContext).also { instance = it }
            }
    }
}
