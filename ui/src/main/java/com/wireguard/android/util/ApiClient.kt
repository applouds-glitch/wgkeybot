package com.wireguard.android.util

import android.net.Uri
import com.wireguard.android.BuildConfig
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

object ApiClient {

    private const val BASE_URL = "https://key.shadowgate.online"

    // ── Exceptions ─────────────────────────────────────────────────────────────

    class UnauthorizedException : Exception("Unauthorized")

    class InvalidTokenException : Exception("Invalid token")

    class UpgradeRequiredException(val downloadUrl: String?) : Exception("Upgrade required")

    // ── Response models ────────────────────────────────────────────────────────

    data class InitResponse(
        val accessToken: String,
        val subscriptionExpiresAt: String,
        val config: String,
        val latestVersion: String?,
        val downloadUrl: String?,
    )

    data class ConfigResponse(
        val subscriptionExpiresAt: String,
        val config: String,
        val latestVersion: String?,
        val downloadUrl: String?,
    )

    // ── API calls ──────────────────────────────────────────────────────────────

    /**
     * The token lands in the request path, so it is checked here as well as at
     * every entry point: a token that slipped through unvalidated must not be
     * able to reshape the URL. [Uri.encode] is belt-and-braces on top of that.
     */
    @Throws(Exception::class)
    fun init(oneTimeToken: String): InitResponse {
        if (!TokenFormat.isValid(oneTimeToken)) throw InvalidTokenException()
        val json = request(
            "$BASE_URL/api/v1/init/${Uri.encode(oneTimeToken, "")}",
            accessToken = null,
        )
        return InitResponse(
            accessToken = json.getString("access_token"),
            subscriptionExpiresAt = json.getString("subscription_expires_at"),
            config = json.getString("config").trim(),
            latestVersion = json.optString("latest_version").takeIf { it.isNotEmpty() },
            downloadUrl = json.optString("download_url").takeIf { it.isNotEmpty() },
        )
    }

    @Throws(Exception::class)
    fun getConfig(accessToken: String): ConfigResponse {
        val json = request("$BASE_URL/api/v1/config", accessToken = accessToken)
        return ConfigResponse(
            subscriptionExpiresAt = json.getString("subscription_expires_at"),
            config = json.getString("config").trim(),
            latestVersion = json.optString("latest_version").takeIf { it.isNotEmpty() },
            downloadUrl = json.optString("download_url").takeIf { it.isNotEmpty() },
        )
    }

    // ── HTTP ───────────────────────────────────────────────────────────────────

    private fun request(urlStr: String, accessToken: String?): JSONObject {
        val connection = (URL(urlStr).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 15_000
            readTimeout = 15_000
            setRequestProperty("Accept", "application/json")
            setRequestProperty("X-App-Version", BuildConfig.VERSION_NAME.substringBefore("-"))
            if (accessToken != null) setRequestProperty("Authorization", "Bearer $accessToken")
        }
        return try {
            val code = connection.responseCode
            when (code) {
                401 -> throw UnauthorizedException()
                426 -> {
                    val body = connection.errorStream
                        ?.let { BufferedReader(InputStreamReader(it)).readText() } ?: ""
                    val url = runCatching { JSONObject(body).optString("download_url") }
                        .getOrNull()?.takeIf { it.isNotEmpty() }
                    throw UpgradeRequiredException(url)
                }
                in 200..299 -> {
                    val body = BufferedReader(InputStreamReader(connection.inputStream)).use { it.readText() }
                    JSONObject(body)
                }
                else -> {
                    val body = connection.errorStream
                        ?.let { BufferedReader(InputStreamReader(it)).readText() } ?: "HTTP $code"
                    throw IllegalStateException("HTTP $code: $body")
                }
            }
        } finally {
            connection.disconnect()
        }
    }
}
