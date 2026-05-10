package com.wireguard.android.util

import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

object ConfigFetcher {

    private const val BASE_URL = "https://key.shadowgate.online/api/config/"

    @Throws(Exception::class)
    fun fetch(token: String): String {
        val url = URL("$BASE_URL$token")
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 15_000
            readTimeout = 15_000
            setRequestProperty("Accept", "application/json")
        }
        return try {
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream
                         else connection.errorStream ?: throw IllegalStateException("HTTP $code")
            val body = BufferedReader(InputStreamReader(stream)).use { it.readText() }
            if (code !in 200..299) throw IllegalStateException("HTTP $code: $body")
            val json = JSONObject(body)
            if (!json.getBoolean("ok")) {
                throw IllegalStateException("Server error: ${json.optString("error")}")
            }
            json.getString("config").trim()
        } finally {
            connection.disconnect()
        }
    }
}
