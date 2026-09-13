package com.wireguard.android.util

import com.wireguard.config.Config
import java.security.MessageDigest

/** Resolve and validate everything before replacing a tunnel or its auth state. */
object ConnectionImport {
    class Prepared(val response: ApiClient.InitResponse, val config: Config)

    fun prepare(raw: String): Prepared {
        val input = ConnectionLink.parse(raw)
        val response = when (input) {
            is ConnectionLink.Input.Token -> ApiClient.init(input.value)
            is ConnectionLink.Input.Embedded -> ApiClient.InitResponse(
                input.accessToken, input.subscriptionExpiresAt, input.config, null, null,
            )
        }
        val config = try {
            Config.parse(response.config.byteInputStream()).also { require(it.peers.isNotEmpty()) }
        } catch (_: Exception) {
            throw ConnectionLink.InvalidLinkException()
        }
        return Prepared(response, config)
    }

    fun saveSession(auth: AuthStore, prepared: Prepared) {
        val response = prepared.response
        val hash = MessageDigest.getInstance("SHA-256")
            .digest(response.config.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        auth.saveConnection(response.accessToken, response.subscriptionExpiresAt, hash)
    }
}
