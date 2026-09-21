package com.wireguard.android.util

import com.wireguard.config.Config
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.IOException
import java.security.MessageDigest

/** Resolve and validate everything before replacing a tunnel or its auth state. */
object ConnectionImport {
    class Prepared(val response: ApiClient.InitResponse, val config: Config)
    class FetchException(cause: IOException) : Exception("Connection fetch failed", cause)

    /** Finish local persistence even if the importing Activity is destroyed.
     * A failed write never publishes the new session/hash. Reconnect and UI work
     * belong after this returns: their failure cannot undo a committed import.
     */
    suspend fun <T> apply(
        prepared: Prepared,
        persistConfig: suspend (Config) -> T,
        commitSession: (Prepared) -> Unit,
    ): T {
        val result = withContext(NonCancellable) {
            val stored = persistConfig(prepared.config)
            commitSession(prepared)
            stored
        }
        // withContext(NonCancellable) keeps the same dispatcher; explicitly stop
        // the cancelled caller before it touches a detached Activity/Fragment.
        currentCoroutineContext().ensureActive()
        return result
    }

    fun prepare(raw: String): Prepared {
        val input = ConnectionLink.parse(raw)
        val response = when (input) {
            is ConnectionLink.Input.Token -> try {
                ApiClient.init(input.value)
            } catch (e: IOException) {
                throw FetchException(e)
            }
            is ConnectionLink.Input.Embedded -> ApiClient.InitResponse(
                input.accessToken, input.subscriptionExpiresAt, input.config, null, null,
            )
        }
        val config = try {
            Config.parse(response.config.byteInputStream()).also { require(it.peers.isNotEmpty()) }
        } catch (_: Exception) {
            throw ConnectionLink.InvalidLinkException(
                if (input is ConnectionLink.Input.Token) ConnectionLink.Failure.INVALID_SERVER_CONFIG
                else ConnectionLink.Failure.INVALID_CONFIG
            )
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
