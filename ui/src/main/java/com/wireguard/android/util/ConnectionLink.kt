package com.wireguard.android.util

import org.json.JSONObject
import org.json.JSONTokener
import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.URLDecoder
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.time.Instant
import java.util.Base64
import java.util.zip.Inflater

/** Versioned offline bootstrap. Base64 and zlib are encoding, not encryption. */
object ConnectionLink {
    const val MAX_LINK_LENGTH = 32_768
    const val MAX_PAYLOAD_BYTES = 65_536

    enum class Failure {
        EMPTY, INVALID_FORMAT, MISSING_TOKEN, INVALID_DATA, UNSUPPORTED_VERSION,
        INVALID_CONFIG, INVALID_SERVER_CONFIG,
    }

    // Keep parser details out of the exception: they can contain private keys.
    class InvalidLinkException(val reason: Failure = Failure.INVALID_FORMAT) : Exception("Invalid connection link")

    sealed interface Input {
        class Token(val value: String) : Input
        class Embedded(
            val accessToken: String,
            val subscriptionExpiresAt: String,
            val config: String,
        ) : Input
    }

    /** Keep the whole link when pasting: extracting only token loses offline data. */
    fun extractInput(raw: String): String? {
        if (raw.length > MAX_LINK_LENGTH) return null
        val normalized = TokenFormat.normalize(raw)
        return if (normalized.startsWith("wgkeybot://")) normalized
        else TokenFormat.extract(raw)
    }

    fun parse(raw: String): Input {
        try {
            require(raw.length <= MAX_LINK_LENGTH)
            if (TokenFormat.normalize(raw).isEmpty()) throw InvalidLinkException(Failure.EMPTY)
            val text = extractInput(raw) ?: throw InvalidLinkException()
            if (!text.startsWith("wgkeybot://")) return Input.Token(text)
            val uri = URI(text)
            require(uri.scheme == "wgkeybot" && uri.host == "config")
            require(uri.rawUserInfo == null && uri.port == -1 && uri.rawPath.isNullOrEmpty())
            require(uri.rawFragment == null)
            val params = linkedMapOf<String, String>()
            for (part in (uri.rawQuery ?: "").split('&')) {
                val key = URLDecoder.decode(part.substringBefore('='), "UTF-8")
                if (key != "token" && key != "data") continue
                require(key !in params && '=' in part)
                params[key] = URLDecoder.decode(part.substringAfter('='), "UTF-8")
            }
            // Data is authoritative. Never downgrade a malformed offline link to
            // an API request, even when it also carries a valid legacy token.
            if ("data" in params) {
                try {
                    params["token"]?.let { require(TokenFormat.isValid(it)) }
                    return decode(params.getValue("data"))
                } catch (e: InvalidLinkException) {
                    if (e.reason != Failure.INVALID_FORMAT) throw e
                    throw InvalidLinkException(Failure.INVALID_DATA)
                } catch (_: Exception) {
                    throw InvalidLinkException(Failure.INVALID_DATA)
                }
            }
            val rawToken = params["token"]?.takeIf { it.isNotBlank() }
                ?: throw InvalidLinkException(Failure.MISSING_TOKEN)
            val token = TokenFormat.extract(rawToken)
                ?: throw InvalidLinkException()
            return Input.Token(token)
        } catch (e: InvalidLinkException) {
            throw e
        } catch (_: Exception) {
            // Parser/config errors must never echo a payload or WireGuard key.
            throw InvalidLinkException()
        }
    }

    private fun decode(encoded: String): Input.Embedded {
        require(encoded.isNotEmpty() && encoded.all {
            it in 'A'..'Z' || it in 'a'..'z' || it in '0'..'9' || it == '-' || it == '_'
        })
        val compressed = Base64.getUrlDecoder().decode(encoded)
        require(Base64.getUrlEncoder().withoutPadding().encodeToString(compressed) == encoded)
        val inflater = Inflater()
        val output = ByteArrayOutputStream()
        try {
            inflater.setInput(compressed)
            val buffer = ByteArray(4096)
            while (!inflater.finished()) {
                val count = inflater.inflate(buffer)
                require(output.size() + count <= MAX_PAYLOAD_BYTES)
                if (count == 0) {
                    require(inflater.finished()) // truncated stream, dictionary or no progress
                } else {
                    output.write(buffer, 0, count)
                }
            }
            require(inflater.remaining == 0)
        } finally {
            inflater.end()
        }
        val jsonText = Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(output.toByteArray())).toString()
        requireFlatObject(jsonText)
        val tokener = JSONTokener(jsonText)
        val json = tokener.nextValue() as? JSONObject ?: throw InvalidLinkException()
        require(tokener.nextClean() == '\u0000')
        val version = json.opt("version")
        if (version is Int && version != 1) throw InvalidLinkException(Failure.UNSUPPORTED_VERSION)
        require(version == 1)
        val accessToken = json.opt("access_token") as? String ?: throw InvalidLinkException()
        val expires = json.opt("subscription_expires_at") as? String ?: throw InvalidLinkException()
        val config = json.opt("config") as? String ?: throw InvalidLinkException(Failure.INVALID_CONFIG)
        require(TokenFormat.isValid(accessToken))
        require(expires.matches(Regex("\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z")))
        val expiry = Instant.parse(expires)
        require(expiry.toString() == expires) // rejects normalized leap seconds / 24:00
        if (config.isBlank() || '\u0000' in config ||
            !config.contains("[Interface]") || !config.contains("[Peer]")) {
            throw InvalidLinkException(Failure.INVALID_CONFIG)
        }
        return Input.Embedded(accessToken, expires, config)
    }

    /** The schema has only scalar fields; reject nesting before recursive JSONTokener. */
    private fun requireFlatObject(json: String) {
        var quoted = false
        var escaped = false
        var depth = 0
        var previous = '\u0000'
        for (char in json) {
            if (quoted) {
                if (escaped) escaped = false
                else if (char == '\\') escaped = true
                else if (char == '"') { quoted = false; previous = '"' }
            } else {
                when (char) {
                    '"' -> {
                        require(previous == '{' || previous == ',' || previous == ':')
                        quoted = true
                    }
                    '{' -> { depth++; require(depth == 1) }
                    '}' -> { depth--; require(depth == 0) }
                    '[', ']' -> throw InvalidLinkException()
                    // Android JSONTokener accepts these extensions, which could
                    // otherwise hide real nesting from a strict-JSON string scan.
                    '\'', '/', '#', '\\' -> throw InvalidLinkException()
                }
                // Match JSON whitespace exactly; Unicode space can be part of
                // JSONTokener's unquoted literal, including a following quote.
                if (char != ' ' && char != '\t' && char != '\r' && char != '\n') previous = char
            }
        }
        require(!quoted && depth == 0)
    }
}
