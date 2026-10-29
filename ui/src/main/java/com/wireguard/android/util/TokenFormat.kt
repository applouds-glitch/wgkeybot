package com.wireguard.android.util

/**
 * The single place that knows what a connection token looks like.
 *
 * Tokens used to be UUIDs and every entry point hard-coded that: the clipboard
 * regex, the TV keyboard's 32-character hex buffer, the dash grouping. The bot
 * may hand out other shapes (short opaque strings, base64url), so the format is
 * kept deliberately wide — any URL-safe string of a sane length — and lives here
 * alone. Widen [MIN_LENGTH]/[MAX_LENGTH] or the character class below and every
 * entry point follows.
 *
 * The character class doubles as a safety property: a token that passes
 * [isValid] cannot contain `/`, `.`, `?` or `#`, so it can never reshape the
 * path of the request it is pasted into.
 */
object TokenFormat {

    const val MIN_LENGTH = 8
    const val MAX_LENGTH = 64

    /** Characters the on-screen TV keyboard offers, in grid order. */
    const val KEYBOARD_CHARS = "0123456789abcdefghijklmnopqrstuvwxyz"

    /** A UUID with its dashes stripped — the shape the TV keyboard buffers, and counts towards. */
    const val UUID_HEX_LENGTH = 32
    private val UUID_DASH_POSITIONS = setOf(8, 12, 16, 20)

    /** Unanchored on purpose: [Regex.matches] already requires the whole input. */
    private val VALID = Regex("[A-Za-z0-9_-]{$MIN_LENGTH,$MAX_LENGTH}")

    /** `?token=…` out of a deeplink. Bot links (`t.me/…?start=…`) never carry a token. */
    private val QUERY_PARAM = Regex("[?&]token=([^&#\\s]+)")

    /** Hosts whose links carry the token in the path: `/open/<t>`, `/api/v1/init/<t>`. Mirrors ApiClient.BASE_URL. */
    private val SERVICE_HOSTS = setOf("key.shadowgate.online")

    private val HTTP_URL = Regex("^https?://([^/?#\\s]+)", RegexOption.IGNORE_CASE)

    /** What a pasted link that is not ours points at; the error message names it. */
    enum class LinkKind { APP_DOWNLOAD, BOT, OTHER }

    private const val ZERO_WIDTH = "\u200B\u200C\u200D\uFEFF"

    fun isValid(token: String): Boolean = VALID.matches(token)

    /**
     * Drop whitespace and invisible characters — messengers love to wrap and
     * decorate a token. Case and dashes are meaningful, so they are kept.
     */
    fun normalize(raw: String): String =
        raw.filterNot { it.isWhitespace() || it in ZERO_WIDTH }

    /**
     * Pull a token out of arbitrary pasted text: the token itself, a
     * `wgkeybot://config?token=…` deeplink, or a link to our own host whose
     * last path segment is the token. Null if nothing valid is found.
     *
     * Only our own links are mined: people paste the APK download page into
     * the field, and `…/wgkeybot/releases` used to turn into a request for the
     * token `releases` — a server round-trip ending in "token expired".
     */
    fun extract(text: String): String? {
        val trimmed = text.trim()
        val candidates = sequence {
            yield(text)
            if (isServiceLink(trimmed)) {
                QUERY_PARAM.find(trimmed)?.let { yield(it.groupValues[1]) }
                yield(trimmed.substringBefore('?').substringBefore('#').substringAfterLast('/'))
            }
        }
        return candidates.map { normalize(it) }.firstOrNull { isValid(it) }
    }

    /**
     * Tell the download page, the bot and any other site apart for the error
     * message. Null for anything that is not an http(s) link, and for our own.
     */
    fun foreignLink(text: String): LinkKind? {
        val host = host(text.trim()) ?: return null
        return when {
            host in SERVICE_HOSTS -> null
            host == "github.com" || host.endsWith(".github.com") -> LinkKind.APP_DOWNLOAD
            host == "t.me" || host == "telegram.me" || host.endsWith(".t.me") -> LinkKind.BOT
            else -> LinkKind.OTHER
        }
    }

    private fun host(text: String): String? = HTTP_URL.find(text)?.groupValues?.get(1)?.lowercase()

    private fun isServiceLink(text: String): Boolean =
        text.startsWith("wgkeybot://", ignoreCase = true) || host(text)?.let { it in SERVICE_HOSTS } == true

    /** True for a dashless UUID, the only shape that gets grouped with dashes. */
    fun isRawUuidHex(raw: String): Boolean =
        raw.length == UUID_HEX_LENGTH && raw.all { it.isHexDigit() }

    /** Format 32 hex characters as `8-4-4-4-12`. */
    fun formatUuid(raw: String): String {
        val sb = StringBuilder()
        for ((i, c) in raw.withIndex()) {
            if (i in UUID_DASH_POSITIONS) sb.append('-')
            sb.append(c)
        }
        return sb.toString()
    }

    /** Is [c] allowed inside a token? Mirrors the character class of [VALID]. */
    fun isTokenChar(c: Char): Boolean =
        c in '0'..'9' || c in 'a'..'z' || c in 'A'..'Z' || c == '-' || c == '_'

    /**
     * The token to send for a TV keyboard buffer: a complete dashless UUID gets
     * its dashes back, anything else goes as typed.
     */
    fun fromKeyboard(buffer: String): String =
        if (isRawUuidHex(buffer)) formatUuid(buffer) else buffer

    /**
     * The TV keyboard's display string: the buffer with a `|` cursor marker, and
     * — while it still looks like a UUID being typed — dashes at the group
     * boundaries. A dash shows only between real characters, or under a cursor
     * parked exactly on a boundary.
     */
    fun display(raw: String, cursor: Int): String {
        if (raw.isEmpty()) return ""
        val grouped = isUuidHexSoFar(raw)
        val sb = StringBuilder()
        for (i in 0..raw.length) {
            if (grouped && i in UUID_DASH_POSITIONS && (i < raw.length || i == cursor)) sb.append('-')
            if (i == cursor) sb.append('|')
            if (i < raw.length) sb.append(raw[i])
        }
        return sb.toString()
    }

    /**
     * Whether [raw] can still become a dashless UUID: hex digits only, no more
     * than 32. The TV keyboard groups such a buffer and counts it towards 32.
     */
    fun isUuidHexSoFar(raw: String): Boolean = raw.length <= UUID_HEX_LENGTH && raw.all { it.isHexDigit() }

    private fun Char.isHexDigit(): Boolean =
        this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'
}
