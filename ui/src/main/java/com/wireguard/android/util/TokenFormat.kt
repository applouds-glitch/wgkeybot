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

    /** A UUID with its dashes stripped — the shape the TV keyboard buffers. */
    private const val UUID_HEX_LENGTH = 32
    private val UUID_DASH_POSITIONS = setOf(8, 12, 16, 20)

    /** Unanchored on purpose: [Regex.matches] already requires the whole input. */
    private val VALID = Regex("[A-Za-z0-9_-]{$MIN_LENGTH,$MAX_LENGTH}")

    /** `?token=…` / `?start=…` out of a deeplink or a bot link. */
    private val QUERY_PARAM = Regex("[?&](?:token|start)=([^&#\\s]+)")

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
     * `wgkeybot://config?token=…` deeplink, a `t.me/…?start=…` bot link, or a
     * URL whose last path segment is the token. Null if nothing valid is found.
     */
    fun extract(text: String): String? {
        val candidates = sequence {
            yield(text)
            QUERY_PARAM.find(text)?.let { yield(it.groupValues[1]) }
            yield(text.trim().substringAfterLast('/'))
        }
        return candidates.map { normalize(it) }.firstOrNull { isValid(it) }
    }

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
        val grouped = raw.length <= UUID_HEX_LENGTH && raw.all { it.isHexDigit() }
        val sb = StringBuilder()
        for (i in 0..raw.length) {
            if (grouped && i in UUID_DASH_POSITIONS && (i < raw.length || i == cursor)) sb.append('-')
            if (i == cursor) sb.append('|')
            if (i < raw.length) sb.append(raw[i])
        }
        return sb.toString()
    }

    private fun Char.isHexDigit(): Boolean =
        this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'
}
