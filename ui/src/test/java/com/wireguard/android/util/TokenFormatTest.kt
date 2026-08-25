package com.wireguard.android.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class TokenFormatTest {

    private val uuid = "550e8400-e29b-41d4-a716-446655440000"
    private val uuidHex = "550e8400e29b41d4a716446655440000"
    private val short = "fjsyalvjdufndhs"

    // ── isValid ────────────────────────────────────────────────────────────────

    @Test
    fun `accepts the shapes the bot can hand out`() {
        assertTrue(TokenFormat.isValid(uuid))
        assertTrue(TokenFormat.isValid(uuidHex))
        assertTrue(TokenFormat.isValid(short))
        assertTrue(TokenFormat.isValid("Xk9_2mQ-7bZaQv"))       // base64url, mixed case
        assertTrue(TokenFormat.isValid("a".repeat(TokenFormat.MIN_LENGTH)))
        assertTrue(TokenFormat.isValid("a".repeat(TokenFormat.MAX_LENGTH)))
    }

    @Test
    fun `rejects lengths outside the window`() {
        assertFalse(TokenFormat.isValid(""))
        assertFalse(TokenFormat.isValid("a".repeat(TokenFormat.MIN_LENGTH - 1)))
        assertFalse(TokenFormat.isValid("a".repeat(TokenFormat.MAX_LENGTH + 1)))
    }

    @Test
    fun `rejects anything that could reshape the request path`() {
        assertFalse(TokenFormat.isValid("../open/fjsyalvjdufndhs"))
        assertFalse(TokenFormat.isValid("fjsyalvjdufndhs/../open"))
        assertFalse(TokenFormat.isValid("fjsyalvjdufndhs?x=1"))
        assertFalse(TokenFormat.isValid("fjsyalvjdufndhs#frag"))
        assertFalse(TokenFormat.isValid("token with spaces"))
        assertFalse(TokenFormat.isValid("fjsyalvjdufndhs\nGET /open"))
    }

    // ── normalize ──────────────────────────────────────────────────────────────

    @Test
    fun `normalize drops whitespace and invisible characters`() {
        assertEquals(short, TokenFormat.normalize("  $short\n"))
        assertEquals(short, TokenFormat.normalize("fjsyalv jdufndhs"))
        assertEquals(short, TokenFormat.normalize("\u200Bfjsyalvjdufndhs\uFEFF"))
    }

    @Test
    fun `normalize keeps case and dashes`() {
        assertEquals("Xk9_2mQ-7bZaQv", TokenFormat.normalize(" Xk9_2mQ-7bZaQv "))
        assertEquals(uuid, TokenFormat.normalize(uuid))
    }

    // ── extract ────────────────────────────────────────────────────────────────

    @Test
    fun `extract takes a bare token`() {
        assertEquals(short, TokenFormat.extract(" $short "))
        assertEquals(uuid, TokenFormat.extract(uuid))
    }

    @Test
    fun `extract unwraps deeplinks and links`() {
        assertEquals(short, TokenFormat.extract("wgkeybot://config?token=$short"))
        assertEquals(uuid, TokenFormat.extract("wgkeybot://config?token=$uuid&x=1"))
        assertEquals(short, TokenFormat.extract("https://t.me/wg_key_bot?start=$short"))
        assertEquals(short, TokenFormat.extract("https://key.shadowgate.online/api/v1/init/$short"))
    }

    @Test
    fun `extract returns null when there is no token`() {
        assertNull(TokenFormat.extract(""))
        assertNull(TokenFormat.extract("hello"))
        assertNull(TokenFormat.extract("../open/short"))
        assertNull(TokenFormat.extract("wgkeybot://config?token=short"))
    }

    // ── UUID handling ──────────────────────────────────────────────────────────

    @Test
    fun `a dashless uuid gets its dashes back on connect`() {
        assertTrue(TokenFormat.isRawUuidHex(uuidHex))
        assertEquals(uuid, TokenFormat.formatUuid(uuidHex))
        assertEquals(uuid, TokenFormat.fromKeyboard(uuidHex))
    }

    @Test
    fun `anything else goes as typed`() {
        assertFalse(TokenFormat.isRawUuidHex(short))
        assertEquals(short, TokenFormat.fromKeyboard(short))
        assertEquals("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", // 32 chars, not hex
            TokenFormat.fromKeyboard("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"))
    }

    // ── display ────────────────────────────────────────────────────────────────

    @Test
    fun `display groups a uuid while it is being typed`() {
        assertEquals("", TokenFormat.display("", 0))
        assertEquals("550e8400-|", TokenFormat.display("550e8400", 8))
        assertEquals("550e|8400", TokenFormat.display("550e8400", 4))
        assertEquals("$uuid|", TokenFormat.display(uuidHex, uuidHex.length))
    }

    @Test
    fun `display leaves a non-uuid token alone`() {
        assertEquals("$short|", TokenFormat.display(short, short.length))
        assertEquals("fjsy|alvjdufndhs", TokenFormat.display(short, 4))
    }

    // ── character class ────────────────────────────────────────────────────────

    @Test
    fun `token characters match the keyboard alphabet`() {
        assertTrue(TokenFormat.KEYBOARD_CHARS.all(TokenFormat::isTokenChar))
        assertTrue(TokenFormat.isTokenChar('-'))
        assertTrue(TokenFormat.isTokenChar('_'))
        assertTrue(TokenFormat.isTokenChar('Z'))
        assertFalse(TokenFormat.isTokenChar('/'))
        assertFalse(TokenFormat.isTokenChar('.'))
        assertFalse(TokenFormat.isTokenChar(' '))
    }
}
