package com.wireguard.android.util

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64
import java.util.zip.DeflaterOutputStream
import java.io.ByteArrayOutputStream

class ConnectionLinkTest {
    private val token = "12345678-1234-1234-1234-123456789abc"
    private val expires = "2099-09-14T00:00:00Z"
    private val config = "[Interface]\n# тест UTF-8\n[Peer]\n"

    private fun payload(): JSONObject = JSONObject()
        .put("version", 1)
        .put("access_token", token)
        .put("subscription_expires_at", expires)
        .put("config", config)

    private fun compress(bytes: ByteArray): ByteArray = ByteArrayOutputStream().apply {
        DeflaterOutputStream(this).use { it.write(bytes) }
    }.toByteArray()

    private fun encoded(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun rawJsonLink(json: String): String =
        "wgkeybot://config?token=primary-token&data=${encoded(compress(json.toByteArray(Charsets.UTF_8)))}"

    private fun link(json: JSONObject = payload()): String = rawJsonLink(json.toString())

    private fun assertInvalid(raw: String): ConnectionLink.InvalidLinkException =
        assertThrows(ConnectionLink.InvalidLinkException::class.java) { ConnectionLink.parse(raw) }

    @Test
    fun `Python generated bot link preserves config session and expiry exactly`() {
        val fixture = javaClass.getResourceAsStream("/python-connection-link.json")!!
            .bufferedReader(Charsets.UTF_8).use { JSONObject(it.readText()) }
        val result = ConnectionLink.parse(fixture.getString("link")) as ConnectionLink.Input.Embedded
        assertEquals(fixture.getString("config"), result.config)
        assertEquals(fixture.getString("access_token"), result.accessToken)
        assertEquals(fixture.getString("subscription_expires_at"), result.subscriptionExpiresAt)
        assertTrue(result.config.contains("#@wgt:VKLink = https://vk.com/call/join/example"))
    }

    @Test
    fun `legacy token and full token links still resolve to API input`() {
        for (raw in listOf(token, "wgkeybot://config?token=$token", "https://key.shadowgate.online/api/v1/init/$token")) {
            assertEquals(token, (ConnectionLink.parse(raw) as ConnectionLink.Input.Token).value)
        }
    }

    @Test
    fun `pasting retains the whole embedded link`() {
        val raw = link()
        assertEquals(raw, ConnectionLink.extractInput(" \n$raw\n "))
        val result = ConnectionLink.parse(raw) as ConnectionLink.Input.Embedded
        assertEquals(config, result.config)
        assertEquals(token, result.accessToken)
        assertEquals(expires, result.subscriptionExpiresAt)
    }

    @Test
    fun `embedded data also works without optional legacy token`() {
        assertEquals(token, (ConnectionLink.parse(link().replace("token=primary-token&", "")) as ConnectionLink.Input.Embedded).accessToken)
    }

    @Test
    fun `present invalid data cannot fall back to legacy token`() {
        for (data in listOf("", "%%%%", "a", "abc=", "hello")) {
            assertInvalid("wgkeybot://config?token=$token&data=$data")
        }
    }

    @Test
    fun `link length limit accepts boundary and rejects one extra character`() {
        val start = "${link()}&padding="
        val boundary = start + "x".repeat(ConnectionLink.MAX_LINK_LENGTH - start.length)
        assertTrue(ConnectionLink.parse(boundary) is ConnectionLink.Input.Embedded)
        assertNull(ConnectionLink.extractInput("${boundary}x"))
        assertInvalid("${boundary}x")
    }

    @Test
    fun `inflation cannot exceed payload byte limit`() {
        val oversized = link(payload().put("config", config + "x".repeat(ConnectionLink.MAX_PAYLOAD_BYTES)))
        assertTrue(oversized.length < ConnectionLink.MAX_LINK_LENGTH)
        assertInvalid(oversized)
    }

    @Test
    fun `payload limit counts UTF-8 bytes`() {
        val oversized = link(payload().put("config", config + "я".repeat(ConnectionLink.MAX_PAYLOAD_BYTES / 2)))
        assertTrue(oversized.length < ConnectionLink.MAX_LINK_LENGTH)
        assertInvalid(oversized)
    }

    @Test
    fun `inflation accepts exact payload byte boundary`() {
        val json = payload()
        val currentSize = json.toString().toByteArray(Charsets.UTF_8).size
        json.put("config", config + "x".repeat(ConnectionLink.MAX_PAYLOAD_BYTES - currentSize))
        assertEquals(ConnectionLink.MAX_PAYLOAD_BYTES, json.toString().toByteArray(Charsets.UTF_8).size)
        assertTrue(ConnectionLink.parse(link(json)) is ConnectionLink.Input.Embedded)
    }

    @Test
    fun `truncated corrupted and trailing compressed bytes are rejected`() {
        val compressed = compress(payload().toString().toByteArray(Charsets.UTF_8))
        val corrupt = compressed.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        for (bytes in listOf(compressed.copyOf(compressed.size - 1), corrupt, compressed + byteArrayOf(0), compressed + compressed)) {
            assertInvalid("wgkeybot://config?token=$token&data=${encoded(bytes)}")
        }
    }

    @Test
    fun `base64 must be canonical unpadded URL encoding`() {
        val good = encoded(compress(payload().toString().toByteArray(Charsets.UTF_8)))
        for (bad in listOf("$good=", "$good+", "$good/", "%2B$good")) {
            assertInvalid("wgkeybot://config?data=$bad")
        }
    }

    @Test
    fun `invalid UTF-8 and extra JSON content are rejected`() {
        val json = payload().toString()
        for (bytes in listOf(json.toByteArray() + byteArrayOf(0xc3.toByte(), 0x28), "$json {}".toByteArray(), "[]".toByteArray())) {
            assertInvalid("wgkeybot://config?data=${encoded(compress(bytes))}")
        }
    }

    @Test
    fun `version requires supported integer`() {
        for (version in listOf(2, 0, "1", 1.5, JSONObject.NULL)) {
            assertInvalid(link(payload().put("version", version)))
        }
        assertInvalid(rawJsonLink(payload().toString().replace("\"version\":1", "\"version\":1.0")))
        assertInvalid(link(payload().apply { remove("version") }))
    }

    @Test
    fun `embedded access token must be a valid token string`() {
        for (bad in listOf("", "short", "../private-key-secret", "contains a space", 12345, JSONObject.NULL)) {
            assertInvalid(link(payload().put("access_token", bad)))
        }
        assertInvalid(link(payload().apply { remove("access_token") }))
        assertInvalid(link().replace("primary-token", "short"))
    }

    @Test
    fun `expiry requires strict valid UTC seconds`() {
        for (bad in listOf("", "2099-02-30T00:00:00Z", "2099-09-14T24:00:00Z", "2099-09-14T00:00:60Z", "2099-09-14T00:00:00+00:00", "2099-09-14T00:00:00.000Z", "2099-09-14", 12345, JSONObject.NULL)) {
            assertInvalid(link(payload().put("subscription_expires_at", bad)))
        }
        assertInvalid(link(payload().apply { remove("subscription_expires_at") }))
    }

    @Test
    fun `config must be a nonempty string with interface and peer`() {
        for (bad in listOf("", " ", "[Interface]", "[Peer]", "$config\u0000", 12345, JSONObject.NULL)) {
            assertInvalid(link(payload().put("config", bad)))
        }
        assertInvalid(link(payload().apply { remove("config") }))
    }

    @Test
    fun `ambiguous query and unexpected URL shape are rejected`() {
        val valid = link()
        for (bad in listOf("$valid&data=bad", "$valid&token=$token", "$valid#fragment", valid.replace("//config?", "//config/path?"), valid.replace("//config?", "//user@config?"), valid.replace("//config?", "//config:123?"))) {
            assertInvalid(bad)
        }
    }

    @Test
    fun `deep JSON arrays and objects are rejected before recursive parsing`() {
        val arrays = "[".repeat(10_000) + "0" + "]".repeat(10_000)
        val objects = "{\"a\":".repeat(10_000) + "0" + "}".repeat(10_000)
        for (raw in listOf(arrays, objects)) {
            assertTrue(raw.toByteArray(Charsets.UTF_8).size <= ConnectionLink.MAX_PAYLOAD_BYTES)
            assertInvalid(rawJsonLink(raw))
        }
    }

    @Test
    fun `single quoted JSON cannot hide nesting from the flat schema guard`() {
        val nested = "[".repeat(10_000) + "0" + "]".repeat(10_000)
        assertInvalid(rawJsonLink("{'x':'\"', 'y':$nested, 'z':'\"'}"))
    }

    @Test
    fun `JSON comments cannot hide nesting from the flat schema guard`() {
        val nested = "[".repeat(10_000) + "0" + "]".repeat(10_000)
        val block = "{\"x\":0 /* \" */, \"y\":$nested, \"z\":0 /* \" */}"
        val line = "{\"x\":0, // \"\n \"y\":$nested, // \"\n \"z\":0}"
        val hash = "{\"x\":0, # \"\n \"y\":$nested, # \"\n \"z\":0}"
        for (raw in listOf(block, line, hash)) assertInvalid(rawJsonLink(raw))
    }

    @Test
    fun `quotes in unquoted literals cannot hide nested JSON`() {
        val nested = "[".repeat(10_000) + "0" + "]".repeat(10_000)
        assertInvalid(rawJsonLink("{\"x\":evil\", y:$nested, z:evil\"}"))
    }

    @Test
    fun `non-JSON Unicode whitespace cannot disguise an unquoted literal`() {
        val nested = "[".repeat(10_000) + "0" + "]".repeat(10_000)
        // Android JSONTokener treats these as unquoted literal characters, while
        // Kotlin Char.isWhitespace treats them as whitespace. A quote after them
        // must not open a JSON string in the guard.
        for (space in listOf('\u00a0', '\u2003', '\u2009')) {
            assertInvalid(rawJsonLink("{\"x\":$space\", y:$nested, z:$space\"}"))
        }
    }

    @Test
    fun `JSON structure characters inside config strings remain intact`() {
        val escapedConfig = config + "# User's example / {\"x\":[1,2]} \\ escaped\n"
        val input = ConnectionLink.parse(link(payload().put("config", escapedConfig))) as ConnectionLink.Input.Embedded
        assertEquals(escapedConfig, input.config)
    }

    @Test
    fun `parser exceptions never expose raw connection secrets`() {
        val secret = "private-key-secret-123456789"
        for (bad in listOf("wgkeybot://config?token=$token&data=$secret", link(payload().put("config", secret)))) {
            val failure = assertInvalid(bad)
            assertEquals("Invalid connection link", failure.message)
            assertFalse(failure.toString().contains(secret))
            assertNull(failure.cause)
        }
    }
}
