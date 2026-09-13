package com.wireguard.android.util

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.util.Base64
import java.util.zip.DeflaterOutputStream

class ConnectionImportTest {
    private fun fixture(): JSONObject = javaClass.getResourceAsStream("/python-connection-link.json")!!
        .bufferedReader(Charsets.UTF_8).use { JSONObject(it.readText()) }

    private fun withConfig(config: String): String {
        val fixture = fixture()
        val payload = JSONObject()
            .put("version", 1)
            .put("access_token", fixture.getString("access_token"))
            .put("subscription_expires_at", fixture.getString("subscription_expires_at"))
            .put("config", config)
        val compressed = ByteArrayOutputStream().apply {
            DeflaterOutputStream(this).use { it.write(payload.toString().toByteArray(Charsets.UTF_8)) }
        }.toByteArray()
        return "wgkeybot://config?token=primary-token&data=${Base64.getUrlEncoder().withoutPadding().encodeToString(compressed)}"
    }

    @Test
    fun `Python link prepares a complete WireGuard config without API request`() {
        // Android Uri is not mocked in this JVM test; an accidental ApiClient.init
        // call fails immediately, before it can make a network request.
        val fixture = fixture()
        val prepared = ConnectionImport.prepare(fixture.getString("link"))
        assertEquals(fixture.getString("config"), prepared.response.config)
        assertEquals(fixture.getString("access_token"), prepared.response.accessToken)
        assertEquals(fixture.getString("subscription_expires_at"), prepared.response.subscriptionExpiresAt)
        assertNull(prepared.response.latestVersion)
        assertNull(prepared.response.downloadUrl)
        assertEquals("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", prepared.config.`interface`.keyPair.privateKey.toBase64())
        assertEquals(1, prepared.config.peers.size)
        val peer = prepared.config.peers.single()
        assertEquals("ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8=", peer.publicKey.toBase64())
        assertEquals("QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl8=", peer.preSharedKey.get().toBase64())
        assertEquals("127.0.0.1:9000", peer.endpoint.get().toString())
        assertEquals(fixture.getString("config").lineSequence().filter { it.startsWith("#@wgt:") }.toList(), peer.extraLines)
    }

    @Test
    fun `invalid WireGuard body is rejected without exposing the offending key`() {
        val secret = "private-key-secret-123456789"
        val raw = withConfig("[Interface]\nPrivateKey = $secret\n[Peer]\nPublicKey = $secret\n")
        assertTrue(ConnectionLink.parse(raw) is ConnectionLink.Input.Embedded)
        val failure = assertThrows(ConnectionLink.InvalidLinkException::class.java) { ConnectionImport.prepare(raw) }
        assertEquals("Invalid connection link", failure.message)
        assertFalse(failure.toString().contains(secret))
        assertNull(failure.cause)
    }
}
