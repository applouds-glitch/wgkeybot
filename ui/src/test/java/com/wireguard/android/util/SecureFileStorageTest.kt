package com.wireguard.android.util

import org.json.JSONObject
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class SecureFileStorageTest {
    @Test fun `legacy config and TURN settings remain eligible for migration`() {
        val fixture = javaClass.getResourceAsStream("/python-connection-link.json")!!
            .bufferedReader().use { JSONObject(it.readText()) }
        assertTrue(SecureFileStorage.isLegacyPlaintext(File("primary.conf"),
            fixture.getString("config").toByteArray()))
        assertTrue(SecureFileStorage.isLegacyPlaintext(File("primary.turn.json"),
            "{\"enabled\":true,\"peer\":\"127.0.0.1:9000\"}".toByteArray()))
    }

    @Test fun `unreadable ciphertext must not be migrated as plaintext`() {
        for (name in listOf("primary.conf", "primary.turn.json")) {
            for (bytes in listOf(byteArrayOf(0, 31, -1, 0, 80), ByteArray(0), "truncated file".toByteArray())) {
                assertFalse(SecureFileStorage.isLegacyPlaintext(File(name), bytes))
            }
        }
    }
}
