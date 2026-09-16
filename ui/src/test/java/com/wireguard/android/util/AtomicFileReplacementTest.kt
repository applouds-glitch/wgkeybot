package com.wireguard.android.util

import com.google.crypto.tink.subtle.AesGcmHkdfStreaming
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.io.IOException

class AtomicFileReplacementTest {
    @get:Rule val temporary = TemporaryFolder()

    @Test fun `failed replacement preserves committed bytes and can be retried`() {
        val target = temporary.newFile("primary.conf").apply { writeText("old config") }
        assertThrows(IOException::class.java) {
            AtomicFileReplacement.write(target) { staged ->
                staged.writeText("incomplete ciphertext")
                assertEquals("old config", target.readText())
                throw IOException("disk full")
            }
        }
        assertEquals("old config", target.readText())
        AtomicFileReplacement.write(target) { it.writeText("new config") }
        assertEquals("new config", target.readText())
        assertEquals(listOf("primary.conf"), temporary.root.list()!!.toList())
    }

    @Test fun `failed first write does not publish a partial config`() {
        val target = File(temporary.root, "primary.conf")
        assertThrows(IOException::class.java) {
            AtomicFileReplacement.write(target) {
                it.writeText("partial")
                throw IOException("write failed")
            }
        }
        assertFalse(target.exists())
    }

    @Test fun `leftover staging file after process death is discarded`() {
        val target = temporary.newFile("primary.conf").apply { writeText("committed") }
        val directory = temporary.newFolder(".primary.conf.pending")
        File(directory, target.name).writeText("interrupted write")
        AtomicFileReplacement.write(target) {
            assertFalse(it.exists()) // EncryptedFile refuses an existing destination.
            assertEquals("committed", target.readText())
            it.writeText("replacement")
        }
        assertEquals("replacement", target.readText())
        assertFalse(directory.exists())
    }

    @Test fun `rename failure preserves destination`() {
        val target = temporary.newFolder("primary.conf")
        File(target, "keep").writeText("existing data")
        assertThrows(IOException::class.java) {
            AtomicFileReplacement.write(target) { it.writeText("replacement") }
        }
        assertEquals("existing data", File(target, "keep").readText())
        assertFalse(File(temporary.root, ".primary.conf.pending").exists())
    }

    @Test fun `encrypted replacement remains decryptable with final filename`() {
        // The same streaming primitive and filename-associated data EncryptedFile
        // uses, without requiring Android Keystore in this JVM regression test.
        val aead = AesGcmHkdfStreaming(ByteArray(32) { it.toByte() }, "HmacSha256", 32, 4096, 0)
        val target = temporary.newFile("primary.conf")
        val plaintext = "private WireGuard config\n".repeat(500).toByteArray()
        repeat(2) {
            AtomicFileReplacement.write(target) { staged ->
                assertEquals(target.name, staged.name)
                aead.newEncryptingStream(staged.outputStream(), staged.name.toByteArray(Charsets.UTF_8))
                    .use { it.write(plaintext) }
            }
            val decrypted = aead.newDecryptingStream(target.inputStream(), target.name.toByteArray(Charsets.UTF_8))
                .use { it.readBytes() }
            assertArrayEquals(plaintext, decrypted)
            assertFalse(target.readBytes().contentEquals(plaintext))
        }
    }
}
