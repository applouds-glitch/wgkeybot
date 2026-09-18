/* SPDX-License-Identifier: Apache-2.0 */

package com.wireguard.android.util

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.BufferedReader
import java.io.File
import java.io.StringReader

class PersistentLogTest {
    @get:Rule
    val tmp = TemporaryFolder()

    // Lines as they arrived in a field log from a HyperOS phone.
    private val turn = "09-18 08:16:52.052 19700 25316 I WireGuard/TurnClient: [DISPATCH] stream 0 silent for 37s — skipped while siblings hear echoes"
    private val turnWithColons = "09-18 08:16:52.100 19700 25316 I WireGuard/TurnClient: [STREAM 4] TX error: write udp 192.168.1.45:35756->95.163.34.144:19302: write: network is unreachable"
    private val wg = "09-18 08:10:00.001 19700 24244 D WireGuard/GoBackend/wgkeybot: peer(cvEv…V4yQ) - Sending keepalive packet"
    private val jni = "09-18 08:16:52.200  1970  2531 I WireGuard/JNI: wgSetNetwork: dials now bind to net 0"
    private val crash = "09-18 08:16:53.000 19700 19700 E AndroidRuntime: FATAL EXCEPTION: main"
    private val insets = "09-18 08:16:53.118 19700 19700 W InsetsSource: Has no intersection or mTmpFrame.height(), return Insets.NONE"
    private val miui = "09-18 08:16:56.038 19700 19700 I MIUIInput: [MotionEvent] ViewRootImpl windowName 'com.wgkeybot.android/x'"
    private val banner = "--------- beginning of main"

    @Test
    fun `reads the tag up to the first colon-space, not a later one in the message`() {
        assertEquals("WireGuard/TurnClient", LogcatLine.tag(turnWithColons))
        assertEquals("WireGuard/GoBackend/wgkeybot", LogcatLine.tag(wg))
        assertEquals("09-18 08:16:52.052", LogcatLine.timestamp(turn))
    }

    @Test
    fun `keeps our tags and crashes, drops the ROM's chatter from the same pid`() {
        for (line in listOf(turn, turnWithColons, wg, jni, crash)) assertTrue(line, LogcatLine.keep(line))
        for (line in listOf(insets, miui, banner, "")) assertFalse(line, LogcatLine.keep(line))
    }

    @Test
    fun `copy keeps only our lines and reports the last kept timestamp`() {
        val file = RotatingLogFile(tmp.root, 1024 * 1024)
        val input = listOf(banner, wg, insets, turn, miui).joinToString("\n")
        val last = file.copyFrom(BufferedReader(StringReader(input)))
        assertEquals("09-18 08:16:52.052", last)
        assertEquals("$wg\n$turn\n", String(file.snapshot()))
    }

    @Test
    fun `copy with nothing of ours reports no timestamp`() {
        val file = RotatingLogFile(tmp.root, 1024 * 1024)
        assertNull(file.copyFrom(BufferedReader(StringReader("$insets\n$miui"))))
        assertEquals(0, file.snapshot().size)
    }

    @Test
    fun `rotation keeps one previous generation and bounds the pair`() {
        val max = 1000L
        val file = RotatingLogFile(tmp.root, max)
        val lines = (1..100).map { "line %03d %s".format(it, "x".repeat(40)) }
        lines.forEach(file::append)
        file.flush()

        val current = File(tmp.root, RotatingLogFile.NAME)
        val previous = File(tmp.root, RotatingLogFile.NAME + ".1")
        assertTrue(current.length() <= max)
        assertTrue(previous.length() <= max)
        assertFalse(File(tmp.root, RotatingLogFile.NAME + ".2").exists())

        // Oldest first, contiguous, and ending with the newest line.
        val kept = String(file.snapshot()).trimEnd('\n').split('\n')
        assertEquals(lines.takeLast(kept.size), kept)
        assertTrue("kept ${kept.size} lines", kept.size in 20 until lines.size)
    }

    @Test
    fun `a new process appends to the file and counts what is already on disk`() {
        val max = 1000L
        val line = "y".repeat(99) // 100 bytes with the newline
        RotatingLogFile(tmp.root, max).apply { repeat(9) { append(line) }; flush() }

        // Next process: one more line fits (900 + 100), the one after must rotate.
        val reopened = RotatingLogFile(tmp.root, max)
        reopened.append(line)
        reopened.flush()
        assertEquals(1000L, File(tmp.root, RotatingLogFile.NAME).length())
        reopened.append(line)
        reopened.flush()
        assertEquals(1000L, File(tmp.root, RotatingLogFile.NAME + ".1").length())
        assertEquals(100L, File(tmp.root, RotatingLogFile.NAME).length())
    }

    @Test
    fun `snapshot of an empty log is empty`() {
        assertArrayEquals(ByteArray(0), RotatingLogFile(File(tmp.root, "never-created"), 1000).snapshot())
    }
}
