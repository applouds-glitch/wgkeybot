/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import com.wireguard.android.util.ProcessExitLog.Exit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ProcessExitLogTest {
    private fun exit(timestamp: Long, pid: Int = 100, reason: Int = 3, description: String? = null) =
        Exit(timestamp, pid, "com.wgkeybot.android", reason, 0, 125, description)

    @Test
    fun `the WebView's renderers are not the app's exits`() {
        val pkg = "com.wgkeybot.android"
        val renderer = exit(1_000, pid = 1).copy(
            process = "com.google.android.webview:sandboxed_process0:org.chromium.content.app.SandboxedProcessService0:0",
        )
        val other = exit(2_000, pid = 2).copy(process = "com.wgkeybot.android.debug")
        val main = exit(3_000, pid = 3)
        val service = exit(4_000, pid = 4).copy(process = "$pkg:service")
        assertEquals(listOf(main, service), ProcessExitLog.own(listOf(renderer, other, main, service), pkg))
    }

    @Test
    fun `an exit is written once`() {
        val exits = listOf(exit(2_000, pid = 2), exit(1_000, pid = 1))
        val first = ProcessExitLog.fresh(exits, emptySet())
        assertEquals(listOf(1_000L, 2_000L), first.map { it.timestamp })
        val reported = ProcessExitLog.remembered(exits, emptySet())
        assertTrue(ProcessExitLog.fresh(exits, reported).isEmpty())
    }

    /** The system files a record late: it is older than one already written. */
    @Test
    fun `a record that turns up behind a newer one is still written`() {
        val reported = ProcessExitLog.remembered(listOf(exit(5_000, pid = 5)), emptySet())
        val exits = listOf(exit(5_000, pid = 5), exit(3_000, pid = 3))
        assertEquals(listOf(3_000L), ProcessExitLog.fresh(exits, reported).map { it.timestamp })
    }

    @Test
    fun `two processes that ended in the same millisecond are two exits`() {
        val exits = listOf(exit(1_000, pid = 1), exit(1_000, pid = 2))
        assertEquals(2, ProcessExitLog.fresh(exits, setOf("1000:3")).size)
    }

    @Test
    fun `only the newest ids are remembered`() {
        val exits = (1..ProcessExitLog.REMEMBERED + 8).map { exit(it * 1_000L, pid = it) }
        val kept = ProcessExitLog.remembered(exits, emptySet())
        assertEquals(ProcessExitLog.REMEMBERED, kept.size)
        assertFalse("1000:1" in kept)
        assertTrue("${(ProcessExitLog.REMEMBERED + 8) * 1_000L}:${ProcessExitLog.REMEMBERED + 8}" in kept)
    }

    @Test
    fun `the line names the reason and stays on one line`() {
        val line = ProcessExitLog.line(exit(1_000, pid = 4242, reason = 3, description = "lmkd\nkill"), "11-11 03:05:00")
        assertEquals(
            "earlier process com.wgkeybot.android pid=4242 ended at 11-11 03:05:00: low memory" +
                " status=0 importance=125 (lmkd kill)",
            line,
        )
    }

    @Test
    fun `a reason this build does not know is written as its number`() {
        assertEquals("reason 99", ProcessExitLog.reasonName(99))
        assertTrue(ProcessExitLog.line(exit(1_000, description = null), "x").endsWith("importance=125"))
    }
}
