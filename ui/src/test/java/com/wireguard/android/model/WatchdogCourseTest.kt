/* SPDX-License-Identifier: Apache-2.0 */

package com.wireguard.android.model

import com.wireguard.android.model.HandshakeWatchdog.REBUILT_GRACE_MS
import com.wireguard.android.model.HandshakeWatchdog.STALE_MS
import com.wireguard.android.model.WatchdogCourse.Companion.SILENT_HOLD_MS
import com.wireguard.android.model.WatchdogCourse.Step
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WatchdogCourseTest {
    private val start = 1_000_000L
    private val pollMs = 30_000L

    /** A tunnel that keeps sending (tx grows every poll), polled every [pollMs]. */
    private inner class Session(private val course: WatchdogCourse) {
        var now = start
        var handshake = 0L
        var network = true
        var silent = false
        var sending = true
        private var tx = 0L

        fun poll(): Step {
            now += pollMs
            if (sending) tx += 1_000
            return course.poll(now, handshake, tx, network, silent)
        }

        /** Polls until something happens; returns the step and when it happened. */
        fun untilStep(limitPolls: Int = 100): Pair<Step, Long> {
            repeat(limitPolls) {
                val step = poll()
                if (step != Step.NONE) return step to now
            }
            throw AssertionError("nothing happened in $limitPolls polls")
        }

        /** Polls past any holds to the next other step; a course that only ever holds fails. */
        fun untilPastHolds(limitSteps: Int = 20): Pair<Step, Long> {
            repeat(limitSteps) {
                val next = untilStep()
                if (next.first != Step.HOLD) return next
            }
            throw AssertionError("held $limitSteps verdicts in a row")
        }
    }

    // The session this replaces took the tunnel down at the first verdict.
    @Test
    fun `a dead session is rebuilt twice before the tunnel goes down`() {
        val course = WatchdogCourse(start)
        val s = Session(course)
        s.handshake = start + 5_000

        val (first, firstAt) = s.untilStep()
        assertEquals(Step.REBUILD, first)
        assertTrue("first verdict before the handshake went stale", firstAt - s.handshake > STALE_MS)
        course.rebuilt(firstAt)

        val (second, secondAt) = s.untilStep()
        assertEquals(Step.REBUILD_NEW_CREDENTIALS, second)
        assertTrue("second verdict inside the rebuilt transport's grace", secondAt - firstAt > REBUILT_GRACE_MS)
        assertTrue("second verdict later than grace plus two polls", secondAt - firstAt <= REBUILT_GRACE_MS + 2 * pollMs)
        course.rebuilt(secondAt)

        val (third, thirdAt) = s.untilStep()
        assertEquals(Step.TEAR_DOWN, third)
        assertTrue("the whole course ran over ten minutes", thirdAt - s.handshake <= 10 * 60_000L)
    }

    // Without this, the stale handshake from before the rebuild would condemn the
    // new transport on the very next poll.
    @Test
    fun `the handshake from before a rebuild does not count against the new transport`() {
        val course = WatchdogCourse(start)
        val s = Session(course)
        s.handshake = start + 5_000
        val (_, at) = s.untilStep()
        course.rebuilt(at)

        while (s.now + pollMs - at <= REBUILT_GRACE_MS) {
            assertEquals("within the grace at +${s.now + pollMs - at}ms", Step.NONE, s.poll())
        }
    }

    @Test
    fun `a handshake after a rebuild is a recovery, and the next failure starts over`() {
        val course = WatchdogCourse(start)
        val s = Session(course)
        s.handshake = start + 5_000
        val (_, at) = s.untilStep()
        course.rebuilt(at)

        s.handshake = at + 3_000
        assertEquals(Step.RECOVERED, s.poll())
        assertEquals(0, course.rebuilds)

        assertEquals(Step.REBUILD, s.untilStep().first)
    }

    // Parked for want of a network is waiting, not a failure of the rebuilt transport.
    @Test
    fun `no physical network holds the course`() {
        val course = WatchdogCourse(start)
        val s = Session(course)
        s.handshake = start + 5_000
        val (_, at) = s.untilStep()
        course.rebuilt(at)

        s.network = false
        repeat(20) { assertEquals(Step.NONE, s.poll()) }
        s.network = true
        assertEquals("one dead poll is not a verdict", Step.NONE, s.poll())
        assertEquals(Step.REBUILD_NEW_CREDENTIALS, s.poll())
    }

    @Test
    fun `a tunnel that never connects is rebuilt too`() {
        val s = Session(WatchdogCourse(start))
        val (step, at) = s.untilStep()
        assertEquals(Step.REBUILD, step)
        assertTrue(at - start > HandshakeWatchdog.NEVER_CONNECTED_MS)
    }

    // The dark spells of 18.10: a rebuild restarted the proxy into the dark, the
    // second dropped the cached credential for a VK request that could not get
    // through. Held instead — and the tunnel still goes down about when the
    // whole course would have taken it.
    @Test
    fun `verdicts while no relay answers are held, then the tunnel goes down`() {
        val course = WatchdogCourse(start)
        val s = Session(course)
        s.handshake = start + 5_000
        s.silent = true

        val (first, firstAt) = s.untilStep()
        assertEquals(Step.HOLD, first)
        val (step, at) = s.untilPastHolds()
        assertEquals("rebuilt while no relay answered", Step.TEAR_DOWN, step)
        assertEquals(0, course.rebuilds)
        assertTrue("torn down before the hold was out", at - firstAt >= SILENT_HOLD_MS)
        assertTrue("torn down later than the hold plus a poll", at - firstAt <= SILENT_HOLD_MS + pollMs)
        assertTrue("the whole course ran over ten minutes", at - s.handshake <= 10 * 60_000L)
    }

    // A hold takes no step of the course: once relays answer again and the
    // tunnel still does not handshake, the step that was next is taken.
    @Test
    fun `the course goes on from where it was once relays answer`() {
        val course = WatchdogCourse(start)
        val s = Session(course)
        s.handshake = start + 5_000
        val (first, at) = s.untilStep()
        assertEquals(Step.REBUILD, first)
        course.rebuilt(at)

        s.silent = true
        assertEquals("a new credential while no relay answered", Step.HOLD, s.untilStep().first)
        s.silent = false
        assertEquals(Step.REBUILD_NEW_CREDENTIALS, s.untilStep().first)
    }

    // A handshake ends the hold, and a later silence is given the whole of it.
    @Test
    fun `a handshake ends the hold`() {
        val course = WatchdogCourse(start)
        val s = Session(course)
        s.handshake = start + 5_000
        s.silent = true
        val (_, heldAt) = s.untilStep()

        s.handshake = heldAt + 3_000
        assertEquals(Step.NONE, s.poll())
        val (again, againAt) = s.untilStep()
        assertEquals(Step.HOLD, again)
        val (step, at) = s.untilPastHolds()
        assertEquals(Step.TEAR_DOWN, step)
        assertTrue("the second silence was not given the whole hold", at - againAt >= SILENT_HOLD_MS)
    }

    // WireGuard gives up its initiations and an idle phone sends nothing, so tx
    // stops growing and no poll reads as dead any more: the hold still runs out
    // (Codex review, 19.10).
    @Test
    fun `the hold runs out with nothing sent`() {
        val course = WatchdogCourse(start)
        val s = Session(course)
        s.handshake = start + 5_000
        s.silent = true
        val (held, heldAt) = s.untilStep()
        assertEquals(Step.HOLD, held)

        s.sending = false
        val (step, at) = s.untilStep()
        assertEquals(Step.TEAR_DOWN, step)
        assertTrue("torn down before the hold was out", at - heldAt >= SILENT_HOLD_MS)
        assertTrue("torn down later than the hold plus a poll", at - heldAt <= SILENT_HOLD_MS + pollMs)
    }

    // The network gone ends the hold; the one that comes back is given the whole
    // of a new one, not the remains of the old.
    @Test
    fun `the network lost ends the hold`() {
        val course = WatchdogCourse(start)
        val s = Session(course)
        s.handshake = start + 5_000
        s.silent = true
        assertEquals(Step.HOLD, s.untilStep().first)

        s.network = false
        repeat(20) { assertEquals(Step.NONE, s.poll()) }
        s.network = true
        val (step, at) = s.untilStep()
        assertEquals("the hold outlived the network lost", Step.HOLD, step)
        val (next, nextAt) = s.untilStep()
        assertEquals(Step.TEAR_DOWN, next)
        assertTrue(nextAt - at >= SILENT_HOLD_MS)
    }
}
