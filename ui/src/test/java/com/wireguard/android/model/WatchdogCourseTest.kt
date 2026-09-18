/* SPDX-License-Identifier: Apache-2.0 */

package com.wireguard.android.model

import com.wireguard.android.model.HandshakeWatchdog.REBUILT_GRACE_MS
import com.wireguard.android.model.HandshakeWatchdog.STALE_MS
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
        private var tx = 0L

        fun poll(): Step {
            now += pollMs
            tx += 1_000
            return course.poll(now, handshake, tx, network)
        }

        /** Polls until something happens; returns the step and when it happened. */
        fun untilStep(limitPolls: Int = 100): Pair<Step, Long> {
            repeat(limitPolls) {
                val step = poll()
                if (step != Step.NONE) return step to now
            }
            throw AssertionError("nothing happened in $limitPolls polls")
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
}
