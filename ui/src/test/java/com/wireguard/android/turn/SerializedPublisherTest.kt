/*
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.turn

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

class SerializedPublisherTest {
    /**
     * The push to native is four calls in a row; two of them side by side leave
     * native with parts of each. And the caller that had to wait must publish
     * what is current when its turn comes, not what was current when it was
     * woken — or the older state lands last and stays.
     */
    @Test
    fun `pushes do not overlap and the one that waited publishes the latest state`() = runBlocking {
        val current = AtomicReference("wifi/UDP")
        val published = CopyOnWriteArrayList<String>()
        val inside = AtomicInteger()
        val overlapped = AtomicInteger()
        val firstIsInside = CountDownLatch(1)
        val letFirstFinish = CountDownLatch(1)

        val publisher = SerializedPublisher(
            readCurrent = { current.get() },
            publish = { value: String ->
                if (inside.incrementAndGet() > 1) overlapped.incrementAndGet()
                if (published.isEmpty()) {
                    firstIsInside.countDown()
                    check(letFirstFinish.await(10, TimeUnit.SECONDS)) { "the test never let the first push finish" }
                }
                published += value
                inside.decrementAndGet()
            },
        )

        val first = async(Dispatchers.IO) { publisher.publishCurrent() }
        check(firstIsInside.await(5, TimeUnit.SECONDS)) { "the first push never started" }

        // Undispatched: the second caller runs right here, on this thread, up to
        // its first suspension — which is the wait for its turn. When launch
        // returns it is parked there (or, without the lock, has already pushed),
        // so nothing below depends on timing.
        val second = launch(start = CoroutineStart.UNDISPATCHED) { publisher.publishCurrent() }
        current.set("cellular/TCP") // the state moves on while it waits
        letFirstFinish.countDown()

        withTimeout(5_000) {
            first.await()
            second.join()
        }
        assertEquals("two pushes ran side by side", 0, overlapped.get())
        assertEquals(listOf("wifi/UDP", "cellular/TCP"), published.toList())
    }
}
