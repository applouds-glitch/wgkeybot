/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant
import java.time.ZoneId

class SubscriptionStatusTest {
    private val now = Instant.parse("2026-11-13T12:00:00Z")

    @Test
    fun `a date ahead is active until that date`() {
        val until = Instant.parse("2027-02-01T00:00:00Z")
        assertEquals(SubscriptionStatus.Active(until), SubscriptionStatus.of("2027-02-01T00:00:00Z", now))
    }

    @Test
    fun `a date behind is expired`() {
        assertEquals(SubscriptionStatus.Expired, SubscriptionStatus.of("2026-11-12T23:59:59Z", now))
    }

    /** The very moment it runs out is no longer paid for. */
    @Test
    fun `the expiry moment itself is expired`() {
        assertEquals(SubscriptionStatus.Expired, SubscriptionStatus.of("2026-11-13T12:00:00Z", now))
    }

    /** A refresh writes the epoch when the server rejects the key (401). */
    @Test
    fun `the epoch written for a rejected key reads as expired, not as a date`() {
        assertEquals(SubscriptionStatus.Expired, SubscriptionStatus.of("1970-01-01T00:00:00Z", now))
    }

    @Test
    fun `nothing stored or nothing readable shows nothing`() {
        assertEquals(SubscriptionStatus.Unknown, SubscriptionStatus.of(null, now))
        assertEquals(SubscriptionStatus.Unknown, SubscriptionStatus.of("", now))
        assertEquals(SubscriptionStatus.Unknown, SubscriptionStatus.of("13.12.2026", now))
    }

    @Test
    fun `the year is written only for a date in another year`() {
        val utc = ZoneId.of("UTC")
        assertFalse(SubscriptionStatus.showsYear(Instant.parse("2026-12-31T20:00:00Z"), now, utc))
        assertTrue(SubscriptionStatus.showsYear(Instant.parse("2027-01-01T00:00:00Z"), now, utc))
    }

    /** The year is the user's: New Year's Eve in UTC is already next year in Moscow. */
    @Test
    fun `the year is counted in the user's zone`() {
        val until = Instant.parse("2026-12-31T22:00:00Z")
        assertFalse(SubscriptionStatus.showsYear(until, now, ZoneId.of("UTC")))
        assertTrue(SubscriptionStatus.showsYear(until, now, ZoneId.of("Europe/Moscow")))
    }
}
