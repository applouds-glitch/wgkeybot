/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.content.Context
import android.text.format.DateFormat
import java.text.SimpleDateFormat
import java.time.Instant
import java.time.ZoneId
import java.util.Date

/**
 * What the stored subscription date ([AuthStore.getSubscriptionExpiresAt]) says,
 * for the two places that show it: the summary card at the top of the settings
 * and the TV's header pill. Kept apart from the formatting below so the JVM
 * tests can pin it.
 */
sealed interface SubscriptionStatus {
    /** No date stored, or one that does not parse: there is nothing to show. */
    data object Unknown : SubscriptionStatus

    /**
     * Past its date. That includes the epoch a config refresh writes when the
     * server rejects the key (401), which reads "expired", never "until
     * 1 January 1970".
     */
    data object Expired : SubscriptionStatus

    data class Active(val until: Instant) : SubscriptionStatus

    companion object {
        fun of(raw: String?, now: Instant): SubscriptionStatus {
            if (raw == null) return Unknown
            val until = try {
                Instant.parse(raw)
            } catch (_: Exception) {
                return Unknown
            }
            return if (until.isAfter(now)) Active(until) else Expired
        }

        /**
         * The year is written only when the date falls in another one: "12 ноября"
         * this year, "12 ноября 2027" past the new year.
         */
        fun showsYear(until: Instant, now: Instant, zone: ZoneId): Boolean =
            until.atZone(zone).year != now.atZone(zone).year
    }
}

/**
 * The day an active subscription runs to, as the user's locale writes a day and
 * a month ("12 ноября", "November 12"), with the year as [SubscriptionStatus.showsYear]
 * decides.
 */
fun Context.formatSubscriptionDay(until: Instant, now: Instant = Instant.now()): String {
    val locale = resources.configuration.locales[0]
    val skeleton = if (SubscriptionStatus.showsYear(until, now, ZoneId.systemDefault())) "dMMMMyyyy" else "dMMMM"
    return SimpleDateFormat(DateFormat.getBestDateTimePattern(locale, skeleton), locale)
        .format(Date(until.toEpochMilli()))
}
