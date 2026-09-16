/* SPDX-License-Identifier: Apache-2.0 */

package com.wireguard.android.turn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TurnSettingsTest {
    @Test
    fun `legacy per-credential values are capped without reducing total streams`() {
        val settings = TurnSettings.fromComments(listOf(
            "#@wgt:StreamNum = 21",
            "#@wgt:StreamsPerCred = 16",
        ))!!

        assertEquals(10, settings.streamsPerCred)
        assertEquals(21, settings.streams)
    }

    @Test
    fun `lower credential limits and default remain available`() {
        val default = TurnSettings.fromComments(listOf("#@wgt:EnableTURN = true"))!!
        assertEquals(4, default.streamsPerCred)
        for (count in listOf(1, 4, 10)) {
            val settings = TurnSettings.fromComments(listOf("#@wgt:StreamsPerCred = $count"))!!
            assertEquals(count, settings.streamsPerCred)
        }
    }

    @Test
    fun `validation enforces ten streams per credential independently of total`() {
        val settings = TurnSettings(
            enabled = true,
            peer = "192.0.2.1:56000",
            vkLink = "test-call",
            streams = 21,
            streamsPerCred = 10,
        )
        assertEquals(settings, TurnSettings.validate(settings))
        assertThrows(IllegalArgumentException::class.java) {
            TurnSettings.validate(settings.copy(streamsPerCred = 11))
        }
    }
}
