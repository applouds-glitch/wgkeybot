/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.model

import com.wireguard.android.model.PeerConflictAlert.Step
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class PeerConflictAlertTest {
    @Test
    fun `alerts once per conflict and clears when it ends`() {
        val a = PeerConflictAlert()
        assertEquals(Step.NONE, a.poll(0))
        assertEquals(Step.ALERT, a.poll(40))
        assertEquals(Step.NONE, a.poll(70))
        assertEquals(Step.NONE, a.poll(400))
        assertEquals(Step.CLEAR, a.poll(0))
        assertFalse(a.alerted)
        assertEquals(Step.NONE, a.poll(0))
        // A second conflict later is told again.
        assertEquals(Step.ALERT, a.poll(5))
    }

    @Test
    fun `no tunnel up reads as no conflict`() {
        val a = PeerConflictAlert()
        assertEquals(Step.NONE, a.poll(-1))
        assertEquals(Step.ALERT, a.poll(1))
        assertEquals(Step.CLEAR, a.poll(-1))
    }
}
