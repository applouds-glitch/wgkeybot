/* SPDX-License-Identifier: Apache-2.0 */

package com.wireguard.android.turn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VkLinksTest {
    @Test
    fun `a link reduces to its join hash the way the native side reduces it`() {
        assertEquals("abc_-123", VkLinks.hash("https://vk.ru/call/join/abc_-123"))
        assertEquals("abc_-123", VkLinks.hash("https://vk.com/call/join/abc_-123?x=1#top"))
        assertEquals("abc_-123", VkLinks.hash("vk.com/call/join/abc_-123/"))
        assertEquals("abc_-123", VkLinks.hash("  abc_-123  "))
    }

    @Test
    fun `text that is not a call link is refused`() {
        assertNull(VkLinks.hash(""))
        assertNull(VkLinks.hash("https://vk.com/id1"))
        assertNull(VkLinks.hash("https://vk.com/call/join/"))
        assertNull(VkLinks.hash("short"))
        assertNull(VkLinks.hash("has space"))
    }

    @Test
    fun `entries split on lines, commas, pipes and spaces, without repeats`() {
        val parsed = VkLinks.parse(
            "https://vk.ru/call/join/first_1\n" +
                "second_2, https://vk.com/call/join/first_1 | third_3 fourth_4\r\n",
        )
        assertEquals(listOf("first_1", "second_2", "third_3", "fourth_4"), parsed.hashes)
        assertEquals(emptyList<String>(), parsed.invalid)
        assertFalse(parsed.truncated)
    }

    @Test
    fun `invalid entries are reported and the rest kept`() {
        val parsed = VkLinks.parse("first_1\nhttps://vk.com/im\nsecond_2")
        assertEquals(listOf("first_1", "second_2"), parsed.hashes)
        assertEquals(listOf("https://vk.com/im"), parsed.invalid)
    }

    @Test
    fun `more than eight links are cut to eight and flagged`() {
        val text = (1..9).joinToString("\n") { "hash_number_$it" }
        val parsed = VkLinks.parse(text)
        assertEquals(VkLinks.MAX, parsed.hashes.size)
        assertEquals("hash_number_8", parsed.hashes.last())
        assertTrue(parsed.truncated)
    }

    @Test
    fun `a config's VKLink splits on commas and pipes like the proxy`() {
        assertEquals(listOf("a_link_1", "b_link_2", "c_link_3"), VkLinks.split(" a_link_1 , b_link_2|c_link_3,"))
        assertEquals(emptyList<String>(), VkLinks.split(""))
    }
}
