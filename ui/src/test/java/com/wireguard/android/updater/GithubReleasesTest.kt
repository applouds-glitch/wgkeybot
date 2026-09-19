/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.updater

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class GithubReleasesTest {
    private val repo = "someone/wgkeybot"

    @Test
    fun `the tag is read off the redirect of releases-latest`() {
        assertEquals("v2.0.6", GithubReleases.tagFromLocation(repo, "https://github.com/someone/wgkeybot/releases/tag/v2.0.6"))
        // GitHub answers with the repository's canonical spelling, whatever was asked for.
        assertEquals("v2.0.6", GithubReleases.tagFromLocation(repo, "https://github.com/SomeOne/WGKeyBot/releases/tag/v2.0.6"))
    }

    @Test
    fun `a repository without releases redirects to the list, which names no version`() {
        assertNull(GithubReleases.tagFromLocation(repo, "https://github.com/someone/wgkeybot/releases"))
        assertNull(GithubReleases.tagFromLocation(repo, "https://github.com/someone/wgkeybot/releases/tag/"))
        assertNull(GithubReleases.tagFromLocation(repo, null))
        assertNull(GithubReleases.tagFromLocation(repo, "not a url at all ::"))
    }

    @Test
    fun `a redirect to some other repository is not an answer`() {
        assertNull(GithubReleases.tagFromLocation(repo, "https://github.com/someone-else/wgkeybot/releases/tag/v9.9.9"))
        assertNull(GithubReleases.tagFromLocation(repo, "https://github.com/someone/wgkeybot/releases/tag/v1.0.0/extra"))
    }

    @Test
    fun `only a tag that is a version counts`() {
        assertEquals("2.0.6", GithubReleases.versionOf("v2.0.6"))
        assertEquals("2.0.6", GithubReleases.versionOf("2.0.6"))
        assertNull(GithubReleases.versionOf("nightly"))
        assertNull(GithubReleases.versionOf("v2"))
        assertNull(GithubReleases.versionOf("v2.0.6-rc1"))
        assertNull(GithubReleases.versionOf(""))
    }

    @Test
    fun `the apk is fetched from the release the tag names`() {
        assertEquals(
            "https://github.com/someone/wgkeybot/releases/download/v2.0.6/wgkeybot-signed.apk",
            GithubReleases.downloadUrl(repo, "v2.0.6"),
        )
        assertTrue(UpdatePolicy.isSecureUrl(GithubReleases.downloadUrl(repo, "v2.0.6")))
    }

    @Test
    fun `newer means a higher number, not a different string`() {
        assertTrue(GithubReleases.isNewer("2.0.6", "2.0.5"))
        assertTrue(GithubReleases.isNewer("2.1.0", "2.0.9"))
        assertTrue(GithubReleases.isNewer("2.0.10", "2.0.9"))
        assertFalse(GithubReleases.isNewer("2.0.5", "2.0.5"))
        assertFalse(GithubReleases.isNewer("2.0.4", "2.0.5"))
    }

    @Test
    fun `a debug build's suffix is not part of its version`() {
        assertTrue(GithubReleases.isNewer("1.4.1", "1.4.0-debug"))
        assertFalse(GithubReleases.isNewer("1.4.0", "1.4.0-debug"))
    }

    @Test
    fun `an empty or malformed repository offers no check`() {
        assertTrue(GithubReleases.isRepo("someone/wgkeybot"))
        assertFalse(GithubReleases.isRepo(""))
        assertFalse(GithubReleases.isRepo("wgkeybot"))
        assertFalse(GithubReleases.isRepo("https://github.com/someone/wgkeybot"))
        assertFalse(GithubReleases.isRepo("someone/wgkeybot/releases"))
    }
}
