package com.wireguard.android.updater

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdatePolicyTest {
    @Test fun acceptsDirectAndSignedHttpsDownloadLinks() {
        assertTrue(UpdatePolicy.isSecureUrl("https://key.shadowgate.online/app.apk"))
        assertTrue(UpdatePolicy.isSecureUrl("https://release-assets.githubusercontent.com/file?sig=abc%2B123&expires=100"))
    }

    @Test fun rejectsDowngradeRedirectsAndNonNetworkUris() {
        for (url in listOf("http://example.com/app.apk", "file:///data/app.apk", "content://apk/1",
            "intent://install", "https:///app.apk", "https://", "not a URL", "")) {
            assertFalse(url, UpdatePolicy.isSecureUrl(url))
        }
    }

    @Test fun rejectsEmbeddedCredentialsAndFragments() {
        assertFalse(UpdatePolicy.isSecureUrl("https://user:password@example.com/app.apk"))
        assertFalse(UpdatePolicy.isSecureUrl("https://example.com/app.apk#download"))
    }

    @Test fun acceptsSameSignerAndForwardRotation() {
        assertTrue(UpdatePolicy.compatibleSigners(setOf("old"), setOf("old"), emptySet()))
        assertTrue(UpdatePolicy.compatibleSigners(setOf("old"), setOf("new"), setOf("old", "new")))
    }

    @Test fun rejectsUnrelatedOrMissingSigners() {
        assertFalse(UpdatePolicy.compatibleSigners(setOf("release"), setOf("debug"), setOf("debug")))
        assertFalse(UpdatePolicy.compatibleSigners(emptySet(), emptySet(), emptySet()))
        assertFalse(UpdatePolicy.compatibleSigners(setOf("release"), emptySet(), setOf("release")))
    }

    @Test fun rejectsReverseRotationEvenWithHigherVersionCode() {
        assertFalse(UpdatePolicy.compatibleSigners(setOf("new"), setOf("old"), setOf("old")))
    }

    @Test fun requiresExactSignerSetForMultipleSigners() {
        assertTrue(UpdatePolicy.compatibleSigners(setOf("a", "b"), setOf("b", "a"), emptySet()))
        assertFalse(UpdatePolicy.compatibleSigners(setOf("a", "b"), setOf("a"), setOf("a", "b")))
        assertFalse(UpdatePolicy.compatibleSigners(setOf("a"), setOf("a", "b"), setOf("a")))
    }
}
