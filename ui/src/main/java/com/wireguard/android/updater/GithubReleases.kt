/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.updater

import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

/**
 * What the newest release on GitHub is, asked for by hand from the settings.
 *
 * The answer is read off a redirect, not off the API: `/releases/latest` answers
 * 302 to `/releases/tag/<tag>`, and the tag is the version. api.github.com would
 * say the same in JSON, but it allows an unauthenticated address 60 requests an
 * hour — and this app's own traffic leaves through the tunnel, so every user of
 * one server is one address to GitHub. The page redirect carries no such quota.
 *
 * The price is that the asset's name cannot be looked up and has to be known:
 * it is whatever release.yml uploads ([ASSET]), and the two change together.
 * What is downloaded is not trusted for having come from here — [AppUpdater]
 * checks the package name, the version code and the signing certificate against
 * the installed app before anything is handed to the installer.
 */
internal object GithubReleases {
    data class Release(val version: String, val downloadUrl: String)

    /** `wgkeybot.apk` as release.yml names it, after r0adkll/sign-android-release. */
    const val ASSET = "wgkeybot-signed.apk"

    private val REPO = Regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    private val VERSION = Regex("^\\d+(\\.\\d+){1,3}$")

    fun isRepo(value: String): Boolean = REPO.matches(value)

    fun latestUrl(repo: String): String = "https://github.com/$repo/releases/latest"

    /**
     * The tag out of where `/releases/latest` redirects to. A repository without
     * a single release redirects to `/releases`, which has no tag in it; anything
     * that is not this repository's own tag page is not an answer either.
     */
    fun tagFromLocation(repo: String, location: String?): String? {
        val path = runCatching { URI(location ?: return null).path }.getOrNull() ?: return null
        val prefix = "/$repo/releases/tag/"
        if (!path.startsWith(prefix, ignoreCase = true)) return null
        return path.substring(prefix.length).takeIf { it.isNotEmpty() && '/' !in it }
    }

    /** `v2.0.6` → `2.0.6`; a tag that is not a version (a nightly, a draft name) is none. */
    fun versionOf(tag: String): String? = tag.removePrefix("v").takeIf { VERSION.matches(it) }

    fun downloadUrl(repo: String, tag: String): String =
        "https://github.com/$repo/releases/download/$tag/$ASSET"

    /**
     * Whether [latest] is ahead of what is [installed]. A debug build calls itself
     * `1.4.0-debug`; the suffix is not part of the number.
     */
    fun isNewer(latest: String, installed: String): Boolean =
        UpdatePolicy.compareVersions(latest, installed.substringBefore('-')) > 0

    /** Blocking; call off the main thread. */
    fun latest(repo: String): Release {
        if (!isRepo(repo)) throw IOException("No release repository configured")
        val connection = (URL(latestUrl(repo)).openConnection() as HttpURLConnection).apply {
            instanceFollowRedirects = false
            requestMethod = "HEAD"
            // A bodyless reply and transparent gzip do not get along on older Android.
            setRequestProperty("Accept-Encoding", "identity")
            connectTimeout = 10_000
            readTimeout = 10_000
        }
        try {
            val code = connection.responseCode
            if (code !in listOf(301, 302, 303, 307, 308)) throw IOException("HTTP $code")
            val tag = tagFromLocation(repo, connection.getHeaderField("Location"))
                ?: throw NoReleaseException()
            val version = versionOf(tag) ?: throw NoReleaseException()
            return Release(version, downloadUrl(repo, tag))
        } finally {
            connection.disconnect()
        }
    }

    /** GitHub answered, and what it named is not a release of this app. */
    class NoReleaseException : IOException("No published release")
}
