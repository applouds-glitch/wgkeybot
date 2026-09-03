/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.tether

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

private const val TAG = "WireGuard/TetherRouting"

/**
 * Keeps a Happ routing profile and its geodata on disk for the native sharing
 * proxy to read (tether_route.go).
 *
 * The profile (WHITELIST.JSON) is a kilobyte of JSON that names the rules and
 * links the two files the rules point into, geosite.dat and geoip.dat. Those
 * links are version-pinned (a jsDelivr tag), so a file is fetched again only
 * when the profile starts naming a different URL — the profile itself is
 * re-read at most every [REFRESH_MS], and only when sharing starts, since that
 * is the only moment the files are opened.
 *
 * Everything lands in [dir] under fixed names Go knows, written to a temporary
 * file and renamed into place so a download that dies halfway never leaves a
 * truncated file where a complete one was.
 *
 * Downloads run through whatever network the app has — the tunnel, while it is
 * up, which is exactly when sharing starts. That is deliberate: the sources are
 * GitHub and jsDelivr, neither of them reliably reachable from a Russian uplink.
 */
object TetherRouting {
    private const val PREFS = "tether"
    private const val KEY_FETCHED_AT = "routing_fetched_at"
    private const val KEY_FETCHED_URL = "routing_fetched_url"
    private const val KEY_GEOIP_URL = "routing_geoip_url"
    private const val KEY_GEOSITE_URL = "routing_geosite_url"

    private const val PROFILE_FILE = "profile.json"
    private const val GEOSITE_FILE = "geosite.dat"
    private const val GEOIP_FILE = "geoip.dat"

    private const val REFRESH_MS = 6L * 60 * 60 * 1000
    private const val CONNECT_TIMEOUT_MS = 15_000
    private const val READ_TIMEOUT_MS = 30_000
    /** The real files are a few hundred kilobytes; this only catches a download that is not the file at all. */
    private const val MAX_FILE_BYTES = 16L * 1024 * 1024

    /**
     * One refresh at a time. The switch, the update button and a sharing start
     * can all ask at once, and two downloads of the same file share a .tmp
     * name: one would rename the other's half-written file into place.
     */
    private val refreshLock = Mutex()

    fun dir(context: Context): File = File(context.filesDir, "tether-routing")

    /**
     * The directory when it holds a complete set of files fetched from the
     * profile address configured right now, else null. Reads disk, no network.
     *
     * The address is part of the question and not a detail: pointed at a new
     * profile, the files on disk belong to the old one, and handing them to the
     * native side would route by rules the user just replaced.
     */
    suspend fun cachedDir(context: Context): File? = withContext(Dispatchers.IO) {
        val dir = dir(context)
        dir.takeIf { isComplete(it) && fetchedUrl(context) == TetherSettings.routingProfileUrl(context) }
    }

    private fun fetchedUrl(context: Context): String? =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY_FETCHED_URL, null)

    /**
     * What the routing settings screen shows about the files on disk. Null when
     * no profile has been fetched yet.
     */
    data class Info(
        val name: String,
        /** The profile's own LastUpdated, epoch seconds; 0 when it names none. */
        val rulesUpdatedAt: Long,
        val domesticDns: String,
        val geoipUrl: String,
        val geositeUrl: String,
        val geoipBytes: Long,
        val geositeBytes: Long,
        /** When the profile was last fetched, epoch millis; 0 when never. */
        val fetchedAt: Long,
    )

    suspend fun info(context: Context): Info? = withContext(Dispatchers.IO) {
        val dir = dir(context)
        val profile = File(dir, PROFILE_FILE)
        if (!profile.isFile) return@withContext null
        val json = try {
            JSONObject(profile.readText())
        } catch (e: Exception) {
            Log.w(TAG, "cannot read the stored routing profile", e)
            return@withContext null
        }
        Info(
            name = json.optString("Name").ifEmpty { PROFILE_FILE },
            rulesUpdatedAt = json.optString("LastUpdated").toLongOrNull() ?: 0L,
            domesticDns = json.optString("DomesticDns"),
            geoipUrl = json.optString("Geoipurl"),
            geositeUrl = json.optString("Geositeurl"),
            geoipBytes = File(dir, GEOIP_FILE).length(),
            geositeBytes = File(dir, GEOSITE_FILE).length(),
            fetchedAt = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getLong(KEY_FETCHED_AT, 0L),
        )
    }

    /**
     * Makes sure a usable profile is on disk and returns its directory, or null
     * when there is none — nothing cached and nothing fetchable. A stale cache
     * beats no cache: a failed refresh keeps whatever was there. force skips the
     * freshness window: the "update now" button.
     */
    suspend fun prepare(context: Context, force: Boolean = false): File? = refreshLock.withLock {
        withContext(Dispatchers.IO) {
            val dir = dir(context).apply { mkdirs() }
            val complete = isComplete(dir)
            try {
                refresh(context, dir, complete, force)
            } catch (e: Exception) {
                // Nothing in here may take the sharing start down with it: the
                // caller awaits this from a coroutine nobody else catches for.
                Log.w(TAG, "routing rules refresh failed", e)
                dir.takeIf { complete }
            }
        }
    }

    private fun refresh(context: Context, dir: File, complete: Boolean, force: Boolean): File? {
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val url = TetherSettings.routingProfileUrl(context)
        // Freshness is per profile address, not per directory. Pointed at a
        // different profile, the app must fetch it now rather than in six hours,
        // and must never report the old profile's files as the new one's.
        val fresh = prefs.getString(KEY_FETCHED_URL, null) == url &&
            System.currentTimeMillis() - prefs.getLong(KEY_FETCHED_AT, 0L) < REFRESH_MS
        if (complete && fresh && !force) return dir

        val profile = try {
            String(download(url), Charsets.UTF_8).also { JSONObject(it) }
        } catch (e: Exception) {
            Log.w(TAG, "cannot fetch the routing profile from $url", e)
            return dir.takeIf { complete }
        }
        val json = JSONObject(profile)
        val geoipUrl = json.optString("Geoipurl").trim()
        val geositeUrl = json.optString("Geositeurl").trim()

        // Geodata first, so the profile on disk never references files that are
        // not there yet: Go refuses a profile whose categories it cannot find.
        val geoipOk = refreshGeoData(dir, GEOIP_FILE, geoipUrl, prefs, KEY_GEOIP_URL)
        val geositeOk = refreshGeoData(dir, GEOSITE_FILE, geositeUrl, prefs, KEY_GEOSITE_URL)
        if (!geoipOk || !geositeOk) {
            return dir.takeIf { complete }
        }
        if (TetherSettings.routingProfileUrl(context) != url) {
            // The address changed while this download was in flight. Storing it
            // now would put the old profile's rules on disk under the new
            // profile's stamp, and every later prepare() would then skip the
            // fetch for the whole refresh window — the user would be routed by
            // the profile they just replaced, while the screen said otherwise.
            Log.i(TAG, "routing profile address changed mid-download; discarding what was fetched")
            return null
        }
        try {
            writeAtomically(File(dir, PROFILE_FILE), profile.toByteArray(Charsets.UTF_8))
        } catch (e: IOException) {
            Log.w(TAG, "cannot store the routing profile", e)
            return dir.takeIf { complete }
        }
        prefs.edit()
            .putLong(KEY_FETCHED_AT, System.currentTimeMillis())
            .putString(KEY_FETCHED_URL, url)
            .apply()
        Log.i(TAG, "routing profile ${json.optString("Name")} updated (${json.optString("LastUpdated")})")
        return dir
    }

    /**
     * Throws away what is on disk. For the native side reporting the files
     * unusable (-5): the next start fetches them afresh rather than failing on
     * the same bytes again.
     */
    fun invalidate(context: Context) {
        dir(context).listFiles()?.forEach { it.delete() }
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .remove(KEY_FETCHED_AT).remove(KEY_FETCHED_URL)
            .remove(KEY_GEOIP_URL).remove(KEY_GEOSITE_URL).apply()
    }

    /**
     * Whether the directory holds everything the profile in it needs: the
     * profile itself, plus each geodata file it actually links.
     *
     * Not "all three files". A profile that references only one .dat is
     * complete without the other — Go opens only what the selectors name — and
     * the blanket rule made this disagree with refresh(), which is happy in the
     * same case: prepare() then handed the directory over while cachedDir()
     * called it empty, so the same session could start with rules and reload
     * without them.
     */
    private fun isComplete(dir: File): Boolean {
        val profile = File(dir, PROFILE_FILE)
        if (!profile.isFile || profile.length() == 0L) return false
        val json = try {
            JSONObject(profile.readText())
        } catch (e: Exception) {
            return false
        }
        fun present(name: String, url: String) =
            url.isEmpty() || File(dir, name).let { it.isFile && it.length() > 0 }
        return present(GEOIP_FILE, json.optString("Geoipurl").trim()) &&
            present(GEOSITE_FILE, json.optString("Geositeurl").trim())
    }

    /**
     * Brings one geodata file up to the URL the profile names. True when the
     * file on disk matches that URL afterwards — including the case where the
     * profile names none and the file is simply not needed.
     */
    private fun refreshGeoData(dir: File, name: String, url: String, prefs: SharedPreferences, key: String): Boolean {
        if (url.isEmpty()) return true
        val file = File(dir, name)
        if (file.isFile && file.length() > 0 && prefs.getString(key, null) == url) return true
        return try {
            writeAtomically(file, download(url))
            prefs.edit().putString(key, url).apply()
            true
        } catch (e: Exception) {
            Log.w(TAG, "cannot fetch $name from $url", e)
            false
        }
    }

    private fun download(urlStr: String): ByteArray {
        val connection = (URL(urlStr).openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            instanceFollowRedirects = true
        }
        try {
            val code = connection.responseCode
            if (code != HttpURLConnection.HTTP_OK) throw IOException("HTTP $code for $urlStr")
            if (connection.contentLengthLong > MAX_FILE_BYTES) throw IOException("$urlStr is too large")
            connection.inputStream.use { input ->
                val out = ByteArrayOutputStream()
                val buf = ByteArray(32 * 1024)
                var total = 0L
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > MAX_FILE_BYTES) throw IOException("$urlStr is too large")
                    out.write(buf, 0, n)
                }
                if (total == 0L) throw IOException("$urlStr is empty")
                return out.toByteArray()
            }
        } finally {
            connection.disconnect()
        }
    }

    private fun writeAtomically(target: File, bytes: ByteArray) {
        val tmp = File(target.parentFile, target.name + ".tmp")
        tmp.writeBytes(bytes)
        if (!tmp.renameTo(target)) {
            tmp.delete()
            throw IOException("cannot move ${tmp.name} into place")
        }
    }
}
