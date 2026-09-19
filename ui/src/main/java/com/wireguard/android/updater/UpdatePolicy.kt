package com.wireguard.android.updater

import java.net.URI

/** Checks shared by initial downloads, redirects and APK validation. */
internal object UpdatePolicy {
    const val MAX_APK_BYTES = 256L * 1024 * 1024

    fun isSecureUrl(value: String): Boolean = runCatching {
        val uri = URI(value)
        uri.scheme.equals("https", ignoreCase = true) &&
            !uri.host.isNullOrBlank() && uri.rawUserInfo == null && uri.rawFragment == null
    }.getOrDefault(false)

    /** MAJOR.MINOR.PATCH, numerically; a missing or unreadable part counts as 0. */
    fun compareVersions(a: String, b: String): Int {
        val ap = a.split(".").map { it.toIntOrNull() ?: 0 }
        val bp = b.split(".").map { it.toIntOrNull() ?: 0 }
        for (i in 0..2) {
            val diff = ap.getOrElse(i) { 0 } - bp.getOrElse(i) { 0 }
            if (diff != 0) return diff
        }
        return 0
    }

    fun compatibleSigners(
        installed: Set<String>,
        incoming: Set<String>,
        incomingHistory: Set<String>,
    ): Boolean {
        if (installed.isEmpty() || incoming.isEmpty()) return false
        if (installed == incoming) return true
        // Rotation is only supported for a single signer. Use the incoming
        // lineage: an old APK must not pass merely because we once trusted it.
        return installed.size == 1 && incoming.size == 1 &&
            incomingHistory.containsAll(installed)
    }
}
