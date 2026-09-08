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
