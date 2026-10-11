/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.turn

import android.util.Log
import com.wireguard.android.Application
import com.wireguard.android.backend.TurnBackend
import com.wireguard.android.util.applicationScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Runs the native VK link check ([TurnBackend.wgTurnCheckVKLink]) over a list
 * of join hashes, one after another, and publishes the verdicts as they come.
 *
 * Process-scoped, like the routing screen's work: a check takes seconds per
 * link and up to ~45 s for one VK cannot reach, and the user who backs out of
 * the screen meanwhile must find the verdicts waiting on return rather than a
 * check that died with the activity. One run at a time — VK's flood control is
 * per client, and the proxy's own fetches admit two at once — and each run
 * names which list it judged, so the screen can show the verdicts under the
 * right field.
 */
object VkLinkChecker {
    private const val TAG = "WireGuard/VkLinkChecker"

    enum class Target { OWN, CONFIG }

    /** One link's verdict: its position in the list and a `LINK_CHECK_*` code. */
    data class Result(val index: Int, val code: Int)

    data class Progress(
        val target: Target? = null,
        val running: Boolean = false,
        val total: Int = 0,
        val results: List<Result> = emptyList(),
    )

    private val _state = MutableStateFlow(Progress())
    val state: StateFlow<Progress> = _state.asStateFlow()

    /** Starts a run; false when one is already running. */
    fun start(target: Target, hashes: List<String>): Boolean {
        synchronized(this) {
            if (_state.value.running) return false
            _state.value = Progress(target = target, running = true, total = hashes.size)
        }
        applicationScope.launch {
            try {
                for ((index, hash) in hashes.withIndex()) {
                    val code = check(hash)
                    // Position only: the link itself stays out of the log.
                    Log.i(TAG, "link ${index + 1} of ${hashes.size}: verdict $code")
                    _state.value = _state.value.let { it.copy(results = it.results + Result(index, code)) }
                }
            } finally {
                _state.value = _state.value.copy(running = false)
            }
        }
        return true
    }

    private suspend fun check(hash: String): Int = withContext(Dispatchers.IO) {
        try {
            // The backend's construction is what loads the native library.
            Application.getBackend()
            TurnBackend.wgTurnCheckVKLink(hash)
        } catch (e: UnsatisfiedLinkError) {
            // A build whose native library predates the entry point (Apply
            // Changes updates the dex, never the .so): say "try later" rather
            // than take the process down over a diagnostic.
            Log.e(TAG, "native link check unavailable", e)
            TurnBackend.LINK_CHECK_TEMPORARY
        }
    }
}
