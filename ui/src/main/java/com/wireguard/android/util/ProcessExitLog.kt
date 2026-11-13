/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.util.Log
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * How this app's earlier processes ended, written into the journal at start.
 *
 * A process that the system kills leaves no line of its own: the journal just
 * stops, and the next one starts minutes or hours later, so "the VPN went off
 * by itself overnight" could not be told apart — low memory, a vendor's battery
 * manager, an ANR, a native crash, the user's swipe or an update all look the
 * same from inside. Android keeps the answer (API 30+), and this copies it next
 * to the lines of the process that reads it. The idea is free-turn-proxy's
 * (ProcessExitReporter, v5.0.0).
 *
 * Each exit is written once: the ones already written are remembered by
 * timestamp and pid. Not by a newest-timestamp watermark, because the system
 * may file a record some time after the death it describes, behind a later one.
 */
internal object ProcessExitLog {
    private const val TAG = "WireGuard/ProcessExit"
    private const val PREFS = "process_exits"
    private const val KEY_REPORTED = "reported"

    /** What the system is asked for; it keeps about this many per package. */
    private const val ASKED = 16

    /** Twice [ASKED], so an id is not forgotten while the system can still return it. */
    const val REMEMBERED = 32

    data class Exit(
        val timestamp: Long,
        val pid: Int,
        val process: String,
        val reason: Int,
        val status: Int,
        val importance: Int,
        val description: String?,
    ) {
        val id: String get() = "$timestamp:$pid"
    }

    /**
     * The app's own processes. The system files the WebView's sandboxed renderers
     * under the package that used them ("…webview:sandboxed_process0:…"), one for
     * every death of ours — half the records, each saying only that a renderer
     * was no longer needed (seen on the Pixel, 2026-11-11).
     */
    fun own(exits: List<Exit>, packageName: String): List<Exit> =
        exits.filter { it.process == packageName || it.process.startsWith("$packageName:") }

    /** The exits not written yet, oldest first. */
    fun fresh(exits: List<Exit>, reported: Set<String>): List<Exit> =
        exits.filter { it.id !in reported }.sortedBy { it.timestamp }

    /** The ids to remember after writing [exits]: the newest [REMEMBERED]. */
    fun remembered(exits: List<Exit>, reported: Set<String>): Set<String> =
        (reported + exits.map { it.id })
            .sortedBy { it.substringBefore(':').toLongOrNull() ?: 0L }
            .takeLast(REMEMBERED)
            .toSet()

    fun line(exit: Exit, at: String): String {
        val description = exit.description.orEmpty().take(200).replace('\n', ' ').replace('\r', ' ')
        return "earlier process ${exit.process} pid=${exit.pid} ended at $at: ${reasonName(exit.reason)}" +
            " status=${exit.status} importance=${exit.importance}" +
            if (description.isEmpty()) "" else " ($description)"
    }

    /** ApplicationExitInfo.REASON_*, by value: the names are API 30+, the numbers are not. */
    fun reasonName(reason: Int): String = when (reason) {
        0 -> "unknown"
        1 -> "exit by itself"
        2 -> "killed by a signal"
        3 -> "low memory"
        4 -> "crash"
        5 -> "native crash"
        6 -> "ANR"
        7 -> "initialization failure"
        8 -> "permission change"
        9 -> "excessive resource usage"
        10 -> "user requested"
        11 -> "user stopped"
        12 -> "dependency died"
        13 -> "other"
        14 -> "freezer"
        15 -> "package state change"
        16 -> "package updated"
        else -> "reason $reason"
    }

    /** Reads the system's records and logs the new ones. Does disk and binder work. */
    fun report(context: Context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return
        try {
            val manager = context.getSystemService(ActivityManager::class.java) ?: return
            val exits = own(
                manager.getHistoricalProcessExitReasons(context.packageName, 0, ASKED).map {
                    Exit(it.timestamp, it.pid, it.processName, it.reason, it.status, it.importance, it.description)
                },
                context.packageName,
            )
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val reported = prefs.getStringSet(KEY_REPORTED, emptySet()).orEmpty()
            // The journal's own clock: logcat's threadtime, in local time.
            val clock = SimpleDateFormat("MM-dd HH:mm:ss", Locale.US)
            for (exit in fresh(exits, reported)) Log.i(TAG, line(exit, clock.format(Date(exit.timestamp))))
            val keep = remembered(exits, reported)
            if (keep != reported) prefs.edit().putStringSet(KEY_REPORTED, keep).apply()
        } catch (e: Exception) {
            Log.w(TAG, "the system's exit records are unavailable: ${e.javaClass.simpleName}")
        }
    }
}
