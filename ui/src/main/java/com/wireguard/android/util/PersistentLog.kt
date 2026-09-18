/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */
package com.wireguard.android.util

import android.os.Process
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStream

/**
 * This process's own log lines, kept on disk.
 *
 * The in-app journal is the device's logcat, and logcat is a ring buffer shared
 * with the whole OS: on a busy ROM (MIUI/HyperOS floods it with UI chatter) the
 * TURN session's start was evicted within minutes, so an exported "it broke"
 * log began seven minutes before the failure and could not say which relay each
 * stream was on or what preceded it. A child `logcat --pid=<ours>` copies the
 * lines this process writes under WireGuard/… tags — Go, C and Kotlin alike, so
 * no logging call had to change — into a rotating file as they appear, before
 * anything can evict them. logd applies the pid filter itself, so the child
 * wakes only for our own lines. The journal export puts this file first.
 */
class PersistentLog(dir: File) {
    private val file = RotatingLogFile(dir, MAX_FILE_BYTES)

    fun start(scope: CoroutineScope) {
        scope.launch(Dispatchers.IO) { tail() }
    }

    /** Everything kept so far, oldest first; empty if nothing could be read. */
    fun snapshot(): ByteArray = file.snapshot()

    private suspend fun tail() {
        val pid = Process.myPid()
        // After a restart of the child, resume from the last kept line instead
        // of replaying the process's whole buffered history into the file again.
        // -T is inclusive, so the boundary line may repeat once; that is all.
        var since: String? = null
        var backoffMs = MIN_RESTART_DELAY_MS
        while (currentCoroutineContext().isActive) {
            val command = mutableListOf("logcat", "--pid=$pid", "-v", "threadtime")
            since?.let { command += listOf("-T", it) }
            val startedAt = System.currentTimeMillis()
            try {
                val process = ProcessBuilder(command).redirectErrorStream(true)
                    .apply { environment()["LC_ALL"] = "C" }
                    .start()
                try {
                    BufferedReader(InputStreamReader(process.inputStream, Charsets.UTF_8)).use { reader ->
                        file.copyFrom(reader)?.let { since = it }
                    }
                } finally {
                    process.destroy()
                }
            } catch (e: IOException) {
                Log.w(TAG, "logcat tail failed: ${e.message}")
            }
            // A child that dies straight away (a ROM that refuses logcat, say)
            // must not turn into a process spawn every few seconds for as long
            // as the app lives; one that ran for a while earns a quick restart.
            backoffMs = if (System.currentTimeMillis() - startedAt > HEALTHY_RUN_MS) MIN_RESTART_DELAY_MS
            else (backoffMs * 2).coerceAtMost(MAX_RESTART_DELAY_MS)
            delay(backoffMs)
        }
    }

    companion object {
        private const val TAG = "WireGuard/PersistentLog"

        // Two files of this size at most: ~4 MiB on disk. A healthy session writes
        // ~25 KB an hour (one WireGuard keepalive line per 25s, a handshake pair
        // per 2 min), so that is days of history; a session stuck reconnecting
        // writes a few lines a second, and still keeps the last couple of hours.
        const val MAX_FILE_BYTES = 2L * 1024 * 1024

        private const val MIN_RESTART_DELAY_MS = 5_000L
        private const val MAX_RESTART_DELAY_MS = 5 * 60_000L
        private const val HEALTHY_RUN_MS = 60_000L
    }
}

/** Reading one `logcat -v threadtime` line: which tag it carries, and when. */
internal object LogcatLine {
    // "09-18 08:16:52.052 19700 25316 I WireGuard/TurnClient: [DISPATCH] ..."
    // Same shape LogViewerActivity parses, including the optional uid column.
    private val THREADTIME =
        Regex("""^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})(?:\s+[0-9A-Za-z]+)?\s+\d+\s+\d+\s+[A-Z]\s+(.+?)\s*: """)

    fun tag(line: String): String? = THREADTIME.find(line)?.groupValues?.get(2)

    fun timestamp(line: String): String? = THREADTIME.find(line)?.groupValues?.get(1)

    /**
     * Ours to keep: every WireGuard/… tag (TURN client, JNI, the Go backend, the
     * Kotlin managers) plus AndroidRuntime, which is where this process's own
     * crash stack lands. The framework's per-app chatter from the same pid —
     * insets, input, render thread — is exactly what drowned the journal.
     */
    fun keep(line: String): Boolean {
        val tag = tag(line) ?: return false
        return tag.startsWith("WireGuard/") || tag == "AndroidRuntime"
    }
}

/**
 * An append-only text file that rotates into one previous generation, so the
 * pair never grows past twice [maxBytes] (plus one line).
 */
internal class RotatingLogFile(private val dir: File, private val maxBytes: Long) {
    private val current = File(dir, NAME)
    private val previous = File(dir, "$NAME.1")
    private var out: OutputStream? = null
    private var size = 0L

    /**
     * Copies the lines [LogcatLine.keep] accepts until [reader] ends, flushing
     * whenever the reader has nothing more buffered — a burst is written in
     * one go, and nothing sits unwritten while the log is quiet. Returns the
     * timestamp of the last kept line, or null if none was kept.
     */
    fun copyFrom(reader: BufferedReader): String? {
        var last: String? = null
        while (true) {
            val line = reader.readLine() ?: break
            if (LogcatLine.keep(line)) {
                append(line)
                last = LogcatLine.timestamp(line) ?: last
            }
            if (!reader.ready()) flush()
        }
        flush()
        return last
    }

    /** Never throws: logging must not be what takes the app down. */
    @Synchronized
    fun append(line: String) {
        try {
            val bytes = (line + "\n").toByteArray(Charsets.UTF_8)
            if (out == null) open()
            if (size > 0 && size + bytes.size > maxBytes) {
                rotate()
                open()
            }
            out!!.write(bytes)
            size += bytes.size
        } catch (_: IOException) {
            closeQuietly()
        }
    }

    @Synchronized
    fun flush() {
        try {
            out?.flush()
        } catch (_: IOException) {
            closeQuietly()
        }
    }

    /** The previous generation followed by the current one; empty on any failure. */
    @Synchronized
    fun snapshot(): ByteArray {
        flush()
        return try {
            (if (previous.exists()) previous.readBytes() else ByteArray(0)) +
                (if (current.exists()) current.readBytes() else ByteArray(0))
        } catch (_: IOException) {
            ByteArray(0)
        }
    }

    // Appends to whatever an earlier process left: the history across restarts
    // is the point, and the size on disk is what the rotation budget counts.
    private fun open() {
        dir.mkdirs()
        size = current.length()
        out = FileOutputStream(current, true).buffered(BUFFER_BYTES)
    }

    private fun rotate() {
        closeQuietly()
        previous.delete()
        current.renameTo(previous)
        size = 0
    }

    private fun closeQuietly() {
        try {
            out?.close()
        } catch (_: IOException) {
        }
        out = null
    }

    companion object {
        const val NAME = "wireguard.log"
        private const val BUFFER_BYTES = 16 * 1024
    }
}
