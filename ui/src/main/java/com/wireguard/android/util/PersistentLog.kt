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
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStream
import java.io.RandomAccessFile
import java.util.Locale

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
 * wakes only for our own lines. The journal export puts the newest part of
 * this file first (see [EXPORT_BYTES]).
 */
class PersistentLog(dir: File) {
    private val file = RotatingLogFile(dir, MAX_FILE_BYTES)

    fun start(scope: CoroutineScope) {
        scope.launch(Dispatchers.IO) { tail() }
    }

    /** The newest [maxBytes] at most, from a line start; see [RotatingLogFile.tail]. */
    internal fun tail(maxBytes: Int): RotatingLogFile.Tail = file.tail(maxBytes)

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
        // ~15 KB an hour (a handshake pair and a line counting the keepalives
        // every 2 min — see wg_log_filter.go), so that is days of history; a
        // session stuck reconnecting writes a few lines a second, and still keeps
        // the last couple of hours.
        const val MAX_FILE_BYTES = 2L * 1024 * 1024

        // What an export carries, which is not what the device keeps. The whole
        // pair — days of an idle tunnel's keepalives, earlier sessions — made
        // exports of 2 MB and more, too much to send or read; the part that is
        // asked about is the latest, and the rest stays on the device.
        const val EXPORT_BYTES = 512 * 1024

        // The device logcat after it: the ROM's own chatter and system events,
        // without our lines, which the part above already has.
        const val EXPORT_DEVICE_BYTES = 128 * 1024

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
 * The exported journal: the newest part of the kept log, then the device logcat
 * without the lines the kept part already has.
 */
internal object LogExport {
    fun compose(
        kept: RotatingLogFile.Tail,
        device: List<String>,
        deviceBytes: Int = PersistentLog.EXPORT_DEVICE_BYTES,
        aloneBytes: Int = PersistentLog.EXPORT_BYTES,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        fun line(text: String) = out.write("$text\n".toByteArray(Charsets.UTF_8))
        if (kept.bytes.isEmpty()) {
            // Nothing kept (a ROM that refused the logcat child): the device
            // logcat is all there is, ours included — bounded all the same.
            device.newest(aloneBytes).forEach(::line)
            return out.toByteArray()
        }
        line(
            "===== app log kept on device (WireGuard/* and crashes)" +
                (if (kept.isWhole) "" else ": the newest ${size(kept.bytes.size.toLong())} of ${size(kept.total)}") +
                " ====="
        )
        out.write(kept.bytes)
        val others = device.filterNot { LogcatLine.tag(it)?.startsWith("WireGuard/") == true }
        val shown = others.newest(deviceBytes)
        line(
            "===== device logcat, all tags but ours (they are above)" +
                (if (shown.size == others.size) "" else ": the newest ${shown.size} of ${others.size} lines") +
                " ====="
        )
        shown.forEach(::line)
        return out.toByteArray()
    }

    /** The newest lines whose total, newlines included, fits in [maxBytes]. */
    private fun List<String>.newest(maxBytes: Int): List<String> {
        var bytes = 0L
        var from = size
        while (from > 0) {
            bytes += this[from - 1].toByteArray(Charsets.UTF_8).size + 1
            if (bytes > maxBytes) break
            from--
        }
        return subList(from, size)
    }

    private fun size(bytes: Long): String =
        if (bytes < 1024 * 1024) "${bytes / 1024} KB"
        else String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024.0))
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

    /** The newest part of the pair; [total] is how much the pair holds on disk. */
    class Tail(val bytes: ByteArray, val total: Long) {
        val isWhole get() = bytes.size.toLong() == total
    }

    /**
     * The newest [maxBytes] of the pair at most, oldest first, beginning on a
     * whole line: a line the cut falls inside is left out rather than exported
     * half. Empty on any failure.
     */
    @Synchronized
    fun tail(maxBytes: Int): Tail {
        flush()
        return try {
            val currentLength = if (current.exists()) current.length() else 0L
            val previousLength = if (previous.exists()) previous.length() else 0L
            val total = currentLength + previousLength
            if (total <= maxBytes) return Tail(snapshot(), total)
            // One byte more than asked for, to see whether the cut falls on a
            // line boundary (that byte is a newline) or inside a line.
            val want = maxBytes + 1L
            val fromCurrent = minOf(want, currentLength)
            val bytes = readEnd(previous, want - fromCurrent) + readEnd(current, fromCurrent)
            val start = bytes.indexOf('\n'.code.toByte()) + 1
            val kept = if (start == 0) ByteArray(0) else bytes.copyOfRange(start, bytes.size)
            Tail(kept, total)
        } catch (_: IOException) {
            Tail(ByteArray(0), 0)
        }
    }

    private fun readEnd(file: File, count: Long): ByteArray {
        if (count <= 0) return ByteArray(0)
        RandomAccessFile(file, "r").use { raf ->
            val bytes = ByteArray(count.toInt())
            raf.seek(raf.length() - count)
            raf.readFully(bytes)
            return bytes
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
