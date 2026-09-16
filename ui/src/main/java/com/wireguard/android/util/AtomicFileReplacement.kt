package com.wireguard.android.util

import java.io.File
import java.io.IOException
import java.io.RandomAccessFile

/** Stage on the same filesystem, keeping the name used as EncryptedFile's associated data. */
internal object AtomicFileReplacement {
    @Synchronized
    fun write(destination: File, writeStaged: (File) -> Unit) {
        val target = destination.absoluteFile
        val directory = File(target.parentFile, ".${target.name}.pending")
        if (!directory.isDirectory && !directory.mkdirs())
            throw IOException("Cannot create staging directory")
        val staged = File(directory, target.name)
        try {
            // Discard an incomplete write left by process death. The committed file
            // is never removed, including when encryption, fsync or rename fails.
            if (staged.exists() && !staged.delete())
                throw IOException("Cannot remove incomplete staged file")
            writeStaged(staged)
            if (!staged.isFile) throw IOException("Staged file was not written")
            // The encrypting stream must be closed before syncing its final tag.
            RandomAccessFile(staged, "rw").use { it.fd.sync() }
            if (!staged.renameTo(target))
                throw IOException("Cannot replace stored file")
        } finally {
            staged.delete()
            directory.delete()
        }
    }
}
