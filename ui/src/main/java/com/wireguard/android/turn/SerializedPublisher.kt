/*
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.turn

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Publishes the current value of something, one publication at a time, from
 * however many callers ask for it.
 *
 * Made for [TurnProxyManager]'s push of the physical network to native, which
 * two coroutines ask for — the collector of the network path and the settings
 * screen changing the relay transport — and which is not one native call but
 * four in a row (the socket binding, the resolvers, the relay transport, the
 * network handle; see wgSetNetwork in jni.c, which must not hold its lock
 * across the calls into Go). Run side by side, two pushes could interleave and
 * leave native with the binding of one network and the transport or the handle
 * of another.
 *
 * The value is read inside the lock, not handed in: whichever caller gets the
 * lock last publishes what is current then, so it does not matter in which
 * order the callers finish, and a caller that waited does not publish the
 * stale value it was woken for. What this does not give is one atomic snapshot
 * to native's readers — a dial may still run between two of the four calls.
 */
internal class SerializedPublisher<T>(
    private val readCurrent: () -> T,
    private val publish: (T) -> Unit,
) {
    private val mutex = Mutex()

    suspend fun publishCurrent() = mutex.withLock { publish(readCurrent()) }
}
