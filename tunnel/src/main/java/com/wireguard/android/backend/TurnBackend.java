/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import android.net.VpnService;
import androidx.annotation.Nullable;
import android.util.Log;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Native interface for TURN proxy management.
 */
public final class TurnBackend {
    private static final AtomicReference<CompletableFuture<VpnService>> vpnServiceFutureRef = new AtomicReference<>(new CompletableFuture<>());

    // Latch for synchronization: signals that JNI is registered and ready to protect sockets
    private static final AtomicReference<CountDownLatch> vpnServiceLatchRef = new AtomicReference<>(new CountDownLatch(1));

    private TurnBackend() {
    }

    /**
     * Registers the VpnService instance and notifies the native layer.
     * @param service The VpnService instance.
     */
    public static void onVpnServiceCreated(@Nullable VpnService service) {
        Log.d(TAG, "onVpnServiceCreated called with service=" + (service != null ? "non-null" : "null"));

        if (service != null) {
            // 1. First set in JNI so sockets can be protected
            Log.d(TAG, "Calling wgSetVpnService()...");
            wgSetVpnService(service);
            Log.d(TAG, "wgSetVpnService() complete");

            // 2. Count down latch — JNI is ready to protect sockets
            vpnServiceLatchRef.get().countDown();
            Log.d(TAG, "vpnServiceLatchRef.countDown()");

            // 3. Then complete Future for Java code
            CompletableFuture<VpnService> currentFuture = vpnServiceFutureRef.getAndSet(new CompletableFuture<>());
            if (!currentFuture.isDone()) {
                currentFuture.complete(service);
                Log.d(TAG, "VpnService future completed");
            } else {
                // Old future already completed — complete the new one
                CompletableFuture<VpnService> newFuture = vpnServiceFutureRef.get();
                if (!newFuture.isDone()) {
                    newFuture.complete(service);
                    Log.d(TAG, "VpnService future completed (replacement)");
                }
            }
        } else {
            // Service destroyed - reset everything for next cycle
            Log.d(TAG, "VpnService destroyed, resetting future and latch");
            wgSetVpnService(null);
            vpnServiceFutureRef.set(new CompletableFuture<>());
            vpnServiceLatchRef.set(new CountDownLatch(1));  // Recreate latch for next launch
        }
    }

    /**
     * Returns a future that completes when the VpnService is created.
     */
    public static CompletableFuture<VpnService> getVpnServiceFuture() {
        return vpnServiceFutureRef.get();
    }
    
    /**
     * Waits until the VpnService is registered in JNI and ready to protect sockets.
     * @param timeout Maximum time to wait in milliseconds
     * @return true if successfully registered, false on timeout or interrupt
     */
    public static boolean waitForVpnServiceRegistered(long timeout) {
        try {
            CountDownLatch latch = vpnServiceLatchRef.get();
            boolean success = latch.await(timeout, TimeUnit.MILLISECONDS);
            Log.d(TAG, "waitForVpnServiceRegistered: " + (success ? "SUCCESS" : "TIMEOUT (" + timeout + "ms)"));
            return success;
        } catch (InterruptedException e) {
            Log.e(TAG, "Interrupted while waiting for VpnService registration", e);
            Thread.currentThread().interrupt();  // Restore interrupt flag
            return false;
        }
    }

    public static native void wgSetVpnService(@Nullable VpnService service);

    public static native int wgTurnProxyStart(
            String peerAddr,
            String vklink,
            int n,
            int useUdp,
            String listenAddr,
            String turnIp,
            int turnPort,
            int noDtls
    );
    public static native void wgTurnProxyStop();
    public static native void wgNotifyNetworkChange();
    
    private static final String TAG = "WireGuard/TurnBackend";
}
