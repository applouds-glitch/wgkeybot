/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import android.net.VpnService;
import androidx.annotation.Nullable;
import java.util.concurrent.CompletableFuture;

/**
 * Native interface for TURN proxy management.
 */
public final class TurnBackend {
    private static final CompletableFuture<VpnService> vpnServiceFuture = new CompletableFuture<>();

    private TurnBackend() {
    }

    /**
     * Registers the VpnService instance and notifies the native layer.
     * @param service The VpnService instance.
     */
    public static void onVpnServiceCreated(@Nullable VpnService service) {
        wgSetVpnService(service);
        if (service != null) {
            vpnServiceFuture.complete(service);
        }
    }

    /**
     * Returns a future that completes when the VpnService is created.
     */
    public static CompletableFuture<VpnService> getVpnServiceFuture() {
        return vpnServiceFuture;
    }

    public static native void wgSetVpnService(@Nullable VpnService service);

    public static native int wgTurnProxyStart(String peerAddr, String vklink, int n, boolean udp, String listenAddr);

    public static native void wgTurnProxyStop();
}
