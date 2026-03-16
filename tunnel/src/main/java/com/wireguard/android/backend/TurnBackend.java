/*
 * Copyright © 2026.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import android.net.VpnService;
import androidx.annotation.Nullable;

/**
 * Native interface for TURN proxy management.
 */
public final class TurnBackend {
    private TurnBackend() {
    }

    public static native void wgSetVpnService(@Nullable VpnService service);

    public static native int wgTurnProxyStart(String peerAddr, String vklink, int n, boolean udp, String listenAddr);

    public static native void wgTurnProxyStop();
}
