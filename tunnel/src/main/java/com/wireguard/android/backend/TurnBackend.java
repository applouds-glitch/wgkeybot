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
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Native interface for TURN proxy management.
 */
public final class TurnBackend {
    private static final AtomicReference<CompletableFuture<VpnService>> vpnServiceFutureRef = new AtomicReference<>(new CompletableFuture<>());

    // Latch for synchronization: signals that JNI is registered and ready to protect sockets
    private static final AtomicReference<CountDownLatch> vpnServiceLatchRef = new AtomicReference<>(new CountDownLatch(1));

    // Captcha handler: called when automatic captcha solving fails and WebView is
    // needed. Arguments are (redirectUri, visible); visible=false asks for the
    // invisible auto-clicking WebView, true for the full-screen dialog. Native
    // states the mode because the escalation ladder lives on the Go side.
    private static volatile BiFunction<String, Boolean, String> captchaHandler;

    // Captcha cancel handler: called when native tears the proxy down while a
    // captcha may still be on screen. Must not block; it only has to make the
    // in-flight captchaHandler call return.
    private static volatile Runnable captchaCancelHandler;

    // Captcha persona-burn handler: called when VK rejects the device identity the
    // captcha layer presents, so the next attempt runs under a fresh one.
    private static volatile Consumer<String> captchaPersonaBurnHandler;

    // Fatal-failure handler: called once when the native TURN session has failed
    // terminally (every worker gave up), with a short technical reason.
    private static volatile Consumer<String> fatalHandler;

    // Sharing-retired handler: called when the native internet-sharing proxy took
    // itself down (a fatal accept error, or the egress guard catching traffic that
    // would have left outside the tunnel). Without it the Android side only finds
    // out at its next stats poll.
    private static volatile Consumer<String> tetherStoppedHandler;

    // Captcha device-profile provider: supplies a JSON blob of REAL device metrics
    // (screen size, devicePixelRatio, core/memory counts) plus a persisted stable
    // browser fingerprint, so the Go captcha solver presents a believable,
    // consistent device instead of freshly randomized synthetic values.
    private static volatile Supplier<String> captchaDeviceProfileProvider;

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

    // --- Captcha support ---

    /**
     * Callback that receives a captcha redirect URI and must return the success_token.
     * The function is called from a background (Go) thread. It should block until
     * the captcha is solved or return empty string on failure/timeout.
     */

    /**
     * Sets the captcha handler. Call this from Application.onCreate() or similar.
     * @param handler Function that takes (redirect_uri, visible) and returns success_token
     */
    public static void setCaptchaHandler(@Nullable BiFunction<String, Boolean, String> handler) {
        captchaHandler = handler;
        Log.d(TAG, "Captcha handler " + (handler != null ? "registered" : "cleared"));
    }

    /**
     * Sets the handler that aborts a captcha in progress. Invoked from a native
     * thread when the proxy stops or restarts, so the blocking captcha handler
     * returns instead of holding its worker (and the native captcha mutex) for
     * the full solve timeout.
     * @param handler Runnable that dismisses any captcha UI, or null to clear
     */
    public static void setCaptchaCancelHandler(@Nullable Runnable handler) {
        captchaCancelHandler = handler;
        Log.d(TAG, "Captcha cancel handler " + (handler != null ? "registered" : "cleared"));
    }

    /**
     * Sets the handler that retires the current captcha device persona. Invoked
     * from a native thread when VK rate-limits the session, returns a BOT verdict,
     * or the whole solve ladder fails. Must not block.
     * @param handler Consumer of a short technical reason, or null to clear
     */
    public static void setCaptchaPersonaBurnHandler(@Nullable Consumer<String> handler) {
        captchaPersonaBurnHandler = handler;
        Log.d(TAG, "Captcha persona-burn handler " + (handler != null ? "registered" : "cleared"));
    }

    /**
     * Sets the handler invoked when the native TURN session fails terminally.
     * @param handler Consumer of a short technical reason, or null to clear
     */
    public static void setFatalHandler(@Nullable Consumer<String> handler) {
        fatalHandler = handler;
        Log.d(TAG, "TURN fatal handler " + (handler != null ? "registered" : "cleared"));
    }

    /**
     * Sets the handler invoked when the native sharing proxy retires itself.
     * @param handler Consumer of a short technical reason, or null to clear
     */
    public static void setTetherStoppedHandler(@Nullable Consumer<String> handler) {
        tetherStoppedHandler = handler;
        Log.d(TAG, "Tether stopped handler " + (handler != null ? "registered" : "cleared"));
    }

    /**
     * Registers the captcha device-profile provider. Call once from
     * Application.onCreate(). The provider must return a JSON string with real
     * device metrics and a persisted browser_fp; it is invoked from a background
     * (Go) thread during captcha solving.
     * @param provider Supplier returning the device-profile JSON, or null to clear
     */
    public static void setCaptchaDeviceProfileProvider(@Nullable Supplier<String> provider) {
        captchaDeviceProfileProvider = provider;
        Log.d(TAG, "Captcha device-profile provider " + (provider != null ? "registered" : "cleared"));
    }

    /**
     * Called from JNI (Go thread) to obtain the captcha device profile.
     * @return device-profile JSON string, or empty string if no provider is set
     */
    @SuppressWarnings("unused") // Called from native code
    public static String getCaptchaDeviceProfile() {
        Supplier<String> provider = captchaDeviceProfileProvider;
        if (provider == null) {
            return "";
        }
        try {
            String result = provider.get();
            return result != null ? result : "";
        } catch (Exception e) {
            Log.e(TAG, "Captcha device-profile provider threw exception", e);
            return "";
        }
    }

    /**
     * Called from JNI (Go thread) when VK API requires captcha.
     * Blocks the calling thread until captcha is solved.
     * @param redirectUri The VK captcha page URL to show in WebView
     * @param visible false for the invisible auto-clicking WebView, true for the
     *                full-screen dialog. Chosen by native, not inferred here.
     * @return success_token string, or empty string on failure
     */
    @SuppressWarnings("unused") // Called from native code
    public static String onCaptchaRequired(String redirectUri, boolean visible) {
        Log.d(TAG, "onCaptchaRequired called, visible=" + visible + ", URI length=" + (redirectUri != null ? redirectUri.length() : 0));
        BiFunction<String, Boolean, String> handler = captchaHandler;
        if (handler == null) {
            Log.e(TAG, "No captcha handler registered!");
            return "";
        }
        try {
            String result = handler.apply(redirectUri, visible);
            Log.d(TAG, "Captcha handler returned: " + (result != null && !result.isEmpty() ? "token" : "empty"));
            return result != null ? result : "";
        } catch (Exception e) {
            Log.e(TAG, "Captcha handler threw exception", e);
            return "";
        }
    }

    /**
     * Called from JNI (native thread) to abort a captcha that is still on screen
     * because the proxy is stopping. Must return promptly — the caller is the
     * stop path, not the captcha's own worker.
     */
    @SuppressWarnings("unused") // Called from native code
    public static void onCaptchaCancel() {
        Log.d(TAG, "onCaptchaCancel");
        Runnable handler = captchaCancelHandler;
        if (handler == null) {
            return;
        }
        try {
            handler.run();
        } catch (Exception e) {
            Log.e(TAG, "Captcha cancel handler threw exception", e);
        }
    }

    /**
     * Called from JNI (native thread) when VK rejected the device identity the
     * captcha layer is presenting. Must return promptly.
     * @param reason Short technical reason, e.g. "solve ladder exhausted"
     */
    @SuppressWarnings("unused") // Called from native code
    public static void onCaptchaPersonaBurn(String reason) {
        Log.d(TAG, "onCaptchaPersonaBurn: " + reason);
        Consumer<String> handler = captchaPersonaBurnHandler;
        if (handler == null) {
            return;
        }
        try {
            handler.accept(reason != null ? reason : "");
        } catch (Exception e) {
            Log.e(TAG, "Captcha persona-burn handler threw exception", e);
        }
    }

    /**
     * Called from JNI (Go thread) when the TURN session failed terminally: every
     * worker gave up, so no retry will restore the tunnel. Must not block.
     * @param reason Short technical reason, e.g. "captcha unsolved"
     */
    @SuppressWarnings("unused") // Called from native code
    public static void onTurnFatal(String reason) {
        Log.e(TAG, "onTurnFatal: " + reason);
        Consumer<String> handler = fatalHandler;
        if (handler == null) {
            Log.e(TAG, "No TURN fatal handler registered!");
            return;
        }
        try {
            handler.accept(reason != null ? reason : "");
        } catch (Exception e) {
            Log.e(TAG, "TURN fatal handler threw exception", e);
        }
    }

    /**
     * Called from JNI (Go thread) when the internet-sharing proxy took itself
     * down: a fatal accept error, or the egress guard catching traffic that would
     * have left outside the tunnel. The access point is still up at this point and
     * has to come down too. Must not block.
     * @param reason Short technical reason, e.g. "egress leak"
     */
    @SuppressWarnings("unused") // Called from native code
    public static void onTetherStopped(String reason) {
        Log.w(TAG, "onTetherStopped: " + reason);
        Consumer<String> handler = tetherStoppedHandler;
        if (handler == null) {
            // Not an error: sharing is an optional feature and the Android side
            // still notices at its next stats poll, only later.
            Log.d(TAG, "No tether stopped handler registered");
            return;
        }
        try {
            handler.accept(reason != null ? reason : "");
        } catch (Exception e) {
            Log.e(TAG, "Tether stopped handler threw exception", e);
        }
    }

    // --- End captcha support ---

    public static native void wgSetVpnService(@Nullable VpnService service);

    public static native int wgTurnProxyStart(
            String peerAddr,
            String vklink,
            String mode,
            int n,
            int useUdp,
            String listenAddr,
            String turnIp,
            int turnPort,
            String peerType,
            int streamsPerCred,
            int watchdogTimeout,
            String wrapKey,
            long networkHandle
    );
    public static native void wgTurnProxyStop();
    public static native void wgNotifyNetworkChange();

    /**
     * Reports whether Android currently has a validated physical upstream.
     * Native combines this hint with recent TURN transport proof. A false value
     * therefore parks normal reconnect work only after that proof expires; one
     * rate-limited probe remains available for recovery.
     */
    public static native void wgSetNetworkAvailable(int available);
    public static native String wgGetNetworkDnsServers(long networkHandle);

    /**
     * Starts the internet-sharing proxy on the access point interface.
     *
     * {@code tunnelAddrs} is the tunnel's own Interface.Address list (comma
     * separated, prefixes allowed). Every upstream socket's local address is
     * checked against it: that is what proves a tethered client's traffic really
     * left through the tunnel, so sharing refuses to start without it.
     *
     * {@code routingDir} is a directory holding a Happ routing profile
     * ({@code profile.json}) and the {@code geosite.dat} / {@code geoip.dat} it
     * references, or empty to route every tethered connection through the
     * tunnel. With a profile, destinations it lists as direct leave over the
     * physical network and destinations it blocks are refused.
     *
     * {@code directDns} (comma separated, optional port) replaces the profile's
     * own domestic resolver for names the profile routes direct; empty keeps
     * the profile's.
     *
     * Returns 0 on success, -2 when the whole port range is busy, -3 when
     * protect() refused the listening socket, -4 when the egress guard could not
     * be built — no usable tunnel address, or a bindIp that is not an IP — and
     * -5 when the routing profile could not be loaded (nothing is listening in
     * that case; call again with an empty {@code routingDir} to share without it).
     */
    public static native int wgTetherStart(String bindIp, int port, String dnsServers, String tunnelAddrs, String routingDir, String directDns);

    public static native void wgTetherStop();

    /** Returns {"port":…,"clients":…,"conns":…,"up":…,"down":…,"routing":…} as JSON. */
    public static native String wgTetherStats();

    private static final String TAG = "WireGuard/TurnBackend";
}
