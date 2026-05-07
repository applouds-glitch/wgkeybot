/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.wireguard.android.backend;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.system.OsConstants;
import android.util.Log;

import com.wireguard.android.backend.BackendException.Reason;
import com.wireguard.android.backend.Tunnel.State;
import com.wireguard.android.util.SharedLibraryLoader;
import com.wireguard.config.Config;
import com.wireguard.config.InetEndpoint;
import com.wireguard.config.InetNetwork;
import com.wireguard.config.Peer;
import com.wireguard.crypto.Key;
import com.wireguard.crypto.KeyFormatException;
import com.wireguard.util.NonNullForAll;

import java.net.InetAddress;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;

import androidx.annotation.Nullable;
import androidx.collection.ArraySet;
import androidx.core.app.NotificationCompat;

@NonNullForAll
public final class GoBackend implements Backend {
    private static final int DNS_RESOLUTION_RETRIES = 10;
    private static final String TAG = "WireGuard/GoBackend";
    private static final String VPN_CHANNEL_ID = "vpn_running";
    private static final int VPN_NOTIFICATION_ID = 1;

    @Nullable private static AlwaysOnCallback alwaysOnCallback;

    private static final AtomicReference<CompletableFuture<VpnService>> vpnServiceRef =
            new AtomicReference<>(new CompletableFuture<>());

    private final Context context;
    @Nullable private Config currentConfig;
    @Nullable private Tunnel currentTunnel;
    private int currentTunnelHandle = -1;

    public GoBackend(final Context context) {
        SharedLibraryLoader.loadSharedLibrary(context, "wg-go");
        this.context = context;
    }

    public static void setAlwaysOnCallback(final AlwaysOnCallback cb) {
        alwaysOnCallback = cb;
    }

    @Nullable private static native String wgGetConfig(int handle);
    private static native int wgGetSocketV4(int handle);
    private static native int wgGetSocketV6(int handle);
    private static native void wgTurnOff(int handle);
    private static native int wgTurnOn(String ifName, int tunFd, String settings);
    private static native String wgVersion();

    @Override
    public Set<String> getRunningTunnelNames() {
        if (currentTunnel != null) {
            final Set<String> runningTunnels = new ArraySet<>();
            runningTunnels.add(currentTunnel.getName());
            return runningTunnels;
        }
        return Collections.emptySet();
    }

    @Override
    public State getState(final Tunnel tunnel) {
        return currentTunnel == tunnel ? State.UP : State.DOWN;
    }

    @Override
    public Statistics getStatistics(final Tunnel tunnel) {
        final Statistics stats = new Statistics();
        if (tunnel != currentTunnel || currentTunnelHandle == -1)
            return stats;
        final String config = wgGetConfig(currentTunnelHandle);
        if (config == null)
            return stats;
        Key key = null;
        long rx = 0, tx = 0, latestHandshakeMSec = 0;
        for (final String line : config.split("\\n")) {
            if (line.startsWith("public_key=")) {
                if (key != null) stats.add(key, rx, tx, latestHandshakeMSec);
                rx = 0; tx = 0; latestHandshakeMSec = 0;
                try { key = Key.fromHex(line.substring(11)); }
                catch (final KeyFormatException ignored) { key = null; }
            } else if (line.startsWith("rx_bytes=")) {
                if (key == null) continue;
                try { rx = Long.parseLong(line.substring(9)); }
                catch (final NumberFormatException ignored) { rx = 0; }
            } else if (line.startsWith("tx_bytes=")) {
                if (key == null) continue;
                try { tx = Long.parseLong(line.substring(9)); }
                catch (final NumberFormatException ignored) { tx = 0; }
            } else if (line.startsWith("last_handshake_time_sec=")) {
                if (key == null) continue;
                try { latestHandshakeMSec += Long.parseLong(line.substring(24)) * 1000; }
                catch (final NumberFormatException ignored) { latestHandshakeMSec = 0; }
            } else if (line.startsWith("last_handshake_time_nsec=")) {
                if (key == null) continue;
                try { latestHandshakeMSec += Long.parseLong(line.substring(25)) / 1000000; }
                catch (final NumberFormatException ignored) { latestHandshakeMSec = 0; }
            }
        }
        if (key != null) stats.add(key, rx, tx, latestHandshakeMSec);
        return stats;
    }

    @Override
    public String getVersion() { return wgVersion(); }

    @Override
    public boolean isAlwaysOn() throws ExecutionException, InterruptedException, TimeoutException {
        return vpnServiceRef.get().get(0, TimeUnit.NANOSECONDS).isAlwaysOn();
    }

    @Override
    public boolean isLockdownEnabled() throws ExecutionException, InterruptedException, TimeoutException {
        return vpnServiceRef.get().get(0, TimeUnit.NANOSECONDS).isLockdownEnabled();
    }

    @Override
    public State setState(final Tunnel tunnel, State state, @Nullable final Config config) throws Exception {
        final State originalState = getState(tunnel);
        if (state == State.TOGGLE)
            state = originalState == State.UP ? State.DOWN : State.UP;
        if (state == originalState && tunnel == currentTunnel && config == currentConfig)
            return originalState;
        if (state == State.UP) {
            final Config originalConfig = currentConfig;
            final Tunnel originalTunnel = currentTunnel;
            if (currentTunnel != null)
                setStateInternal(currentTunnel, null, State.DOWN);
            try {
                setStateInternal(tunnel, config, state);
            } catch (final Exception e) {
                if (originalTunnel != null)
                    setStateInternal(originalTunnel, originalConfig, State.UP);
                throw e;
            }
        } else if (state == State.DOWN && tunnel == currentTunnel) {
            setStateInternal(tunnel, null, State.DOWN);
        }
        return getState(tunnel);
    }

    private void setStateInternal(final Tunnel tunnel, @Nullable final Config config, final State state)
            throws Exception {
        Log.i(TAG, "Bringing tunnel " + tunnel.getName() + ' ' + state);

        if (state == State.UP) {
            if (config == null)
                throw new BackendException(Reason.TUNNEL_MISSING_CONFIG);
            if (VpnService.prepare(context) != null)
                throw new BackendException(Reason.VPN_NOT_AUTHORIZED);

            final VpnService service;
            if (!vpnServiceRef.get().isDone()) {
                Log.d(TAG, "Requesting to start VpnService");
                context.startService(new Intent(context, VpnService.class));
            }
            try {
                service = vpnServiceRef.get().get(2, TimeUnit.SECONDS);
            } catch (final TimeoutException e) {
                final Exception be = new BackendException(Reason.UNABLE_TO_START_VPN);
                be.initCause(e);
                throw be;
            }
            service.setOwner(this);

            if (currentTunnelHandle != -1) {
                Log.w(TAG, "Tunnel already up");
                return;
            }

            dnsRetry:
            for (int i = 0; i < DNS_RESOLUTION_RETRIES; ++i) {
                for (final Peer peer : config.getPeers()) {
                    final InetEndpoint ep = peer.getEndpoint().orElse(null);
                    if (ep == null) continue;
                    if (ep.getResolved().orElse(null) == null) {
                        if (i < DNS_RESOLUTION_RETRIES - 1) {
                            Log.w(TAG, "DNS host \"" + ep.getHost() + "\" failed to resolve; trying again");
                            Thread.sleep(1000);
                            continue dnsRetry;
                        } else
                            throw new BackendException(Reason.DNS_RESOLUTION_FAILURE, ep.getHost());
                    }
                }
                break;
            }

            final String goConfig = config.toWgUserspaceString();
            final VpnService.Builder builder = service.getBuilder();
            builder.setSession(tunnel.getName());

            for (final String excludedApplication : config.getInterface().getExcludedApplications())
                builder.addDisallowedApplication(excludedApplication);
            for (final String includedApplication : config.getInterface().getIncludedApplications())
                builder.addAllowedApplication(includedApplication);
            for (final InetNetwork addr : config.getInterface().getAddresses())
                builder.addAddress(addr.getAddress(), addr.getMask());
            for (final InetAddress addr : config.getInterface().getDnsServers())
                builder.addDnsServer(addr.getHostAddress());
            for (final String dnsSearchDomain : config.getInterface().getDnsSearchDomains())
                builder.addSearchDomain(dnsSearchDomain);

            boolean sawDefaultRoute = false;
            for (final Peer peer : config.getPeers()) {
                for (final InetNetwork addr : peer.getAllowedIps()) {
                    if (addr.getMask() == 0) sawDefaultRoute = true;
                    builder.addRoute(addr.getAddress(), addr.getMask());
                }
            }

            if (!(sawDefaultRoute && config.getPeers().size() == 1)) {
                builder.allowFamily(OsConstants.AF_INET);
                builder.allowFamily(OsConstants.AF_INET6);
            }

            builder.setMtu(config.getInterface().getMtu().orElse(1280));
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                builder.setMetered(false);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M)
                service.setUnderlyingNetworks(null);

            builder.setBlocking(true);
            try (final ParcelFileDescriptor tun = builder.establish()) {
                if (tun == null)
                    throw new BackendException(Reason.TUN_CREATION_ERROR);
                Log.d(TAG, "Go backend " + wgVersion());
                currentTunnelHandle = wgTurnOn(tunnel.getName(), tun.detachFd(), goConfig);
            }
            if (currentTunnelHandle < 0)
                throw new BackendException(Reason.GO_ACTIVATION_ERROR_CODE, currentTunnelHandle);

            currentTunnel = tunnel;
            currentConfig = config;

            service.protect(wgGetSocketV4(currentTunnelHandle));
            service.protect(wgGetSocketV6(currentTunnelHandle));
            service.acquireWifiLock();
            service.updateNotification(tunnel.getName());
        } else {
            if (currentTunnelHandle == -1) {
                Log.w(TAG, "Tunnel already down");
                return;
            }
            int handleToClose = currentTunnelHandle;
            currentTunnel = null;
            currentTunnelHandle = -1;
            currentConfig = null;
            wgTurnOff(handleToClose);
            try {
                final VpnService svc = vpnServiceRef.get().get(0, TimeUnit.NANOSECONDS);
                svc.releaseWifiLock();
                svc.stopSelf();
            } catch (final TimeoutException ignored) { }
        }
        tunnel.onStateChange(state);
    }

    public interface AlwaysOnCallback {
        void alwaysOnTriggered();
    }

    public static class VpnService extends android.net.VpnService {
        @Nullable private GoBackend owner;
        @Nullable private PowerManager.WakeLock wakeLock;
        @Nullable private WifiManager.WifiLock wifiLock;
        @Nullable private BroadcastReceiver dozeModeReceiver;
        @Nullable private ConnectivityManager connectivityManager;
        @Nullable private ConnectivityManager.NetworkCallback networkCallback;
        @Nullable private String lastNotificationText;
        private long lastNetworkChangeTime = 0L;

        public Builder getBuilder() { return new Builder(); }

        private void createNotificationChannel() {
            final NotificationChannel channel = new NotificationChannel(
                    VPN_CHANNEL_ID, "VPN Running", NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Persistent VPN tunnel notification");
            channel.setShowBadge(false);
            channel.setLockscreenVisibility(Notification.VISIBILITY_PUBLIC);
            channel.setSound(null, null);
            channel.enableVibration(false);
            final NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(channel);
        }

        private Notification buildNotification(@Nullable final String tunnelName) {
            final Intent launchIntent = getPackageManager().getLaunchIntentForPackage(getPackageName());
            final PendingIntent pendingIntent = PendingIntent.getActivity(
                    this, 0,
                    launchIntent != null ? launchIntent : new Intent(),
                    PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
            final String text = "VPN service running";
            return new NotificationCompat.Builder(this, VPN_CHANNEL_ID)
                    .setSmallIcon(android.R.drawable.ic_lock_lock)
                    //.setContentTitle("WGKeyBot")
                    .setContentText(text)
                    .setContentIntent(pendingIntent)
                    .setOngoing(true)
                    .setLocalOnly(true)
                    .setPriority(NotificationCompat.PRIORITY_LOW)
                    .setCategory(NotificationCompat.CATEGORY_SERVICE)
                    .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
                    .setOnlyAlertOnce(true)
                    .setSilent(true)
                    .setShowWhen(false)
                    .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
                    .build();
        }

        public void updateNotification(@Nullable final String tunnelName) {
            final String text = "VPN service running";
            if (text.equals(lastNotificationText)) return;
            lastNotificationText = text;
            final NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.notify(VPN_NOTIFICATION_ID, buildNotification(tunnelName));
        }

        private void acquireWakeLock() {
            if (wakeLock != null && wakeLock.isHeld()) return;
            final PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "wgkeybot:vpn_cpu");
            wakeLock.setReferenceCounted(false);
            wakeLock.acquire();
            Log.d(TAG, "WakeLock acquired");
        }

        private void releaseWakeLock() {
            if (wakeLock != null && wakeLock.isHeld()) {
                wakeLock.release();
                Log.d(TAG, "WakeLock released");
            }
            wakeLock = null;
        }

        @SuppressWarnings("deprecation")
        void acquireWifiLock() {
            if (wifiLock != null && wifiLock.isHeld()) return;
            final WifiManager wm = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);
            if (wm == null) return;
            final int mode = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                    ? WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                    : WifiManager.WIFI_MODE_FULL_HIGH_PERF;
            wifiLock = wm.createWifiLock(mode, "wgkeybot:vpn_wifi");
            wifiLock.setReferenceCounted(false);
            wifiLock.acquire();
            Log.d(TAG, "WifiLock acquired");
        }

        void releaseWifiLock() {
            if (wifiLock != null && wifiLock.isHeld()) {
                wifiLock.release();
                Log.d(TAG, "WifiLock released");
            }
            wifiLock = null;
        }

        private void setupNetworkCallback() {
            connectivityManager = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (connectivityManager == null) return;
            networkCallback = new ConnectivityManager.NetworkCallback() {
                @Override public void onAvailable(final Network network) {
                    Log.d(TAG, "Network available: " + network);
                    handleNetworkChange();
                }
                @Override public void onLost(final Network network) {
                    Log.d(TAG, "Network lost: " + network);
                }
            };
            final NetworkRequest request = new NetworkRequest.Builder()
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                    .build();
            connectivityManager.registerNetworkCallback(request, networkCallback);
        }

        private void teardownNetworkCallback() {
            if (connectivityManager != null && networkCallback != null) {
                connectivityManager.unregisterNetworkCallback(networkCallback);
                networkCallback = null;
            }
        }

        private void handleNetworkChange() {
            final long now = System.currentTimeMillis();
            if (now - lastNetworkChangeTime < 5000) return;
            lastNetworkChangeTime = now;
//            Log.d(TAG, "Network changed, signalling TurnBackend");
//            TurnBackend.wgSetPauseFlag(0);
        }

        @Override
        public void onCreate() {
            Log.d(TAG, "VpnService.onCreate()");

            createNotificationChannel();

            // Android 14+ (API 34) → specialUse
            // Android 10-13 (API 29-33) → dataSync (не требует доп. разрешений)
            // Android 9 и ниже → без типа
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(VPN_NOTIFICATION_ID, buildNotification(null),
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(VPN_NOTIFICATION_ID, buildNotification(null),
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
            } else {
                startForeground(VPN_NOTIFICATION_ID, buildNotification(null));
            }
            Log.d(TAG, "startForeground() done");
            vpnServiceRef.get().complete(this);
            Log.d(TAG, "vpnServiceRef completed");

            // Затем регистрируем в TurnBackend — это вызывает wgSetVpnService + latch.countDown()
            // без этого TurnProxyManager.waitForVpnServiceRegistered() всегда таймаутится
            TurnBackend.onVpnServiceCreated(this);

            acquireWakeLock();
            setupNetworkCallback();

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                dozeModeReceiver = new BroadcastReceiver() {
                    @Override
                    public void onReceive(final Context context, final Intent intent) {
                        final PowerManager pm = (PowerManager) context.getSystemService(Context.POWER_SERVICE);
                        final boolean idle = pm != null && pm.isDeviceIdleMode();
                        Log.d(TAG, "Doze idle=" + idle);
                       // TurnBackend.wgSetPauseFlag(idle ? 1 : 0);
                    }
                };
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    registerReceiver(dozeModeReceiver,
                            new IntentFilter(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED),
                            Context.RECEIVER_NOT_EXPORTED);
                } else {
                    registerReceiver(dozeModeReceiver,
                            new IntentFilter(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED));
                }
            }



            super.onCreate();
        }

        @Override
        public void onDestroy() {
            TurnBackend.onVpnServiceCreated(null);
            Log.d(TAG, "VpnService.onDestroy()");
            stopForeground(STOP_FOREGROUND_REMOVE);
            releaseWakeLock();
            releaseWifiLock();
            teardownNetworkCallback();
            if (dozeModeReceiver != null) {
                unregisterReceiver(dozeModeReceiver);
                dozeModeReceiver = null;
            }
            if (owner != null) {
                final Tunnel tunnel = owner.currentTunnel;
                if (tunnel != null) {
                    if (owner.currentTunnelHandle != -1)
                        wgTurnOff(owner.currentTunnelHandle);
                    owner.currentTunnel = null;
                    owner.currentTunnelHandle = -1;
                    owner.currentConfig = null;
                    tunnel.onStateChange(State.DOWN);
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                vpnServiceRef.set(vpnServiceRef.get().newIncompleteFuture());
            } else {
                vpnServiceRef.set(new CompletableFuture<>());
            }
            Log.d(TAG, "vpnServiceRef reset");
            super.onDestroy();
        }

        @Override
        public int onStartCommand(@Nullable final Intent intent, final int flags, final int startId) {
            final CompletableFuture<VpnService> current = vpnServiceRef.get();
            if (!current.isDone()) {
                current.complete(this);
            }
            if (intent == null || intent.getComponent() == null
                    || !intent.getComponent().getPackageName().equals(getPackageName())) {
                Log.d(TAG, "Service started by Always-on VPN feature");
                if (alwaysOnCallback != null)
                    alwaysOnCallback.alwaysOnTriggered();
            }
            return START_STICKY;
        }

        public void setOwner(final GoBackend owner) {
            this.owner = owner;
        }
    }
}