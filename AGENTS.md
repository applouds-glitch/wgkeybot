# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

This is a WireGuard Android VPN client fork with custom TURN proxy integration and VK authentication. The app lets users quickly connect via configs fetched from a Telegram bot (@wg_key_bot) using a deeplink (`wgkeybot://import?token=X`). It is based on the official WireGuard Android client, rebranded as `com.wgkeybot.android`.

- Min SDK: 24, Target SDK: 36, compiled with JDK 17
- Languages: Kotlin (UI), Java (backend), Go + C (native layer)
- Two Gradle modules: `:tunnel` (library, native backend) and `:ui` (application)

## Build Commands

```bash
# Build debug APK
./gradlew :ui:assembleDebug

# Build release APK
./gradlew :ui:assembleRelease

# Build Google Play variant
./gradlew :ui:assembleGoogleplay

# Build only the tunnel library
./gradlew :tunnel:build

# Run unit tests
./gradlew :tunnel:testDebugUnitTest

# Clean
./gradlew clean
```

The native Go/C layer is compiled via CMake during the Gradle build. Native ABIs built: `armeabi-v7a`, `arm64-v8a`. Go version required: 1.25 (see `.github/workflows/release.yml`).

## Architecture

### Three-Layer Architecture

```
UI (Kotlin, :ui module)
  └── Backend (Java, :tunnel module)
        └── Native (Go + JNI C, tunnel/tools/libwg-go/)
```

**Native layer** (`tunnel/tools/libwg-go/`): wireguard-go plus custom TURN client. Key files:

- `turn-client.go` — TURN relay with DTLS handshake, round-robin load balancing across streams
- `vk.go`, `vk_captcha.go`, `slider_captcha.go` — VK/OK.ru OAuth2 + captcha solving for TURN credentials
- `turn-dns-resolver.go` — Custom DNS resolver with Yandex DNS fallback and 5-min host cache
- `credentials.go` — Per-stream TURN credential caching (default 4 streams per cache boundary)
- `jni.c` — JNI bridge; `wgProtectSocket()` ensures TURN sockets route outside the VPN tunnel
- `api-android.go` — Android-specific wireguard-go entry points

**Backend layer** (`tunnel/src/main/java/com/wireguard/android/backend/`):

- `GoBackend.java` — Userspace WireGuard via wireguard-go (primary backend)
- `WgQuickBackend.java` — Kernel module backend (requires root, optional)
- `TurnBackend.java` — Manages TURN proxy lifecycle calls into native layer

**UI/Application layer** (`ui/src/main/java/com/wireguard/android/`):

- `Application.kt` — Global singletons: `TunnelManager`, `GoBackend`, `TurnProxyManager`
- `model/TunnelManager.kt` — Core tunnel CRUD, state sync with backend, TURN settings injection
- `turn/TurnProxyManager.kt` — Per-tunnel TURN lifecycle; restarts on network change
- `turn/TurnConfigProcessor.kt` — Injects/extracts DTLS proxy endpoint into WireGuard config
- `turn/PhysicalNetworkMonitor.kt` — Detects WiFi/cellular switches, debounces ~2s before restart
- `configStore/FileConfigStore.kt` — Reads/writes WireGuard config files to disk

### Tunnel Connection Flow

1. User toggles tunnel → `TunnelManager.setTunnelState()` (main thread)
2. Load config from `FileConfigStore`, extract TURN settings via `TurnConfigProcessor`
3. If TURN enabled, inject proxy endpoint into WireGuard config
4. Call `GoBackend.setState(UP, config)` on IO dispatcher
5. Native `wgTurnOn()` starts userspace TURN relay; `wgSetConfig()` + VpnService starts tunnel
6. `TurnProxyManager.onTunnelEstablished()` starts the TURN proxy over protected sockets

### TURN Network Recovery

`PhysicalNetworkMonitor` → debounce → `TurnProxyManager.handleNetworkChange()` → `wgNotifyNetworkChange()` (clears DNS/HTTP caches in Go) → restart TURN proxy on new network.

### Deeplink Import

`wgkeybot://import?token=ABC123` → `MainActivity` fetches config from `https://key.shadowgate.online/api/config/{token}` → `Config.parse()` → `TunnelManager.create()`.

### Key Design Decisions

- **Pluggable backends**: Runtime selection between kernel (`WgQuickBackend`) and userspace (`GoBackend`) based on root availability and user preference.
- **Separated TURN settings**: Stored outside WireGuard config in `TurnSettingsStore` (DataStore); `TurnConfigProcessor` injects them at connect time.
- **Protected sockets**: `wgProtectSocket()` via JNI ensures TURN relay traffic bypasses the VPN interface itself.
- **DTLS handshake**: 17-byte handshake with Session ID + Stream ID for Proxy v2 protocol; 10s timeout; streams start with 200ms stagger.
- **Observable MVVM**: `ObservableTunnel` wraps tunnel state for XML data binding; `ConfigProxy`/`InterfaceProxy`/`PeerProxy`/`TurnSettingsProxy` serve as ViewModels.
- **Threading**: Main thread for UI, `Dispatchers.IO` for file/network/backend calls, coroutine Flows for preferences.

## Key Customizations vs Upstream WireGuard Android

- `wgkeybot://` deeplink for one-tap config import from Telegram bot
- TURN/DTLS relay layer with VK OAuth2 authentication and captcha support
- Split tunneling with app search (`AppListDialogFragment`)
- `PhysicalNetworkMonitor` for TURN reconnection on network switches
- Custom DNS resolver (Yandex DNS + DoH/DoT fallback)
- Biometric unlock (`BiometricAuthenticator`)
- Quick Settings tile (`QuickTileService`)
- In-app update checker (`updater/`)
- Android TV support (`TvMainActivity` + `LEANBACK_LAUNCHER`): reuses the shared `TunnelListFragment`; D-pad token entry via `TvHexKeyboard`; TV-specific layouts live in `res/layout-television/` (resolved only on `uiMode=television`, so the phone/tablet UI is untouched)

## Release Process

Releases are automated via `.github/workflows/release.yml` on tags matching `v*`. The workflow builds with Java 17 + Go 1.25, signs the APK using secrets (`SIGNING_KEY`, `ALIAS`, `KEYSTORE_PASSWORD`, `KEY_PASSWORD`), and publishes a GitHub Release. Version is set in `gradle.properties` (`wireguardVersionCode`, `wireguardVersionName`).

## Supplemental Architecture Docs

- `info/TURN_INTEGRATION_DETAILS.md` — Deep dive into TURN/DTLS protocol, credential modes, load balancing, DNS resolver, captcha handling
- `info/version2.md` — Notes on Session ID (UUID) support and round-robin vs sticky load balancing plans
