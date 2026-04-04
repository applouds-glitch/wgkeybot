# WireGuard Android with VK TURN Proxy

This is a specialized fork of the official [WireGuard Android](https://git.zx2c4.com/wireguard-android) client with integrated support for **VK TURN Proxy**.

It allows WireGuard traffic to be encapsulated within DTLS/TURN streams using the VK Calls infrastructure, providing a robust way to bypass network restrictions while maintaining high performance and stability.

## Important Disclaimer

**This project is created solely for educational and research purposes.**

Unauthorized use of the VK Calls infrastructure (TURN servers) without explicit permission from the rights holder may violate the Terms of Service and VK platform rules. The project author is not responsible for any damage or policy violations resulting from the use of this software. This project serves as a demonstration of protocol integration technical feasibility and is not intended for the misuse of third-party service resources.

## Key Features

- **Native Integration**: The TURN client is integrated directly into `libwg-go.so` for maximum performance and minimal battery impact.
- **Two Authentication Modes**:
  - **VK Link** — Automated retrieval of TURN credentials via VK Calls anonymous tokens.
  - **WB** — Automated retrieval of TURN credentials via WB Stream API (guest registration → room creation → LiveKit ICE).
- **Multi-Stream Load Balancing**: High performance and reliability with parallel DTLS streams, Session ID aggregation, and round-robin outbound balancing.
- **Custom DNS Resolver**: All HTTP and WebSocket requests go through a built-in DNS resolver with socket protection via VPN.
- **MTU Optimization**: Automatic MTU adjustment to 1280 when using TURN to ensure encapsulated packets fit standard network limits.
- **Auto-Reconnect on Network Change**: Automatic TURN restart when switching between WiFi and 4G/5G with debounce protection.
- **Fast Network Recovery**: DNS and HTTP connection reset on network change for quick reconnection.
- **Seamless Configuration**: TURN settings are stored directly inside standard WireGuard `.conf` files as special metadata comments (`#@wgt:`).

## Technical Credits

This project is built upon the foundations laid by:
1. **[Official WireGuard Android](https://git.zx2c4.com/wireguard-android)** — The core VPN application and user interface.
2. **[vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy)** — the author of the original idea and inspiration for this project.
3. **[lionheart](https://github.com/jaykaiperson/lionheart)** — The original WB mode implementation for TURN credentials retrieval.

> **Important**: For correct client operation (Session ID stream aggregation), it is recommended to use the v2 server-side implementation from the [kiper292/vk-turn-proxy](https://github.com/kiper292/vk-turn-proxy) fork.

## Building

```bash
# Requires Go 1.25+ and Android NDK 29
$ git clone --recurse-submodules https://github.com/your-repo/wireguard-turn-android
$ cd wireguard-turn-android
$ ./gradlew assembleRelease
```

## Configuration

You can enable the proxy in the Tunnel Editor. The settings are appended to the Peer section of your configuration:

```ini
[Peer]
PublicKey = <key>
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0

# [Peer] TURN extensions
#@wgt:EnableTURN = true
#@wgt:UseUDP = false
#@wgt:IPPort = 1.2.3.4:56000
#@wgt:VKLink = https://vk.com/call/join/...
#@wgt:Mode = vk_link              # Auth mode: vk_link or wb
#@wgt:PeerType = proxy_v2          # proxy_v2 | proxy_v1 | wireguard
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000
#@wgt:StreamsPerCred = 4           # Streams per credentials cache

# Advanced settings (optional)
#@wgt:TurnIP = 155.212.199.166      # Override TURN server IP
#@wgt:TurnPort = 19302              # Override TURN server port
```

**Note:** The `PeerType` parameter determines the operating mode:
- `proxy_v2` (default) — DTLS with Session ID transmission for stream aggregation
- `proxy_v1` — DTLS without Session ID handshake
- `wireguard` — no DTLS, direct relay (for debugging or direct connection)

For more technical details, see [info/TURN_INTEGRATION_DETAILS.md](info/TURN_INTEGRATION_DETAILS.md).

## Donations

Are welcome here:

<img width="16" height="16" alt="bitcoin" src="https://github.com/user-attachments/assets/ea73b5cc-cba4-4428-8704-d5345acf58d4" /> BTC:
```plaintext
1ERKmMSyfxtKNNpU3TeaYCaJfDKY9s8jdX
```

<img width="16" height="16" alt="ethereum" src="https://github.com/user-attachments/assets/2a2fcba2-66d9-4eb9-a5e7-35e6889f76f0" /> ETH Ethereum (ERC20):
```plaintext
0xfa8fdae60010e3d6b446d7479a9ccacfc56c0936
```

<img width="16" height="16" alt="tether" src="https://github.com/user-attachments/assets/9f88aa41-fcfd-48ea-ae5a-c0bef933666d" /> USDT TRON (TRC20):
```plaintext
TMgojRMiya1nJ2uEtw8u7p5YZ9J7Ykdmd9
```

<img width="16" height="16" alt="tether" src="https://github.com/user-attachments/assets/9f88aa41-fcfd-48ea-ae5a-c0bef933666d" /> USDT APTOS:
```plaintext
0x741a8b707b75aa57dc603fa30d1c4750198866b0e9eb6d9a7a1a7dde8ec7f4d2
```

<img width="16" height="16" alt="tontoken" src="https://github.com/user-attachments/assets/14e9293f-5ca2-49fe-b5ae-4bf48be065a4" /> TON / USDT TON:
```plaintext
UQD0BQTBSVo19hrjKyXnRc61MXW0j9dTZaLEXOUJwxLT2qRQ
```

<img width="16" height="16" alt="litecoin" src="https://github.com/user-attachments/assets/193b09c3-eca6-4feb-b887-a603813c11eb" /> LTC:
```plaintext
La2H1YD2zKxqhsziGrx74anjJYwAQJ67er
```

## Contributing

For UI translations, please refer to the original [WireGuard Crowdin](https://crowdin.com/project/WireGuard). For technical bugs related to the TURN integration, please open an issue in this repository.
