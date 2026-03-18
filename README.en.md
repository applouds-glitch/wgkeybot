# WireGuard Android with VK TURN Proxy

This is a specialized fork of the official [WireGuard Android](https://git.zx2c4.com/wireguard-android) client with integrated support for **VK TURN Proxy**. 

It allows WireGuard traffic to be encapsulated within DTLS/TURN streams using the VK Calls infrastructure, providing a robust way to bypass network restrictions while maintaining high performance and stability.

## Important Disclaimer

**This project is created solely for educational and research purposes.**

Unauthorized use of the VK Calls infrastructure (TURN servers) without explicit permission from the rights holder may violate the Terms of Service and VK platform rules. The project author is not responsible for any damage or policy violations resulting from the use of this software. This project serves as a demonstration of protocol integration technical feasibility and is not intended for the misuse of third-party service resources.

## Key Features

- **Native Integration**: The TURN client is integrated directly into `libwg-go.so` for maximum performance and minimal battery impact.
- **VK Authentication**: Automated retrieval of TURN credentials via VK Calls anonymous tokens.
- **Multi-Stream Load Balancing**: High performance and reliability with parallel DTLS streams, Session ID aggregation, and round-robin outbound balancing.
- **MTU Optimization**: Automatic MTU adjustment to 1280 when using TURN to ensure encapsulated packets fit standard network limits.
- **Seamless Configuration**: TURN settings are stored directly inside standard WireGuard `.conf` files as special metadata comments (`#@wgt:`).
- **VpnService Protection**: All proxy traffic is automatically protected from being looped back into the VPN tunnel.

## Technical Credits

This project is built upon the foundations laid by:
1. **[Official WireGuard Android](https://git.zx2c4.com/wireguard-android)** — The core VPN application and user interface.
2. **[vk-turn-proxy](https://github.com/kiper292/vk-turn-proxy)** — The proxy server implementation (v2) required for this client.

> **Important**: This client requires the server-side implementation from the [kiper292/vk-turn-proxy](https://github.com/kiper292/vk-turn-proxy) fork to function correctly (Multi-stream Session ID support).

## Building

```bash
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
#@wgt:StreamNum = 4
#@wgt:LocalPort = 9000
```

For more technical details, see [info/TURN_INTEGRATION_DETAILS.md](info/TURN_INTEGRATION_DETAILS.md).

## Donations / Поддержать разработчика
Are welcome here :

* **BTC:** `1KxW8gGEv27YR1ckygrLoEftb89eqFtwgt`
* **TON / USDT TON:** `UQBPqDx7s_mKBEp7kGRGok_qpEehI2yYUUw1djwyofaKVX3o`
* **USDT TRC20:** `TAN2vABggLn9FN4PoRGWjfQVFmgZxxZWYp`

## Contributing

For UI translations, please refer to the original [WireGuard Crowdin](https://crowdin.com/project/WireGuard). For technical bugs related to the TURN integration, please open an issue in this repository.
