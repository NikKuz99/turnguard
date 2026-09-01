# TurnGuard

> Cross-platform WireGuard + VK TURN desktop client with SRTP-mimicry wrap, DNS fallback, auto-captcha, and auto-update.
>
> **Windows · Linux · macOS** — one binary, no runtime dependencies.

## Features

- **SRTP-mimicry wrap** (RFC 3550 RTP, ChaCha20-Poly1305) — 4.9x speedup vs baseline TURN
- **DNS fallback** (VKHosts) — 16 baseline IPs + dynamic DNS resolution with RTT metrics
- **Cascading DNS** — system → Yandex → Google (plain/DoH/DoT)
- **Auto-captcha** — PoW v2 + captcha API auto-solve + browser proxy solver
- **WireGuard TUN** — standalone VPN mode (built-in wireguard-go, no external client needed)
- **Auto-update** — checks GitHub Releases every 6h, downloads and replaces self
- **Config file** — JSON config support (`-config config.json`)
- **Multi-stream** — up to 4 parallel TURN streams
- **VK + Yandex Telemost** — supports both VK calls and Yandex Telemost links
- **Embedded CA bundle** — works on systems without /etc/ssl/certs/

## Quick Start

### Option 1: CLI Flags
```bash
# Download for your platform
chmod +x turnguard-linux-amd64

# Proxy only (external WireGuard)
./turnguard \
  -vk-link https://vk.com/call/join/... \
  -peer your.server.com:56001 \
  -wrap-key <generate with: openssl rand -hex 32>

# Standalone VPN (TUN + WireGuard built-in, requires root on Linux)
sudo ./turnguard \
  -vk-link https://vk.com/call/join/... \
  -peer your.server.com:56001 \
  -wrap-key e979270b... \
  -vpn \
  -private-key <client_privkey_hex> \
  -server-key <server_pubkey_hex>
```

### Option 2: Config File
```bash
# Generate example config
./turnguard -gen-config

# Edit config.json with your settings
vi config.json

# Run with config
./turnguard -config config.json
```

### Option 3: Check for Updates
```bash
./turnguard -check-update
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-config` | (empty) | Path to config.json (overrides all CLI flags) |
| `-gen-config` | `false` | Generate example config.json and exit |
| `-vk-link` | (required) | VK call link |
| `-peer` | (required) | Peer server address (host:port) |
| `-listen` | `127.0.0.1:9000` | Local UDP listener for WireGuard |
| `-wrap-key` | (empty) | SRTP-mimicry wrap key (64 hex chars) |
| `-streams` | `4` | Parallel TURN streams (1-4) |
| `-udp` | `false` | Use UDP mode |
| `-mode` | `vk_link` | Mode: vk_link or wb |
| `-peer-type` | `proxy_v1` | Peer type: proxy_v1 or wireguard |
| `-vpn` | `false` | Start WireGuard TUN device |
| `-private-key` | (VPN) | Client WireGuard private key (hex) |
| `-server-key` | (VPN) | Server WireGuard public key (hex) |
| `-server-addr` | `127.0.0.1:9000` | WireGuard server endpoint |
| `-allowed-ips` | `0.0.0.0/0, ::0` | Allowed IPs for WireGuard |
| `-mtu` | `1280` | TUN MTU |
| `-keepalive` | `25` | Persistent keepalive (seconds) |
| `-check-update` | `false` | Check for updates and exit |
| `-auto-update` | `true` | Enable background update checker |

## Config File Format

```json
{
  "vk_link": "https://vk.com/call/join/...",
  "peer": "your.server.com:56001",
  "listen": "127.0.0.1:9000",
  "wrap_key": "e979270b...",
  "streams": 4,
  "udp": false,
  "mode": "vk_link",
  "peer_type": "proxy_v1",
  "vpn": {
    "enabled": true,
    "private_key": "abc123...",
    "server_key": "def456...",
    "server_addr": "127.0.0.1:9000",
    "allowed_ips": "0.0.0.0/0, ::0",
    "mtu": 1280,
    "keepalive": 25
  },
  "auto_update": true
}
```

## Architecture

```
turnguard/
├── cmd/turnguard/main.go       # CLI entry point + config + VPN + update
├── internal/
│   ├── core/
│   │   ├── turn_client.go      # TURN relay + DTLS + multi-stream
│   │   ├── vk_auth.go          # VK auth + TURN credentials
│   │   ├── vk_captcha_api.go   # captcha API (PoW, initSession, check)
│   │   ├── slider_captcha.go   # slider auto-solver
│   │   ├── captcha_server.go   # local HTTP proxy for browser captcha
│   │   ├── browser.go          # browser open + stdin fallback
│   │   ├── resolver.go         # cascading DNS (system→Yandex→Google)
│   │   ├── vk_hosts.go         # DNS fallback (VKHosts: 16 baseline IPs)
│   │   ├── wrap.go             # SRTP-mimicry AEAD (ChaCha20-Poly1305)
│   │   ├── credentials.go      # wrap key + TURN creds cache
│   │   ├── ca_bundle.go        # embedded Mozilla CA (HARICA Root CA)
│   │   ├── vpn.go              # WireGuard TUN device integration
│   │   ├── updater.go          # GitHub Releases auto-update
│   │   ├── config.go           # JSON config file support
│   │   ├── wb.go               # Warp Backend mode
│   │   ├── profiles.go         # browser profiles for tls-client
│   │   └── namegen.go          # Russian name generator
│   └── util/util.go            # logging + socket protection
└── go.mod
```

## Two Modes

### Mode 1: Proxy Only
TurnGuard runs as a TURN proxy. Connect your own WireGuard client to `127.0.0.1:9000`.
```
WireGuard client → 127.0.0.1:9000 → TurnGuard → TURN relay → VK → your server
```

### Mode 2: Standalone VPN
TurnGuard creates a TUN device and runs WireGuard internally. All-in-one.
```
System traffic → TUN device → WireGuard → 127.0.0.1:9000 → TurnGuard → TURN → VK → your server
```

## Platform Notes

- **Linux**: TUN device creation requires root (`sudo`) or `CAP_NET_ADMIN`
- **Windows**: Requires `wintun.dll` (automatically loaded by wireguard-go)
- **macOS**: Uses built-in `utun` device

## Credits

- Based on [cacggghp/vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy)
- Uses [wireguard-go](https://github.com/WireGuard/wireguard-go), [pion/dtls](https://github.com/pion/dtls), [pion/turn](https://github.com/pion/turn)
- SRTP-mimicry wrap ported from [NikKuz99/wireguard-turn-android](https://github.com/NikKuz99/wireguard-turn-android)

## License

Apache-2.0
