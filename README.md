# TurnGuard

> Cross-platform WireGuard + VK TURN desktop client with SRTP-mimicry wrap, DNS fallback, and auto-captcha.
>
> **Windows · Linux · macOS** — one binary, no runtime dependencies.

## Features

- **SRTP-mimicry wrap** (RFC 3550 RTP) — 4.9x speedup vs baseline TURN
- **DNS fallback** (VKHosts) — 16 baseline IPs + dynamic DNS resolution with metrics
- **Auto-captcha** — browser-based VK captcha solver
- **WireGuard userspace** — uses wireguard-go (no kernel module needed)
- **Cascading DNS** — system → Yandex → Google (plain/DoH/DoT)
- **Embedded CA bundle** — works on systems without /etc/ssl/certs/

## Quick Start

```bash
# Build
go build -o turnguard ./cmd/turnguard/

# Run (connects to VK TURN relay → your server)
./turnguard \
  -vk-link https://vk.com/call/join/... \
  -peer your.server.com:56001 \
  -wrap-key e979270b5240918e9f3764b0daf9bd825f6d95185481926407435665b37e53ca

# Then configure WireGuard:
#   Endpoint = 127.0.0.1:9000
#   MTU = 1280
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-vk-link` | (required) | VK call link (`https://vk.com/call/join/...`) |
| `-peer` | (required) | Peer server address (`host:port`) |
| `-listen` | `127.0.0.1:9000` | Local UDP listener for WireGuard |
| `-wrap-key` | (empty) | SRTP-mimicry wrap key (64 hex chars = 32 bytes) |
| `-streams` | `4` | Number of parallel TURN streams (1-4) |
| `-udp` | `false` | Use UDP mode (default: TCP) |

## Architecture

```
TurnGuard/
├── cmd/turnguard/        # CLI entry point
├── internal/
│   ├── core/             # Wrap key management, VPN core
│   ├── dns/              # VKHosts (DNS fallback) + cascading resolver + CA bundle
│   ├── wrap/             # SRTP-mimicry AEAD (ChaCha20-Poly1305, RFC 3550 RTP)
│   ├── vk/               # VK auth + TURN credentials + captcha API
│   ├── captcha/          # Slider captcha auto-solver
│   └── util/             # Logging, socket protection (no-op on desktop)
└── go.mod
```

## Credits

- Based on [cacggghp/vk-turn-proxy](https://github.com/cacggghp/vk-turn-proxy) — original TURN proxy concept
- Uses [wireguard-go](https://github.com/WireGuard/wireguard-go) — userspace WireGuard
- Uses [pion/dtls](https://github.com/pion/dtls) — DTLS 1.2 implementation
- SRTP-mimicry wrap ported from [NikKuz99/wireguard-turn-android](https://github.com/NikKuz99/wireguard-turn-android)

## License

Apache-2.0
