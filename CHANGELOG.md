# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.7.0] - 2026-10-02

### Added

- Captcha architecture v2: JS tokenizer (`jstoken.go`) + structural
  classification of the powInput call (ladder L1a–L1d) with legacy regex as a
  safety net.
- go-test CI workflow (build, vet, test on push/PR).
- Regression tests: wrap-key decode and stream-credentials cache sharing.

### Fixed

- BUG-013: VK BFF obfuscation single-quote regression (11th pattern; the
  architectural tokenizer change closes the whole class).
- DNS resolver syntax + graceful VPN session shutdown.
- Captcha stack brought to parity with Android v1.5.2/v1.5.3: BUG-011
  (captcha API overhaul: initSession settings, stdlib HTTP, dynamic
  debug_info/adFp, PoW telemetry) and BUG-012 (custom dialer: vkHosts
  cascading DNS + bundled CA).

### Changed

- Version bump 0.6.9 → 0.7.0; lockfiles and tracked sidecar binaries synced
  (`1602fa2` + `cb07b67`). The intermediate 0.6.9 version was never released
  on its own — all fixes ship inside 0.7.0.

## [0.6.8] - 2026-09-10

### Fixed

- Auto-solver fixed (BFF powInput parser), VPN TUN creation and internet E2E
  test, parser fix, disk monitoring.
