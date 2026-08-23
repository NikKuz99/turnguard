/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * vpn.go — WireGuard TUN device integration.
 * Creates a TUN interface, configures WireGuard peer,
 * and routes traffic through the TURN proxy.
 */
package core

import (
	"encoding/hex"
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/NikKuz99/turnguard/internal/util"
)

// VPNConfig holds WireGuard configuration.
type VPNConfig struct {
	PrivateKey    string // Client's WireGuard private key (hex, 64 chars)
	ServerPubKey   string // Server's WireGuard public key (hex, 64 chars)
	ServerAddr    string // Server address (host:port) — usually 127.0.0.1:9000
	AllowedIPs    string // Allowed IPs (default: 0.0.0.0/0, ::0)
	Endpoint      string // Override endpoint (if different from ServerAddr)
	MTU           int    // MTU (default: 1280)
	Keepalive     int    // Persistent keepalive interval (seconds, 0 = disabled)
	TunnelName    string // TUN device name (default: turnguard0)
}

// VPNDevice holds the WireGuard device and TUN interface.
type VPNDevice struct {
	dev *device.Device
	tun tun.Device
}

// StartVPN creates a TUN device, configures WireGuard, and brings it up.
func StartVPN(cfg VPNConfig) (*VPNDevice, error) {
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	if cfg.TunnelName == "" {
		cfg.TunnelName = "turnguard0"
	}
	if cfg.AllowedIPs == "" {
		cfg.AllowedIPs = "0.0.0.0/0, ::0"
	}

	util.TurnLog("[VPN] Creating TUN device: %s (MTU %d)", cfg.TunnelName, cfg.MTU)

	tunDevice, err := tun.CreateTUN(cfg.TunnelName, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN: %w", err)
	}

	realName, err := tunDevice.Name()
	if err != nil {
		tunDevice.Close()
		return nil, fmt.Errorf("failed to get TUN name: %w", err)
	}
	util.TurnLog("[VPN] TUN device created: %s", realName)

	logger := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			util.TurnLog("[WG] "+format, args...)
		},
		Errorf: func(format string, args ...interface{}) {
			util.TurnLog("[WG ERROR] "+format, args...)
		},
	}

	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), logger)

	uapi := fmt.Sprintf(
		"private_key=%s\npublic_key=%s\nendpoint=%s\nallowed_ip=%s\npersistent_keepalive_interval=%d\n",
		cfg.PrivateKey, cfg.ServerPubKey, cfg.ServerAddr, cfg.AllowedIPs, cfg.Keepalive,
	)

	err = dev.IpcSet(uapi)
	if err != nil {
		tunDevice.Close()
		return nil, fmt.Errorf("failed to configure WireGuard: %w", err)
	}

	err = dev.Up()
	if err != nil {
		tunDevice.Close()
		return nil, fmt.Errorf("failed to bring up WireGuard: %w", err)
	}

	util.TurnLog("[VPN] WireGuard device up — tunnel active")
	util.TurnLog("[VPN] Peer: %s (pubkey: %s...)", cfg.ServerAddr, cfg.ServerPubKey[:16])

	return &VPNDevice{dev: dev, tun: tunDevice}, nil
}

// StopVPN brings down the WireGuard device and closes the TUN.
func (v *VPNDevice) Stop() {
	if v.dev != nil {
		v.dev.Down()
	}
	if v.tun != nil {
		v.tun.Close()
	}
	util.TurnLog("[VPN] WireGuard device stopped")
}

// ValidateKey checks if a hex key is valid (64 chars = 32 bytes).
func ValidateKey(key string) error {
	if len(key) != 64 {
		return fmt.Errorf("key must be 64 hex chars (32 bytes), got %d", len(key))
	}
	_, err := hex.DecodeString(key)
	if err != nil {
		return fmt.Errorf("invalid hex: %w", err)
	}
	return nil
}

// ParseAllowedIPs parses a comma-separated list of CIDR ranges.
func ParseAllowedIPs(s string) ([]*net.IPNet, error) {
	var nets []*net.IPNet
	for _, cidr := range splitComma(s) {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		nets = append(nets, ipNet)
	}
	return nets, nil
}

func splitComma(s string) []string {
	var parts []string
	current := ""
	for _, c := range s {
		if c == ',' {
			parts = append(parts, current)
			current = ""
		} else if c != ' ' {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
