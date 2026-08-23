/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * config.go — JSON configuration file support.
 * Allows loading all TurnGuard parameters from a config file
 * instead of CLI flags.
 *
 * Config file format (config.json):
 * {
 *   "vk_link": "https://vk.com/call/join/...",
 *   "peer": "server.com:56001",
 *   "listen": "127.0.0.1:9000",
 *   "wrap_key": "e979270b...",
 *   "streams": 4,
 *   "udp": false,
 *   "mode": "vk_link",
 *   "peer_type": "proxy_v1",
 *   "vpn": {
 *     "enabled": true,
 *     "private_key": "abc123...",
 *     "server_key": "def456...",
 *     "server_addr": "127.0.0.1:9000",
 *     "allowed_ips": "0.0.0.0/0, ::0",
 *     "mtu": 1280,
 *     "keepalive": 25
 *   },
 *   "auto_update": true
 * }
 */
package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NikKuz99/turnguard/internal/util"
)

// VPNConfigSection is the VPN section of the config file.
type VPNConfigSection struct {
	Enabled    bool   `json:"enabled"`
	PrivateKey  string `json:"private_key"`
	ServerKey   string `json:"server_key"`
	ServerAddr  string `json:"server_addr"`
	AllowedIPs  string `json:"allowed_ips"`
	MTU         int    `json:"mtu"`
	Keepalive   int    `json:"keepalive"`
}

// Config holds all TurnGuard configuration.
type Config struct {
	VKLink    string           `json:"vk_link"`
	Peer      string           `json:"peer"`
	Listen    string           `json:"listen"`
	WrapKey   string           `json:"wrap_key"`
	Streams   int              `json:"streams"`
	UDP       bool             `json:"udp"`
	Mode      string           `json:"mode"`
	PeerType  string           `json:"peer_type"`
	VPN       VPNConfigSection `json:"vpn"`
	AutoUpdate bool            `json:"auto_update"`
}

// DefaultConfig returns a Config with default values.
func DefaultConfig() *Config {
	return &Config{
		Listen:    "127.0.0.1:9000",
		Streams:   4,
		UDP:       false,
		Mode:      "vk_link",
		PeerType:  "proxy_v1",
		AutoUpdate: true,
		VPN: VPNConfigSection{
			Enabled:    false,
			ServerAddr: "127.0.0.1:9000",
			AllowedIPs: "0.0.0.0/0, ::0",
			MTU:        1280,
			Keepalive:  25,
		},
	}
}

// LoadConfig reads a JSON config file.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Validate required fields
	if cfg.VKLink == "" {
		return nil, fmt.Errorf("vk_link is required in config")
	}
	if cfg.Peer == "" {
		return nil, fmt.Errorf("peer is required in config")
	}

	// Set defaults for empty optional fields
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:9000"
	}
	if cfg.Mode == "" {
		cfg.Mode = "vk_link"
	}
	if cfg.PeerType == "" {
		cfg.PeerType = "proxy_v1"
	}
	if cfg.Streams == 0 {
		cfg.Streams = 4
	}
	if cfg.VPN.AllowedIPs == "" {
		cfg.VPN.AllowedIPs = "0.0.0.0/0, ::0"
	}
	if cfg.VPN.MTU == 0 {
		cfg.VPN.MTU = 1280
	}
	if cfg.VPN.Keepalive == 0 {
		cfg.VPN.Keepalive = 25
	}
	if cfg.VPN.ServerAddr == "" {
		cfg.VPN.ServerAddr = cfg.Listen
	}

	util.TurnLog("[Config] Loaded from %s", path)
	return cfg, nil
}

// SaveConfig writes a Config to a JSON file.
func SaveConfig(cfg *Config, path string) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if dir := filepath.Dir(path); dir != "." {
		os.MkdirAll(dir, 0755)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	util.TurnLog("[Config] Saved to %s", path)
	return nil
}

// ConfigPath returns the default config file path.
// Looks for config.json in:
// 1. Current directory
// 2. ~/.config/turnguard/config.json
// 3. /etc/turnguard/config.json (Linux only)
func DefaultConfigPath() string {
	// Check current directory first
	if _, err := os.Stat("config.json"); err == nil {
		return "config.json"
	}

	// Check user config directory
	home, err := os.UserHomeDir()
	if err == nil {
		p := filepath.Join(home, ".config", "turnguard", "config.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}

	// Check system config (Linux)
	if _, err := os.Stat("/etc/turnguard/config.json"); err == nil {
		return "/etc/turnguard/config.json"
	}

	// Default: current directory
	return "config.json"
}

// GenerateExampleConfig creates an example config.json file.
func GenerateExampleConfig(path string) error {
	cfg := DefaultConfig()
	cfg.VKLink = "https://vk.com/call/join/your_link_here"
	cfg.Peer = "your.server.com:56001"
	cfg.WrapKey = "e979270b5240918e9f3764b0daf9bd825f6d95185481926407435665b37e53ca"
	cfg.VPN.Enabled = true
	cfg.VPN.PrivateKey = "your_client_private_key_hex_64_chars"
	cfg.VPN.ServerKey = "your_server_public_key_hex_64_chars"

	return SaveConfig(cfg, path)
}
