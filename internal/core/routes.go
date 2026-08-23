/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * routes.go — Platform-specific routing setup.
 * When using VPN mode (0.0.0.0/0), we need to:
 * 1. Add a route for the TURN server IP through the default gateway
 *    (so TURN traffic doesn't go through the VPN tunnel → routing loop)
 * 2. Add a route for VK TURN relay IPs through the default gateway
 * 3. Add default route through the TUN device
 *
 * On Linux: uses `ip route` commands
 * On Windows: uses `route add` commands
 * On macOS: uses `route add` commands
 */
package core

import (
	"net"
	"os/exec"
	"runtime"
	"strings"

	"github.com/NikKuz99/turnguard/internal/util"
)

// SetupVPNRouting sets up routing for full-tunnel VPN mode.
// This prevents routing loops by ensuring TURN server traffic

//
// Parameters:
// - tunName: TUN device name (e.g. "turnguard0")
// - turnServerIP: IP address of the TURN peer server
// - vkRelayIPs: IP addresses of VK TURN relays (to exclude from VPN)
// - defaultGateway: default gateway IP (for adding bypass routes)
func SetupVPNRouting(tunName string, turnServerIP string, vkRelayIPs []string, defaultGateway string) {
	util.TurnLog("[Routes] Setting up VPN routing (platform: %s)", runtime.GOOS)

	switch runtime.GOOS {
	case "linux":
		setupRoutingLinux(tunName, turnServerIP, vkRelayIPs, defaultGateway)
	case "windows":
		setupRoutingWindows(tunName, turnServerIP, vkRelayIPs, defaultGateway)
	case "darwin":
		setupRoutingDarwin(tunName, turnServerIP, vkRelayIPs, defaultGateway)
	default:
		util.TurnLog("[Routes] Unsupported platform: %s", runtime.GOOS)
	}
}

// CleanupVPNRouting removes routes added by SetupVPNRouting.
func CleanupVPNRouting(tunName string, turnServerIP string, vkRelayIPs []string) {
	util.TurnLog("[Routes] Cleaning up VPN routing")

	switch runtime.GOOS {
	case "linux":
		cleanupRoutingLinux(tunName, turnServerIP, vkRelayIPs)
	case "windows":
		cleanupRoutingWindows(tunName, turnServerIP, vkRelayIPs)
	case "darwin":
		cleanupRoutingDarwin(tunName, turnServerIP, vkRelayIPs)
	}
}

// --- Linux ---

func setupRoutingLinux(tunName, turnIP string, vkIPs []string, gateway string) {
	if gateway == "" {
		gateway = getDefaultGatewayLinux()
	}
	if gateway == "" {
		util.TurnLog("[Routes] No default gateway found, skipping route setup")
		return
	}

	// Bypass route for TURN server
	runCmd("ip", "route", "add", turnIP, "via", gateway)

	// Bypass routes for VK relay IPs
	for _, ip := range vkIPs {
		runCmd("ip", "route", "add", ip+"/32", "via", gateway)
	}

	util.TurnLog("[Routes] Linux routing setup complete (gateway: %s, bypass: %d IPs)", gateway, len(vkIPs)+1)
}

func cleanupRoutingLinux(tunName, turnIP string, vkIPs []string) {
	runCmd("ip", "route", "del", turnIP)
	for _, ip := range vkIPs {
		runCmd("ip", "route", "del", ip+"/32")
	}
	util.TurnLog("[Routes] Linux routing cleanup complete")
}

func getDefaultGatewayLinux() string {
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	// Output: "default via 192.168.1.1 dev eth0"
	parts := strings.Fields(string(out))
	for i, p := range parts {
		if p == "via" && i+1 < len(parts) {
			return parts[i+1]
		}
	}
	return ""
}

// --- Windows ---

func setupRoutingWindows(tunName, turnIP string, vkIPs []string, gateway string) {
	// Bypass route for TURN server
	runCmd("route", "ADD", turnIP, gateway)

	// Bypass routes for VK relay IPs
	for _, ip := range vkIPs {
		runCmd("route", "ADD", ip, gateway)
	}

	util.TurnLog("[Routes] Windows routing setup complete (bypass: %d IPs)", len(vkIPs)+1)
}

func cleanupRoutingWindows(tunName, turnIP string, vkIPs []string) {
	runCmd("route", "DELETE", turnIP)
	for _, ip := range vkIPs {
		runCmd("route", "DELETE", ip)
	}
	util.TurnLog("[Routes] Windows routing cleanup complete")
}

// --- macOS ---

func setupRoutingDarwin(tunName, turnIP string, vkIPs []string, gateway string) {
	if gateway == "" {
		gateway = getDefaultGatewayDarwin()
	}
	if gateway == "" {
		util.TurnLog("[Routes] No default gateway found, skipping route setup")
		return
	}

	// Bypass route for TURN server
	runCmd("route", "add", turnIP, gateway)

	// Bypass routes for VK relay IPs
	for _, ip := range vkIPs {
		runCmd("route", "add", ip, gateway)
	}

	util.TurnLog("[Routes] macOS routing setup complete (gateway: %s, bypass: %d IPs)", gateway, len(vkIPs)+1)
}

func cleanupRoutingDarwin(tunName, turnIP string, vkIPs []string) {
	runCmd("route", "delete", turnIP)
	for _, ip := range vkIPs {
		runCmd("route", "delete", ip)
	}
	util.TurnLog("[Routes] macOS routing cleanup complete")
}

func getDefaultGatewayDarwin() string {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return ""
	}
	// Output contains: "gateway: 192.168.1.1"
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
	}
	return ""
}

// runCmd runs a command and logs the result.
func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		util.TurnLog("[Routes] %s %s: %v (output: %s)", name, strings.Join(args, " "), err, string(output))
	}
}

// GetVKRelayIPs returns known VK TURN relay IP ranges.
// These should be bypassed from VPN routing to avoid loops.
func GetVKRelayIPs() []string {
	return []string{
		"90.156.236.96",   // VK TURN relay (calls)
		"5.255.211.241",   // Yandex Telemost relay
	}
}

// IsPrivateIP checks if an IP address is private (RFC 1918).
func IsPrivateIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	return parsedIP.IsPrivate() || parsedIP.IsLoopback() || parsedIP.IsLinkLocalUnicast()
}
