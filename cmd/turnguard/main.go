/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * TurnGuard - Cross-platform WireGuard + VK TURN desktop client.
 */
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/NikKuz99/turnguard/internal/core"
	"github.com/NikKuz99/turnguard/internal/util"
)

func main() {
	configPath := flag.String("config", "", "Path to config.json file (overrides CLI flags)")
	vkLink := flag.String("vk-link", "", "VK call link (https://vk.com/call/join/...)")
	peerAddr := flag.String("peer", "", "Peer server address (host:port)")
	listenAddr := flag.String("listen", "127.0.0.1:9000", "Local UDP listener for WireGuard")
	wrapKey := flag.String("wrap-key", "", "SRTP-mimicry wrap key (64 hex chars = 32 bytes)")
	streams := flag.Int("streams", 4, "Number of parallel TURN streams (1-4)")
	useUDP := flag.Bool("udp", false, "Use UDP mode (default: TCP)")
	mode := flag.String("mode", "vk_link", "Mode: vk_link or wb")
	peerType := flag.String("peer-type", "proxy_v1", "Peer type: proxy_v1 or wireguard")
	useVPN := flag.Bool("vpn", false, "Start WireGuard TUN device (standalone VPN mode)")
	privateKey := flag.String("private-key", "", "Client WireGuard private key (64 hex chars)")
	serverPubKey := flag.String("server-key", "", "Server WireGuard public key (64 hex chars)")
	serverAddr := flag.String("server-addr", "127.0.0.1:9000", "WireGuard server endpoint")
	allowedIPs := flag.String("allowed-ips", "0.0.0.0/0, ::0", "Allowed IPs for WireGuard")
	mtu := flag.Int("mtu", 1280, "MTU for TUN device")
	keepalive := flag.Int("keepalive", 25, "Persistent keepalive interval (seconds)")
	checkUpdate := flag.Bool("check-update", false, "Check for updates and exit")
	autoUpdate := flag.Bool("auto-update", true, "Enable background update checker")
	genConfig := flag.Bool("gen-config", false, "Generate example config.json and exit")
	showVersion := flag.Bool("version", false, "Show version and exit")
	logFile := flag.String("log-file", "", "Path to log file (default: no file logging)")
	useWebUI := flag.Bool("webui", false, "Start web UI (open http://127.0.0.1:8080)")
	webUIPort := flag.Int("webui-port", 8080, "Port for web UI")
	flag.Parse()

	if *showVersion {
		fmt.Printf("TurnGuard %s\n", core.CurrentVersion)
		os.Exit(0)
	}

	if *genConfig {
		if err := core.GenerateExampleConfig("config.json"); err != nil {
			fmt.Fprintf(os.Stderr, "Failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Example config written to config.json")
		os.Exit(0)
	}

	if *checkUpdate {
		url, version, err := core.CheckForUpdate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Update check failed: %v\n", err)
			os.Exit(1)
		}
		if url == "" {
			fmt.Printf("No updates available (current: %s)\n", core.CurrentVersion)
		} else {
			fmt.Printf("Update available: %s (current: %s)\n", version, core.CurrentVersion)
			if err := core.DownloadAndUpdate(url); err != nil {
				fmt.Fprintf(os.Stderr, "Update failed: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("Update installed! Restart to apply.")
		}
		os.Exit(0)
	}

	// Load config file if specified
	if *configPath != "" {
		cfg, err := core.LoadConfig(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
			os.Exit(1)
		}
		*vkLink = cfg.VKLink
		*peerAddr = cfg.Peer
		*listenAddr = cfg.Listen
		*wrapKey = cfg.WrapKey
		*streams = cfg.Streams
		*useUDP = cfg.UDP
		*mode = cfg.Mode
		*peerType = cfg.PeerType
		*useVPN = cfg.VPN.Enabled
		*privateKey = cfg.VPN.PrivateKey
		*serverPubKey = cfg.VPN.ServerKey
		*serverAddr = cfg.VPN.ServerAddr
		*allowedIPs = cfg.VPN.AllowedIPs
		*mtu = cfg.VPN.MTU
		*keepalive = cfg.VPN.Keepalive
		*autoUpdate = cfg.AutoUpdate
	}

	if *vkLink == "" && !*useWebUI {
		fmt.Fprintln(os.Stderr, "Error: -vk-link is required (or use -config config.json or -webui)")
		fmt.Fprintln(os.Stderr, "Usage: turnguard -vk-link <URL> -peer <host:port> [-wrap-key <hex>] [-vpn -private-key <hex> -server-key <hex>]")
		fmt.Fprintln(os.Stderr, "       turnguard -config config.json")
		fmt.Fprintln(os.Stderr, "       turnguard -webui")
		fmt.Fprintln(os.Stderr, "       turnguard -gen-config")
		fmt.Fprintln(os.Stderr, "       turnguard -version")
		fmt.Fprintln(os.Stderr, "       turnguard -check-update")
		os.Exit(1)
	}
	if *peerAddr == "" && !*useWebUI {
		fmt.Fprintln(os.Stderr, "Error: -peer is required")
		os.Exit(1)
	}

	// Init file logging if requested
	if *logFile != "" {
		if err := core.InitFileLogging(*logFile); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: file logging failed: %v\n", err)
		}
		defer core.CloseFileLogging()
	}

	if *wrapKey != "" {
		if err := core.SetWrapKey(*wrapKey); err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid wrap key: %v\n", err)
			os.Exit(1)
		}
		util.TurnLog("Wrap key set (%d bytes)", len(core.GetWrapKey()))
	} else {
		util.TurnLog("No wrap key - SRTP-mimicry wrap disabled")
	}

	core.SetVkCredsFetcher(core.FetchVkCreds)
	core.SetCaptchaCallback(core.SolveCaptchaBrowser)

	util.TurnLog("TurnGuard %s starting...", core.CurrentVersion)
	if *useWebUI {
		util.TurnLog("  Mode: Web UI")
	} else {
		util.TurnLog("  VK Link: %s", *vkLink)
		util.TurnLog("  Peer: %s", *peerAddr)
		util.TurnLog("  Listen: %s", *listenAddr)
		util.TurnLog("  Streams: %d", *streams)
		util.TurnLog("  UDP: %v", *useUDP)
		util.TurnLog("  Wrap: %v", core.IsWrapEnabled())
		if *useVPN {
			util.TurnLog("  VPN: enabled (TUN device)")
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT)
	signal.Notify(sigChan, syscall.SIGTERM)

	var vpnDev *core.VPNDevice

	go func() {
		sig := <-sigChan
		util.TurnLog("Received signal %v, shutting down...", sig)
		if vpnDev != nil {
			vpnDev.Stop()
		}
		core.StopProxy()
		cancel()
	}()

	// Web UI mode
	if *useWebUI {
		webUI := core.NewWebUI(*webUIPort)
		if err := webUI.Start(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "Web UI failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("TurnGuard Web UI: http://127.0.0.1:%d\n", webUI.GetPort())
		fmt.Println("Press Ctrl+C to stop.")
		<-ctx.Done()
		os.Exit(0)
	}

	// Start TURN proxy
	ret := core.StartProxy(*peerAddr, *vkLink, *mode, *streams, *useUDP, *listenAddr, "", 0, *peerType, 4, 0)
	if ret != 0 {
		util.TurnLog("Failed to start TURN proxy (code %d)", ret)
		os.Exit(1)
	}
	util.TurnLog("TurnGuard TURN proxy ready on %s", *listenAddr)

	// Start WireGuard TUN device if requested
	if *useVPN {
		if *privateKey == "" || *serverPubKey == "" {
			util.TurnLog("[VPN] Error: -private-key and -server-key required for VPN mode")
			core.StopProxy()
			os.Exit(1)
		}
		util.TurnLog("[VPN] Starting WireGuard TUN device...")
		vpnDev, err := core.StartVPN(core.VPNConfig{
			PrivateKey:   *privateKey,
			ServerPubKey: *serverPubKey,
			ServerAddr:   *serverAddr,
			AllowedIPs:   *allowedIPs,
			MTU:          *mtu,
			Keepalive:    *keepalive,
			TunnelName:   "turnguard0",
		})
		if err != nil {
			util.TurnLog("[VPN] Failed to start: %v", err)
			core.StopProxy()
			os.Exit(1)
		}
		vpnDev = vpnDev

		if *allowedIPs == "0.0.0.0/0, ::0" || *allowedIPs == "0.0.0.0/0" {
			util.TurnLog("[VPN] Full-tunnel mode: setting up bypass routes...")
			core.SetupVPNRouting("turnguard0", *peerAddr, core.GetVKRelayIPs(), "")
			defer core.CleanupVPNRouting("turnguard0", *peerAddr, core.GetVKRelayIPs())
		}

		util.TurnLog("[VPN] Tunnel active. All traffic routed through WireGuard -> TURN -> %s", *peerAddr)
	} else {
		util.TurnLog("Connect WireGuard to %s (MTU %d)", *listenAddr, *mtu)
	}

	if *autoUpdate {
		core.StartUpdateChecker(ctx)
	}

	<-ctx.Done()
	util.TurnLog("TurnGuard stopped.")
}
