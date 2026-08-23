/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2023 The Pion community <https://pion.ly>
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package core

/*
#include <stdlib.h>
#include <android/log.h>
extern int wgProtectSocket(int fd);
extern const char* getNetworkDnsServers(long long network_handle);
*/

import (
	"github.com/NikKuz99/turnguard/internal/util"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/pion/dtls/v3"
	"github.com/pion/logging"
	"github.com/pion/turn/v5"
)

func turnLog(format string, args ...interface{}) {
	util.TurnLog(format, args...)
}

type connectedUDPConn struct{ *net.UDPConn }
func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

func init() {
	os.Setenv("GODEBUG", "netdns=go")
}

// wgNotifyNetworkChange (desktop: no-op, just clears DNS cache)
func wgNotifyNetworkChange() {
	// Clear DNS cache
	ClearCache()

	turnHTTPClient.CloseIdleConnections()
	util.TurnLog("[NETWORK] Network change notified: HTTP connections cleared, DNS cache cleared")
}

var turnHTTPClient = &http.Client{
	Timeout: 20 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 30 * time.Second,
			Control: util.ProtectControl,
		}).DialContext,
		MaxIdleConns: 100,
		IdleConnTimeout: 90 * time.Second,
		TLSClientConfig: &tls.Config{RootCAs: loadCABundle()},
	},
}

type stream struct {
	ctx       context.Context
	id        int
	in        chan []byte
	out       net.PacketConn
	peer      atomic.Pointer[net.Addr] // Last seen addr from WireGuard
	ready     atomic.Bool
	sessionID []byte
	cert      *tls.Certificate
	watchdogTimeout int
}

const iPacketBuffMaxSize = 2048;

var packetPool = sync.Pool{
    New: func() interface{} {
        return make([]byte, iPacketBuffMaxSize)
    },
}

// Metrics for diagnostics
var (
	dtlsTxDropCount   atomic.Uint64      // Drops in DTLS TX goroutine
	dtlsRxErrorCount  atomic.Uint64      // Errors in DTLS RX goroutine
	relayTxErrorCount atomic.Uint64      // Errors in relay TX
	relayRxErrorCount atomic.Uint64      // Errors in relay RX
	noDtlsTxDropCount atomic.Uint64      // Drops in NoDTLS TX
	noDtlsRxErrorCount atomic.Uint64     // Errors in NoDTLS RX
)

func (s *stream) run(link string, peer *net.UDPAddr, udp bool, okchan chan<- struct{}, turnIp string, turnPort int, peerType string) {
	for {
		select {
		case <-s.ctx.Done(): return
		default:
		}

		err := func() error {
			s.ready.Store(false)
			sCtx, sCancel := context.WithCancel(s.ctx)
			defer sCancel()

			if globalGetCreds == nil {
				return fmt.Errorf("credentials function not initialized")
			}
			user, pass, addr, err := globalGetCreds(sCtx, link, s.id)
			if err != nil { return fmt.Errorf("TURN creds failed: %w", err) }

			// Override TURN address if provided
			if turnIp != "" {
				_, origPort, _ := net.SplitHostPort(addr)
				if turnPort != 0 {
					addr = net.JoinHostPort(turnIp, fmt.Sprintf("%d", turnPort))
				} else if origPort != "" {
					addr = net.JoinHostPort(turnIp, origPort)
				} else {
					addr = turnIp
				}
				util.TurnLog("[STREAM %d] Using custom TURN IP: %s", s.id, addr)
			} else if turnPort != 0 {
				origHost, _, _ := net.SplitHostPort(addr)
				addr = net.JoinHostPort(origHost, fmt.Sprintf("%d", turnPort))
				util.TurnLog("[STREAM %d] Using custom TURN port: %s", s.id, addr)
			}

			util.TurnLog("[STREAM %d] Dialing TURN server %s...", s.id, addr)
			// addr is already resolved during credential fetch via cascading DNS, so use DialContext without Resolver
			dialer := &net.Dialer{
				Timeout: 30 * time.Second,
				Control: util.ProtectControl,
			}
			var turnConn net.PacketConn
			if udp {
				c, err := dialer.DialContext(sCtx, "udp", addr)
				if err != nil { return fmt.Errorf("TURN UDP dial failed: %w", err) }
				defer c.Close()
				turnConn = &connectedUDPConn{c.(*net.UDPConn)}
			} else {
				c, err := dialer.DialContext(sCtx, "tcp", addr)
				if err != nil { return fmt.Errorf("TURN TCP dial failed: %w", err) }
				defer c.Close()
				turnConn = turn.NewSTUNConn(c)
			}

			client, err := turn.NewClient(&turn.ClientConfig{
				STUNServerAddr: addr, TURNServerAddr: addr, Username: user, Password: pass,
				Conn: turnConn, LoggerFactory: logging.NewDefaultLoggerFactory(),
			})
			if err != nil { return fmt.Errorf("TURN client creation failed: %w", err) }
			defer client.Close()
			if err := client.Listen(); err != nil {
				// Check if this is an authentication error (stale credentials)
				if isAuthError(err) {
					handleAuthError(s.id)
				}
				return fmt.Errorf("TURN listen failed: %w", err)
			}

			util.TurnLog("[STREAM %d] Requesting TURN allocation...", s.id)
			relayConn, err := client.Allocate()
			if err != nil {
				// Check if this is an authentication error (stale credentials)
				if isAuthError(err) {
					handleAuthError(s.id)
				}
				return fmt.Errorf("TURN allocation failed: %w", err)
			}
			defer relayConn.Close()

			util.TurnLog("[STREAM %d] Allocated relay address: %s", s.id, relayConn.LocalAddr())

			// Delegate to mode-specific handler
			if peerType == "wireguard" {
				return s.runNoDTLS(sCtx, relayConn, peer, okchan)
			}
			// proxy_v2 and proxy_v1 both use DTLS, but v2 sends session+stream handshake
			sendHandshake := peerType != "proxy_v1"
			return s.runDTLS(sCtx, relayConn, peer, okchan, sendHandshake)
		}()

		if err != nil && s.ctx.Err() == nil {
			util.TurnLog("[STREAM %d] Error: %v. Reconnecting in 1s...", s.id, err)
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(1 * time.Second):
			}
		}
	}
}

// runNoDTLS handles packet relay without DTLS obfuscation
func (s *stream) runNoDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr, okchan chan<- struct{}) error {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()

	// WRAP integration: same as runDTLS, wrap relayConn if wrap key set
	if len(wrapKeyBytes) == wrapKeyLen {
		wc, werr := newWrapConn(wrapKeyBytes, false)
		if werr != nil {
			util.TurnLog("[STREAM %d] WRAP init failed: %v", s.id, werr)
		} else {
			relayConn = &wrappedPacketConn{relay: relayConn, peer: peer, wc: wc}
			util.TurnLog("[STREAM %d] WRAP enabled in NoDTLS mode", s.id)
		}
	}

	util.TurnLog("[STREAM %d] No DTLS mode - direct relay", s.id)
	util.TurnLog("[STREAM %d] Forwarding to WireGuard server: %s", s.id, peer.String())

	wg := sync.WaitGroup{}
	wg.Add(2)

	// WireGuard backend (s.in channel) -> TURN -> WireGuard server (TX)
	go func() {
		defer wg.Done(); defer sCancel()
		for {
			select {
			case <-sCtx.Done(): return
			case b := <-s.in:
                _, err := relayConn.WriteTo(b, peer)
                packetPool.Put(b[:cap(b)])

                if err != nil {
					noDtlsTxDropCount.Add(1)
					util.TurnLog("[STREAM %d] TX error: %v", s.id, err)
					return
				}
			}
		}
	}()

	// WireGuard server -> TURN -> WireGuard backend (s.out socket) (RX)
	go func() {
		defer wg.Done(); defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, from, err := relayConn.ReadFrom(buf)
			if err != nil {
				noDtlsRxErrorCount.Add(1)
				util.TurnLog("[STREAM %d] RX error: %v", s.id, err)
				return
			}
			if from.String() == peer.String() {
				addr := s.peer.Load()
				if addr == nil {
					util.TurnLog("[STREAM %d] RX: no peer address yet", s.id)
					continue
				}
				if _, err := s.out.WriteTo(buf[:n], *addr); err != nil {
					noDtlsRxErrorCount.Add(1)
					util.TurnLog("[STREAM %d] RX write error: %v", s.id, err)
					return
				}
			}
		}
	}()

	s.ready.Store(true)
	select { case okchan <- struct{}{}: default: }

	wg.Wait()
	return nil
}

// runDTLS handles packet relay with DTLS obfuscation
func (s *stream) runDTLS(ctx context.Context, relayConn net.PacketConn, peer *net.UDPAddr, okchan chan<- struct{}, sendHandshake bool) error {
	sCtx, sCancel := context.WithCancel(ctx)
	defer sCancel()

	// WRAP integration: if wrapKeyBytes is set, wrap relayConn so DTLS
	// packets get AEAD-wrapped as SRTP-looking RTP packets to bypass
	// VK TURN content filter (issue #164).
	if len(wrapKeyBytes) == wrapKeyLen {
		wc, werr := newWrapConn(wrapKeyBytes, false)
		if werr != nil {
			util.TurnLog("[STREAM %d] WRAP init failed: %v", s.id, werr)
		} else {
			relayConn = &wrappedPacketConn{relay: relayConn, peer: peer, wc: wc}
			util.TurnLog("[STREAM %d] WRAP enabled (SRTP-mimicry)", s.id)
		}
	}

	var dtlsConn *dtls.Conn

	c1, c2 := connutil.AsyncPacketPipe()
	defer c1.Close()
	defer c2.Close()

	dtlsConn, err := dtls.Client(c1, peer, &dtls.Config{
		Certificates: []tls.Certificate{*s.cert}, InsecureSkipVerify: true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		CipherSuites: []dtls.CipherSuiteID{dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		ConnectionIDGenerator: dtls.OnlySendCIDGenerator(),
	})
	if err != nil { return fmt.Errorf("DTLS client creation failed: %w", err) }
	defer dtlsConn.Close()

	wg := sync.WaitGroup{}
	wg.Add(3)

	// Robust cleanup
	context.AfterFunc(sCtx, func() {
		relayConn.Close()
		c1.Close() // Breaks dtlsConn
	})

	// DTLS <-> Relay (via Pipe) - MUST start before handshake
	go func() {
		defer wg.Done(); defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, _, err := c2.ReadFrom(buf)
			if err != nil { return }
			if _, err := relayConn.WriteTo(buf[:n], peer); err != nil {
				relayTxErrorCount.Add(1)
				util.TurnLog("[STREAM %d] Relay TX error: %v", s.id, err)
				return
			}
		}
	}()

	go func() {
		defer wg.Done(); defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, from, err := relayConn.ReadFrom(buf)
			if err != nil {
				relayRxErrorCount.Add(1)
				util.TurnLog("[STREAM %d] Relay RX error: %v", s.id, err)
				return
			}
			if from.String() == peer.String() {
				if _, err := c2.WriteTo(buf[:n], peer); err != nil {
					relayTxErrorCount.Add(1)
					util.TurnLog("[STREAM %d] Relay RX->Pipe error: %v", s.id, err)
					return
				}
			}
		}
	}()

	// Deadline updater
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-sCtx.Done(): return
			case <-ticker.C:
				deadline := time.Now().Add(30 * time.Second)
				relayConn.SetDeadline(deadline)
				dtlsConn.SetDeadline(deadline)
				c2.SetDeadline(deadline)
			}
		}
	}()

	// Set explicit deadline for handshake
	util.TurnLog("[STREAM %d] Starting DTLS handshake...", s.id)
	dtlsConn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := dtlsConn.HandshakeContext(sCtx); err != nil {
		util.TurnLog("[STREAM %d] DTLS handshake FAILED: %v", s.id, err)
		return fmt.Errorf("DTLS handshake timeout: %w", err)
	}

	// Clear deadline after successful handshake
	dtlsConn.SetDeadline(time.Time{})
	util.TurnLog("[STREAM %d] DTLS handshake SUCCESS", s.id)

	// Session ID + Stream ID Handshake (17 bytes total) — only for Proxy v2
	if sendHandshake {
		dtlsConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		handshakeBuf := make([]byte, 17)
		copy(handshakeBuf[:16], s.sessionID)
		handshakeBuf[16] = byte(s.id)

		if _, err := dtlsConn.Write(handshakeBuf); err != nil {
			return fmt.Errorf("session ID handshake failed: %w", err)
		}
		dtlsConn.SetWriteDeadline(time.Time{})
	}

	s.ready.Store(true)
	select { case okchan <- struct{}{}: default: }

	var lastRx atomic.Int64
	lastRx.Store(time.Now().Unix())

	wg.Add(2)

	// WireGuard -> DTLS (TX)
	go func() {
		defer wg.Done(); defer sCancel()
		for {
			select {
			case <-sCtx.Done(): return
			case b := <-s.in:

				// Watchdog (only active if watchdogTimeout > 0)
				if s.watchdogTimeout > 0 && time.Since(time.Unix(lastRx.Load(), 0)) > time.Duration(s.watchdogTimeout)*time.Second {
				    packetPool.Put(b[:cap(b)])
					dtlsTxDropCount.Add(1)
					util.TurnLog("[STREAM %d] TX watchdog timeout (%ds)", s.id, s.watchdogTimeout)
					return
				}

				_, err := dtlsConn.Write(b)
				packetPool.Put(b[:cap(b)])

				if err != nil {
					dtlsTxDropCount.Add(1)
					util.TurnLog("[STREAM %d] TX error: %v", s.id, err)
					return
				}
			}
		}
	}()

	// DTLS -> WireGuard (RX)
	go func() {
		defer wg.Done(); defer sCancel()
		buf := make([]byte, iPacketBuffMaxSize)
		for {
			n, err := dtlsConn.Read(buf)
			if err != nil {
				dtlsRxErrorCount.Add(1)
				util.TurnLog("[STREAM %d] RX error: %v", s.id, err)
				return
			}
			lastRx.Store(time.Now().Unix())
			if last := s.peer.Load(); last != nil {
				if _, err := s.out.WriteTo(buf[:n], *last); err != nil {
					dtlsRxErrorCount.Add(1)
					util.TurnLog("[STREAM %d] RX write error: %v", s.id, err)
					return
				}
			}
		}
	}()

	wg.Wait()
	return nil
}

var currentTurnCancel context.CancelFunc
var turnMutex sync.Mutex

// Global credentials function for mode selection (set by wgTurnProxyStart)
var globalGetCreds getCredsFunc
//export wgTurnProxyStart
// StartProxy starts the TURN proxy with the given parameters.
// This is the desktop equivalent of wgTurnProxyStart (which used cgo on Android).
func StartProxy(
	peerAddr string,
	vklink string,
	mode string,
	numStreams int,
	useUDP bool,
	listenAddr string,
	turnIP string,
	turnPort int,
	peerType string,
	streamsPerCred int,
	watchdogTimeout int,
) int32 {
	// DNS: on desktop, use system DNS (no Android network handle needed)
	InitSystemDns(nil)

	// Wrap key
	wrapKeyStr := ""
	if IsWrapEnabled() {
		wrapKeyStr = fmt.Sprintf("%x", GetWrapKey())
	}

	// Call the internal start function
	ret := startProxyImpl(peerAddr, vklink, mode, numStreams, useUDP, listenAddr, turnIP, turnPort, peerType, streamsPerCred, watchdogTimeout, wrapKeyStr)
	return ret
}



// startProxyImpl is the main proxy logic.
// TODO: port from wgTurnProxyStart (Android cgo version).
// For now, stub that logs parameters.
func startProxyImpl(
	peerAddr, vklink, mode string,
	numStreams int, useUDP bool,
	listenAddr, turnIP string,
	turnPort int, peerType string,
	streamsPerCred, watchdogTimeout int,
	wrapKeyStr string,
) int32 {
	turnLog("startProxyImpl called (STUB):")
	turnLog("  peer=%s vklink=%s mode=%s streams=%d udp=%v", peerAddr, vklink[:40], mode, numStreams, useUDP)
	turnLog("  listen=%s turnIP=%s turnPort=%d peerType=%s", listenAddr, turnIP, turnPort, peerType)
	turnLog("  streamsPerCred=%d watchdog=%d wrap=%v", streamsPerCred, watchdogTimeout, wrapKeyStr != "")
	// TODO: implement actual proxy logic
	return 0
}
