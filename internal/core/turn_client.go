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
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/google/uuid"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/turn/v5"
	"strconv"
)

func turnLog(format string, args ...interface{}) {
	util.TurnLog(format, args...)
}
const iPacketBuffMaxSize = 2048

var packetPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, iPacketBuffMaxSize)
	},
}

// Error counters
var (
	dtlsTxDropCount   atomic.Uint64
	dtlsRxErrorCount  atomic.Uint64
	noDtlsTxDropCount atomic.Uint64
	noDtlsRxErrorCount atomic.Uint64
	relayTxErrorCount atomic.Uint64
	relayRxErrorCount atomic.Uint64
)


type stream struct {
	ctx              context.Context
	id               int
	in               chan []byte
	out              net.PacketConn
	peer             atomic.Pointer[net.Addr]
	ready            atomic.Bool
	sessionID        []byte
	cert             *tls.Certificate
	watchdogTimeout  int
}

func init() {
	os.Setenv("GODEBUG", "netdns=go")
}



func (s *stream) run(link string, peer *net.UDPAddr, udp bool, okchan chan<- struct{}, turnIp string, turnPort int, peerType string) {
	sCtx, sCancel := context.WithCancel(s.ctx)
	defer sCancel()

	var getCreds func() (string, string, string, error)
	if globalGetCreds == nil {
		util.TurnLog("[STREAM %d] No credentials function set", s.id)
		sCancel()
		return
	}
	getCreds = func() (string, string, string, error) {
		user, pass, addr, err := globalGetCreds(sCtx, link, s.id)
		return user, pass, addr, err
	}

	for {
		user, pass, turnAddr, err := getCreds()
		if err != nil {
			util.TurnLog("[STREAM %d] Error: TURN creds failed: %v. Reconnecting in 1s...", s.id, err)
			select {
			case <-sCtx.Done(): return
			case <-time.After(1 * time.Second):
			}
			continue
		}

		// Connect to TURN server
		var turnConn net.PacketConn
		var client *turn.Client
		addr := turnAddr
		if turnIp != "" {
			addr = net.JoinHostPort(turnIp, strconv.Itoa(turnPort))
			if turnPort == 0 {
				_, portStr, _ := net.SplitHostPort(turnAddr)
				addr = net.JoinHostPort(turnIp, portStr)
			}
		}

		dialer := &net.Dialer{Timeout: 10 * time.Second, Control: util.ProtectControl}
		if udp {
			c, err := dialer.DialContext(sCtx, "udp", addr)
			if err != nil { util.TurnLog("[STREAM %d] TURN UDP dial failed: %v", s.id, err); continue }
			defer c.Close()
			turnConn = &connectedUDPConn{c.(*net.UDPConn)}
		} else {
			c, err := dialer.DialContext(sCtx, "tcp", addr)
			if err != nil { util.TurnLog("[STREAM %d] TURN TCP dial failed: %v", s.id, err); continue }
			defer c.Close()
			turnConn = turn.NewSTUNConn(c)
		}

		client, err = turn.NewClient(&turn.ClientConfig{
			STUNServerAddr: addr,
			Conn:           turnConn,
			Username:       user,
			Password:       pass,
			Realm:          "vk.com",
			Software:       "",
		})
		if err != nil { util.TurnLog("[STREAM %d] TURN client creation failed: %v", s.id, err); continue }

		err = client.Listen()
		if err != nil { util.TurnLog("[STREAM %d] TURN listen failed: %v", s.id, err); continue }
		defer client.Close()

		relayConn, err := client.Allocate()
		if err != nil { util.TurnLog("[STREAM %d] TURN allocation failed: %v", s.id, err); continue }
		defer relayConn.Close()

		// CreatePermission for peer
		err = client.CreatePermission(peer)
		if err != nil { util.TurnLog("[STREAM %d] CreatePermission failed: %v", s.id, err); continue }

		sendHandshake := peerType == "proxy_v2"
		var runErr error
		if peerType == "wireguard" || peerType == "proxy_v1" || peerType == "proxy_v2" {
			runErr = s.runDTLS(sCtx, relayConn, peer, okchan, sendHandshake)
		} else {
			runErr = s.runNoDTLS(sCtx, relayConn, peer, okchan)
		}

		if runErr != nil {
			util.TurnLog("[STREAM %d] Stream ended: %v. Reconnecting in 1s...", s.id, runErr)
		}
		select {
		case <-sCtx.Done(): return
		case <-time.After(1 * time.Second):
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
func startProxyImpl(
	peerAddr, vklink, mode string,
	numStreams int, useUDP bool,
	listenAddr, turnIP string,
	turnPort int, peerType string,
	streamsPerCredVal, watchdogTimeout int,
	wrapKeyStr string,
) int32 {
	streamsPerCred = streamsPerCredVal
	if wrapKeyStr != "" {
		wk, err := decodeWrapKey(true, wrapKeyStr)
		if err != nil {
			util.TurnLog("[PROXY] WRAP key decode failed: %v", err)
			wrapKeyBytes = nil
		} else {
			wrapKeyBytes = wk
			util.TurnLog("[PROXY] WRAP mode enabled (SRTP-mimicry AEAD)")
		}
	} else {
		wrapKeyBytes = nil
	}
	util.TurnLog("[PROXY] Hub starting on %s (streams=%d, mode=%s, peerType=%s, streamsPerCred=%d, wrap=%v)",
		listenAddr, numStreams, mode, peerType, streamsPerCred, wrapKeyBytes != nil)
	turnMutex.Lock()
	if currentTurnCancel != nil { currentTurnCancel() }
	ctx, cancel := context.WithCancel(context.Background())
	currentTurnCancel = cancel
	turnMutex.Unlock()
	if mode == "wb" {
		util.TurnLog("[PROXY] Using WB credential mode")
		globalGetCreds = func(ctx context.Context, link string, streamID int) (string, string, string, error) {
			return getCredsCached(ctx, link, streamID, wbFetch)
		}
	} else {
		util.TurnLog("[PROXY] Using VK Link credential mode")
		globalGetCreds = func(ctx context.Context, lk string, streamID int) (string, string, string, error) {
			return getCredsCached(ctx, lk, streamID, fetchVkCredsProxy)
		}
	}
	var peer *net.UDPAddr
	host, port, err := net.SplitHostPort(peerAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip == nil {
			resolvedIP, err := vkHosts.Resolve(context.Background(), host)
			if err != nil {
				util.TurnLog("[DNS] Warning: failed to resolve peer: %v", err)
				peer, err = net.ResolveUDPAddr("udp", peerAddr)
				if err != nil { return -1 }
			} else {
				peerAddr = net.JoinHostPort(resolvedIP, port)
				util.TurnLog("[DNS] Resolved peer %s -> %s", host, resolvedIP)
				peer, err = net.ResolveUDPAddr("udp", peerAddr)
				if err != nil { return -1 }
			}
		} else {
			peer, err = net.ResolveUDPAddr("udp", peerAddr)
			if err != nil { return -1 }
		}
	} else {
		peer, err = net.ResolveUDPAddr("udp", peerAddr)
		if err != nil { return -1 }
	}
	var link string
	if mode == "wb" {
		link = "wb"
	} else {
		parts := strings.Split(vklink, "join/")
		link = parts[len(parts)-1]
		if idx := strings.IndexAny(link, "/?#"); idx != -1 { link = link[:idx] }
	}
	lc, err := net.ListenPacket("udp", listenAddr)
	if err != nil { return -1 }
	context.AfterFunc(ctx, func() { lc.Close() })
	sessionID, _ := uuid.New().MarshalBinary()
	util.TurnLog("[PROXY] Session ID generated: %x", sessionID)
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		util.TurnLog("[PROXY] Failed to generate DTLS certificate: %v", err)
		return -1
	}
	ok := make(chan struct{}, numStreams)
	streams := make([]*stream, numStreams)
	for i := 0; i < numStreams; i++ {
		streams[i] = &stream{ctx: ctx, id: i, in: make(chan []byte, 512), out: lc, sessionID: sessionID, cert: &cert, watchdogTimeout: watchdogTimeout}
		go streams[i].run(link, peer, useUDP, ok, turnIP, turnPort, peerType)
		time.Sleep(200 * time.Millisecond)
	}
	vkHosts.StartMetricsCollector(ctx)
	go func() {
		nStreams := len(streams)
		lastUsed := 0
		for {
			b := packetPool.Get().([]byte)[:iPacketBuffMaxSize]
			nRead, addr, err := lc.ReadFrom(b)
			if err != nil {
				packetPool.Put(b[:cap(b)])
				return
			}
			lastUsed = (lastUsed + 1) % nStreams
			var s *stream
			for i := 0; i < nStreams; i++ {
				st := streams[(lastUsed+i)%nStreams]
				if st.ready.Load() { s = st; break }
			}
			if s == nil {
				packetPool.Put(b[:cap(b)])
				continue
			}
			returnAddr := addr
			s.peer.Store(&returnAddr)
			select {
			case s.in <- b[:nRead]:
			default:
				packetPool.Put(b[:cap(b)])
			}
		}
	}()
	select {
	case <-ok:
		util.TurnLog("[PROXY] First stream is ready, tunnel can start")
		return 0
	case <-ctx.Done():
		util.TurnLog("[PROXY] PROXY startup cancelled")
		return -1
	}
}

type connectedUDPConn struct { *net.UDPConn }
func (c *connectedUDPConn) WriteTo(p []byte, _ net.Addr) (int, error) { return c.Write(p) }

// StartProxy starts the TURN proxy with the given parameters.
func StartProxy(peerAddr, vklink, mode string, numStreams int, useUDP bool,
	listenAddr, turnIP string, turnPort int, peerType string,
	streamsPerCred, watchdogTimeout int) int32 {
	InitSystemDns(nil)
	wrapKeyStr := ""
	if IsWrapEnabled() {
		wrapKeyStr = fmt.Sprintf("%x", GetWrapKey())
	}
	return startProxyImpl(peerAddr, vklink, mode, numStreams, useUDP, listenAddr,
		turnIP, turnPort, peerType, streamsPerCred, watchdogTimeout, wrapKeyStr)
}

// StopProxy stops the TURN proxy.
func StopProxy() {
	turnMutex.Lock()
	defer turnMutex.Unlock()
	if currentTurnCancel != nil {
		util.TurnLog("[PROXY] Stopping TURN proxy")
		currentTurnCancel()
		currentTurnCancel = nil
	}
}

// fetchVkCredsProxy is set by main.go via SetVkCredsFetcher.
var fetchVkCredsProxy func(ctx context.Context, link string) (string, string, string, error)

// SetVkCredsFetcher sets the VK credentials fetcher function.
func SetVkCredsFetcher(fn func(ctx context.Context, link string) (string, string, string, error)) {
	fetchVkCredsProxy = fn
}
