/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright © 2026 WireGuard LLC. All Rights Reserved.
 */

package core

import (
	"encoding/hex"
	"fmt"
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// TurnCredentials stores cached TURN credentials
type TurnCredentials struct {
	Username   string
	Password   string
	ServerAddr string
	ExpiresAt  time.Time
	Link       string
}

// StreamCredentialsCache holds credentials cache for a single stream
type StreamCredentialsCache struct {
	creds         TurnCredentials
	mutex         sync.RWMutex
	errorCount    atomic.Int32
	lastErrorTime atomic.Int64
}

const (
	credentialLifetime = 10 * time.Minute
	cacheSafetyMargin  = 60 * time.Second
	maxCacheErrors     = 3
	errorWindow        = 10 * time.Second
)

var streamsPerCred = 4 // Number of streams sharing one credentials cache
var (
	wrapKeyMu    sync.RWMutex
	wrapKeyBytes []byte
) // Shared wrap key (32 bytes), empty = wrap disabled

// getCacheID returns the shared cache ID for a given stream ID
func getCacheID(streamID int) int {
	return streamID / streamsPerCred
}

// credentialsStore manages per-stream credentials caches
var credentialsStore = struct {
	mu     sync.RWMutex
	caches map[int]*StreamCredentialsCache
}{
	caches: make(map[int]*StreamCredentialsCache),
}

// getStreamCache returns or creates a shared cache for the given stream ID
func getStreamCache(streamID int) *StreamCredentialsCache {
	cacheID := getCacheID(streamID)

	// Try read lock first for fast path
	credentialsStore.mu.RLock()
	cache, exists := credentialsStore.caches[cacheID]
	credentialsStore.mu.RUnlock()

	if exists {
		return cache
	}

	// Need to create new cache
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	// Double-check after acquiring write lock
	if cache, exists = credentialsStore.caches[cacheID]; exists {
		return cache
	}

	cache = &StreamCredentialsCache{}
	credentialsStore.caches[cacheID] = cache
	return cache
}

// isAuthError checks if the error is an authentication error
func isAuthError(err error) bool {
	errStr := err.Error()
	return strings.Contains(errStr, "401") ||
		strings.Contains(errStr, "Unauthorized") ||
		strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "invalid credential") ||
		strings.Contains(errStr, "stale nonce")
}

// handleAuthError handles authentication errors for a specific stream.
// Returns true if cache was invalidated, false otherwise.
func handleAuthError(streamID int) bool {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	now := time.Now().Unix()

	// Reset counter if enough time has passed
	if now - cache.lastErrorTime.Load() > int64(errorWindow.Seconds()) {
		cache.errorCount.Store(0)
	}

	count := cache.errorCount.Add(1)
	cache.lastErrorTime.Store(now)

	turnLog("[STREAM %d] Auth error (cache=%d, count=%d/%d)", streamID, cacheID, count, maxCacheErrors)

	// Invalidate cache only after N errors within the time window
	if count >= maxCacheErrors {
		turnLog("[VK Auth] Multiple auth errors detected (%d), invalidating cache %d for stream %d...", count, cacheID, streamID)
		cache.invalidate(streamID)
		return true
	}

	return false
}

// invalidate invalidates the credentials cache for this stream
func (c *StreamCredentialsCache) invalidate(streamID int) {
	c.mutex.Lock()
	c.creds = TurnCredentials{}
	c.mutex.Unlock()

	// Reset auth error counter
	c.errorCount.Store(0)
	c.lastErrorTime.Store(0)

	turnLog("[STREAM %d] [VK Auth] Credentials cache invalidated", streamID)
}

// invalidateAllCaches invalidates all shared caches (called on network change)
func invalidateAllCaches() {
	credentialsStore.mu.Lock()
	defer credentialsStore.mu.Unlock()

	// Clear the map — old caches will be garbage collected
	credentialsStore.caches = make(map[int]*StreamCredentialsCache)
	turnLog("[VK Auth] All shared caches cleared (streams per cred: %d)", streamsPerCred)
}

// fetchMu serializes credential fetching to avoid API rate limiting
var fetchMu sync.Mutex

// fetchFunc is the signature for credential retrieval functions (without cache logic)
type fetchFunc func(ctx context.Context, link string) (string, string, string, error)

// serializeFetch wraps a fetch call with the global fetchMu to avoid API rate limiting
func serializeFetch(ctx context.Context, link string, storeFn fetchFunc) (string, string, string, error) {
	fetchMu.Lock()
	defer fetchMu.Unlock()
	return storeFn(ctx, link)
}

// getCredsCached checks cache before fetching credentials.
// This is the general entry point for credential retrieval with caching.
func getCredsCached(ctx context.Context, link string, streamID int, storeFn fetchFunc) (string, string, string, error) {
	cache := getStreamCache(streamID)
	cacheID := getCacheID(streamID)

	cache.mutex.Lock()
	defer cache.mutex.Unlock()

	// Check cache — another stream may have populated it while waiting
	if cache.creds.Link == link && time.Now().Before(cache.creds.ExpiresAt) {
		expires := time.Until(cache.creds.ExpiresAt)
		turnLog("[Auth] Using cached credentials (cache=%d, expires in %v)", cacheID, expires)
		return cache.creds.Username, cache.creds.Password, cache.creds.ServerAddr, nil
	}

	turnLog("[Auth] Cache miss (cache=%d), starting credential fetch...", cacheID)

	// Check context before long fetch
	select {
	case <-ctx.Done():
		return "", "", "", ctx.Err()
	default:
	}

	// Fetch credentials with global mutex to avoid API rate limiting
	user, pass, addr, err := serializeFetch(ctx, link, storeFn)

	if err != nil {
		return "", "", "", err
	}

	// Store in cache
	cache.creds = TurnCredentials{
		Username:   user,
		Password:   pass,
		ServerAddr: addr,
		ExpiresAt:  time.Now().Add(credentialLifetime - cacheSafetyMargin),
		Link:       link,
	}

	turnLog("[Auth] Success! Credentials cached until %v (cache=%d)", cache.creds.ExpiresAt, cacheID)
	return user, pass, addr, nil
}

// getCredsFunc is the signature for credential retrieval functions
type getCredsFunc func(context.Context, string, int) (string, string, string, error)

func IsWrapEnabled() bool {
	wrapKeyMu.RLock()
	defer wrapKeyMu.RUnlock()
	return len(wrapKeyBytes) > 0
}

func GetWrapKey() []byte {
	wrapKeyMu.RLock()
	defer wrapKeyMu.RUnlock()
	return wrapKeyBytes
}

// SetWrapKey sets the wrap key from a hex string (64 chars = 32 bytes).
func SetWrapKey(hexKey string) error {
	if hexKey == "" {
		wrapKeyMu.Lock()
		wrapKeyBytes = nil
		wrapKeyMu.Unlock()
		return nil
	}
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return fmt.Errorf("invalid wrap key hex: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("wrap key must be 32 bytes (64 hex chars), got %d bytes", len(key))
	}
	wrapKeyMu.Lock()
	wrapKeyBytes = key
	wrapKeyMu.Unlock()
	return nil
}
