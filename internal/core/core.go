package core

import (
	"encoding/hex"
	"fmt"
	"sync"
)

var (
	wrapKeyMu    sync.RWMutex
	wrapKeyBytes []byte
)

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

func GetWrapKey() []byte {
	wrapKeyMu.RLock()
	defer wrapKeyMu.RUnlock()
	return wrapKeyBytes
}

func IsWrapEnabled() bool {
	wrapKeyMu.RLock()
	defer wrapKeyMu.RUnlock()
	return len(wrapKeyBytes) > 0
}
