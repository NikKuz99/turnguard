package core

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Тесты регрессии 2026-09-30: decodeWrapKey и раскладка кэшей кредов по стримам
// (StreamsPerCred=4 из клиентского конфига), плюс regression-cover для SRTP-mimicry
// wrap-конфигурации, используемой живыми ключами msc-wg.

func TestDecodeWrapKey(t *testing.T) {
	valid32 := "9a5e2999fbcf5d615b6c0f274526af845c0625d178cf6e2ab340c7a87d9a1afb"

	t.Run("disabled returns nil key", func(t *testing.T) {
		key, err := decodeWrapKey(false, "whatever")
		if err != nil {
			t.Fatalf("disabled mode must not error: %v", err)
		}
		if key != nil {
			t.Fatalf("disabled mode must return nil key, got %v", key)
		}
	})

	t.Run("enabled requires key", func(t *testing.T) {
		if _, err := decodeWrapKey(true, ""); err == nil {
			t.Fatal("enabled mode with empty key must fail")
		}
	})

	t.Run("rejects non-hex", func(t *testing.T) {
		if _, err := decodeWrapKey(true, "not-hex-data!"); err == nil {
			t.Fatal("non-hex key must fail")
		}
	})

	t.Run("rejects wrong length", func(t *testing.T) {
		short := hex.EncodeToString(make([]byte, 16)) // 32 hex = 16 bytes
		if _, err := decodeWrapKey(true, short); err == nil {
			t.Fatal("16-byte key must fail: wrap key is 32 bytes")
		}
	})

	t.Run("accepts 32-byte hex key", func(t *testing.T) {
		key, err := decodeWrapKey(true, valid32)
		if err != nil {
			t.Fatalf("valid 32-byte key rejected: %v", err)
		}
		want, _ := hex.DecodeString(valid32)
		if !bytes.Equal(key, want) {
			t.Fatal("decoded key mismatch")
		}
	})
}

func TestGetCacheIDSharing(t *testing.T) {
	// streamsPerCred = 4: стримы 0-3 делят кэш 0, 4-7 — кэш 1 и т.д.
	cases := map[int]int{0: 0, 1: 0, 3: 0, 4: 1, 7: 1, 8: 2, 12: 3}
	for stream, want := range cases {
		if got := getCacheID(stream); got != want {
			t.Fatalf("getCacheID(%d) = %d, want %d", stream, got, want)
		}
	}
}
