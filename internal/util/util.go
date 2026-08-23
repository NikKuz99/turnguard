package util

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	"time"
)

var logEnabled = true

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.SetOutput(os.Stdout)
}

func TurnLog(format string, args ...interface{}) {
	if logEnabled {
		log.Printf("[TurnGuard] "+format, args...)
	}
}

// ProtectControl is a no-op on desktop.
func ProtectControl(network, address string, c syscall.RawConn) error {
	return nil
}

func ProtectAndDial(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	return dialer.DialContext(ctx, network, addr)
}

// Unused import to avoid errors
var _ = fmt.Sprintf
