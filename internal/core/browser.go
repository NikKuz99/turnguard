package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/NikKuz99/turnguard/internal/util"
)

// SolveCaptchaBrowser opens the system browser with the VK captcha URL,
// starts a local HTTP server to receive the success_token callback,
// and returns the token when the captcha is solved.
//
// The redirect_uri from VK contains the captcha page URL.
// We open it in the browser and wait for the user to solve it.
// The success_token is extracted from the page's JavaScript callback.
//
// For now, this is a simple implementation:
// 1. Open browser with the captcha URL
// 2. Start HTTP server on a random port
// 3. Wait for callback (or timeout after 120s)
func SolveCaptchaBrowser(redirectURI string) string {
	return SolveCaptchaWithProxy(redirectURI)
}

func SolveCaptchaBrowserStdin(redirectURI string) string {
	util.TurnLog("[Captcha] Opening browser for manual captcha solving...")
	util.TurnLog("[Captcha] URL: %s", redirectURI[:80]+"...")

	// Open system browser
	openBrowser(redirectURI)

	// Start HTTP server to receive the success_token
	// The VK captcha page will POST the token to a callback URL
	// For simplicity, we'll use a different approach:
	// Ask the user to paste the success_token manually
	// (A proper browser integration would require a browser extension or
	// local proxy to intercept the token)

	// For now, use stdin to read the token
	// TODO: implement proper browser callback interception
	fmt.Println("\n[Captcha] Please solve the captcha in your browser.")
	fmt.Println("[Captcha] After solving, paste the success_token here and press Enter:")

	// Read token from stdin with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	type result struct {
		token string
		err   error
	}
	ch := make(chan result, 1)

	go func() {
		var token string
		_, err := fmt.Scanln(&token)
		ch <- result{token, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			util.TurnLog("[Captcha] Error reading token: %v", r.err)
			return ""
		}
		util.TurnLog("[Captcha] Got success_token (length=%d)", len(r.token))
		return r.token
	case <-ctx.Done():
		util.TurnLog("[Captcha] Timeout waiting for token")
		return ""
	}
}

// openBrowser opens the default browser with the given URL.
func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	if err != nil {
		util.TurnLog("[Captcha] Failed to open browser: %v", err)
	}
}

// StartCallbackServer starts an HTTP server that listens for captcha callback.
// Returns the port number and a channel that receives the success_token.
func StartCallbackServer() (int, chan string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, nil, fmt.Errorf("failed to listen: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	tokenChan := make(chan string, 1)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("success_token")
			if token != "" {
				w.WriteHeader(200)
				w.Write([]byte("OK"))
				tokenChan <- token
			} else {
				w.WriteHeader(400)
				w.Write([]byte("Missing success_token"))
			}
		}),
	}

	go server.Serve(ln)
	util.TurnLog("[Captcha] Callback server listening on port %d", port)

	return port, tokenChan, nil
}
