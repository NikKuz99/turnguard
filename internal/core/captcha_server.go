/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * captcha_server.go — Local HTTP server for captcha callback.
 * Opens browser with VK captcha page, intercepts success_token
 * via injected JavaScript callback to local HTTP server.
 *
 * Flow:
 * 1. Start local HTTP server on random port
 * 2. Generate modified captcha page HTML with JS that POSTs success_token to local server
 * 3. Open browser with local URL (proxy to VK captcha page)
 * 4. User solves captcha in browser
 * 5. JS sends success_token to local server
 * 6. Return token to caller
 */
package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/NikKuz99/turnguard/internal/util"
)

// SolveCaptchaWithProxy starts a local HTTP proxy that:
// 1. Proxies VK captcha page
// 2. Injects JS to intercept success_token
// 3. Opens browser

func SolveCaptchaWithProxy(redirectURI string) string {
	util.TurnLog("[Captcha] Starting local proxy for captcha solving...")

	// Parse the redirect URI to get VK host
	vkURL, err := url.Parse(redirectURI)
	if err != nil {
		util.TurnLog("[Captcha] Failed to parse URI: %v", err)
		return SolveCaptchaBrowser(redirectURI) // fallback to stdin
	}

	// Start local HTTP server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		util.TurnLog("[Captcha] Failed to listen: %v", err)
		return SolveCaptchaBrowser(redirectURI)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	util.TurnLog("[Captcha] Local proxy on port %d", port)

	tokenChan := make(chan string, 1)

	// Create reverse proxy to VK
	targetURL := fmt.Sprintf("https://%s", vkURL.Host)
	target, _ := url.Parse(targetURL)

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Modify response to inject JS
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = vkURL.Host
		req.URL.Path = vkURL.Path
		req.URL.RawQuery = vkURL.RawQuery
	}

	// Custom transport to handle TLS
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Always connect to VK host
			return net.Dial(network, vkURL.Host+":443")
		},
	}
	proxy.Transport = transport

	// Wrap to inject JS into HTML responses
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is the callback from our injected JS
		if r.URL.Path == "/captcha_callback" {
			token := r.URL.Query().Get("token")
			if token != "" {
				w.WriteHeader(200)
				w.Write([]byte("OK"))
				tokenChan <- token
				return
			}
			w.WriteHeader(400)
			return
		}

		// Proxy the request
		// Capture response to inject JS if HTML
		recorder := &responseRecorder{header: make(http.Header), statusCode: 200}
		proxy.ServeHTTP(recorder, r)

		contentType := recorder.header.Get("Content-Type")
		if strings.Contains(contentType, "text/html") {
			// Inject JS to intercept captcha success
			body := recorder.body.String()
			injectedJS := fmt.Sprintf(`
<script>
(function() {
    // Intercept XHR to capture success_token
    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {
        this._captchaUrl = url;
        return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function() {
        var xhr = this;
        if (xhr._captchaUrl && xhr._captchaUrl.indexOf('captchaNotRobot.check') !== -1) {
            xhr.addEventListener('load', function() {
                try {
                    var data = JSON.parse(xhr.responseText);
                    if (data.response && data.response.success_token) {
                        // Send token to local server
                        fetch('http://127.0.0.1:%d/captcha_callback?token=' + encodeURIComponent(data.response.success_token));
                    }
                } catch(e) {}
            });
        }
        return origSend.apply(this, arguments);
    };
    // Also intercept fetch
    var origFetch = window.fetch;
    if (origFetch) {
        window.fetch = function() {
            var url = arguments[0];
            if (typeof url === 'string' && url.indexOf('captchaNotRobot.check') !== -1) {
                return origFetch.apply(this, arguments).then(function(resp) {
                    resp.clone().text().then(function(text) {
                        try {
                            var data = JSON.parse(text);
                            if (data.response && data.response.success_token) {
                                fetch('http://127.0.0.1:%d/captcha_callback?token=' + encodeURIComponent(data.response.success_token));
                            }
                        } catch(e) {}
                    });
                    return resp;
                });
            }
            return origFetch.apply(this, arguments);
        };
    }
    console.log('[TurnGuard] Captcha interceptor installed');
})();
</script>
`, port, port)
			body = strings.Replace(body, "</head>", injectedJS+"</head>", 1)
			w.Header().Set("Content-Type", contentType)
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(recorder.statusCode)
			io.WriteString(w, body)
			return
		}

		// Non-HTML: pass through
		for k, v := range recorder.header {
			w.Header()[k] = v
		}
		w.WriteHeader(recorder.statusCode)
		w.Write([]byte(recorder.body.String()))
	})

	server := &http.Server{Handler: handler}
	go server.Serve(ln)

	// Open browser to local proxy
	localURL := fmt.Sprintf("http://127.0.0.1:%d/", port)
	util.TurnLog("[Captcha] Opening browser: %s", localURL)
	openBrowser(localURL)
	util.TurnLog("[Captcha] Solve captcha in browser. Waiting for success_token...")

	// Wait for token with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	select {
	case token := <-tokenChan:
		util.TurnLog("[Captcha] Got success_token (length=%d)", len(token))
		server.Shutdown(context.Background())
		return token
	case <-ctx.Done():
		util.TurnLog("[Captcha] Timeout waiting for token")
		server.Shutdown(context.Background())
		return ""
	}
}

// responseRecorder captures HTTP response for modification
type responseRecorder struct {
	header     http.Header
	body       strings.Builder
	statusCode int
}

func (r *responseRecorder) Header() http.Header {
	return r.header
}

func (r *responseRecorder) WriteHeader(code int) {
	r.statusCode = code
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	r.body.Write(b)
	return len(b), nil
}

