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
 * 2. Proxy VK captcha page (with proper gzip handling + asset proxying)
 * 3. Inject JS to capture success_token
 * 4. Open browser with local URL
 * 5. User solves captcha in browser
 * 6. JS sends success_token to local server
 * 7. Return token to caller
 */
package core

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
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
// 1. Proxies VK captcha page AND all its assets (JS/CSS/images/XHR)
// 2. Injects JS to intercept success_token
// 3. Opens browser
func SolveCaptchaWithProxy(redirectURI string) string {
	util.TurnLog("[Captcha] Starting local proxy for captcha solving...")

	// Parse the redirect URI to get VK host
	vkURL, err := url.Parse(redirectURI)
	if err != nil {
		util.TurnLog("[Captcha] Failed to parse URI: %v", err)
		return SolveCaptchaBrowserStdin(redirectURI)
	}

	// Start local HTTP server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		util.TurnLog("[Captcha] Failed to listen: %v", err)
		return SolveCaptchaBrowserStdin(redirectURI)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	util.TurnLog("[Captcha] Local proxy on port %d", port)

	tokenChan := make(chan string, 1)

	// The captcha page URL path — used to identify the "main" request
	captchaPath := vkURL.Path
	captchaQuery := vkURL.RawQuery
	vkHost := vkURL.Host

	// Create reverse proxy to VK
	targetURL := fmt.Sprintf("https://%s", vkHost)
	target, _ := url.Parse(targetURL)

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Modify request:
	// - Set proper Host
	// - For the INITIAL request (browser navigating to our local proxy root),
	//   rewrite to the captcha page path+query
	// - For SUBSEQUENT requests (assets, XHR, etc.), pass through the path as-is
	//   so that JS/CSS/images load correctly from their original paths
	// - Strip Accept-Encoding so Transport auto-decompresses
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = vkHost

		// Only rewrite path for the initial navigation request (root path "/")
		// or when the browser requests the exact captcha path.
		// All other requests (JS, CSS, images, XHR) should use their own paths.
		if req.URL.Path == "/" || req.URL.Path == "" {
			req.URL.Path = captchaPath
			req.URL.RawQuery = captchaQuery
		}

		// Remove Accept-Encoding so http.Transport auto-decompresses gzip/deflate.
		req.Header.Del("Accept-Encoding")

		// Fix Referer header: browser sends http://127.0.0.1:PORT/ as referer
		// but VK expects https://vkhost/...
		referer := req.Header.Get("Referer")
		if strings.Contains(referer, "127.0.0.1") {
			req.Header.Set("Referer", fmt.Sprintf("https://%s/", vkHost))
		}

		// Fix Origin header similarly
		origin := req.Header.Get("Origin")
		if strings.Contains(origin, "127.0.0.1") {
			req.Header.Set("Origin", fmt.Sprintf("https://%s", vkHost))
		}
	}

	// Custom transport: always connect to the VK host on port 443
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.Dial(network, vkHost+":443")
		},
		DisableCompression: false,
	}
	proxy.Transport = transport

	// Handle gzip/deflate decompression in ModifyResponse
	proxy.ModifyResponse = func(resp *http.Response) error {
		encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
		if encoding == "" {
			return nil
		}

		ct := strings.ToLower(resp.Header.Get("Content-Type"))
		if !strings.Contains(ct, "text/html") &&
			!strings.Contains(ct, "application/javascript") &&
			!strings.Contains(ct, "text/javascript") &&
			!strings.Contains(ct, "application/json") &&
			!strings.Contains(ct, "text/css") {
			return nil
		}

		switch encoding {
		case "gzip":
			gr, err := gzip.NewReader(resp.Body)
			if err != nil {
				util.TurnLog("[Captcha] gzip reader init failed: %v", err)
				return nil
			}
			resp.Body = &readClose{Reader: gr, Closer: resp.Body}
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.Uncompressed = true
		case "deflate":
			zr, err := zlib.NewReader(resp.Body)
			if err != nil {
				util.TurnLog("[Captcha] zlib reader init failed: %v", err)
				return nil
			}
			resp.Body = &readClose{Reader: zr, Closer: resp.Body}
			resp.Header.Del("Content-Encoding")
			resp.Header.Del("Content-Length")
			resp.Uncompressed = true
		default:
			util.TurnLog("[Captcha] Unsupported Content-Encoding: %s (will pass through)", encoding)
		}
		return nil
	}

	// Wrap to inject JS into HTML responses and handle callbacks
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if this is the callback from our injected JS
		if r.URL.Path == "/captcha_callback" {
			token := r.URL.Query().Get("token")
			if token != "" {
				w.WriteHeader(200)
				w.Write([]byte("OK"))
				select {
				case tokenChan <- token:
				default:
				}
				return
			}
			w.WriteHeader(400)
			return
		}

		// Log proxied requests for debugging
		util.TurnLog("[Captcha] Proxying: %s %s", r.Method, r.URL.Path)

		// Capture response to inject JS if HTML
		recorder := &responseRecorder{header: make(http.Header), statusCode: 200}
		proxy.ServeHTTP(recorder, r)

		contentType := recorder.header.Get("Content-Type")
		contentEncoding := strings.ToLower(recorder.header.Get("Content-Encoding"))

		// Fallback decompression if still encoded
		bodyBytes := recorder.body.Bytes()
		if contentEncoding == "gzip" {
			if gr, err := gzip.NewReader(bytes.NewReader(bodyBytes)); err == nil {
				if decoded, err := io.ReadAll(gr); err == nil {
					bodyBytes = decoded
					gr.Close()
				}
			}
			contentEncoding = ""
		} else if contentEncoding == "deflate" {
			if zr, err := zlib.NewReader(bytes.NewReader(bodyBytes)); err == nil {
				if decoded, err := io.ReadAll(zr); err == nil {
					bodyBytes = decoded
				}
				zr.Close()
			}
			contentEncoding = ""
		}

		if strings.Contains(contentType, "text/html") {
			// Inject JS to intercept captcha success
			body := string(bodyBytes)
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
        if (xhr._captchaUrl && (xhr._captchaUrl.indexOf('captchaNotRobot.check') !== -1 || xhr._captchaUrl.indexOf('captchaNotRobot') !== -1)) {
            xhr.addEventListener('load', function() {
                try {
                    var data = JSON.parse(xhr.responseText);
                    if (data.response && data.response.success_token) {
                        fetch('http://127.0.0.1:%d/captcha_callback?token=' + encodeURIComponent(data.response.success_token));
                    }
                } catch(e) { console.log('[TG] XHR parse error:', e); }
            });
        }
        return origSend.apply(this, arguments);
    };
    // Also intercept fetch
    var origFetch = window.fetch;
    if (origFetch) {
        window.fetch = function() {
            var url = arguments[0];
            var urlStr = typeof url === 'string' ? url : (url && url.url ? url.url : '');
            if (urlStr.indexOf('captchaNotRobot') !== -1) {
                return origFetch.apply(this, arguments).then(function(resp) {
                    resp.clone().text().then(function(text) {
                        try {
                            var data = JSON.parse(text);
                            if (data.response && data.response.success_token) {
                                fetch('http://127.0.0.1:%d/captcha_callback?token=' + encodeURIComponent(data.response.success_token));
                            }
                        } catch(e) { console.log('[TG] fetch parse error:', e); }
                    });
                    return resp;
                });
            }
            return origFetch.apply(this, arguments);
        };
    }
    // Also watch for success_token in window object (some VK flows set it globally)
    var checkToken = setInterval(function() {
        if (window.success_token) {
            fetch('http://127.0.0.1:%d/captcha_callback?token=' + encodeURIComponent(window.success_token));
            clearInterval(checkToken);
        }
    }, 500);
    console.log('[TurnGuard] Captcha interceptor installed');
})();
</script>
`, port, port, port)
			// Try to inject before </head>, or before </body> if no </head>
			if strings.Contains(body, "</head>") {
				body = strings.Replace(body, "</head>", injectedJS+"</head>", 1)
			} else if strings.Contains(body, "</body>") {
				body = strings.Replace(body, "</body>", injectedJS+"</body>", 1)
			} else {
				body = body + injectedJS
			}
			// Copy headers except Content-Encoding and Content-Length (body length changed)
			for k, v := range recorder.header {
				if strings.EqualFold(k, "Content-Encoding") || strings.EqualFold(k, "Content-Length") {
					continue
				}
				w.Header()[k] = v
			}
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.WriteHeader(recorder.statusCode)
			io.WriteString(w, body)
			return
		}

		// Non-HTML: pass through (with original headers, but drop
		// Content-Length if we decoded the body)
		for k, v := range recorder.header {
			if contentEncoding == "" && (strings.EqualFold(k, "Content-Encoding") || strings.EqualFold(k, "Content-Length")) {
				continue
			}
			w.Header()[k] = v
		}
		w.WriteHeader(recorder.statusCode)
		w.Write(bodyBytes)
	})

	server := &http.Server{Handler: handler}
	go server.Serve(ln)

	// Open browser to local proxy
	localURL := fmt.Sprintf("http://127.0.0.1:%d/", port)
	util.TurnLog("[Captcha] Opening browser: %s", localURL)
	openBrowser(localURL)
	util.TurnLog("[Captcha] Solve captcha in browser. Waiting for success_token...")

	// Wait for token with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
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

// readClose combines a Reader with a separate Closer so we can wrap
// decompression readers while still closing the original body.
type readClose struct {
	Reader io.Reader
	Closer io.Closer
}

func (rc *readClose) Read(p []byte) (int, error) { return rc.Reader.Read(p) }
func (rc *readClose) Close() error                { return rc.Closer.Close() }

// responseRecorder captures HTTP response for modification.
// Uses bytes.Buffer (not strings.Builder) so we can use Bytes() for
// zero-copy access when injecting JS.
type responseRecorder struct {
	header     http.Header
	body       bytes.Buffer
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
