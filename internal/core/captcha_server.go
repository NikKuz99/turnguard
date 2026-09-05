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
 * 2. Proxy VK captcha page (with proper gzip handling)
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
// 1. Proxies VK captcha page
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

        // Create reverse proxy to VK
        targetURL := fmt.Sprintf("https://%s", vkURL.Host)
        target, _ := url.Parse(targetURL)

        proxy := httputil.NewSingleHostReverseProxy(target)

        // Modify request: set proper Host/Path/Query, strip Accept-Encoding
        // so that Transport auto-decompresses gzipped responses.
        // (When Accept-Encoding is set explicitly by the client, Go's Transport
        //  returns the raw gzipped body without decompression, which breaks
        //  the responseRecorder/body injection below.)
        originalDirector := proxy.Director
        proxy.Director = func(req *http.Request) {
                originalDirector(req)
                req.Host = vkURL.Host
                req.URL.Path = vkURL.Path
                req.URL.RawQuery = vkURL.RawQuery
                // Remove Accept-Encoding so http.Transport auto-decompresses gzip/deflate.
                // This is critical: otherwise VK returns gzipped HTML and we'd have to
                // decompress manually. With this, Transport decompresses for us and
                // strips Content-Encoding/Content-Length from the response.
                req.Header.Del("Accept-Encoding")
        }

        // Custom transport to handle TLS
        transport := &http.Transport{
                DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                        // Always connect to VK host
                        return net.Dial(network, vkURL.Host+":443")
                },
                // DisableCompression = false (default) → Transport auto-adds
                // "Accept-Encoding: gzip" and auto-decompresses responses when
                // the request didn't have Accept-Encoding set explicitly.
                // We've already removed Accept-Encoding in the Director, so this works.
                DisableCompression: false,
        }
        proxy.Transport = transport

        // Use ModifyResponse to also handle any remaining edge cases where
        // Content-Encoding is still set (e.g., brotli-encoded responses, which
        // Go's Transport does NOT auto-decompress).
        proxy.ModifyResponse = func(resp *http.Response) error {
                encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))
                if encoding == "" {
                        return nil
                }

                // Only attempt decompression for content types we care about
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
                        // Unknown encoding (e.g., br / zstd): leave as-is.
                        // Transport will return raw bytes; if HTML body looks binary,
                        // our injection handler will skip injection but still pass bytes
                        // through — the browser will likely show garbled text.
                        util.TurnLog("[Captcha] Unsupported Content-Encoding: %s (will pass through)", encoding)
                }
                return nil
        }

        // Wrap to inject JS into HTML responses
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

                // Proxy the request
                // Capture response to inject JS if HTML
                recorder := &responseRecorder{header: make(http.Header), statusCode: 200}
                proxy.ServeHTTP(recorder, r)

                contentType := recorder.header.Get("Content-Type")
                contentEncoding := strings.ToLower(recorder.header.Get("Content-Encoding"))

                // If body is still encoded (e.g., Transport couldn't decompress),
                // try one more time to decompress based on Content-Encoding.
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
