/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * webui.go — Embedded web UI for TurnGuard.
 * Starts an HTTP server on localhost with a web interface
 * for configuring and controlling the TURN proxy.
 *
 * The UI is a single HTML page with embedded CSS/JS.
 * No external dependencies — pure Go + HTML.
 *
 * Usage: turnguard -webui
 * Then open: http://127.0.0.1:8080
 */
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/NikKuz99/turnguard/internal/util"
)

// WebUI holds the web server state.
type WebUI struct {
	server   *http.Server
	port     int
	mu       sync.Mutex
	status   string // "stopped", "starting", "running", "error"
	lastLog  string
	startTime time.Time
}

// NewWebUI creates a new web UI server.
func NewWebUI(port int) *WebUI {
	return &WebUI{
		port:   port,
		status: "stopped",
	}
}

// Start begins serving the web UI.
func (w *WebUI) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Serve the HTML UI
	mux.HandleFunc("/", w.handleIndex)

	// API endpoints
	mux.HandleFunc("/api/status", w.handleStatus)
	mux.HandleFunc("/api/start", w.handleStart)
	mux.HandleFunc("/api/stop", w.handleStop)
	mux.HandleFunc("/api/config", w.handleConfig)
	mux.HandleFunc("/api/check-update", w.handleCheckUpdate)

	w.server = &http.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", w.port),
		Handler: mux,
	}

	ln, err := net.Listen("tcp", w.server.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", w.port, err)
	}

	w.port = ln.Addr().(*net.TCPAddr).Port

	go func() {
		<-ctx.Done()
		w.server.Shutdown(context.Background())
	}()

	go func() {
		util.TurnLog("[WebUI] Serving on http://127.0.0.1:%d", w.port)
		if err := w.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			util.TurnLog("[WebUI] Server error: %v", err)
		}
	}()

	return nil
}

// GetPort returns the actual port the server is listening on.
func (w *WebUI) GetPort() int {
	return w.port
}

// SetStatus updates the current status.
func (w *WebUI) SetStatus(status string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status = status
	if status == "running" {
		w.startTime = time.Now()
	}
}

// GetStatus returns the current status.
func (w *WebUI) GetStatus() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

// handleIndex serves the main HTML page.
func (w *WebUI) handleIndex(res http.ResponseWriter, req *http.Request) {
	res.Header().Set("Content-Type", "text/html; charset=utf-8")
	res.Write([]byte(webUIHTML))
}

// handleStatus returns current proxy status as JSON.
func (w *WebUI) handleStatus(res http.ResponseWriter, req *http.Request) {
	w.mu.Lock()
	uptime := ""
	if w.status == "running" && !w.startTime.IsZero() {
		d := time.Since(w.startTime)
		uptime = fmt.Sprintf("%dh %dm %ds", int(d.Hours()), int(d.Minutes())%60, int(d.Seconds())%60)
	}
	status := w.status
	w.mu.Unlock()

	json.NewEncoder(res).Encode(map[string]interface{}{
		"status":  status,
		"uptime":  uptime,
		"version": CurrentVersion,
		"wrap":    IsWrapEnabled(),
	})
}

// handleStart starts the TURN proxy with given parameters.
func (w *WebUI) handleStart(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(res, "Method not allowed", 405)
		return
	}

	var params struct {
		VkLink   string `json:"vk_link"`
		Peer     string `json:"peer"`
		Listen   string `json:"listen"`
		WrapKey  string `json:"wrap_key"`
		Streams  int    `json:"streams"`
		UDP      bool   `json:"udp"`
		Mode     string `json:"mode"`
		PeerType string `json:"peer_type"`
	}

	if err := json.NewDecoder(req.Body).Decode(&params); err != nil {
		http.Error(res, "Invalid JSON: "+err.Error(), 400)
		return
	}

	if params.VkLink == "" || params.Peer == "" {
		http.Error(res, "vk_link and peer are required", 400)
		return
	}

	if params.Listen == "" {
		params.Listen = "127.0.0.1:9000"
	}
	if params.Streams == 0 {
		params.Streams = 4
	}
	if params.Mode == "" {
		params.Mode = "vk_link"
	}
	if params.PeerType == "" {
		params.PeerType = "proxy_v1"
	}

	// Set wrap key
	if params.WrapKey != "" {
		if err := SetWrapKey(params.WrapKey); err != nil {
			http.Error(res, "Invalid wrap key: "+err.Error(), 400)
			return
		}
	}

	// Wire up callbacks
	SetVkCredsFetcher(FetchVkCreds)
	SetCaptchaCallback(SolveCaptchaBrowser)

	w.SetStatus("starting")

	go func() {
		ret := StartProxy(
			params.Peer, params.VkLink, params.Mode,
			params.Streams, params.UDP, params.Listen,
			"", 0, params.PeerType, 4, 0,
		)
		if ret != 0 {
			w.SetStatus("error")
			util.TurnLog("[WebUI] Proxy start failed (code %d)", ret)
		} else {
			w.SetStatus("running")
			util.TurnLog("[WebUI] Proxy started successfully")
		}
	}()

	json.NewEncoder(res).Encode(map[string]interface{}{
		"status":  "starting",
		"listen":  params.Listen,
		"message": "Proxy starting...",
	})
}

// handleStop stops the TURN proxy.
func (w *WebUI) handleStop(res http.ResponseWriter, req *http.Request) {
	StopProxy()
	w.SetStatus("stopped")
	json.NewEncoder(res).Encode(map[string]interface{}{
		"status":  "stopped",
		"message": "Proxy stopped",
	})
}

// handleConfig returns/generates config.
func (w *WebUI) handleConfig(res http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		// Generate example config
		cfg := DefaultConfig()
		cfg.VKLink = "https://vk.com/call/join/..."
		cfg.Peer = "your.server.com:56001"
		json.NewEncoder(res).Encode(cfg)
		return
	}

	// Return current config
	cfg := DefaultConfig()
	json.NewEncoder(res).Encode(cfg)
}

// handleCheckUpdate checks for updates.
func (w *WebUI) handleCheckUpdate(res http.ResponseWriter, req *http.Request) {
	url, version, err := CheckForUpdate()
	if err != nil {
		json.NewEncoder(res).Encode(map[string]interface{}{
			"status":  "error",
			"message": err.Error(),
		})
		return
	}

	if url == "" {
		json.NewEncoder(res).Encode(map[string]interface{}{
			"status":  "up-to-date",
			"version": CurrentVersion,
		})
		return
	}

	json.NewEncoder(res).Encode(map[string]interface{}{
		"status":      "update-available",
		"version":     version,
		"current":     CurrentVersion,
		"downloadUrl": url,
	})
}

// webUIHTML is the embedded HTML/CSS/JS for the web interface.
const webUIHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TurnGuard</title>
<style>
:root {
  --bg: #1a1a2e;
  --card: #16213e;
  --accent: #0f3460;
  --text: #e0e0e0;
  --green: #00d68f;
  --red: #ff5252;
  --yellow: #ffd93d;
  --input: #0a0a1a;
  --border: #2a2a4a;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
  padding: 20px;
}
.container { max-width: 800px; margin: 0 auto; }
h1 {
  text-align: center;
  font-size: 28px;
  margin-bottom: 8px;
  background: linear-gradient(135deg, #00d68f, #0f3460);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.subtitle { text-align: center; color: #888; margin-bottom: 24px; font-size: 14px; }
.card {
  background: var(--card);
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 16px;
  border: 1px solid var(--border);
}
.card h2 { font-size: 16px; margin-bottom: 16px; color: #aaa; text-transform: uppercase; letter-spacing: 1px; }
.form-group { margin-bottom: 16px; }
label { display: block; margin-bottom: 6px; font-size: 14px; color: #aaa; }
input, select {
  width: 100%;
  padding: 10px 12px;
  background: var(--input);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--text);
  font-size: 14px;
  outline: none;
  transition: border-color 0.2s;
}
input:focus, select:focus { border-color: var(--green); }
.row { display: flex; gap: 12px; }
.row .form-group { flex: 1; }
.status-badge {
  display: inline-block;
  padding: 4px 12px;
  border-radius: 20px;
  font-size: 12px;
  font-weight: 600;
  text-transform: uppercase;
}
.status-stopped { background: rgba(255,82,82,0.2); color: var(--red); }
.status-running { background: rgba(0,214,143,0.2); color: var(--green); }
.status-starting { background: rgba(255,217,61,0.2); color: var(--yellow); }
.status-error { background: rgba(255,82,82,0.2); color: var(--red); }
.btn {
  padding: 12px 24px;
  border: none;
  border-radius: 8px;
  font-size: 14px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}
.btn-start { background: var(--green); color: #000; }
.btn-start:hover { background: #00b377; }
.btn-stop { background: var(--red); color: #fff; }
.btn-stop:hover { background: #cc4040; }
.btn-secondary { background: var(--accent); color: #fff; }
.btn-secondary:hover { background: #1a4a80; }
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-row { display: flex; gap: 12px; margin-top: 20px; }
.log-box {
  background: #000;
  border-radius: 8px;
  padding: 12px;
  height: 200px;
  overflow-y: auto;
  font-family: 'Courier New', monospace;
  font-size: 12px;
  line-height: 1.6;
  color: #0f0;
}
.log-line { white-space: pre-wrap; }
.info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.info-item { display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid var(--border); }
.info-label { color: #888; }
.info-value { font-weight: 600; }
.checkbox-group { display: flex; align-items: center; gap: 8px; }
.checkbox-group input { width: auto; }
.switch { position: relative; width: 40px; height: 22px; }
.switch input { opacity: 0; width: 0; height: 0; }
.slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background: var(--input); border: 1px solid var(--border); border-radius: 22px; transition: 0.3s; }
.slider:before { content: ""; position: absolute; height: 16px; width: 16px; left: 2px; bottom: 2px; background: #888; border-radius: 50%; transition: 0.3s; }
input:checked + .slider { background: var(--green); }
input:checked + .slider:before { transform: translateX(18px); background: #000; }
</style>
</head>
<body>
<div class="container">
  <h1>🛡️ TurnGuard</h1>
  <p class="subtitle" id="version">v0.3.1</p>

  <div class="card">
    <h2>📊 Status</h2>
    <div class="info-grid">
      <div class="info-item"><span class="info-label">Status</span><span id="status-badge" class="status-badge status-stopped">Stopped</span></div>
      <div class="info-item"><span class="info-label">Uptime</span><span class="info-value" id="uptime">—</span></div>
      <div class="info-item"><span class="info-label">Wrap</span><span class="info-value" id="wrap-status">Disabled</span></div>
      <div class="info-item"><span class="info-label">Listen</span><span class="info-value" id="listen-addr">127.0.0.1:9000</span></div>
    </div>
  </div>

  <div class="card">
    <h2>⚙️ Configuration</h2>
    <div class="form-group">
      <label>VK Call Link</label>
      <input type="text" id="vk-link" placeholder="https://vk.com/call/join/...">
    </div>
    <div class="row">
      <div class="form-group">
        <label>Peer Server (host:port)</label>
        <input type="text" id="peer" placeholder="your.server.com:56001">
      </div>
      <div class="form-group">
        <label>Listen Address</label>
        <input type="text" id="listen" value="127.0.0.1:9000">
      </div>
    </div>
    <div class="form-group">
      <label>Wrap Key (64 hex chars, optional)</label>
      <input type="text" id="wrap-key" placeholder="e979270b5240918e9f3764b0daf9bd825f6d95185481926407435665b37e53ca">
    </div>
    <div class="row">
      <div class="form-group">
        <label>Streams</label>
        <select id="streams">
          <option value="1">1</option>
          <option value="2">2</option>
          <option value="3">3</option>
          <option value="4" selected>4</option>
        </select>
      </div>
      <div class="form-group">
        <label>Peer Type</label>
        <select id="peer-type">
          <option value="proxy_v1">proxy_v1</option>
          <option value="wireguard">wireguard</option>
        </select>
      </div>
      <div class="form-group">
        <label>Mode</label>
        <select id="mode">
          <option value="vk_link">vk_link</option>
          <option value="wb">wb</option>
        </select>
      </div>
    </div>
    <div class="form-group checkbox-group">
      <label class="switch"><input type="checkbox" id="udp"><span class="slider"></span></label>
      <label for="udp" style="margin: 0;">UDP Mode</label>
    </div>
    <div class="btn-row">
      <button class="btn btn-start" id="btn-start" onclick="startProxy()">▶ Start</button>
      <button class="btn btn-stop" id="btn-stop" onclick="stopProxy()" disabled>⏹ Stop</button>
      <button class="btn btn-secondary" onclick="checkUpdate()">🔄 Check Updates</button>
    </div>
  </div>

  <div class="card">
    <h2>📋 Logs</h2>
    <div class="log-box" id="log-box"></div>
  </div>
</div>

<script>
const API = '';
let statusInterval;

function log(msg) {
  const box = document.getElementById('log-box');
  const time = new Date().toLocaleTimeString();
  const line = document.createElement('div');
  line.className = 'log-line';
  line.textContent = '[' + time + '] ' + msg;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

async function startProxy() {
  const params = {
    vk_link: document.getElementById('vk-link').value,
    peer: document.getElementById('peer').value,
    listen: document.getElementById('listen').value,
    wrap_key: document.getElementById('wrap-key').value,
    streams: parseInt(document.getElementById('streams').value),
    udp: document.getElementById('udp').checked,
    mode: document.getElementById('mode').value,
    peer_type: document.getElementById('peer-type').value,
  };

  if (!params.vk_link || !params.peer) {
    log('Error: VK Link and Peer are required');
    return;
  }

  log('Starting proxy...');
  document.getElementById('btn-start').disabled = true;

  try {
    const res = await fetch(API + '/api/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    const data = await res.json();
    if (res.ok) {
      log('Proxy starting on ' + data.listen);
      startStatusPolling();
    } else {
      log('Error: ' + data.error);
      document.getElementById('btn-start').disabled = false;
    }
  } catch (e) {
    log('Error: ' + e.message);
    document.getElementById('btn-start').disabled = false;
  }
}

async function stopProxy() {
  log('Stopping proxy...');
  try {
    await fetch(API + '/api/stop', { method: 'POST' });
    log('Proxy stopped');
  } catch (e) {
    log('Stop error: ' + e.message);
  }
  stopStatusPolling();
  updateUI('stopped');
}

async function checkUpdate() {
  log('Checking for updates...');
  try {
    const res = await fetch(API + '/api/check-update');
    const data = await res.json();
    if (data.status === 'up-to-date') {
      log('Up to date (v' + data.version + ')');
    } else if (data.status === 'update-available') {
      log('Update available: ' + data.version + ' (current: ' + data.current + ')');
      log('Download: ' + data.downloadUrl);
    } else {
      log('Update check failed: ' + data.message);
    }
  } catch (e) {
    log('Update check error: ' + e.message);
  }
}

function startStatusPolling() {
  statusInterval = setInterval(updateStatus, 2000);
  updateStatus();
}

function stopStatusPolling() {
  if (statusInterval) clearInterval(statusInterval);
}

async function updateStatus() {
  try {
    const res = await fetch(API + '/api/status');
    const data = await res.json();
    updateUI(data.status, data);
  } catch (e) {
    // Server might not be running
  }
}

function updateUI(status, data) {
  const badge = document.getElementById('status-badge');
  badge.className = 'status-badge status-' + status;
  badge.textContent = status.charAt(0).toUpperCase() + status.slice(1);

  if (data) {
    document.getElementById('uptime').textContent = data.uptime || '—';
    document.getElementById('wrap-status').textContent = data.wrap ? 'Enabled' : 'Disabled';
    document.getElementById('version').textContent = data.version || 'v0.3.1';
  }

  const isRunning = status === 'running' || status === 'starting';
  document.getElementById('btn-start').disabled = isRunning;
  document.getElementById('btn-stop').disabled = !isRunning;
}

// Initial status check
updateStatus();
log('TurnGuard Web UI ready. Configure and press Start.');
</script>
</body>
</html>`
