// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 NikKuz99. All Rights Reserved.

import { useState, useEffect } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import "./App.css";

interface VpnConfig {
  enabled: boolean;
  private_key: string;
  server_key: string;
  server_addr: string;
  allowed_ips: string;
  mtu: number;
  keepalive: number;
}

interface AppConfig {
  vk_link: string;
  peer: string;
  listen: string;
  wrap_key: string;
  streams: number;
  udp: boolean;
  mode: string;
  peer_type: string;
  vpn: VpnConfig;
  auto_update: boolean;
}

const defaultConfig: AppConfig = {
  vk_link: "",
  peer: "",
  listen: "127.0.0.1:9000",
  wrap_key: "",
  streams: 4,
  udp: false,
  mode: "vk_link",
  peer_type: "proxy_v1",
  vpn: {
    enabled: false,
    private_key: "",
    server_key: "",
    server_addr: "127.0.0.1:9000",
    allowed_ips: "0.0.0.0/0, ::0",
    mtu: 1280,
    keepalive: 25,
  },
  auto_update: true,
};

function App() {
  const [config, setConfig] = useState<AppConfig>(defaultConfig);
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [status, setStatus] = useState<string>("stopped");
  const [version, setVersion] = useState<string>("");
  const [updateMsg, setUpdateMsg] = useState<string>("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>("");

  // Load saved config + status on mount
  useEffect(() => {
    (async () => {
      try {
        const saved = await invoke<AppConfig>("load_config");
        setConfig({ ...defaultConfig, ...saved });
      } catch (e) {
        console.warn("load_config failed", e);
      }
      try {
        const v = await invoke<string>("get_version");
        setVersion(v);
      } catch (e) {
        console.warn("get_version failed", e);
      }
      try {
        const r = await invoke<boolean>("get_status");
        setRunning(r);
      } catch (e) {
        console.warn("get_status failed", e);
      }
    })();
  }, []);

  // Listen for proxy events
  useEffect(() => {
    const unlistenLog = listen<string>("proxy-log", (event) => {
      setLogs((prev) => [...prev.slice(-500), event.payload]);
    });
    const unlistenStatus = listen<string>("proxy-status", (event) => {
      setStatus(event.payload);
      if (event.payload === "stopped") setRunning(false);
      if (event.payload === "running") setRunning(true);
    });
    return () => {
      unlistenLog.then((fn) => fn());
      unlistenStatus.then((fn) => fn());
    };
  }, []);

  const handleSave = async () => {
    try {
      await invoke("save_config", { config });
      setError("");
    } catch (e) {
      setError(String(e));
    }
  };

  const handleStart = async () => {
    setLoading(true);
    setError("");
    try {
      await invoke("save_config", { config });
      await invoke("start_proxy", { config });
      setRunning(true);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleStop = async () => {
    setLoading(true);
    try {
      await invoke("stop_proxy");
      setRunning(false);
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  };

  const handleCheckUpdate = async () => {
    setUpdateMsg("Checking...");
    try {
      const msg = await invoke<string>("check_update");
      setUpdateMsg(msg);
    } catch (e) {
      setUpdateMsg("Error: " + String(e));
    }
  };

  const updateConfig = (patch: Partial<AppConfig>) => {
    setConfig((prev) => ({ ...prev, ...patch }));
  };

  const updateVpn = (patch: Partial<VpnConfig>) => {
    setConfig((prev) => ({ ...prev, vpn: { ...prev.vpn, ...patch } }));
  };

  return (
    <div className="app">
      <header className="app-header">
        <h1>TurnGuard {version && <span className="version">v{version}</span>}</h1>
        <div className={`status status-${status}`}>
          Status: <strong>{status}</strong>
        </div>
      </header>

      {error && <div className="error">{error}</div>}

      <div className="tabs">
        <details open>
          <summary>Connection</summary>
          <div className="form">
            <label>
              VK Call Link
              <input
                type="text"
                value={config.vk_link}
                onChange={(e) => updateConfig({ vk_link: e.target.value })}
                placeholder="https://vk.com/call/join/..."
              />
            </label>
            <label>
              Peer Server (host:port)
              <input
                type="text"
                value={config.peer}
                onChange={(e) => updateConfig({ peer: e.target.value })}
                placeholder="your.server.com:56001"
              />
            </label>
            <label>
              Listen Address
              <input
                type="text"
                value={config.listen}
                onChange={(e) => updateConfig({ listen: e.target.value })}
              />
            </label>
            <label>
              Wrap Key (64 hex chars)
              <input
                type="text"
                value={config.wrap_key}
                onChange={(e) => updateConfig({ wrap_key: e.target.value })}
                placeholder="e979270b5240918e9f3764b0daf9bd825f6d95185481926407435665b37e53ca"
              />
            </label>
            <div className="row">
              <label>
                Streams
                <input
                  type="number"
                  min={1}
                  max={4}
                  value={config.streams}
                  onChange={(e) => updateConfig({ streams: parseInt(e.target.value) || 1 })}
                />
              </label>
              <label>
                Mode
                <select
                  value={config.mode}
                  onChange={(e) => updateConfig({ mode: e.target.value })}
                >
                  <option value="vk_link">VK Link</option>
                  <option value="wb">WB (Wildberries)</option>
                </select>
              </label>
              <label>
                Peer Type
                <select
                  value={config.peer_type}
                  onChange={(e) => updateConfig({ peer_type: e.target.value })}
                >
                  <option value="proxy_v1">proxy_v1</option>
                  <option value="wireguard">wireguard</option>
                </select>
              </label>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={config.udp}
                  onChange={(e) => updateConfig({ udp: e.target.checked })}
                />
                UDP mode
              </label>
            </div>
          </div>
        </details>

        <details>
          <summary>VPN Mode (TUN device)</summary>
          <div className="form">
            <label className="checkbox">
              <input
                type="checkbox"
                checked={config.vpn.enabled}
                onChange={(e) => updateVpn({ enabled: e.target.checked })}
              />
              Enable WireGuard TUN device
            </label>
            <label>
              Client Private Key (hex)
              <input
                type="text"
                value={config.vpn.private_key}
                onChange={(e) => updateVpn({ private_key: e.target.value })}
                disabled={!config.vpn.enabled}
              />
            </label>
            <label>
              Server Public Key (hex)
              <input
                type="text"
                value={config.vpn.server_key}
                onChange={(e) => updateVpn({ server_key: e.target.value })}
                disabled={!config.vpn.enabled}
              />
            </label>
            <label>
              Server Endpoint
              <input
                type="text"
                value={config.vpn.server_addr}
                onChange={(e) => updateVpn({ server_addr: e.target.value })}
                disabled={!config.vpn.enabled}
              />
            </label>
            <div className="row">
              <label>
                MTU
                <input
                  type="number"
                  value={config.vpn.mtu}
                  onChange={(e) => updateVpn({ mtu: parseInt(e.target.value) || 1280 })}
                  disabled={!config.vpn.enabled}
                />
              </label>
              <label>
                Keepalive (s)
                <input
                  type="number"
                  value={config.vpn.keepalive}
                  onChange={(e) => updateVpn({ keepalive: parseInt(e.target.value) || 25 })}
                  disabled={!config.vpn.enabled}
                />
              </label>
            </div>
          </div>
        </details>

        <details>
          <summary>Logs</summary>
          <div className="logs">
            {logs.length === 0 ? (
              <p className="empty">No logs yet</p>
            ) : (
              logs.map((line, i) => <div key={i} className="log-line">{line}</div>)
            )}
          </div>
        </details>
      </div>

      <div className="actions">
        <button onClick={handleSave} disabled={loading}>Save Config</button>
        {!running ? (
          <button onClick={handleStart} disabled={loading || !config.vk_link || !config.peer} className="primary">
            {loading ? "Starting..." : "Start"}
          </button>
        ) : (
          <button onClick={handleStop} disabled={loading} className="danger">
            {loading ? "Stopping..." : "Stop"}
          </button>
        )}
        <button onClick={handleCheckUpdate} disabled={loading}>Check Updates</button>
      </div>

      {updateMsg && <div className="update-msg">{updateMsg}</div>}

      <footer className="app-footer">
        <a href="https://github.com/NikKuz99/turnguard" target="_blank" rel="noopener noreferrer">
          GitHub
        </a>
        {" • "}
        <span>WireGuard + VK TURN</span>
      </footer>
    </div>
  );
}

export default App;
