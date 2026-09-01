// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 NikKuz99. All Rights Reserved.
//
// TurnGuard GUI — Material 3 styled UI with multi-tunnel support.

import { useState, useEffect, useRef } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { open as openDialog } from "@tauri-apps/plugin-dialog";
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

interface UpdateInfo {
  available: boolean;
  current_version: string;
  latest_version: string;
  download_url: string;
  download_size: number;
  release_notes: string;
}

interface Tunnel {
  name: string;
  config: AppConfig;
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

type View = "list" | "editor" | "logs" | "about";

function App() {
  const [tunnels, setTunnels] = useState<Tunnel[]>([]);
  const [running, setRunning] = useState(false);
  const [activeTunnel, setActiveTunnel] = useState("");
  const [view, setView] = useState<View>("list");
  const [editingTunnel, setEditingTunnel] = useState<Tunnel | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [version, setVersion] = useState("");
  const [updateMsg, setUpdateMsg] = useState("");
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const logsEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    refreshTunnels();
    invoke<string>("get_version").then(setVersion).catch(() => {});

    // Auto-check for updates on start (T15)
    invoke<UpdateInfo>("check_for_gui_update")
      .then((info) => {
        if (info.available) {
          setUpdateInfo(info);
        }
      })
      .catch((e) => console.warn("Update check failed:", e));
    invoke<boolean>("get_status").then(setRunning).catch(() => {});
    invoke<string>("get_active_tunnel").then(setActiveTunnel).catch(() => {});
  }, []);

  useEffect(() => {
    const unlog = listen<string>("proxy-log", (e) => {
      setLogs((p) => [...p.slice(-500), e.payload]);
      requestAnimationFrame(() => logsEndRef.current?.scrollIntoView({ behavior: "smooth" }));
    });
    const unstat = listen<string>("proxy-status", (e) => {
      setRunning(e.payload === "running");
      if (e.payload === "stopped") setActiveTunnel("");
    });
    const unact = listen<string>("proxy-active-tunnel", (e) => setActiveTunnel(e.payload));
    return () => { unlog.then(f=>f()); unstat.then(f=>f()); unact.then(f=>f()); };
  }, []);

  const refreshTunnels = async () => {
    try { setTunnels(await invoke<Tunnel[]>("list_tunnels")); }
    catch (e) { setError(String(e)); }
  };

  const handleToggle = async (tunnel: Tunnel) => {
    setLoading(true); setError("");
    try {
      if (activeTunnel === tunnel.name) {
        await invoke("stop_tunnel");
      } else {
        await invoke("start_tunnel", { name: tunnel.name });
        setView("list");
      }
    } catch (e) { setError(String(e)); }
    finally { setLoading(false); }
  };

  const handleSave = async (tunnel: Tunnel) => {
    try {
      await invoke("save_tunnel", { tunnel });
      await refreshTunnels();
      setView("list");
      setError("");
    } catch (e) { setError(String(e)); }
  };

  const handleDelete = async (name: string) => {
    if (!confirm(`Delete tunnel "${name}"?`)) return;
    try {
      await invoke("delete_tunnel", { name });
      await refreshTunnels();
    } catch (e) { setError(String(e)); }
  };

  const handleNewTunnel = () => {
    setEditingTunnel({ name: "", config: { ...defaultConfig } });
    setView("editor");
  };

  const handleImport = async () => {
    try {
      const selected = await openDialog({
        filters: [{ name: "WireGuard Config", extensions: ["conf", "zip"] }],
        multiple: false,
      });
      if (!selected) return;
      const path = typeof selected === "string" ? selected : (selected as string[])[0];
      if (!path) return;
      const imported = await invoke<Tunnel[]>("import_tunnel", { path });
      await refreshTunnels();
      if (imported.length === 1) {
        setError(`Imported tunnel: ${imported[0].name}`);
      } else {
        setError(`Imported ${imported.length} tunnels`);
      }
    } catch (e) {
      setError(String(e));
    }
  };

  const handleEdit = (tunnel: Tunnel) => {
    setEditingTunnel({ ...tunnel, config: { ...tunnel.config } });
    setView("editor");
  };

  const handleCheckUpdate = async () => {
    setUpdateMsg("Checking...");
    try {
      const info = await invoke<UpdateInfo>("check_for_gui_update");
      if (info.available) {
        setUpdateInfo(info);
        setUpdateMsg("");
      } else {
        setUpdateMsg("You are using the latest version (" + info.current_version + ")");
        setUpdateInfo(null);
      }
    } catch (e) { setUpdateMsg("Error: " + String(e)); }
  };

  return (
    <div className="app">
      <header className="app-bar">
        <div className="app-bar-left">
          <div className="logo">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L2 7v10l10 5 10-5V7L12 2z" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"/>
              <path d="M2 7l10 5 10-5M12 22V12" stroke="currentColor" strokeWidth="2" strokeLinejoin="round"/>
            </svg>
          </div>
          <div className="title-block">
            <h1>TurnGuard</h1>
            {version && <span className="version">v{version}</span>}
          </div>
        </div>
        <div className="app-bar-right">
          {running && activeTunnel && (
            <span className="active-tunnel-name">{activeTunnel}</span>
          )}
          <div className={`status-chip status-${running ? "running" : "stopped"}`}>
            <span className="status-dot" />
            {running ? "Running" : "Stopped"}
          </div>
        </div>
      </header>

      {error && (
        <div className="error-banner">
          <span>{error}</span>
          <button onClick={() => setError("")}>&times;</button>
        </div>
      )}

      {updateInfo && (
        <div className="update-banner">
          <div className="update-banner-info">
            <strong>Update available: {updateInfo.latest_version}</strong>
            <span>You are using {updateInfo.current_version}</span>
          </div>
          <a href={updateInfo.download_url} target="_blank" rel="noopener noreferrer" className="update-download-btn">
            Download
          </a>
          <button onClick={() => setUpdateInfo(null)}>&times;</button>
        </div>
      )}

      <nav className="tabs">
        <button className={view === "list" ? "tab active" : "tab"} onClick={() => setView("list")}>
          Tunnels
        </button>
        <button className={view === "logs" ? "tab active" : "tab"} onClick={() => setView("logs")}>
          Logs {logs.length > 0 && <span className="badge">{logs.length}</span>}
        </button>
        <button className={view === "about" ? "tab active" : "tab"} onClick={() => setView("about")}>
          About
        </button>
      </nav>

      <main className="content">
        {view === "list" && (
          <div className="tunnel-list">
            {tunnels.length === 0 ? (
              <div className="empty-state">
                <p>No tunnels configured.</p>
                <div className="empty-actions">
                  <button className="filled-button" onClick={handleNewTunnel}>Add Tunnel</button>
                  <button className="outlined-button" onClick={handleImport}>Import .conf</button>
                </div>
              </div>
            ) : (
              <>
                {tunnels.map((t) => (
                  <div key={t.name} className="tunnel-card">
                    <div className="tunnel-card-info" onClick={() => handleEdit(t)}>
                      <span className="tunnel-name">{t.name}</span>
                      <span className="tunnel-peer">{t.config.peer || "—"}</span>
                    </div>
                    <div className="tunnel-card-actions">
                      <button className="icon-button" onClick={() => handleEdit(t)} title="Edit">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
                          <path d="M12 20h9M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                      </button>
                      <button className="icon-button danger" onClick={() => handleDelete(t.name)} title="Delete">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
                          <path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                        </svg>
                      </button>
                      <label className="switch" title={running && activeTunnel !== t.name ? "Stop current tunnel first" : ""}>
                        <input
                          type="checkbox"
                          checked={activeTunnel === t.name && running}
                          onChange={() => handleToggle(t)}
                          disabled={loading}
                        />
                        <span className="slider" />
                      </label>
                    </div>
                  </div>
                ))}
                <div className="list-actions">
                  <button className="outlined-button" onClick={handleImport}>Import .conf</button>
                  <button className="outlined-button add-tunnel-btn" onClick={handleNewTunnel}>
                    + Add Tunnel
                  </button>
                </div>
              </>
            )}
          </div>
        )}

        {view === "editor" && editingTunnel && (
          <TunnelEditor
            tunnel={editingTunnel}
            onSave={handleSave}
            onCancel={() => setView("list")}
          />
        )}

        {view === "logs" && (
          <div className="card log-card">
            <div className="card-header">
              <h2 className="card-title">Logs</h2>
              <button className="text-button" onClick={() => {
                  const text = logs.join("\n");
                  navigator.clipboard.writeText(text).then(() => {
                    const btn = event?.target as HTMLButtonElement;
                    if (btn) { btn.textContent = "Copied!"; setTimeout(() => btn.textContent = "Copy", 2000); }
                  });
                }}>Copy</button>
                <button className="text-button" onClick={() => setLogs([])}>Clear</button>
            </div>
            <div className="logs">
              {logs.length === 0 ? (
                <div className="empty-logs">No logs yet.</div>
              ) : (
                logs.map((line, i) => <div key={i} className="log-line">{line}</div>)
              )}
              <div ref={logsEndRef} />
            </div>
          </div>
        )}

        {view === "about" && (
          <div className="card">
            <div className="card-header"><h2 className="card-title">About</h2></div>
            <div className="about-content">
              <p><strong>TurnGuard</strong> — Cross-platform WireGuard + VK TURN desktop client</p>
              <p>Version: v{version}</p>
              <p><a href="https://github.com/NikKuz99/turnguard" target="_blank" rel="noopener noreferrer">GitHub Repository</a></p>
              <button className="outlined-button" onClick={handleCheckUpdate}>Check for updates</button>
              {updateMsg && <div className="update-msg">{updateMsg}</div>}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

// ─── Tunnel Editor Component ───

function TunnelEditor({ tunnel, onSave, onCancel }: {
  tunnel: Tunnel;
  onSave: (t: Tunnel) => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState(tunnel.name);
  const [config, setConfig] = useState<AppConfig>(tunnel.config);
  const [showVpn, setShowVpn] = useState(config.vpn.enabled);

  const update = (p: Partial<AppConfig>) => setConfig((c) => ({ ...c, ...p }));
  const updateVpn = (p: Partial<VpnConfig>) => setConfig((c) => ({ ...c, vpn: { ...c.vpn, ...p } }));

  const handleSave = () => {
    if (!name.trim()) { alert("Tunnel name is required"); return; }
    if (!config.vk_link.trim()) { alert("VK Link is required"); return; }
    if (!config.peer.trim()) { alert("Peer address is required"); return; }
    onSave({ name: name.trim(), config: { ...config, vpn: { ...config.vpn, enabled: showVpn } } });
  };

  return (
    <div className="card">
      <div className="card-header">
        <h2 className="card-title">{tunnel.name ? "Edit Tunnel" : "New Tunnel"}</h2>
      </div>

      <div className="form-grid">
        <div className="field full">
          <label>Tunnel name</label>
          <input type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="My VK Tunnel" />
        </div>

        <div className="field full">
          <label>VK Calls link</label>
          <input type="text" value={config.vk_link} onChange={(e) => update({ vk_link: e.target.value })} placeholder="https://vk.com/call/join/..." />
        </div>

        <div className="field">
          <label>Peer address</label>
          <input type="text" value={config.peer} onChange={(e) => update({ peer: e.target.value })} placeholder="your.server.com:56001" />
        </div>

        <div className="field">
          <label>Listen address</label>
          <input type="text" value={config.listen} onChange={(e) => update({ listen: e.target.value })} />
        </div>

        <div className="field full">
          <label>Wrap key (64 hex chars)</label>
          <input type="text" value={config.wrap_key} onChange={(e) => update({ wrap_key: e.target.value })} placeholder="e979270b..." className="mono" />
        </div>

        <div className="field">
          <label>Mode</label>
          <select value={config.mode} onChange={(e) => update({ mode: e.target.value })}>
            <option value="vk_link">VK Link</option>
            <option value="wb">WB (Wildberries)</option>
          </select>
        </div>

        <div className="field">
          <label>Streams</label>
          <input type="number" min={1} max={4} value={config.streams} onChange={(e) => update({ streams: parseInt(e.target.value) || 1 })} />
        </div>

        <div className="field checkbox-field">
          <label className="checkbox">
            <input type="checkbox" checked={config.udp} onChange={(e) => update({ udp: e.target.checked })} />
            <span>UDP mode</span>
          </label>
        </div>
      </div>

      {/* VPN Section */}
      <div className="section-divider" />
      <div className="card-header">
        <h2 className="card-title">WireGuard TUN</h2>
        <label className="switch">
          <input type="checkbox" checked={showVpn} onChange={(e) => setShowVpn(e.target.checked)} />
          <span className="slider" />
        </label>
      </div>

      {showVpn && (
        <div className="form-grid">
          <div className="field full">
            <label>Client private key (hex)</label>
            <input type="text" value={config.vpn.private_key} onChange={(e) => updateVpn({ private_key: e.target.value })} className="mono" />
          </div>
          <div className="field full">
            <label>Server public key (hex)</label>
            <input type="text" value={config.vpn.server_key} onChange={(e) => updateVpn({ server_key: e.target.value })} className="mono" />
          </div>
          <div className="field">
            <label>Server endpoint</label>
            <input type="text" value={config.vpn.server_addr} onChange={(e) => updateVpn({ server_addr: e.target.value })} />
          </div>
          <div className="field">
            <label>MTU</label>
            <input type="number" value={config.vpn.mtu} onChange={(e) => updateVpn({ mtu: parseInt(e.target.value) || 1280 })} />
          </div>
          <div className="field">
            <label>Keepalive (s)</label>
            <input type="number" value={config.vpn.keepalive} onChange={(e) => updateVpn({ keepalive: parseInt(e.target.value) || 25 })} />
          </div>
          <div className="field full">
            <label>Allowed IPs</label>
            <input type="text" value={config.vpn.allowed_ips} onChange={(e) => updateVpn({ allowed_ips: e.target.value })} />
          </div>
          <div className="field full checkbox-field">
            <label className="checkbox">
              <input
                type="checkbox"
                checked={config.vpn.allowed_ips !== "0.0.0.0/0, ::0"}
                onChange={(e) => {
                  if (e.target.checked) {
                    updateVpn({ allowed_ips: "0.0.0.0/0, ::0, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16" });
                  } else {
                    updateVpn({ allowed_ips: "0.0.0.0/0, ::0" });
                  }
                }}
              />
              <span>Exclude private addresses</span>
            </label>
          </div>
        </div>
      )}

      <div className="editor-actions">
        <button className="outlined-button" onClick={onCancel}>Cancel</button>
        <button className="filled-button" onClick={handleSave}>Save</button>
      </div>
    </div>
  );
}

export default App;
