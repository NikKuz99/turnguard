// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 NikKuz99. All Rights Reserved.
//
// TurnGuard GUI — Tauri backend.
// Multi-tunnel support: stores multiple tunnel configs, spawns turnguard binary.

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::process::{Child, Command, Stdio};
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, State};

// ─────────────────────────────────────────────────────────────────────────────
// State
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ProxyState {
    child: Arc<Mutex<Option<Child>>>,
    running: Arc<AtomicBool>,
    active_tunnel: Arc<Mutex<String>>,
}

impl Default for ProxyState {
    fn default() -> Self {
        Self {
            child: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            active_tunnel: Arc::new(Mutex::new(String::new())),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Config structs
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    pub enabled: bool,
    pub private_key: String,
    pub server_key: String,
    pub server_addr: String,
    pub allowed_ips: String,
    pub mtu: u32,
    pub keepalive: u32,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            private_key: String::new(),
            server_key: String::new(),
            server_addr: "127.0.0.1:9000".to_string(),
            allowed_ips: "0.0.0.0/0, ::0".to_string(),
            mtu: 1280,
            keepalive: 25,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub vk_link: String,
    pub peer: String,
    pub listen: String,
    pub wrap_key: String,
    pub streams: u32,
    pub udp: bool,
    pub mode: String,
    pub peer_type: String,
    pub vpn: VpnConfig,
    pub auto_update: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            vk_link: String::new(),
            peer: String::new(),
            listen: "127.0.0.1:9000".to_string(),
            wrap_key: String::new(),
            streams: 4,
            udp: false,
            mode: "vk_link".to_string(),
            peer_type: "proxy_v1".to_string(),
            vpn: VpnConfig::default(),
            auto_update: true,
        }
    }
}

/// Tunnel = name + config. Stored as individual JSON files.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tunnel {
    pub name: String,
    pub config: AppConfig,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn app_data_dir(app: &tauri::AppHandle) -> Option<PathBuf> {
    app.path().app_data_dir().ok().map(|d| {
        let _ = fs::create_dir_all(&d);
        d
    })
}

fn tunnels_dir(app: &tauri::AppHandle) -> Option<PathBuf> {
    app_data_dir(app).map(|d| {
        let dir = d.join("tunnels");
        let _ = fs::create_dir_all(&dir);
        dir
    })
}

fn dns_cache_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    app_data_dir(app).map(|d| d.join("dns_cache.json"))
}

fn find_turnguard_binary(app: &tauri::AppHandle) -> Option<PathBuf> {
    let bin_name = if cfg!(windows) { "turnguard.exe" } else { "turnguard" };

    // 1. App data dir /bin/
    if let Some(data_dir) = app.path().app_data_dir().ok() {
        let candidate = data_dir.join("bin").join(bin_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    // 2. Resources (bundled)
    if let Some(resource_dir) = app.path().resource_dir().ok() {
        let candidate = resource_dir.join(bin_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    // 3. PATH
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(if cfg!(windows) { ';' } else { ':' }) {
            let candidate = PathBuf::from(dir).join(bin_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}

/// Sanitize tunnel name for use as filename
fn sanitize_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Tunnel management commands
// ─────────────────────────────────────────────────────────────────────────────

#[tauri::command]
fn list_tunnels(app: tauri::AppHandle) -> Result<Vec<Tunnel>, String> {
    let dir = tunnels_dir(&app).ok_or("no app data dir")?;
    let mut tunnels = Vec::new();

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(data) = fs::read_to_string(&path) {
                    if let Ok(tunnel) = serde_json::from_str::<Tunnel>(&data) {
                        tunnels.push(tunnel);
                    }
                }
            }
        }
    }

    tunnels.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(tunnels)
}

#[tauri::command]
fn save_tunnel(app: tauri::AppHandle, tunnel: Tunnel) -> Result<(), String> {
    let dir = tunnels_dir(&app).ok_or("no app data dir")?;
    let filename = format!("{}.json", sanitize_name(&tunnel.name));
    let path = dir.join(filename);
    let data = serde_json::to_string_pretty(&tunnel).map_err(|e| e.to_string())?;
    fs::write(&path, data).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn delete_tunnel(app: tauri::AppHandle, name: String) -> Result<(), String> {
    let dir = tunnels_dir(&app).ok_or("no app data dir")?;
    let filename = format!("{}.json", sanitize_name(&name));
    let path = dir.join(filename);
    if path.exists() {
        fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn start_tunnel(app: tauri::AppHandle, name: String, state: State<'_, ProxyState>) -> Result<(), String> {
    // Stop any running tunnel first
    if state.running.load(Ordering::SeqCst) {
        stop_tunnel_internal(&state);
    }

    // Load tunnel config
    let dir = tunnels_dir(&app).ok_or("no app data dir")?;
    let filename = format!("{}.json", sanitize_name(&name));
    let tunnel_path = dir.join(filename);

    if !tunnel_path.exists() {
        return Err(format!("tunnel '{}' not found", name));
    }

    let tunnel_data = fs::read_to_string(&tunnel_path).map_err(|e| e.to_string())?;
    let tunnel: Tunnel = serde_json::from_str(&tunnel_data).map_err(|e| e.to_string())?;

    let binary = find_turnguard_binary(&app).ok_or_else(|| {
        "turnguard binary not found. Place it in app data dir /bin/ or PATH".to_string()
    })?;

    // Write config to temp file for the child process
    let cfg_path = app_data_dir(&app).ok_or("no app data dir")?.join("active_config.json");
    let cfg_data = serde_json::to_string_pretty(&tunnel.config).map_err(|e| e.to_string())?;
    fs::write(&cfg_path, cfg_data).map_err(|e| e.to_string())?;

    let dns_cache = dns_cache_path(&app).ok_or("no app data dir")?;

    // Build command: turnguard -config <path> -dns-cache <path>
    let mut cmd = Command::new(&binary);
    cmd.arg("-config").arg(&cfg_path);
    cmd.arg("-dns-cache").arg(&dns_cache);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.stdin(Stdio::null());

    let mut child = cmd.spawn().map_err(|e| {
        format!("failed to spawn {}: {}", binary.display(), e)
    })?;

    // Take stdout/stderr before storing child
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    state.running.store(true, Ordering::SeqCst);
    *state.active_tunnel.lock().unwrap() = name.clone();
    let _ = app.emit("proxy-status", "starting");
    let _ = app.emit("proxy-active-tunnel", &name);

    // Spawn threads to read stdout/stderr
    if let Some(stdout) = stdout {
        let app_clone = app.clone();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines().flatten() {
                let _ = app_clone.emit("proxy-log", &line);
            }
        });
    }
    if let Some(stderr) = stderr {
        let app_clone = app.clone();
        std::thread::spawn(move || {
            use std::io::BufRead;
            let reader = std::io::BufReader::new(stderr);
            for line in reader.lines().flatten() {
                let _ = app_clone.emit("proxy-log", &line);
            }
        });
    }

    // Store child handle
    *state.child.lock().unwrap() = Some(child);

    // Monitor child exit
    let child_arc = state.child.clone();
    let running_arc = state.running.clone();
    let active_arc = state.active_tunnel.clone();
    let app_clone = app.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let mut child_lock = child_arc.lock().unwrap();
            if let Some(child) = child_lock.as_mut() {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        *child_lock = None;
                        drop(child_lock);
                        running_arc.store(false, Ordering::SeqCst);
                        *active_arc.lock().unwrap() = String::new();
                        let _ = app_clone.emit("proxy-status", "stopped");
                        let _ = app_clone.emit("proxy-active-tunnel", "");
                        return;
                    }
                    Ok(None) => {}
                    Err(_) => {
                        *child_lock = None;
                        drop(child_lock);
                        running_arc.store(false, Ordering::SeqCst);
                        *active_arc.lock().unwrap() = String::new();
                        let _ = app_clone.emit("proxy-status", "stopped");
                        let _ = app_clone.emit("proxy-active-tunnel", "");
                        return;
                    }
                }
            } else {
                return;
            }
        }
    });

    let _ = app.emit("proxy-status", "running");
    Ok(())
}

fn stop_tunnel_internal(state: &ProxyState) {
    if let Some(mut child) = state.child.lock().unwrap().take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    state.running.store(false, Ordering::SeqCst);
    *state.active_tunnel.lock().unwrap() = String::new();
}

#[tauri::command]
fn stop_tunnel(state: State<'_, ProxyState>) -> Result<(), String> {
    stop_tunnel_internal(&state);
    Ok(())
}

#[tauri::command]
fn get_status(state: State<'_, ProxyState>) -> bool {
    state.running.load(Ordering::SeqCst)
}

#[tauri::command]
fn get_active_tunnel(state: State<'_, ProxyState>) -> String {
    state.active_tunnel.lock().unwrap().clone()
}

#[tauri::command]
fn check_update(app: tauri::AppHandle) -> Result<String, String> {
    let binary = find_turnguard_binary(&app)
        .ok_or("turnguard binary not found")?;

    let output = Command::new(&binary)
        .arg("-check-update")
        .output()
        .map_err(|e| format!("failed to spawn: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    if !stderr.is_empty() {
        Ok(stderr.trim().to_string())
    } else {
        Ok(stdout.trim().to_string())
    }
}

#[tauri::command]
fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ─────────────────────────────────────────────────────────────────────────────
// Import from .conf file (WireGuard format)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse WireGuard .conf file and create a Tunnel.
/// Supports .conf (single) and .zip (multiple tunnels).
/// TURN-specific fields stored as comments: #turn.vk_link = ...
#[tauri::command]
fn import_tunnel(app: tauri::AppHandle, path: String) -> Result<Vec<Tunnel>, String> {
    let p = PathBuf::from(&path);
    if !p.exists() {
        return Err(format!("file not found: {}", path));
    }

    let filename = p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("imported");

    let is_zip = filename.to_lowercase().ends_with(".zip");
    let is_conf = filename.to_lowercase().ends_with(".conf");

    if !is_zip && !is_conf {
        return Err("file must be .conf or .zip".to_string());
    }

    let mut tunnels = Vec::new();

    if is_conf {
        let name = filename.trim_end_matches(".conf")
            .trim_end_matches(".CONF")
            .to_string();
        let tunnel = parse_conf_file(&p, &name)?;
        tunnels.push(tunnel);
    } else {
        let file = fs::File::open(&p).map_err(|e| e.to_string())?;
        let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;

        for i in 0..zip.len() {
            let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
            let entry_name = entry.name().to_string();

            if !entry_name.to_lowercase().ends_with(".conf") {
                continue;
            }

            let name = entry_name
                .rsplit('/')
                .next()
                .unwrap_or(&entry_name)
                .trim_end_matches(".conf")
                .trim_end_matches(".CONF")
                .to_string();

            let mut content_str = String::new();
            std::io::Read::read_to_string(&mut entry, &mut content_str)
                .map_err(|e| e.to_string())?;

            let tunnel = parse_conf_content(&content_str, &name)?;
            tunnels.push(tunnel);
        }
    }

    for tunnel in &tunnels {
        save_tunnel(app.clone(), tunnel.clone())?;
    }

    Ok(tunnels)
}

fn parse_conf_file(path: &PathBuf, name: &str) -> Result<Tunnel, String> {
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_conf_content(&content, name)
}

fn parse_conf_content(content: &str, name: &str) -> Result<Tunnel, String> {
    let mut config = AppConfig::default();
    let mut tunnel_name = name.to_string();
    let mut current_section = "";
    let mut has_interface = false;
    let mut has_peer = false;
    let mut turn_enabled = false;

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        // Support both #@wgt: (Android export format) and #turn. (legacy)
        let turn_prefix = if trimmed.starts_with("#@wgt:") {
            Some(&trimmed["#@wgt:".len()..])
        } else if trimmed.starts_with("#turn.") {
            Some(&trimmed["#turn.".len()..])
        } else {
            None
        };

        if let Some(rest) = turn_prefix {
            if let Some(eq_pos) = rest.find('=') {
                let key = rest[..eq_pos].trim();
                let value = rest[eq_pos + 1..].trim();
                match key {
                    "VKLink" | "vk_link" => config.vk_link = value.to_string(),
                    "WrapKey" | "wrap_key" => config.wrap_key = value.to_string(),
                    "Mode" | "mode" => config.mode = value.to_string(),
                    "StreamNum" | "streams" => config.streams = value.parse().unwrap_or(4),
                    "UseUDP" | "udp" => config.udp = value == "true" || value == "1",
                    "LocalPort" | "listen" => {
                        let listen_val = if value.contains(':') {
                            value.to_string()
                        } else {
                            format!("127.0.0.1:{}", value)
                        };
                        config.listen = listen_val;
                    }
                    "IPPort" | "peer" => config.peer = value.to_string(),
                    "PeerType" | "peer_type" => config.peer_type = value.to_string(),
                    "EnableTURN" | "enable_turn" => turn_enabled = value == "true" || value == "1",
                    "Name" | "name" => tunnel_name = value.to_string(),
                    _ => {}
                }
            }
            continue;
        }

        // Skip regular comments
        if trimmed.starts_with('#') { continue; }

        // Section headers
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            current_section = &trimmed[1..trimmed.len() - 1];
            if current_section == "Interface" { has_interface = true; }
            else if current_section == "Peer" { has_peer = true; }
            continue;
        }

        // Key = Value
        if let Some(eq_pos) = trimmed.find('=') {
            let key = trimmed[..eq_pos].trim();
            let value = trimmed[eq_pos + 1..].trim();
            match current_section {
                "Interface" => match key {
                    "PrivateKey" => config.vpn.private_key = base64_to_hex(value),
                    "MTU" => config.vpn.mtu = value.parse().unwrap_or(1280),
                    _ => {}
                },
                "Peer" => match key {
                    "Endpoint" => {
                        // Endpoint is the WireGuard server address (for VPN mode)
                        config.vpn.server_addr = value.to_string();
                    }
                    "PublicKey" => config.vpn.server_key = base64_to_hex(value),
                    "AllowedIPs" => config.vpn.allowed_ips = value.to_string(),
                    "PersistentKeepalive" => config.vpn.keepalive = value.parse().unwrap_or(25),
                    _ => {}
                },
                _ => {}
            }
        }
    }

    // If .conf has interface + peer, enable VPN mode
    if has_interface && has_peer { config.vpn.enabled = true; }

    Ok(Tunnel { name: tunnel_name, config })
}

fn base64_to_hex(base64_str: &str) -> String {
    let table: [u8; 256] = {
        let mut t = [255u8; 256];
        for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".iter().enumerate() {
            t[*c as usize] = i as u8;
        }
        t
    };
    let input = base64_str.trim().trim_end_matches('=').as_bytes();
    let mut output = Vec::new();
    let mut i = 0;
    while i < input.len() {
        let a = table[input[i] as usize];
        let b = if i + 1 < input.len() { table[input[i + 1] as usize] } else { 0 };
        let c2 = if i + 2 < input.len() { table[input[i + 2] as usize] } else { 0 };
        let d = if i + 3 < input.len() { table[input[i + 3] as usize] } else { 0 };
        if a == 255 || b == 255 { break; }
        output.push((a << 2) | (b >> 4));
        if i + 2 < input.len() && c2 != 255 {
            output.push((b << 4) | (c2 >> 2));
            if i + 3 < input.len() && d != 255 {
                output.push((c2 << 6) | d);
            }
        }
        i += 4;
    }
    output.iter().map(|b| format!("{:02x}", b)).collect()
}


// ─────────────────────────────────────────────────────────────────────────────
// App entry point
// ─────────────────────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_notification::init())
        .manage(ProxyState::default())
        .invoke_handler(tauri::generate_handler![
            list_tunnels,
            save_tunnel,
            delete_tunnel,
            start_tunnel,
            stop_tunnel,
            get_status,
            get_active_tunnel,
            check_update,
            get_version,
            import_tunnel,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                let state: State<ProxyState> = window.state();
                let child_opt = state.child.lock().unwrap().take();
                if let Some(mut child) = child_opt {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
