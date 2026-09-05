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

#[cfg(windows)]
use std::os::windows::process::CommandExt;

// CREATE_NO_WINDOW flag for Windows — prevents console window from appearing
// when launching console subprocesses (turnguard CLI) from a GUI app.
// 0x08000000 = CREATE_NO_WINDOW
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

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
// Tunnel config (must match frontend)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone, Serialize, Deserialize)]
struct TunnelConfig {
    #[serde(default)]
    vk_link: String,
    #[serde(default)]
    peer: String,
    #[serde(default)]
    wrap_key: String,
    #[serde(default)]
    streams: i32,
    #[serde(default)]
    udp: bool,
    #[serde(default)]
    mode: String,
    #[serde(default)]
    vpn: bool,
    #[serde(default)]
    private_key: String,
    #[serde(default)]
    server_key: String,
    #[serde(default)]
    server_addr: String,
    #[serde(default)]
    allowed_ips: String,
    #[serde(default)]
    mtu: i32,
    #[serde(default)]
    keepalive: i32,
    #[serde(default)]
    exclude_private: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct Tunnel {
    name: String,
    config: TunnelConfig,
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn app_data_dir(app: &tauri::AppHandle) -> Option<PathBuf> {
    app.path().app_data_dir().ok()
}

fn tunnels_dir(app: &tauri::AppHandle) -> Option<PathBuf> {
    let dir = app_data_dir(app)?.join("tunnels");
    let _ = fs::create_dir_all(&dir);
    Some(dir)
}

fn dns_cache_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    app_data_dir(app).map(|d| d.join("dns_cache.json"))
}

/// Locate the turnguard CLI binary. Looks in:
/// 1. App data dir /bin/turnguard(.exe)
/// 2. Same dir as the GUI executable (sidecar)
/// 3. PATH
fn find_turnguard_binary(app: &tauri::AppHandle) -> Option<PathBuf> {
    let exe_name = if cfg!(windows) { "turnguard.exe" } else { "turnguard" };

    // 1. App data dir /bin/
    if let Some(bin_dir) = app_data_dir(app).map(|d| d.join("bin")) {
        let candidate = bin_dir.join(exe_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    // 2. Resource dir (externalBin)
    if let Some(resource_dir) = app.path().resource_dir().ok() {
        let candidate = resource_dir.join(exe_name);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    // 3. Side-by-side with GUI exe
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let candidate = parent.join(exe_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    // 4. PATH lookup
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(if cfg!(windows) { ';' } else { ':' }) {
            let candidate = PathBuf::from(dir).join(exe_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}

/// Apply platform-specific flags to hide console window on Windows.
/// On Windows, spawning a console subprocess from a GUI app produces
/// a visible console window. CREATE_NO_WINDOW suppresses it.
fn apply_no_window(cmd: &mut Command) {
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(not(windows))]
    {
        let _ = cmd;
    }
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
    Ok(tunnels)
}

#[tauri::command]
fn save_tunnel(app: tauri::AppHandle, tunnel: Tunnel) -> Result<(), String> {
    let dir = tunnels_dir(&app).ok_or("no app data dir")?;
    let safe_name = sanitize_name(&tunnel.name);
    let path = dir.join(format!("{}.json", safe_name));
    let data = serde_json::to_string_pretty(&tunnel).map_err(|e| e.to_string())?;
    fs::write(&path, data).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn delete_tunnel(app: tauri::AppHandle, name: String) -> Result<(), String> {
    let dir = tunnels_dir(&app).ok_or("no app data dir")?;
    let safe_name = sanitize_name(&name);
    let path = dir.join(format!("{}.json", safe_name));
    if path.exists() {
        fs::remove_file(&path).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn sanitize_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .collect::<String>()
        .trim()
        .to_string()
}

#[tauri::command]
fn start_tunnel(app: tauri::AppHandle, state: State<'_, ProxyState>, name: String) -> Result<(), String> {
    // Stop any existing tunnel first
    stop_tunnel_internal(&state);

    let dir = tunnels_dir(&app).ok_or("no app data dir")?;
    let tunnel_path = dir.join(format!("{}.json", sanitize_name(&name)));
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

    // Hide console window on Windows
    apply_no_window(&mut cmd);

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

    let mut cmd = Command::new(&binary);
    cmd.arg("-check-update");
    apply_no_window(&mut cmd);
    let output = cmd.output()
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

            let mut content = String::new();
            use std::io::Read;
            entry.read_to_string(&mut content).map_err(|e| e.to_string())?;

            if let Ok(tunnel) = parse_conf_content(&content, &name) {
                tunnels.push(tunnel);
            }
        }
    }

    Ok(tunnels)
}

fn parse_conf_file(path: &PathBuf, name: &str) -> Result<Tunnel, String> {
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_conf_content(&content, name)
}

fn parse_conf_content(content: &str, name: &str) -> Result<Tunnel, String> {
    let mut vk_link = String::new();
    let mut peer = String::new();
    let mut wrap_key = String::new();
    let mut private_key = String::new();
    let mut server_key = String::new();
    let mut server_addr = String::new();
    let mut allowed_ips = String::new();
    let mut mtu: i32 = 1280;
    let mut keepalive: i32 = 25;
    let mut listen_port: i32 = 9000;
    let mut exclude_private = false;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            // Parse TURN-specific comments: #turn.vk_link = ...
            // Also support Android export format: #@wgt:vk_link=...
            if line.starts_with("#turn.") || line.starts_with("#@wgt:") {
                let comment_content = if line.starts_with("#turn.") {
                    &line[6..]
                } else {
                    &line[6..]
                };
                if let Some(eq_pos) = comment_content.find('=') {
                    let key = comment_content[..eq_pos].trim();
                    let value = comment_content[eq_pos + 1..].trim();
                    match key {
                        "vk_link" | "vk-link" => vk_link = value.to_string(),
                        "peer" => peer = value.to_string(),
                        "wrap_key" | "wrap-key" => wrap_key = value.to_string(),
                        "exclude_private" | "exclude-private" => {
                            exclude_private = value == "true" || value == "1";
                        }
                        _ => {}
                    }
                }
            }
            continue;
        }
        if line.starts_with('[') {
            continue;
        }
        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_lowercase();
            let value = line[eq_pos + 1..].trim();
            match key.as_str() {
                "privatekey" => private_key = value.to_string(),
                "publickey" | "serverkey" => server_key = value.to_string(),
                "endpoint" => {
                    // If value already has host:port, use as server_addr
                    // Otherwise default to 127.0.0.1:<port>
                    if value.contains(':') {
                        server_addr = value.to_string();
                    } else {
                        server_addr = format!("127.0.0.1:{}", value);
                    }
                }
                "allowedips" => allowed_ips = value.to_string(),
                "mtu" => mtu = value.parse().unwrap_or(1280),
                "persistentkeepalive" | "keepalive" => {
                    keepalive = value.parse().unwrap_or(25)
                }
                "listenport" => {
                    listen_port = value.parse().unwrap_or(9000);
                }
                _ => {}
            }
        }
    }

    // If server_addr is empty, default to 127.0.0.1:listen_port
    if server_addr.is_empty() {
        server_addr = format!("127.0.0.1:{}", listen_port);
    }

    Ok(Tunnel {
        name: name.to_string(),
        config: TunnelConfig {
            vk_link,
            peer,
            wrap_key,
            streams: 4,
            udp: false,
            mode: "vk_link".to_string(),
            vpn: true,
            private_key,
            server_key,
            server_addr,
            allowed_ips: if allowed_ips.is_empty() {
                "0.0.0.0/0, ::0".to_string()
            } else {
                allowed_ips
            },
            mtu,
            keepalive,
            exclude_private,
        },
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// GUI update checker
// ─────────────────────────────────────────────────────────────────────────────

#[derive(serde::Deserialize, Debug)]
struct GithubRelease {
    tag_name: String,
    #[serde(default)]
    body: String,
    #[serde(default)]
    html_url: String,
    #[serde(default)]
    assets: Vec<GithubAsset>,
}

#[derive(serde::Deserialize, Debug)]
struct GithubAsset {
    #[serde(default)]
    name: String,
    #[serde(default)]
    browser_download_url: String,
}

#[tauri::command]
fn check_for_gui_update() -> Result<String, String> {
    let url = "https://api.github.com/repos/NikKuz99/turnguard/releases/latest";
    let resp = reqwest::blocking::Client::new()
        .get(url)
        .header("User-Agent", "TurnGuard-GUI")
        .send()
        .map_err(|e| format!("request failed: {}", e))?;

    if !resp.status().is_success() {
        return Err(format!("github API status: {}", resp.status()));
    }

    let release: GithubRelease = resp.json()
        .map_err(|e| format!("json parse failed: {}", e))?;

    let latest = release.tag_name.trim_start_matches('v');
    let current = env!("CARGO_PKG_VERSION");

    if version_gt(latest, current) {
        // Find Windows .exe asset if on Windows
        let asset_pattern = if cfg!(windows) {
            ".exe"
        } else if cfg!(target_os = "linux") {
            if cfg!(target_arch = "x86_64") {
                "_amd64.deb"
            } else {
                "_arm64.deb"
            }
        } else if cfg!(target_os = "macos") {
            ".dmg"
        } else {
            ""
        };

        let download_url = release.assets.iter()
            .find(|a| a.name.contains(asset_pattern))
            .map(|a| a.browser_download_url.clone())
            .unwrap_or_else(|| release.html_url.clone());

        let result = serde_json::json!({
            "update_available": true,
            "latest_version": latest,
            "current_version": current,
            "download_url": download_url,
            "release_url": release.html_url,
            "release_notes": release.body,
        });
        Ok(result.to_string())
    } else {
        let result = serde_json::json!({
            "update_available": false,
            "current_version": current,
            "latest_version": latest,
        });
        Ok(result.to_string())
    }
}

/// Compare semantic versions: returns true if `a` > `b`
fn version_gt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .filter_map(|p| p.parse::<u64>().ok())
            .collect()
    };
    let av = parse(a);
    let bv = parse(b);
    for i in 0..std::cmp::max(av.len(), bv.len()) {
        let an = av.get(i).copied().unwrap_or(0);
        let bn = bv.get(i).copied().unwrap_or(0);
        if an != bn {
            return an > bn;
        }
    }
    false
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
            check_for_gui_update,
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
