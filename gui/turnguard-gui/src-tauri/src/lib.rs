// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 NikKuz99. All Rights Reserved.
//
// TurnGuard GUI — Tauri backend.
// Spawns turnguard Go binary as child process with config file.

use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::process::{Child, Command, Stdio};
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use tauri::{Emitter, Manager, State};

// ─────────────────────────────────────────────────────────────────────────────
// State (uses Arc internally so threads can take clones)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct ProxyState {
    child: Arc<Mutex<Option<Child>>>,
    running: Arc<AtomicBool>,
}

impl Default for ProxyState {
    fn default() -> Self {
        Self {
            child: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Config struct (mirrors Go config.go)
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

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

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

fn config_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    app.path().app_data_dir().ok().map(|d| {
        let _ = fs::create_dir_all(&d);
        d.join("config.json")
    })
}

fn dns_cache_path(app: &tauri::AppHandle) -> Option<PathBuf> {
    app.path().app_data_dir().ok().map(|d| d.join("dns_cache.json"))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tauri commands
// ─────────────────────────────────────────────────────────────────────────────

#[tauri::command]
fn load_config(app: tauri::AppHandle) -> Result<AppConfig, String> {
    let path = config_path(&app).ok_or("no app data dir")?;
    if !path.exists() {
        return Ok(AppConfig::default());
    }
    let data = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let cfg: AppConfig = serde_json::from_str(&data).map_err(|e| e.to_string())?;
    Ok(cfg)
}

#[tauri::command]
fn save_config(app: tauri::AppHandle, config: AppConfig) -> Result<(), String> {
    let path = config_path(&app).ok_or("no app data dir")?;
    let data = serde_json::to_string_pretty(&config).map_err(|e| e.to_string())?;
    fs::write(&path, data).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn start_proxy(app: tauri::AppHandle, state: State<'_, ProxyState>) -> Result<(), String> {
    if state.running.load(Ordering::SeqCst) {
        return Err("proxy already running".to_string());
    }

    let binary = find_turnguard_binary(&app).ok_or_else(|| {
        "turnguard binary not found. Place it in app data dir /bin/ or PATH".to_string()
    })?;

    let cfg_path = config_path(&app).ok_or("no app data dir")?;
    if !cfg_path.exists() {
        return Err("config not saved. Save it first.".to_string());
    }
    let dns_cache = dns_cache_path(&app).ok_or("no app data dir")?;

    // Build command
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
    let _ = app.emit("proxy-status", "starting");

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

    // Store child handle in state
    *state.child.lock().unwrap() = Some(child);

    // Spawn thread to monitor child exit
    let child_arc = state.child.clone();
    let running_arc = state.running.clone();
    let app_clone = app.clone();
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let mut child_lock = child_arc.lock().unwrap();
            if let Some(child) = child_lock.as_mut() {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        // Process exited
                        *child_lock = None;
                        drop(child_lock);
                        running_arc.store(false, Ordering::SeqCst);
                        let _ = app_clone.emit("proxy-status", "stopped");
                        return;
                    }
                    Ok(None) => {
                        // Still running
                    }
                    Err(_) => {
                        // Error — treat as exited
                        *child_lock = None;
                        drop(child_lock);
                        running_arc.store(false, Ordering::SeqCst);
                        let _ = app_clone.emit("proxy-status", "stopped");
                        return;
                    }
                }
            } else {
                // child was taken by stop_proxy
                return;
            }
        }
    });

    let _ = app.emit("proxy-status", "running");
    Ok(())
}

#[tauri::command]
fn stop_proxy(state: State<'_, ProxyState>) -> Result<(), String> {
    if !state.running.load(Ordering::SeqCst) {
        return Ok(());
    }

    // Kill child
    if let Some(mut child) = state.child.lock().unwrap().take() {
        let _ = child.kill();
        let _ = child.wait();
    }

    state.running.store(false, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
fn get_status(state: State<'_, ProxyState>) -> bool {
    state.running.load(Ordering::SeqCst)
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
            load_config,
            save_config,
            start_proxy,
            stop_proxy,
            get_status,
            check_update,
            get_version,
        ])
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { .. } = event {
                // Kill child on window close
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
