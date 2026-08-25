/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * updater.go — Auto-update via GitHub Releases.
 * Checks for new releases, downloads binary, replaces self.
 */
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/NikKuz99/turnguard/internal/util"
)

const (
	githubOwner = "NikKuz99"
	githubRepo  = "turnguard"
)

type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

// CurrentVersion returns the current version string.
var CurrentVersion = "v0.5.0"

// assetNameForPlatform returns the expected binary name for the current platform.
func assetNameForPlatform() string {
	switch runtime.GOOS {
	case "windows":
		return fmt.Sprintf("turnguard-windows-amd64.exe")
	case "darwin":
		if runtime.GOARCH == "arm64" {
			return "turnguard-darwin-arm64"
		}
		return "turnguard-darwin-amd64"
	default:
		if runtime.GOARCH == "arm64" {
			return "turnguard-linux-arm64"
		}
		return "turnguard"
	}
}

// CheckForUpdate checks GitHub Releases for a newer version.
// Returns the download URL if an update is available, empty string otherwise.
func CheckForUpdate() (string, string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", githubOwner, githubRepo)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to check updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", "", fmt.Errorf("failed to parse release: %w", err)
	}

	if release.TagName == "" || release.TagName == CurrentVersion {
		return "", "", nil
	}

	// Find the right asset for this platform
	assetName := assetNameForPlatform()
	for _, asset := range release.Assets {
		if asset.Name == assetName {
			util.TurnLog("[Updater] Update available: %s (current: %s)", release.TagName, CurrentVersion)
			util.TurnLog("[Updater] Download: %s (%.1f MB)", asset.Name, float64(asset.Size)/1024/1024)
			return asset.URL, release.TagName, nil
		}
	}

	return "", "", fmt.Errorf("no asset found for %s", assetName)
}

// DownloadAndUpdate downloads the new binary and replaces the current process.
// Note: The actual replacement requires a restart. This function:
// 1. Downloads the new binary to a temp file
// 2. Renames the current binary to .old
// 3. Renames the new binary to the current binary name
// 4. The user needs to restart the application
func DownloadAndUpdate(downloadURL string) error {
	util.TurnLog("[Updater] Downloading update...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	// Get current executable path
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

	// Download to temp file
	tmpPath := exePath + ".new"
	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	written, err := io.Copy(tmpFile, resp.Body)
	tmpFile.Close()
	if err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("download write failed: %w", err)
	}

	util.TurnLog("[Updater] Downloaded %d bytes", written)

	// Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod failed: %w", err)
	}

	// Backup current binary
	backupPath := exePath + ".old"
	os.Remove(backupPath)
	if err := os.Rename(exePath, backupPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("backup failed: %w", err)
	}

	// Move new binary to current path
	if err := os.Rename(tmpPath, exePath); err != nil {
		// Restore backup
		os.Rename(backupPath, exePath)
		return fmt.Errorf("replace failed: %w", err)
	}

	util.TurnLog("[Updater] Update installed! Restart TurnGuard to apply.")
	util.TurnLog("[Updater] Old version backed up at: %s", backupPath)

	return nil
}

// StartUpdateChecker runs a background goroutine that checks for updates.
//
// T15: Behavior (synced with Android Updater.kt):
//   - First check immediately on start
//   - On failure (no internet, etc.): silent retry every 60 seconds
//     (Log.d equivalent — util.TurnLog, no user notification)
//   - On success (response received, even if no new version): exit the loop —
//     do not poll GitHub again until next app launch
//   - If new version available: download + install, then exit the loop
func StartUpdateChecker(ctx context.Context) {
	go func() {
		util.TurnLog("[Updater] Update monitoring started: will check immediately, retry 60s on failure, stop on success")

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			url, version, err := CheckForUpdate()
			if err != nil {
				// T15: silent retry — do not notify user (likely no internet)
				util.TurnLog("[Updater] Update check failed, retry in 60s: %v", err)
				select {
				case <-ctx.Done():
					return
				case <-time.After(60 * time.Second):
				}
				continue
			}

			// Success — response received
			if url == "" {
				util.TurnLog("[Updater] Update check succeeded — no new version available (current: %s), stopping periodic check", CurrentVersion)
				return
			}

			util.TurnLog("[Updater] New version available: %s", version)
			if err := DownloadAndUpdate(url); err != nil {
				util.TurnLog("[Updater] Update download failed: %v", err)
				// Retry the whole cycle in 60s — maybe transient error
				select {
				case <-ctx.Done():
					return
				case <-time.After(60 * time.Second):
				}
				continue
			}

			// Update installed — exit loop (will apply on next restart)
			util.TurnLog("[Updater] Update installed, stopping periodic check (restart to apply)")
			return
		}
	}()
}
