/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * updater.go — Auto-update via GitHub Releases.
 * Checks for new releases, downloads binary, replaces self.
 *
 * Uses ETag-based conditional requests to avoid GitHub API rate limits.
 * (304 Not Modified responses don't count against the 60 req/hour limit.)
 */
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
var CurrentVersion = "v0.6.3"

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

// etagCachePath returns the path to the ETag cache file.
// Stored in the same directory as the executable (or temp dir if that fails).
func etagCachePath() string {
	exePath, err := os.Executable()
	if err != nil {
		return filepath.Join(os.TempDir(), "turnguard_etag.txt")
	}
	return exePath + ".etag"
}

// loadCachedETag reads the cached ETag from disk.
func loadCachedETag() string {
	data, err := os.ReadFile(etagCachePath())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// saveCachedETag writes the ETag to disk for future conditional requests.
func saveCachedETag(etag string) {
	if etag == "" {
		return
	}
	_ = os.WriteFile(etagCachePath(), []byte(etag), 0644)
}

// CheckForUpdate checks GitHub Releases for a newer version.
// Uses ETag-based conditional requests to minimize API rate limit consumption.
// Returns the download URL if an update is available, empty string otherwise.
func CheckForUpdate() (string, string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/releases/latest", githubOwner, githubRepo)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "TurnGuard-Updater")

	// Use cached ETag for conditional request — GitHub returns 304 (doesn't
	// count against rate limit) if the release hasn't changed since last check.
	cachedETag := loadCachedETag()
	if cachedETag != "" {
		req.Header.Set("If-None-Match", cachedETag)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("failed to check updates: %w", err)
	}
	defer resp.Body.Close()

	// 304 = Not Modified (release unchanged since last check)
	// This doesn't count against the rate limit — safe to retry frequently.
	if resp.StatusCode == 304 {
		util.TurnLog("[Updater] GitHub API: 304 Not Modified (cached, rate-limit-free)")
		// No new version — the cached release is the same as before
		return "", "", nil
	}

	if resp.StatusCode == 403 {
		// Rate limited — check X-RateLimit-Reset header for when to retry
		reset := resp.Header.Get("X-RateLimit-Reset")
		remaining := resp.Header.Get("X-RateLimit-Remaining")
		util.TurnLog("[Updater] GitHub API rate limited (remaining=%s, reset=%s)", remaining, reset)
		return "", "", fmt.Errorf("GitHub API rate limited (403) — will retry later")
	}

	if resp.StatusCode != 200 {
		return "", "", fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	// Cache the new ETag for future requests
	newETag := resp.Header.Get("ETag")
	if newETag != "" {
		saveCachedETag(newETag)
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
func DownloadAndUpdate(downloadURL string) error {
	util.TurnLog("[Updater] Downloading update...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, "GET", downloadURL, nil)
	req.Header.Set("User-Agent", "TurnGuard-Updater")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("download returned %d", resp.StatusCode)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}

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

	if err := os.Chmod(tmpPath, 0755); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("chmod failed: %w", err)
	}

	backupPath := exePath + ".old"
	os.Remove(backupPath)
	if err := os.Rename(exePath, backupPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("backup failed: %w", err)
	}

	if err := os.Rename(tmpPath, exePath); err != nil {
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
//   - On failure (no internet, rate limited, etc.): silent retry every 60 seconds
//     (no user notification, just Log)
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
				select {
				case <-ctx.Done():
					return
				case <-time.After(60 * time.Second):
				}
				continue
			}

			util.TurnLog("[Updater] Update installed, stopping periodic check (restart to apply)")
			return
		}
	}()
}
