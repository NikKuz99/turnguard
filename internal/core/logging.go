/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * logging.go — File logging with rotation.
 * Logs to both stdout and a file (turnguard.log).
 * File rotates when > 10 MB.
 */
package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/NikKuz99/turnguard/internal/util"
)

const (
	maxLogSize   = 10 * 1024 * 1024 // 10 MB
	maxLogFiles  = 3
	logFileName  = "turnguard.log"
)

var (
	logMu      sync.Mutex
	logFile    *os.File
	logFileDir string
)

// InitFileLogging enables logging to a file in addition to stdout.
// The log file is created in the specified directory.
func InitFileLogging(dir string) error {
	logMu.Lock()
	defer logMu.Unlock()

	logFileDir = dir
	if dir == "" {
		logFileDir = "."
	}

	if err := os.MkdirAll(logFileDir, 0755); err != nil {
		return fmt.Errorf("failed to create log dir: %w", err)
	}

	path := filepath.Join(logFileDir, logFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	logFile = f
	util.TurnLog("[Logging] File logging enabled: %s", path)
	return nil
}

// WriteLog writes a log line to the file (called by util.TurnLog via hook).
func WriteLog(line string) {
	logMu.Lock()
	defer logMu.Unlock()

	if logFile == nil {
		return
	}

	// Check if rotation needed
	if info, err := logFile.Stat(); err == nil && info.Size() > maxLogSize {
		rotateLogFile()
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	fmt.Fprintf(logFile, "%s %s\n", timestamp, line)
}

// CloseFileLogging closes the log file.
func CloseFileLogging() {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		logFile.Close()
		logFile = nil
	}
}

// rotateLogFile rotates the current log file.
func rotateLogFile() {
	if logFile == nil {
		return
	}

	logFile.Close()
	path := filepath.Join(logFileDir, logFileName)

	// Rotate: .log.2 → .log.3 (delete), .log.1 → .log.2, .log → .log.1
	for i := maxLogFiles - 1; i > 0; i-- {
		oldPath := fmt.Sprintf("%s.%d", path, i)
		newPath := fmt.Sprintf("%s.%d", path, i+1)
		os.Rename(oldPath, newPath)
	}

	os.Rename(path, fmt.Sprintf("%s.1", path))

	// Open new file
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		logFile = f
	}
}

// LogDir returns the default log directory.
func LogDir() string {
	home, err := os.UserHomeDir()
	if err == nil {
		return filepath.Join(home, ".local", "share", "turnguard", "logs")
	}
	return "."
}
