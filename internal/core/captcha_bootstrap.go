/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 NikKuz99. All Rights Reserved.
 *
 * captcha_bootstrap.go — Improved powInput parser with multiple fallback patterns.
 *
 * VK periodically changes the captcha page structure. This file collects
 * multiple regex patterns for powInput / difficulty extraction so that
 * a change in one pattern does not break the entire auto-solver.
 *
 * If all patterns fail, the bootstrap returns an error and the caller
 * falls back to the API-only flow (with empty PoW hash) or to manual
 * solving via the local proxy browser.
 */
package core

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// powInputPatterns lists every known way powInput can appear in the
// captcha page HTML or embedded JS.  Order matters: more-specific patterns
// should come first so that false positives are less likely.
//
// Each pattern must have at least one capture group — the captured value
// is treated as the powInput string.
var powInputPatterns = []*regexp.Regexp{
	// Classic: const powInput = "..."
	regexp.MustCompile(`const\s+powInput\s*=\s*"([^"]+)"`),
	// Modern: let powInput = "..."  /  var powInput = "..."
	regexp.MustCompile(`(?:let|var)\s+powInput\s*=\s*"([^"]+)"`),
	// Global assignment: window.powInput = "..."  /  self.powInput = "..."
	regexp.MustCompile(`(?:window|self|globalThis)\.powInput\s*=\s*"([^"]+)"`),
	// JSON-like: "powInput": "..."
	regexp.MustCompile(`"powInput"\s*:\s*"([^"]+)"`),
	// Snake-case JSON: "pow_input": "..."
	regexp.MustCompile(`"pow_input"\s*:\s*"([^"]+)"`),
	// Backtick string: const powInput = `...`
	regexp.MustCompile(`const\s+powInput\s*=\s*\x60([^\x60]+)\x60`),
	// Single-quoted: const powInput = '...'
	regexp.MustCompile(`const\s+powInput\s*=\s*'([^']+)'`),
	// Function return: function getPowInput() { return "..."; }
	regexp.MustCompile(`getPowInput\s*\(\s*\)\s*\{[^}]*return\s+"([^"]+)"`),
	// Object property: powInput: "..." (inside JS object literal)
	regexp.MustCompile(`\bpowInput\s*:\s*"([^"]+)"`),
}

// difficultyPatterns lists known ways the PoW difficulty is encoded.
var difficultyPatterns = []*regexp.Regexp{
	// startsWith('0'.repeat(N))
	regexp.MustCompile(`startsWith\('0'\.repeat\((\d+)\)\)`),
	// const difficulty = N
	regexp.MustCompile(`const\s+difficulty\s*=\s*(\d+)`),
	// let difficulty = N  /  var difficulty = N
	regexp.MustCompile(`(?:let|var)\s+difficulty\s*=\s*(\d+)`),
	// "difficulty": N (JSON)
	regexp.MustCompile(`"difficulty"\s*:\s*(\d+)`),
}

// extractPowInput tries every known pattern and returns the first match.
func extractPowInput(html string) (string, bool) {
	for _, re := range powInputPatterns {
		if m := re.FindStringSubmatch(html); len(m) >= 2 && m[1] != "" {
			return m[1], true
		}
	}
	return "", false
}

// extractDifficulty tries every known pattern, defaults to 2.
func extractDifficulty(html string) int {
	for _, re := range difficultyPatterns {
		if m := re.FindStringSubmatch(html); len(m) >= 2 {
			if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
				return n
			}
		}
	}
	return 2
}

// parseCaptchaBootstrapHTMLExt is the extended version of
// parseCaptchaBootstrapHTML. It tries multiple patterns and also
// handles the case where powInput is split across multiple lines or
// embedded in a JSON blob.
func parseCaptchaBootstrapHTMLExt(html string) (*captchaBootstrap, error) {
	powInput, ok := extractPowInput(html)
	if !ok {
		// One last attempt: maybe powInput is in a JSON string that
		// got HTML-escaped. Try unescaping and re-searching.
		unescaped := strings.NewReplacer(
			`&quot;`, `"`,
			`&#34;`, `"`,
			`&amp;`, `&`,
			`&#x27;`, `'`,
			`&#39;`, `'`,
		).Replace(html)
		powInput, ok = extractPowInput(unescaped)
	}
	if !ok {
		return nil, fmt.Errorf("powInput not found in captcha HTML (tried %d patterns)", len(powInputPatterns))
	}

	difficulty := extractDifficulty(html)

	settings, err := parseCaptchaSettingsFromHTML(html)
	if err != nil {
		// Settings parsing is best-effort; if it fails, use empty settings
		// and let the caller decide whether to proceed.
		settings = &captchaSettingsResponse{SettingsByType: make(map[string]string)}
	}

	return &captchaBootstrap{
		PowInput:   powInput,
		Difficulty: difficulty,
		Settings:   settings,
	}, nil
}
