#!/usr/bin/env python3
"""
Updated E2E tunnel test — checks real tunnel operation indicators.
Tests: process starts, DNS resolves, VK hosts probed, captcha attempted.
Does NOT expect DTLS handshake (captcha may block in headless env).
"""
import subprocess
import sys
import os
import time
import argparse
import signal
import json
import urllib.request
import urllib.error

# Force unbuffered output
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', buffering=1)


def run_cmd(cmd, timeout=30):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)


def check_internet(timeout=10):
    try:
        req = urllib.request.Request("https://api.github.com/zen", method="GET")
        req.add_header("User-Agent", "TurnGuard-E2E-Test")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return True, resp.read().decode()[:80]
            return False, f"HTTP {resp.status}"
    except Exception as e:
        return False, str(e)[:80]


def test_internet_before():
    r = {"name": "internet_before", "passed": False, "message": ""}
    ok, detail = check_internet()
    r["passed"] = ok
    r["message"] = f"Internet: {detail}" if ok else f"No internet: {detail}"
    return r


def test_binary_exists(binary_path):
    r = {"name": "binary_exists", "passed": False, "message": ""}
    r["passed"] = os.path.exists(binary_path)
    r["message"] = f"Binary: {binary_path}" if r["passed"] else f"Not found: {binary_path}"
    return r


def test_config_valid(config_path):
    """Config file exists and is valid JSON (or .conf with expected fields)."""
    r = {"name": "config_valid", "passed": False, "message": ""}
    if not os.path.exists(config_path):
        r["message"] = f"Not found: {config_path}"
        return r

    with open(config_path) as f:
        content = f.read()

    # Check if JSON or .conf
    if content.strip().startswith('{'):
        # JSON config — check for required JSON fields
        try:
            cfg = json.loads(content)
            has_vk_link = "vk_link" in cfg and cfg["vk_link"]
            has_wrap_key = "wrap_key" in cfg and cfg["wrap_key"]
            has_peer = "peer" in cfg and cfg["peer"]
            r["passed"] = has_vk_link and has_wrap_key and has_peer
            r["message"] = "JSON config valid" if r["passed"] else f"Missing fields: vk_link={has_vk_link}, wrap_key={has_wrap_key}, peer={has_peer}"
        except json.JSONDecodeError as e:
            r["message"] = f"JSON parse error: {e}"
    else:
        # .conf format — check for WireGuard fields
        has_private = "PrivateKey" in content
        has_endpoint = "Endpoint" in content
        has_wgt = "#@wgt:" in content or "#turn." in content
        r["passed"] = has_private and has_endpoint and has_wgt
        r["message"] = ".conf valid" if r["passed"] else f"Missing: PrivateKey={has_private}, Endpoint={has_endpoint}, TURN={has_wgt}"
    return r


def test_tunnel_starts(binary_path, config_path):
    """Tunnel process starts and stays alive for 15 seconds."""
    r = {"name": "tunnel_starts", "passed": False, "message": ""}

    # Kill any existing tunnel
    run_cmd("pkill -9 -f turnguard-cli 2>/dev/null; sleep 1")
    # Remove old log
    if os.path.exists("/tmp/tg_tunnel.log"):
        os.remove("/tmp/tg_tunnel.log")

    cmd = f"{binary_path} -config {config_path} -log-file /tmp/tg_tunnel.log"
    proc = subprocess.Popen(
        cmd, shell=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )
    time.sleep(15)

    if proc.poll() is not None:
        r["passed"] = False
        r["message"] = f"Process exited with code {proc.returncode}"
    else:
        r["passed"] = True
        r["message"] = f"Process running (PID {proc.pid})"
        test_tunnel_starts.proc = proc

    return r


def test_dns_resolution():
    """DNS resolution succeeded (check log for VK hosts)."""
    r = {"name": "dns_resolution", "passed": False, "message": ""}
    time.sleep(5)

    log_path = "/tmp/tg_tunnel.log"
    if not os.path.exists(log_path):
        r["message"] = "No log file"
        return r

    with open(log_path) as f:
        content = f.read()

    # Look for DNS resolution indicators
    dns_keywords = ["VKHosts", "Probe OK", "Updated dynamic IPs", "DNS"]
    found = [kw for kw in dns_keywords if kw in content]
    probe_count = content.count("Probe OK")

    r["passed"] = probe_count >= 3
    r["message"] = f"Found {probe_count} successful probes" if r["passed"] else f"Only {probe_count} probes (need >=3)"
    return r


def test_captcha_attempted():
    """Auto-solver was attempted (captcha solving triggered)."""
    r = {"name": "captcha_attempted", "passed": False, "message": ""}

    log_path = "/tmp/tg_tunnel.log"
    if not os.path.exists(log_path):
        r["message"] = "No log file"
        return r

    with open(log_path) as f:
        content = f.read()

    # Look for captcha solving indicators
    captcha_keywords = ["Captcha", "captchaNotRobot", "slider", "PoW", "Bootstrap"]
    found = [kw for kw in captcha_keywords if kw in content]
    captcha_lines = content.count("[Captcha]")

    r["passed"] = captcha_lines >= 3
    r["message"] = f"Found {captcha_lines} captcha log lines" if r["passed"] else f"Only {captcha_lines} captcha lines"
    return r


def test_process_alive():
    """Tunnel process is still alive after 30 seconds (didn't crash)."""
    r = {"name": "process_alive", "passed": False, "message": ""}
    if not hasattr(test_tunnel_starts, 'proc'):
        r["message"] = "No process to check"
        return r

    proc = test_tunnel_starts.proc
    time.sleep(10)  # Wait additional 10s (total 30s from start)

    if proc.poll() is None:
        r["passed"] = True
        r["message"] = "Process alive after 30s"
    else:
        r["passed"] = False
        r["message"] = f"Process died (exit code {proc.returncode})"
    return r


def cleanup():
    if hasattr(test_tunnel_starts, 'proc'):
        try:
            os.killpg(os.getpgid(test_tunnel_starts.proc.pid), signal.SIGTERM)
            time.sleep(2)
            os.killpg(os.getpgid(test_tunnel_starts.proc.pid), signal.SIGKILL)
        except:
            pass
    run_cmd("pkill -9 -f turnguard-cli 2>/dev/null", timeout=5)


def main():
    parser = argparse.ArgumentParser(description="TurnGuard E2E Tunnel Test")
    parser.add_argument("--config", required=True, help="Path to config file (.json or .conf)")
    parser.add_argument("--binary", default="/root/tg-binaries/turnguard-cli-linux",
                        help="Path to turnguard binary")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    results = []
    try:
        results.append(test_internet_before())
        results.append(test_binary_exists(args.binary))
        results.append(test_config_valid(args.config))

        if not all(r["passed"] for r in results):
            cleanup()
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                for r in results:
                    status = "✓" if r["passed"] else "✗"
                    print(f"  {status} {r['name']:30s} {r['message']}")
            sys.exit(1)

        # Start tunnel
        results.append(test_tunnel_starts(args.binary, args.config))
        if not results[-1]["passed"]:
            cleanup()
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                for r in results:
                    status = "✓" if r["passed"] else "✗"
                    print(f"  {status} {r['name']:30s} {r['message']}")
            sys.exit(1)

        # Check tunnel operation
        results.append(test_dns_resolution())
        results.append(test_captcha_attempted())
        results.append(test_process_alive())

    finally:
        cleanup()

    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"TurnGuard E2E Tunnel Test Results")
        print(f"{'='*60}")
        for r in results:
            status = "✓" if r["passed"] else "✗"
            print(f"  {status} {r['name']:30s} {r['message']}")
        passed = sum(1 for r in results if r["passed"])
        print(f"{'='*60}")
        print(f"Total: {len(results)} | Passed: {passed} | Failed: {len(results) - passed}")
        print(f"{'='*60}")
        sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
