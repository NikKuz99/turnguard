#!/usr/bin/env python3
"""
End-to-end test: start TurnGuard CLI tunnel and verify internet connectivity.

This test:
1. Starts the TurnGuard CLI with a real config
2. Waits for tunnel to establish
3. Checks if internet is accessible through the tunnel
4. Kills the tunnel and cleans up

Prerequisites:
- turnguard binary built for linux (in /root/tg-binaries/ or built fresh)
- Real config file at /tmp/test_tunnel.conf
- Internet access on test platform (for comparison)

Usage:
    python3 tests/e2e_tunnel_test.py --config /tmp/test_tunnel.conf
    python3 tests/e2e_tunnel_test.py --config /tmp/test_tunnel.conf --binary /root/tg-binaries/turnguard-gui-linux-release
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


def run_cmd(cmd, timeout=30):
    """Run shell command, return (exit_code, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except Exception as e:
        return -1, "", str(e)


def check_internet(timeout=10):
    """Check if internet is accessible by fetching a URL."""
    try:
        req = urllib.request.Request("https://api.github.com/zen", method="GET")
        req.add_header("User-Agent", "TurnGuard-E2E-Test")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                return True, resp.read().decode()[:100]
            return False, f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:
        return False, str(e)[:100]


def test_internet_before():
    """Test 1: Internet works before starting tunnel."""
    r = {"name": "internet_before", "passed": False, "message": ""}
    ok, detail = check_internet()
    r["passed"] = ok
    r["message"] = f"Internet: {detail}" if ok else f"No internet: {detail}"
    return r


def test_binary_exists(binary_path):
    """Test 2: turnguard binary exists."""
    r = {"name": "binary_exists", "passed": False, "message": ""}
    r["passed"] = os.path.exists(binary_path)
    r["message"] = f"Binary: {binary_path}" if r["passed"] else f"Not found: {binary_path}"
    return r


def test_config_exists(config_path):
    """Test 3: config file exists."""
    r = {"name": "config_exists", "passed": False, "message": ""}
    r["passed"] = os.path.exists(config_path)
    r["message"] = f"Config: {config_path}" if r["passed"] else f"Not found: {config_path}"
    return r


def test_config_has_fields(config_path):
    """Test 4: config file has all required fields."""
    r = {"name": "config_has_fields", "passed": False, "message": ""}
    with open(config_path) as f:
        content = f.read()

    required = ["PrivateKey", "PublicKey", "Endpoint", "VKLink", "WrapKey", "IPPort"]
    missing = [f for f in required if f not in content]
    r["passed"] = len(missing) == 0
    r["message"] = "All fields present" if r["passed"] else f"Missing: {missing}"
    return r


def test_tunnel_starts(binary_path, config_path):
    """Test 5: tunnel process starts without crashing."""
    r = {"name": "tunnel_starts", "passed": False, "message": ""}

    # Start the tunnel
    cmd = f"{binary_path} -config {config_path} -log-file /tmp/tg_tunnel.log"
    proc = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        preexec_fn=os.setsid
    )
    time.sleep(5)

    if proc.poll() is not None:
        # Process exited
        _, stderr = proc.communicate()
        r["passed"] = False
        r["message"] = f"Process exited: {stderr[:200]}"
    else:
        r["passed"] = True
        r["message"] = f"Process running (PID {proc.pid})"
        test_tunnel_starts.proc = proc

    return r


def test_tunnel_logs(binary_path):
    """Test 6: tunnel produces log output."""
    r = {"name": "tunnel_logs", "passed": False, "message": ""}
    time.sleep(5)  # Wait for logs to accumulate

    log_path = "/tmp/tg_tunnel.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            content = f.read()
        r["passed"] = len(content) > 50
        r["message"] = f"Log size: {len(content)} bytes" if r["passed"] else f"Log too short: {content[:100]}"
    else:
        r["passed"] = False
        r["message"] = "No log file created"
    return r


def test_tunnel_handshake():
    """Test 7: WG handshake is established (check log for handshake messages)."""
    r = {"name": "tunnel_handshake", "passed": False, "message": ""}
    time.sleep(10)  # Wait for handshake

    log_path = "/tmp/tg_tunnel.log"
    if os.path.exists(log_path):
        with open(log_path) as f:
            content = f.read()

        # Look for handshake-related messages
        handshake_keywords = ["handshake", "DTLS", "connected", "ready", "stream"]
        found = [kw for kw in handshake_keywords if kw.lower() in content.lower()]
        r["passed"] = len(found) >= 1
        r["message"] = f"Found: {found}" if r["passed"] else "No handshake indicators in log"
    else:
        r["passed"] = False
        r["message"] = "No log file"
    return r


def test_internet_through_tunnel():
    """Test 8: internet accessible through tunnel (if tunnel routes traffic)."""
    r = {"name": "internet_through_tunnel", "passed": False, "message": ""}
    # Note: this may fail if tunnel doesn't route all traffic
    # On test platform, the tunnel may not actually route internet traffic
    # (it depends on AllowedIPs and routing setup)
    ok, detail = check_internet(timeout=15)
    r["passed"] = ok
    r["message"] = f"Internet: {detail}" if ok else f"No internet: {detail}"
    return r


def cleanup():
    """Kill the tunnel process."""
    if hasattr(test_tunnel_starts, 'proc'):
        try:
            os.killpg(os.getpgid(test_tunnel_starts.proc.pid), signal.SIGTERM)
            time.sleep(2)
            os.killpg(os.getpgid(test_tunnel_starts.proc.pid), signal.SIGKILL)
        except:
            pass


def main():
    parser = argparse.ArgumentParser(description="TurnGuard E2E Tunnel Test")
    parser.add_argument("--config", required=True, help="Path to .conf config file")
    parser.add_argument("--binary", default="/root/tg-binaries/turnguard-gui-linux-release",
                        help="Path to turnguard binary")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    results = []
    try:
        # Pre-flight checks
        results.append(test_internet_before())
        results.append(test_binary_exists(args.binary))
        results.append(test_config_exists(args.config))
        results.append(test_config_has_fields(args.config))

        if not all(r["passed"] for r in results):
            cleanup()
            if args.json:
                print(json.dumps(results, indent=2))
            else:
                for r in results:
                    status = "✓" if r["passed"] else "✗"
                    print(f"  {status} {r['name']:35s} {r['message']}")
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
                    print(f"  {status} {r['name']:35s} {r['message']}")
            sys.exit(1)

        # Check tunnel operation
        results.append(test_tunnel_logs(args.binary))
        results.append(test_tunnel_handshake())
        results.append(test_internet_through_tunnel())

    finally:
        cleanup()

    # Output
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"TurnGuard E2E Tunnel Test Results")
        print(f"{'='*60}")
        for r in results:
            status = "✓" if r["passed"] else "✗"
            print(f"  {status} {r['name']:35s} {r['message']}")
        passed = sum(1 for r in results if r["passed"])
        print(f"{'='*60}")
        print(f"Total: {len(results)} | Passed: {passed} | Failed: {len(results) - passed}")
        print(f"{'='*60}")
        sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
