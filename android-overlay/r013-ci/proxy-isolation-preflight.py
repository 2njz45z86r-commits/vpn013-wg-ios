#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Preflight independent Android UID over its actual default (non-VPN) network."""
import json
import os
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path

if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
    raise SystemExit("hosted CI only")
if len(sys.argv) != 2:
    raise SystemExit("fixture path required")
f = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
nonce = f.get("nonce", "")
port = f.get("port")
if f.get("host") != "198.18.0.1" or not isinstance(port, int) or not 1024 <= port <= 65535 or not re.fullmatch(r"[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}", nonce):
    raise SystemExit("invalid synthetic fixture")
route = subprocess.run(["ip", "-4", "-j", "route", "show", "exact", "198.18.0.1/32"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5, check=False)
if route.returncode or len(route.stdout) > 16384:
    raise RuntimeError("fixture host route unavailable")
routes = json.loads(route.stdout)
if len(routes) != 1 or routes[0].get("type") != "blackhole" or routes[0].get("dst") not in ("198.18.0.1", "198.18.0.1/32"):
    raise RuntimeError("fixture host route is not blackholed")

def adb(*args, timeout=15):
    completed = subprocess.run(["adb", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
    if len(completed.stdout) > 16384 or len(completed.stderr) > 16384:
        raise RuntimeError("bounded adb output exceeded")
    return completed

def uid(package):
    result = adb("shell", "cmd", "package", "list", "packages", "-U", package)
    if result.returncode:
        raise RuntimeError("package lookup failed")
    pattern = r"^package:" + re.escape(package) + r"\s+uid:(\d+)\s*$"
    matches = re.findall(pattern, result.stdout.decode("utf-8", "replace"), re.MULTILINE)
    if len(matches) != 1:
        raise RuntimeError("package identity unavailable")
    return int(matches[0])

other = uid("com.vpn013.routingprobe")
app = uid("com.vpn013.awg.debug")
instrumentation = uid("com.vpn013.awg.debug.test")
if other in (app, instrumentation):
    raise RuntimeError("probe does not have independent UID")
request = str(uuid.uuid4())
broadcast = adb("shell", "am", "broadcast", "-f", "0x20", "-n", "com.vpn013.routingprobe/.RoutingProbeReceiver",
                "--es", "request", request, "--es", "nonce", nonce, "--ei", "port", str(port))
if broadcast.returncode or b"Broadcast completed" not in broadcast.stdout or b"Permission Denial" in broadcast.stdout + broadcast.stderr:
    raise RuntimeError("probe broadcast failed")
deadline = time.monotonic() + 10
proof = None
while time.monotonic() < deadline:
    result = adb("shell", "run-as", "com.vpn013.routingprobe", "cat", "files/probe.json", timeout=5)
    if result.returncode == 0:
        try:
            candidate = json.loads(result.stdout)
            if candidate.get("requestID") == request:
                proof = candidate
                break
        except (ValueError, TypeError):
            pass
    time.sleep(0.1)
if proof is None:
    raise RuntimeError("fresh independent probe result unavailable")
if proof.get("uid") != other or proof.get("vpn") is not False or proof.get("matched") is not False:
    raise RuntimeError("physical-network isolation preflight failed")
Path("output/review/proxy-isolation-preflight.json").write_text(json.dumps({
    "separateUID": True, "freshRequest": True, "physicalVPN": False,
    "physicalNonceMatched": False, "fixtureHostRouteBlackholed": True,
}), encoding="utf-8")
print("Independent UID physical-network isolation preflight PASS")
