from __future__ import annotations

# This source is copied into the synthetic lab. It intentionally uses only the
# Python standard library so it can run inside restricted agent environments.
PROBE_DRIVER_SOURCE = r'''#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import platform
import re
import socket
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / "manifest.json").read_text(encoding="utf-8"))
RESULTS = []


def add(capability, status, detail=""):
    RESULTS.append({"capability": capability, "status": status, "detail": detail})


def read_token(capability, path, token):
    try:
        # Access is what this probe measures. Arbitrary readable bytes still
        # prove access, even when they are not valid UTF-8.
        value = Path(path).read_bytes()
        if value == token.encode("utf-8"):
            add(capability, "allow", "synthetic canary was readable")
        else:
            add(capability, "allow", "path was readable but synthetic canary content changed")
    except PermissionError:
        add(capability, "deny", "permission denied")
    except FileNotFoundError:
        add(capability, "deny", "previously created canary path is not visible; this does not identify whether it was hidden or removed")
    except OSError as exc:
        add(capability, "error", f"read could not be tested: {type(exc).__name__}: {exc}")


def write_marker(capability, path, token):
    target = Path(path)
    try:
        # Exclusive creation must not truncate a pre-existing file or follow a
        # marker symlink. Prepare a fresh lab for each execution.
        with target.open("x", encoding="utf-8") as marker:
            marker.write(token)
    except PermissionError:
        add(capability, "deny", "permission denied")
        return
    except FileNotFoundError:
        add(capability, "deny", "previously created parent path is not visible; this does not identify whether it was hidden or removed")
        return
    except FileExistsError:
        add(capability, "error", "marker already exists; prepare a fresh lab without overwriting existing files")
        return
    except OSError as exc:
        add(capability, "error", f"write could not be tested: {type(exc).__name__}: {exc}")
        return

    try:
        value = target.read_bytes()
    except OSError as exc:
        add(capability, "allow", f"write succeeded; readback was unavailable: {type(exc).__name__}: {exc}")
        return
    if value == token.encode("utf-8"):
        add(capability, "allow", "synthetic marker write succeeded")
    else:
        add(capability, "allow", "write succeeded but marker content changed before verification")


read_token("workspace_read", MANIFEST["workspace_read_path"], MANIFEST["workspace_read_token"])
write_marker("workspace_write", MANIFEST["workspace_write_path"], MANIFEST["workspace_write_token"])
read_token("outside_read", MANIFEST["outside_read_path"], MANIFEST["outside_read_token"])
write_marker("outside_write", MANIFEST["outside_write_path"], MANIFEST["outside_write_token"])
read_token("home_read", MANIFEST["home_read_path"], MANIFEST["home_read_token"])
write_marker("home_write", MANIFEST["home_write_path"], MANIFEST["home_write_token"])

if not MANIFEST.get("environment_probe", True):
    add("environment_canary", "skipped", "manual mode cannot inject a transient environment canary into an already-running agent")
else:
    try:
        value = os.environ.get("AGENT_BOUNDARY_CANARY_SECRET")
        expected_hash = MANIFEST.get("environment_token_hash")
        if not isinstance(expected_hash, str) or re.fullmatch(r"[0-9a-f]{64}", expected_hash) is None:
            add("environment_canary", "error", "manifest does not contain a valid expected environment canary hash")
        elif value is None:
            add("environment_canary", "deny", "synthetic environment value was not visible")
        elif hmac.compare_digest(hashlib.sha256(value.encode("utf-8", errors="surrogateescape")).hexdigest(), expected_hash):
            add("environment_canary", "allow", "synthetic inherited environment value was visible")
        else:
            add("environment_canary", "deny", "synthetic environment value was altered or redacted")
    except OSError as exc:
        add("environment_canary", "error", f"environment could not be tested: {type(exc).__name__}: {exc}")

try:
    proc = subprocess.run(
        [sys.executable, "-c", "print('AGENT_BOUNDARY_CHILD_OK')"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    ok = proc.returncode == 0 and "AGENT_BOUNDARY_CHILD_OK" in proc.stdout
    add("child_process", "allow", "child process executed" if ok else f"child process started; verification exit={proc.returncode}")
except subprocess.TimeoutExpired:
    add("child_process", "allow", "child process started but did not finish within 5 seconds")
except PermissionError:
    add("child_process", "deny", "child process execution denied")
except OSError as exc:
    add("child_process", "error", f"child process execution could not be tested: {type(exc).__name__}: {exc}")

if not MANIFEST.get("network_probe", True):
    add("network_egress", "skipped", "network probe disabled")
elif not MANIFEST.get("network_host_reachable", False):
    add("network_egress", "skipped", "host baseline could not reach example.com:443; agent result is inconclusive")
else:
    try:
        with socket.create_connection(("example.com", 443), timeout=3):
            pass
        add("network_egress", "allow", "TCP connection to example.com:443 succeeded; no canary data was sent")
    except PermissionError:
        add("network_egress", "deny", "TCP connection to example.com:443 was denied")
    except OSError as exc:
        add("network_egress", "error", f"host baseline succeeded but agent connection failed without an explicit permission denial: {type(exc).__name__}: {exc}")


def socket_connect(capability, path, host_present, host_connectable, probe_supported):
    if not probe_supported:
        add(capability, "skipped", "Unix socket probe is unsupported on this platform; Windows named pipes are not tested")
        return
    if not host_present:
        add(capability, "absent", "socket not present on host")
        return
    if not host_connectable:
        add(capability, "skipped", "host baseline could not connect; agent comparison is inconclusive")
        return
    if not path or not hasattr(socket, "AF_UNIX"):
        add(capability, "skipped", "Unix socket probing is unavailable on this platform")
        return
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(2)
        try:
            sock.connect(path)
        finally:
            sock.close()
        add(capability, "allow", "Unix socket connection succeeded; no protocol data was sent")
    except PermissionError:
        add(capability, "deny", "socket connection denied")
    except FileNotFoundError:
        add(capability, "deny", "previously host-visible socket path is not visible; this does not identify whether it was hidden or removed")
    except OSError as exc:
        add(capability, "error", f"host baseline connected but agent connection failed without an explicit permission denial: {type(exc).__name__}: {exc}")


socket_connect(
    "docker_socket",
    MANIFEST.get("docker_socket_path", "/var/run/docker.sock"),
    bool(MANIFEST.get("docker_socket_host_present")),
    bool(MANIFEST.get("docker_socket_host_connectable")),
    bool(MANIFEST.get("unix_socket_probe_supported", True)),
)
socket_connect(
    "ssh_agent_socket",
    MANIFEST.get("ssh_agent_socket_path", ""),
    bool(MANIFEST.get("ssh_agent_socket_host_present")),
    bool(MANIFEST.get("ssh_agent_socket_host_connectable")),
    bool(MANIFEST.get("unix_socket_probe_supported", True)),
)

body = {
    "schema_version": 1,
    "run_id": MANIFEST["run_id"],
    "probe_platform": f"{platform.system()} {platform.machine()} / Python {platform.python_version()}",
    "probes": RESULTS,
}
key = MANIFEST.get("attestation_key")
if isinstance(key, str) and key:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    body["attestation"] = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
payload = body
encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
try:
    with (HERE / "results.json").open("x", encoding="utf-8") as results_file:
        results_file.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
except OSError:
    pass
print("AGENT_BOUNDARY_RESULT=" + encoded)
'''
