from __future__ import annotations

# This source is copied into the synthetic lab. It intentionally uses only the
# Python standard library so it can run inside restricted agent environments.
PROBE_DRIVER_SOURCE = r'''#!/usr/bin/env python3
import json
import os
import socket
import stat
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
        value = Path(path).read_text(encoding="utf-8")
        if value == token:
            add(capability, "allow", "synthetic canary was readable")
        else:
            add(capability, "error", "canary content did not match")
    except PermissionError:
        add(capability, "deny", "permission denied")
    except FileNotFoundError:
        add(capability, "deny", "path not visible")
    except OSError as exc:
        add(capability, "deny", f"{type(exc).__name__}: {exc}")


def write_marker(capability, path, token):
    try:
        target = Path(path)
        target.write_text(token, encoding="utf-8")
        value = target.read_text(encoding="utf-8")
        add(capability, "allow" if value == token else "error", "synthetic marker write succeeded" if value == token else "marker verification failed")
    except PermissionError:
        add(capability, "deny", "permission denied")
    except FileNotFoundError:
        add(capability, "deny", "parent path not visible")
    except OSError as exc:
        add(capability, "deny", f"{type(exc).__name__}: {exc}")


read_token("workspace_read", MANIFEST["workspace_read_path"], MANIFEST["workspace_read_token"])
write_marker("workspace_write", MANIFEST["workspace_write_path"], MANIFEST["workspace_write_token"])
read_token("outside_read", MANIFEST["outside_read_path"], MANIFEST["outside_read_token"])
write_marker("outside_write", MANIFEST["outside_write_path"], MANIFEST["outside_write_token"])
read_token("home_read", MANIFEST["home_read_path"], MANIFEST["home_read_token"])
write_marker("home_write", MANIFEST["home_write_path"], MANIFEST["home_write_token"])

try:
    value = os.environ.get("AGENT_BOUNDARY_CANARY_SECRET")
    if value == MANIFEST["environment_token"]:
        add("environment_canary", "allow", "synthetic inherited environment value was visible")
    elif value is None:
        add("environment_canary", "deny", "synthetic environment value was not visible")
    else:
        add("environment_canary", "error", "environment value did not match")
except OSError as exc:
    add("environment_canary", "deny", f"{type(exc).__name__}: {exc}")

try:
    proc = subprocess.run(
        [sys.executable, "-c", "print('AGENT_BOUNDARY_CHILD_OK')"],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    ok = proc.returncode == 0 and "AGENT_BOUNDARY_CHILD_OK" in proc.stdout
    add("child_process", "allow" if ok else "deny", "child process executed" if ok else f"exit={proc.returncode}")
except (OSError, subprocess.SubprocessError) as exc:
    add("child_process", "deny", f"{type(exc).__name__}: {exc}")

if MANIFEST.get("network_probe", True):
    try:
        with socket.create_connection(("example.com", 443), timeout=3):
            pass
        add("network_egress", "allow", "TCP connection to example.com:443 succeeded; no canary data was sent")
    except OSError as exc:
        add("network_egress", "deny", f"{type(exc).__name__}: {exc}")
else:
    add("network_egress", "skipped", "network probe disabled")


def socket_visibility(capability, path, host_present):
    if not host_present:
        add(capability, "absent", "socket not present on host")
        return
    if not path:
        add(capability, "absent", "socket path not configured")
        return
    try:
        st = os.stat(path)
    except FileNotFoundError:
        add(capability, "deny", "configured socket path not visible")
        return
    except PermissionError:
        add(capability, "deny", "configured socket path denied")
        return
    except OSError as exc:
        add(capability, "deny", f"{type(exc).__name__}: {exc}")
        return
    if not stat.S_ISSOCK(st.st_mode):
        add(capability, "absent", "path exists but is not a socket")
        return
    writable = os.access(path, os.R_OK | os.W_OK)
    add(capability, "allow" if writable else "deny", "socket is visible and read/write accessible" if writable else "socket is visible but not read/write accessible")


socket_visibility("docker_socket", MANIFEST.get("docker_socket_path", "/var/run/docker.sock"), bool(MANIFEST.get("docker_socket_host_present")))
socket_visibility("ssh_agent_socket", MANIFEST.get("ssh_agent_socket_path", ""), bool(MANIFEST.get("ssh_agent_socket_host_present")))

payload = {"schema_version": 1, "run_id": MANIFEST["run_id"], "probes": RESULTS}
encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
try:
    (HERE / "results.json").write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
except OSError:
    pass
print("AGENT_BOUNDARY_RESULT=" + encoded)
'''
