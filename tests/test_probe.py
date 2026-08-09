import json
import os
import subprocess
import sys
from pathlib import Path

from agent_boundary_check.lab import create_lab
from agent_boundary_check.report import parse_probe_payload


def test_probe_driver_runs_and_returns_evidence(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = create_lab(tmp_path / "lab", network_probe=False)
    manifest = json.loads(lab.manifest_path.read_text())
    env = os.environ.copy()
    env["AGENT_BOUNDARY_CANARY_SECRET"] = manifest["environment_token"]
    proc = subprocess.run(
        [sys.executable, ".agent-boundary/probe_driver.py"],
        cwd=lab.workspace,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    payload = parse_probe_payload(lab.results_path, proc.stdout)
    assert payload is not None
    by_name = {p["capability"]: p["status"] for p in payload["probes"]}
    assert by_name["workspace_read"] == "allow"
    assert by_name["workspace_write"] == "allow"
    assert by_name["outside_read"] == "allow"
    assert by_name["home_read"] == "allow"
    assert by_name["environment_canary"] == "allow"
    assert by_name["child_process"] == "allow"
    assert by_name["network_egress"] == "skipped"
    lab.cleanup_home_canary()
