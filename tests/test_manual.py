import json
import os
import subprocess
import sys
from pathlib import Path

from agent_boundary_check.cli import main


def test_prepare_collect_flow(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = tmp_path / "manual"
    assert main(["prepare", "--output", str(lab), "--no-network"]) == 0
    manifest = json.loads((lab / "workspace" / ".agent-boundary" / "manifest.json").read_text())
    env = os.environ.copy()
    env["AGENT_BOUNDARY_CANARY_SECRET"] = manifest["environment_token"]
    proc = subprocess.run(
        [sys.executable, ".agent-boundary/probe_driver.py"],
        cwd=lab / "workspace",
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    report = tmp_path / "manual.json"
    assert main(["collect", str(lab), "--json", str(report)]) == 0
    data = json.loads(report.read_text())
    assert data["agent"] == "manual"
