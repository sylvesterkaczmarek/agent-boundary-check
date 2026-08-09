import json
import subprocess
import sys
from pathlib import Path

from agent_boundary_check.cli import main


def test_prepare_collect_flow_marks_environment_as_skipped(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = tmp_path / "manual"
    assert main(["prepare", "--output", str(lab), "--no-network"]) == 0
    proc = subprocess.run(
        [sys.executable, ".agent-boundary/probe_driver.py"],
        cwd=lab / "workspace",
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    report = tmp_path / "manual.json"
    assert main(["collect", str(lab), "--json", str(report)]) == 0
    data = json.loads(report.read_text())
    assert data["agent"] == "manual"
    env_probe = next(p for p in data["probes"] if p["capability"] == "environment_canary")
    assert env_probe["status"] == "skipped"
    assert data["risk_level"] == "CRITICAL"


def test_collect_bad_manifest_returns_clean_error(tmp_path, capsys):
    lab = tmp_path / "bad"
    manifest = lab / "workspace" / ".agent-boundary" / "manifest.json"
    manifest.parent.mkdir(parents=True)
    manifest.write_text("{not json")
    assert main(["collect", str(lab)]) == 2
    assert "error:" in capsys.readouterr().err


def test_collect_rejects_invalid_manifest_run_id(tmp_path, capsys):
    lab = tmp_path / "bad-run-id"
    internal = lab / "workspace" / ".agent-boundary"
    internal.mkdir(parents=True)
    (internal / "manifest.json").write_text(json.dumps({
        "schema_version": 1,
        "run_id": "../../escape",
        "attestation_key": "synthetic-key",
    }))
    assert main(["collect", str(lab)]) == 2
    assert "valid run identifier" in capsys.readouterr().err


def test_collect_rejects_boolean_manifest_schema(tmp_path, capsys):
    lab = tmp_path / "bad-schema"
    internal = lab / "workspace" / ".agent-boundary"
    internal.mkdir(parents=True)
    (internal / "manifest.json").write_text(json.dumps({
        "schema_version": True,
        "run_id": "0123456789abcdef",
        "attestation_key": "synthetic-key",
    }))
    assert main(["collect", str(lab)]) == 2
    assert "schema version" in capsys.readouterr().err
