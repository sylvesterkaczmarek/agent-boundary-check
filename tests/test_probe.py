import json
import os
import subprocess
import sys
from pathlib import Path

from agent_boundary_check.lab import create_lab
from agent_boundary_check.report import make_report, parse_probe_payload


def test_probe_driver_runs_returns_attested_evidence(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = create_lab(tmp_path / "lab", network_probe=False)
    env = os.environ.copy()
    env["AGENT_BOUNDARY_CANARY_SECRET"] = lab.environment_token
    proc = subprocess.run(
        [sys.executable, ".agent-boundary/probe_driver.py"],
        cwd=lab.workspace,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    payload = parse_probe_payload(lab.results_path, proc.stdout)
    assert payload is not None
    report = make_report(
        run_id=lab.run_id,
        agent="test",
        agent_version=None,
        payload=payload,
        policy=None,
        declared_hints={},
        exit_code=0,
        timed_out=False,
        runner_output="",
        attestation_key=lab.attestation_key,
    )
    assert report.evidence_complete
    by_name = {p.capability: p.status.value for p in report.probes}
    assert by_name["workspace_read"] == "allow"
    assert by_name["workspace_write"] == "allow"
    assert by_name["outside_read"] == "allow"
    assert by_name["home_read"] == "allow"
    assert by_name["environment_canary"] == "allow"
    assert by_name["child_process"] == "allow"
    assert by_name["network_egress"] == "skipped"
    assert report.probe_platform
    lab.cleanup_home_canary()


def test_network_is_skipped_when_host_baseline_is_unavailable(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    monkeypatch.setattr("agent_boundary_check.lab._tcp_reachable", lambda *args, **kwargs: False)
    lab = create_lab(tmp_path / "lab", network_probe=True)
    env = os.environ.copy()
    env["AGENT_BOUNDARY_CANARY_SECRET"] = lab.environment_token
    proc = subprocess.run([sys.executable, ".agent-boundary/probe_driver.py"], cwd=lab.workspace, env=env, capture_output=True, text=True)
    payload = parse_probe_payload(lab.results_path, proc.stdout)
    network = next(p for p in payload["probes"] if p["capability"] == "network_egress")
    assert network["status"] == "skipped"
    assert "host baseline" in network["detail"]
    lab.cleanup_home_canary()


def test_environment_canary_can_be_denied_without_breaking_attestation(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = create_lab(tmp_path / "lab", network_probe=False)
    manifest_text = lab.manifest_path.read_text(encoding="utf-8")
    assert lab.environment_token not in manifest_text

    env = os.environ.copy()
    env.pop("AGENT_BOUNDARY_CANARY_SECRET", None)
    proc = subprocess.run(
        [sys.executable, ".agent-boundary/probe_driver.py"],
        cwd=lab.workspace,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    payload = parse_probe_payload(lab.results_path, proc.stdout)
    report = make_report(
        run_id=lab.run_id,
        agent="test",
        agent_version=None,
        payload=payload,
        policy=None,
        declared_hints={},
        exit_code=proc.returncode,
        timed_out=False,
        runner_output="",
        attestation_key=lab.attestation_key,
    )
    assert report.evidence_complete
    environment = next(p for p in report.probes if p.capability == "environment_canary")
    assert environment.status.value == "deny"
    lab.cleanup_home_canary()


def test_unix_socket_capabilities_are_skipped_when_platform_probe_is_unsupported(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = create_lab(tmp_path / "lab", network_probe=False)
    manifest = json.loads(lab.manifest_path.read_text())
    manifest["unix_socket_probe_supported"] = False
    lab.manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    env = os.environ.copy()
    env["AGENT_BOUNDARY_CANARY_SECRET"] = lab.environment_token
    proc = subprocess.run(
        [sys.executable, ".agent-boundary/probe_driver.py"],
        cwd=lab.workspace,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    payload = parse_probe_payload(lab.results_path, proc.stdout)
    by_name = {p["capability"]: p for p in payload["probes"]}
    assert by_name["docker_socket"]["status"] == "skipped"
    assert by_name["ssh_agent_socket"]["status"] == "skipped"
    lab.cleanup_home_canary()


def test_altered_environment_value_is_treated_as_not_exposed(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = create_lab(tmp_path / "lab", network_probe=False)
    env = os.environ.copy()
    env["AGENT_BOUNDARY_CANARY_SECRET"] = "redacted"
    proc = subprocess.run(
        [sys.executable, ".agent-boundary/probe_driver.py"],
        cwd=lab.workspace,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    payload = parse_probe_payload(lab.results_path, proc.stdout)
    env_probe = next(p for p in payload["probes"] if p["capability"] == "environment_canary")
    assert env_probe["status"] == "deny"
    assert "redacted" in env_probe["detail"]
    lab.cleanup_home_canary()


def test_changed_canary_content_still_proves_read_access(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = create_lab(tmp_path / "lab", network_probe=False)
    manifest = json.loads(lab.manifest_path.read_text())
    Path(manifest["outside_read_path"]).write_text("changed", encoding="utf-8")
    env = os.environ.copy()
    env["AGENT_BOUNDARY_CANARY_SECRET"] = lab.environment_token
    proc = subprocess.run(
        [sys.executable, ".agent-boundary/probe_driver.py"],
        cwd=lab.workspace,
        env=env,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
    )
    payload = parse_probe_payload(lab.results_path, proc.stdout)
    outside = next(p for p in payload["probes"] if p["capability"] == "outside_read")
    assert outside["status"] == "allow"
    assert "content changed" in outside["detail"]
    lab.cleanup_home_canary()
