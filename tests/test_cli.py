import json
from pathlib import Path

from agent_boundary_check.cli import main


def test_version(capsys):
    with __import__("pytest").raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_demo_writes_json(tmp_path):
    report = tmp_path / "report.json"
    code = main(["demo", "--json", str(report)])
    assert code == 0
    data = json.loads(report.read_text())
    assert data["agent"] == "demo-runner"
    assert data["risk_level"] == "CRITICAL"
    assert "outside_write" in data["exposures"]


def test_agents_command():
    assert main(["agents"]) == 0


def test_verify_auto_reports_when_no_agent(monkeypatch, capsys):
    monkeypatch.setattr("agent_boundary_check.cli.detect_agents", lambda: [])
    code = main(["verify", "--no-network"])
    assert code == 2
    assert "no supported coding agent detected" in capsys.readouterr().err


def test_verify_auto_requires_choice_for_multiple(monkeypatch, capsys):
    monkeypatch.setattr("agent_boundary_check.cli.detect_agents", lambda: ["codex", "claude"])
    code = main(["verify", "--no-network"])
    assert code == 2
    assert "multiple supported agents detected" in capsys.readouterr().err
