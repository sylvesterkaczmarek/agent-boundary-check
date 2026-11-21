import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from agent_boundary_check.cli import main
from agent_boundary_check.diffing import diff_reports, load_report
from agent_boundary_check.policy import load_policy

DRIVER = [sys.executable, "-I", "-S", ".agent-boundary/probe_driver.py"]


@pytest.mark.parametrize("condition,expected", [
    ("allowed", 1), ("missing", 2), ("replaced", 2), ("changed", 2), ("denied", 0),
])
def test_manual_policy_controls(tmp_path, condition, expected):
    root = tmp_path / "lab"
    assert main(["prepare", "--output", str(root), "--no-sockets", "--no-network"]) == 0
    fixture = root / "outside" / "outside-canary.txt"
    if condition == "missing":
        fixture.rename(root / "parked")
    elif condition == "changed":
        fixture.write_text("different")
    elif condition == "replaced":
        original = fixture.read_bytes()
        fixture.rename(root / "parked")
        fixture.write_bytes(original)
    elif condition == "denied":
        if os.name != "posix" or os.geteuid() == 0:
            pytest.skip("requires unprivileged POSIX mode enforcement")
        fixture.chmod(0)
    try:
        subprocess.run(DRIVER, cwd=root/"workspace", capture_output=True, check=True)
    finally:
        if condition == "denied":
            fixture.chmod(0o600)
    report = tmp_path / "report.json"
    policy = tmp_path / "policy.toml"
    policy.write_text('version=1\ndeny=["outside_read"]')
    argv = ["collect", str(root), "--policy", str(policy), "--json", str(report)]
    assert main(argv) == expected
    before = load_report(report)
    assert before["evidence_complete"] == (expected != 2)
    assert before["host_observations"]["workspace_write"] == "marker_verified"
    if expected != 2:
        assert main(argv) == expected
        assert load_report(report) == before


def test_auto_detects_lost_control_before_cleanup(tmp_path):
    worker = tmp_path / "worker.py"
    worker.write_text("from pathlib import Path\nimport runpy\n"
                      "Path('../outside/outside-canary.txt').rename('../outside/parked')\n"
                      "runpy.run_path('.agent-boundary/probe_driver.py')\n")
    out = tmp_path / "report.json"
    assert main(["verify", "command", "--command", f'"{sys.executable}" "{worker}"',
                 "--no-sockets", "--no-network", "--json", str(out)]) == 2
    data = load_report(out)
    assert data["host_observations"]["outside_read"] == "unavailable"
    assert data["evidence_complete"] is False


@pytest.fixture
def reference():
    bundle = Path(__file__).resolve().parents[1] / "verification/calibration-local.json"
    return {s["case"]: s["report"] for s in json.loads(bundle.read_text())["samples"]}


def test_policy_removed_or_replaced_cannot_go_green(tmp_path, reference):
    from copy import deepcopy
    before = reference["allowed"]
    after = deepcopy(before)
    after.update(policy=None, policy_violations=[])
    assert diff_reports(before, after).has_unusable_evidence
    path = tmp_path / "rules.toml"
    path.write_text('deny=["outside_read"]\nallow=["workspace_read"]\nversion=1')
    result = diff_reports(before, after, policy=load_policy(path))
    assert result.after_policy_violations and result.has_unusable_evidence
    after["policy"] = before["policy"]
    assert diff_reports(before, after, policy=load_policy(path)).after_policy_violations
    after["policy"] = {**before["policy"], "sha256": "0" * 64}
    with pytest.raises(ValueError, match="digest"):
        diff_reports(before, after)


def test_coverage_first_access_and_failed_baseline(reference):
    from copy import deepcopy
    before = reference["denied"]
    after = deepcopy(before)
    probe = next(p for p in after["probes"] if p["capability"] == "network_egress")
    probe["reason"] = "baseline_unavailable"
    result = diff_reports(before, after)
    assert result.changes[0].before_reason == "disabled" and result.has_unusable_evidence
    probe.update(status="allow", reason=None)
    result = diff_reports(before, after)
    assert result.changes[0].first_observation and not result.has_new_exposure
    assert diff_reports(before, reference["allowed"]).has_new_exposure


def test_explicit_gate_rejects_legacy_provenance(tmp_path, reference):
    old = {**reference["denied"], "schema_version": 1}
    for key in ("host_observations", "policy", "tool_path", "fixture_profile", "checker_version"):
        del old[key]
    policy = Path(__file__).resolve().parents[1] / "examples/calibration/policy.toml"
    result = diff_reports(old, old, policy=load_policy(policy))
    assert result.has_unusable_evidence
    assert not diff_reports(old, old).has_unusable_evidence


def test_refuses_report_output_over_host_evidence(tmp_path):
    root = tmp_path / "manual"
    assert main(["prepare", "--output", str(root), "--no-network", "--no-sockets"]) == 0
    for name in ("fixture-baseline.json", "fixture-receipt.json"):
        assert main(["collect", str(root), "--json", str(root/name)]) == 2


def test_copied_candidate_report_cannot_pass_a_release_gate(tmp_path, reference):
    for name in ("baseline", "candidate"):
        (tmp_path / name).write_text(json.dumps(reference["denied"]))
    rules = Path(__file__).resolve().parents[1] / "examples/calibration/policy.toml"
    args = ["diff", str(tmp_path / "baseline"), str(tmp_path / "candidate"), "--policy", str(rules)]
    assert main(args) == 2
    (tmp_path / "candidate").write_text(json.dumps(reference["denied_repeat"]))
    assert main(args) == 0
