import json

import pytest

from agent_boundary_check.diffing import diff_reports, load_report
from agent_boundary_check.models import CAPABILITIES


def report(status):
    probes = [{"capability": name, "status": "deny", "detail": ""} for name in CAPABILITIES]
    next(item for item in probes if item["capability"] == "outside_read")["status"] = status
    return {
        "schema_version": 1,
        "agent": "codex",
        "agent_version": "1",
        "risk_level": "LOW" if status == "deny" else "HIGH",
        "evidence_complete": True,
        "evidence_error": None,
        "runner_exit_code": 0,
        "runner_timed_out": False,
        "policy_violations": [],
        "probes": probes,
    }


def test_diff_flags_new_exposure():
    result = diff_reports(report("deny"), report("allow"))
    assert result.has_new_exposure
    assert next(c for c in result.changes if c.capability == "outside_read").new_exposure


def test_diff_does_not_flag_restriction_as_exposure():
    result = diff_reports(report("allow"), report("deny"))
    assert not result.has_new_exposure


def test_load_report_rejects_duplicate_capability(tmp_path):
    data = report("deny")
    data["probes"].append(dict(data["probes"][0]))
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="duplicate"):
        load_report(path)


def test_load_report_rejects_missing_capabilities(tmp_path):
    path = tmp_path / "partial.json"
    path.write_text(json.dumps({
        "schema_version": 1,
        "agent": "x",
        "risk_level": "UNKNOWN",
        "probes": [{"capability": "workspace_read", "status": "allow", "detail": ""}],
    }))
    import pytest
    with pytest.raises(ValueError, match="missing capabilities"):
        load_report(path)


def test_load_report_rejects_boolean_schema_version(tmp_path):
    data = report("deny")
    data["schema_version"] = True
    path = tmp_path / "bad-version.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="unsupported report schema"):
        load_report(path)


def test_diff_surfaces_runner_failure_when_probe_states_unchanged():
    before, after = report("deny"), report("deny")
    after["runner_timed_out"] = True
    after["evidence_complete"] = False
    result = diff_reports(before, after)
    assert result.changes == []
    assert result.has_unusable_evidence
    assert result.after_risk == "UNKNOWN"
    assert "agent runner timed out" in result.after_evidence_issues


def test_diff_rejects_missing_evidence_state():
    after = report("deny")
    del after["evidence_complete"]
    with pytest.raises(ValueError, match="evidence_complete"):
        diff_reports(report("deny"), after)


@pytest.mark.parametrize("status", ["unknown", "error", "skipped"])
def test_lost_observation_is_inconclusive_even_without_new_exposure(status):
    result = diff_reports(report("allow"), report(status))
    assert not result.has_new_exposure
    assert result.has_unusable_evidence
    assert result.after_evidence_issues


def test_unchanged_intentionally_skipped_probe_stays_explicitly_partial():
    before, after = report("deny"), report("deny")
    for value in (before, after):
        next(p for p in value["probes"] if p["capability"] == "network_egress")["status"] = "skipped"
    result = diff_reports(before, after)
    assert not result.has_unusable_evidence
    assert result.before_skipped == result.after_skipped == ["network_egress"]
    assert result.before_risk == result.after_risk == "PARTIAL"


def test_diff_surfaces_existing_policy_violations():
    before, after = report("deny"), report("deny")
    after["policy_violations"] = ["workspace_read: deny but policy requires allow"]
    result = diff_reports(before, after)
    assert result.changes == []
    assert result.after_policy_violations == after["policy_violations"]
    assert result.after_risk == "HIGH"


def test_diff_derives_risk_from_observations_instead_of_stale_summary():
    after = report("allow")
    after["risk_level"] = "LOW"
    result = diff_reports(report("deny"), after)
    assert result.after_risk == "HIGH"
    assert result.has_new_exposure


@pytest.mark.parametrize("field,value", [
    ("evidence_complete", "false"),
    ("evidence_error", ["bad"]),
    ("runner_timed_out", "false"),
    ("runner_exit_code", False),
    ("policy_violations", "failed"),
    ("policy_violations", [1]),
    ("agent", None),
    ("agent_version", {}),
])
def test_diff_rejects_invalid_report_metadata(field, value, tmp_path):
    data = report("deny")
    data[field] = value
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match=field):
        load_report(path)


def test_direct_diff_rejects_duplicate_probes():
    after = report("deny")
    after["probes"].append(dict(after["probes"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        diff_reports(report("deny"), after)
