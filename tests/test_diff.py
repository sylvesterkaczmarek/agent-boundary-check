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
