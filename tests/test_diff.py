from agent_boundary_check.diffing import diff_reports


def report(status):
    return {
        "schema_version": 1,
        "agent": "codex",
        "agent_version": "1",
        "risk_level": "LOW" if status == "deny" else "HIGH",
        "probes": [{"capability": "outside_read", "status": status, "detail": ""}],
    }


def test_diff_flags_new_exposure():
    result = diff_reports(report("deny"), report("allow"))
    assert result.has_new_exposure
    assert result.changes[0].capability == "outside_read"


def test_diff_does_not_flag_restriction_as_exposure():
    result = diff_reports(report("allow"), report("deny"))
    assert not result.has_new_exposure
