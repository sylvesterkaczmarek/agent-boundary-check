import hashlib
import hmac
import json
from pathlib import Path

import pytest

from agent_boundary_check.models import CAPABILITIES, ProbeResult, ProbeStatus
from agent_boundary_check.report import make_report, parse_probe_payload, risk_summary


def test_risk_is_critical_for_outside_write():
    level, exposures = risk_summary([ProbeResult("outside_write", ProbeStatus.ALLOW, "")])
    assert level == "CRITICAL"
    assert exposures == ["outside_write"]


def test_risk_low_when_broad_capabilities_denied_or_absent():
    probes = [ProbeResult(name, ProbeStatus.DENY, "") for name in CAPABILITIES]
    probes[-2] = ProbeResult("docker_socket", ProbeStatus.ABSENT, "")
    probes[-1] = ProbeResult("ssh_agent_socket", ProbeStatus.ABSENT, "")
    level, exposures = risk_summary(probes)
    assert level == "LOW"
    assert exposures == []


def test_risk_is_partial_when_risky_probe_was_skipped():
    probes = [ProbeResult(name, ProbeStatus.DENY, "") for name in CAPABILITIES]
    probes[8] = ProbeResult("network_egress", ProbeStatus.SKIPPED, "")
    level, _ = risk_summary(probes)
    assert level == "PARTIAL"


def test_parse_stdout_payload_ignores_trailing_text(tmp_path):
    stdout = 'noise\nAGENT_BOUNDARY_RESULT={"schema_version":1,"run_id":"x","probes":[]} trailing {noise}\n'
    payload = parse_probe_payload(tmp_path / "missing.json", stdout)
    assert payload["run_id"] == "x"


def test_make_report_rejects_wrong_run_id():
    payload = {
        "schema_version": 1,
        "run_id": "wrong",
        "probe_platform": "x",
        "probes": [{"capability": name, "status": "deny", "detail": ""} for name in CAPABILITIES],
    }
    report = make_report(
        run_id="expected",
        agent="test",
        agent_version=None,
        payload=payload,
        policy=None,
        declared_hints={},
        exit_code=0,
        timed_out=False,
        runner_output="",
    )
    assert report.risk_level == "UNKNOWN"
    assert not report.evidence_complete
    assert "identifier" in report.evidence_error
    assert all(p.status == ProbeStatus.UNKNOWN for p in report.probes)


def test_make_report_marks_missing_capabilities_unknown():
    payload = {
        "schema_version": 1,
        "run_id": "r",
        "probe_platform": "x",
        "probes": [{"capability": "workspace_read", "status": "allow", "detail": ""}],
    }
    report = make_report(
        run_id="r",
        agent="test",
        agent_version=None,
        payload=payload,
        policy=None,
        declared_hints={},
        exit_code=0,
        timed_out=False,
        runner_output="",
    )
    assert not report.evidence_complete
    assert report.risk_level == "UNKNOWN"
    assert len(report.probes) == len(CAPABILITIES)
    assert next(p for p in report.probes if p.capability == "outside_read").status == ProbeStatus.UNKNOWN


def test_attestation_rejects_fabricated_payload():
    body = {
        "schema_version": 1,
        "run_id": "r",
        "probe_platform": "x",
        "probes": [{"capability": name, "status": "deny", "detail": ""} for name in CAPABILITIES],
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    body["attestation"] = hmac.new(b"right", canonical, hashlib.sha256).hexdigest()
    report = make_report(
        run_id="r",
        agent="test",
        agent_version=None,
        payload=body,
        policy=None,
        declared_hints={},
        exit_code=0,
        timed_out=False,
        runner_output="",
        attestation_key="wrong",
    )
    assert report.risk_level == "UNKNOWN"
    assert "attestation" in report.evidence_error


def test_nonzero_runner_exit_marks_evidence_incomplete():
    payload = {
        "schema_version": 1,
        "run_id": "run-1",
        "probe_platform": "test",
        "probes": [{"capability": name, "status": "deny", "detail": ""} for name in CAPABILITIES],
    }
    report = make_report(
        run_id="run-1",
        agent="test",
        agent_version=None,
        payload=payload,
        policy=None,
        declared_hints={},
        exit_code=7,
        timed_out=False,
        runner_output="",
    )
    assert report.evidence_complete is False
    assert "exited with status 7" in report.evidence_error


def test_runner_timeout_marks_evidence_incomplete():
    payload = {
        "schema_version": 1,
        "run_id": "run-1",
        "probe_platform": "test",
        "probes": [{"capability": name, "status": "deny", "detail": ""} for name in CAPABILITIES],
    }
    report = make_report(
        run_id="run-1",
        agent="test",
        agent_version=None,
        payload=payload,
        policy=None,
        declared_hints={},
        exit_code=None,
        timed_out=True,
        runner_output="",
    )
    assert report.evidence_complete is False
    assert "timed out" in report.evidence_error


def test_non_risky_unknown_prevents_low_risk_conclusion():
    payload = {
        "schema_version": 1,
        "run_id": "run-1",
        "probe_platform": "test",
        "probes": [
            {
                "capability": name,
                "status": "unknown" if name == "workspace_read" else ("absent" if name in {"docker_socket", "ssh_agent_socket"} else "deny"),
                "detail": "",
            }
            for name in CAPABILITIES
        ],
    }
    report = make_report(
        run_id="run-1",
        agent="test",
        agent_version=None,
        payload=payload,
        policy=None,
        declared_hints={},
        exit_code=0,
        timed_out=False,
        runner_output="",
    )
    assert report.risk_level == "UNKNOWN"
    assert report.evidence_complete is False


def test_probe_schema_rejects_boolean_version():
    payload = {
        "schema_version": True,
        "run_id": "r",
        "probe_platform": "x",
        "probes": [{"capability": name, "status": "deny", "detail": ""} for name in CAPABILITIES],
    }
    report = make_report(
        run_id="r",
        agent="test",
        agent_version=None,
        payload=payload,
        policy=None,
        declared_hints={},
        exit_code=0,
        timed_out=False,
        runner_output="",
    )
    assert report.risk_level == "UNKNOWN"
    assert "schema" in report.evidence_error


def test_parse_payload_falls_back_to_stdout_when_result_file_is_not_object(tmp_path):
    results = tmp_path / "results.json"
    results.write_text("[]")
    stdout = 'AGENT_BOUNDARY_RESULT={"schema_version":1,"run_id":"stdout","probes":[]}\n'
    payload = parse_probe_payload(results, stdout)
    assert payload["run_id"] == "stdout"


def test_parse_payload_falls_back_to_stdout_when_result_file_is_invalid_utf8(tmp_path):
    results = tmp_path / "results.json"
    results.write_bytes(b"\xff\xfe")
    stdout = 'AGENT_BOUNDARY_RESULT={"schema_version":1,"run_id":"stdout","probes":[]}\n'
    payload = parse_probe_payload(results, stdout)
    assert payload["run_id"] == "stdout"


def complete_payload(**updates):
    data = {
        "schema_version": 1,
        "run_id": "r",
        "probe_platform": "test",
        "probes": [{"capability": name, "status": "deny", "detail": ""} for name in CAPABILITIES],
    }
    data.update(updates)
    return data


def build_report(payload, **updates):
    kwargs = dict(
        run_id="r", agent="test", agent_version=None, payload=payload,
        policy=None, declared_hints={}, exit_code=0, timed_out=False, runner_output="",
    )
    kwargs.update(updates)
    return make_report(**kwargs)


def test_absent_synthetic_fixture_cannot_establish_a_boundary():
    from agent_boundary_check.policy import BoundaryPolicy

    payload = complete_payload()
    next(p for p in payload["probes"] if p["capability"] == "outside_read")["status"] = "absent"
    report = build_report(payload, policy=BoundaryPolicy(frozenset({"outside_read"}), frozenset()))
    assert not report.evidence_complete
    assert report.risk_level == "UNKNOWN"
    assert "absent" in report.evidence_error
    assert report.policy_violations


def test_non_ascii_attestation_is_invalid_evidence_without_crashing():
    report = build_report(complete_payload(attestation="é" * 64), attestation_key="key")
    assert not report.evidence_complete
    assert report.risk_level == "UNKNOWN"
    assert "attestation" in report.evidence_error


def test_risk_cannot_be_low_with_no_observations():
    assert risk_summary([]) == ("UNKNOWN", [])


def test_risk_cannot_be_low_with_missing_non_risky_observation():
    probes = [ProbeResult(name, ProbeStatus.DENY) for name in CAPABILITIES if name != "workspace_read"]
    assert risk_summary(probes) == ("UNKNOWN", [])


def test_risk_cannot_be_low_with_duplicate_observation():
    probes = [ProbeResult(name, ProbeStatus.DENY) for name in CAPABILITIES]
    assert risk_summary(probes + [probes[0]]) == ("UNKNOWN", [])


def test_payload_non_object_is_reported_as_invalid():
    report = build_report([])
    assert not report.evidence_complete
    assert "object" in report.evidence_error


def test_probe_detail_must_be_text():
    payload = complete_payload()
    payload["probes"][0]["detail"] = {"status": "deny"}
    report = build_report(payload)
    assert not report.evidence_complete
    assert "detail" in report.evidence_error


def test_unknown_probe_fields_are_not_silently_discarded():
    payload = complete_payload()
    payload["probes"][0]["error"] = "measurement failed"
    report = build_report(payload)
    assert not report.evidence_complete
    assert "unexpected fields" in report.evidence_error


def test_current_stdout_takes_precedence_over_retained_result_file(tmp_path):
    old = complete_payload()
    current = complete_payload()
    current["probes"][0]["status"] = "error"
    path = tmp_path / "results.json"
    path.write_text(json.dumps(old))
    payload = parse_probe_payload(path, "AGENT_BOUNDARY_RESULT=" + json.dumps(current))
    report = build_report(payload)
    assert not report.evidence_complete
    assert report.probes[0].status == ProbeStatus.ERROR


def test_latest_parseable_stdout_result_is_selected(tmp_path):
    first = complete_payload(run_id="first")
    latest = complete_payload(run_id="latest")
    stdout = "\n".join("AGENT_BOUNDARY_RESULT=" + json.dumps(p) for p in (first, latest))
    assert parse_probe_payload(tmp_path / "missing", stdout)["run_id"] == "latest"


def test_probe_failure_has_an_explicit_incomplete_evidence_reason():
    payload = complete_payload()
    next(p for p in payload["probes"] if p["capability"] == "outside_read")["status"] = "error"
    next(p for p in payload["probes"] if p["capability"] == "outside_write")["status"] = "allow"
    report = build_report(payload)
    assert report.risk_level == "CRITICAL"
    assert not report.evidence_complete
    assert "outside_read (error)" in report.evidence_error


def test_result_marker_inside_probe_detail_is_not_a_second_result(tmp_path):
    payload = complete_payload()
    payload["probes"][0]["detail"] = "path /synthetic/AGENT_BOUNDARY_RESULT={} was not visible"
    stdout = "AGENT_BOUNDARY_RESULT=" + json.dumps(payload)
    assert parse_probe_payload(tmp_path / "missing", stdout) == payload


@pytest.mark.parametrize("current", ['{incomplete', '[]', 'null', '"not a result"', ''])
@pytest.mark.parametrize("previous_stdout", [False, True])
def test_invalid_current_stdout_cannot_reuse_successful_evidence(tmp_path, current, previous_stdout):
    old = complete_payload()
    canonical = json.dumps(old, sort_keys=True, separators=(",", ":")).encode()
    old["attestation"] = hmac.new(b"key", canonical, hashlib.sha256).hexdigest()
    path = tmp_path / "results.json"
    path.write_text(json.dumps(old))
    stdout = "AGENT_BOUNDARY_RESULT=" + json.dumps(old) + "\n" if previous_stdout else ""
    stdout += "AGENT_BOUNDARY_RESULT=" + current
    payload = parse_probe_payload(path, stdout)
    assert payload is None
    report = build_report(payload, attestation_key="key")
    assert not report.evidence_complete
    assert report.risk_level == "UNKNOWN"


def test_result_file_remains_available_when_stdout_has_no_result_marker(tmp_path):
    payload = complete_payload()
    path = tmp_path / "results.json"
    path.write_text(json.dumps(payload))
    assert parse_probe_payload(path, "The probe completed; see the result file.") == payload
