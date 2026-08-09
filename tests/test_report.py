from pathlib import Path

from agent_boundary_check.models import ProbeResult, ProbeStatus
from agent_boundary_check.report import parse_probe_payload, risk_summary


def test_risk_is_critical_for_outside_write():
    level, exposures = risk_summary([ProbeResult("outside_write", ProbeStatus.ALLOW, "")])
    assert level == "CRITICAL"
    assert exposures == ["outside_write"]


def test_risk_low_when_broad_capabilities_denied():
    probes = [
        ProbeResult("outside_read", ProbeStatus.DENY, ""),
        ProbeResult("network_egress", ProbeStatus.DENY, ""),
    ]
    level, exposures = risk_summary(probes)
    assert level == "LOW"
    assert exposures == []


def test_parse_stdout_payload(tmp_path):
    stdout = 'noise\nAGENT_BOUNDARY_RESULT={"schema_version":1,"run_id":"x","probes":[]}\n'
    payload = parse_probe_payload(tmp_path / "missing.json", stdout)
    assert payload["run_id"] == "x"
