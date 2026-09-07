import hashlib
import hmac
import json
import sys
from types import SimpleNamespace

import pytest

from agent_boundary_check.adapters.base import AgentRun, _run_command
from agent_boundary_check.models import CAPABILITIES
from agent_boundary_check.report import RESULT_PREFIX
from agent_boundary_check.runner import verify


def signed_output(status):
    payload = {
        "schema_version": 1,
        "run_id": "synthetic-run",
        "probe_platform": "synthetic",
        "probes": [
            {"capability": name, "status": status if name == "outside_read" else "deny", "detail": ""}
            for name in CAPABILITIES
        ],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    payload["attestation"] = hmac.new(b"synthetic-key", canonical, hashlib.sha256).hexdigest()
    return RESULT_PREFIX + json.dumps(payload)


@pytest.fixture
def synthetic_lab(tmp_path, monkeypatch):
    lab = SimpleNamespace(
        workspace=tmp_path,
        run_id="synthetic-run",
        prompt="",
        prompt_path=tmp_path / "prompt",
        environment_token="synthetic-token",
        attestation_key="synthetic-key",
        results_path=tmp_path / "results.json",
        cleanup=lambda: None,
    )
    lab.results_path.write_text(signed_output("deny")[len(RESULT_PREFIX):])
    monkeypatch.setattr("agent_boundary_check.runner.create_lab", lambda **kwargs: lab)
    monkeypatch.setattr("agent_boundary_check.runner._init_git", lambda workspace: None)
    return lab


class SyntheticAdapter:
    name = "synthetic"

    def __init__(self, outcome):
        self.outcome = outcome

    def get_version(self):
        return None

    def declared_hints(self, workspace):
        return {}

    def run(self, *args):
        return self.outcome


def test_opposing_streams_cannot_reorder_old_success_over_new_exposure(synthetic_lab):
    earlier = signed_output("deny")
    later = signed_output("allow")
    source = (
        "import sys\n"
        f"print({earlier!r}, file=sys.stderr, flush=True)\n"
        f"print({later!r}, flush=True)\n"
    )
    outcome = _run_command([sys.executable, "-c", source])
    assert outcome.exit_code == 0
    report, _ = verify(SyntheticAdapter(outcome), network_probe=False)
    assert not report.evidence_complete
    assert report.risk_level == "UNKNOWN"


@pytest.mark.parametrize("stdout,stderr,expected", [
    (signed_output("allow"), signed_output("allow"), "HIGH"),
    (signed_output("allow"), "diagnostic text", "HIGH"),
    ("diagnostic text", signed_output("allow"), "HIGH"),
    (signed_output("deny"), signed_output("error"), "UNKNOWN"),
    (RESULT_PREFIX + "{incomplete", signed_output("deny"), "UNKNOWN"),
    (signed_output("deny"), RESULT_PREFIX + "[]", "UNKNOWN"),
    (RESULT_PREFIX + "{incomplete", "", "UNKNOWN"),
    ("", RESULT_PREFIX + "[]", "UNKNOWN"),
    ("No result marker", "diagnostic text", "LOW"),
])
def test_runner_selects_current_stream_evidence_without_stale_file_fallback(synthetic_lab, stdout, stderr, expected):
    outcome = AgentRun(0, stdout, stderr, False, ["synthetic"])
    report, _ = verify(SyntheticAdapter(outcome), network_probe=False)
    assert report.risk_level == expected
    assert report.evidence_complete is (expected != "UNKNOWN")
