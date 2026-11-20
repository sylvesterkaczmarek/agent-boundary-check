import copy
import json
from pathlib import Path
import runpy

import pytest

ROOT = Path(__file__).resolve().parents[1]
score = runpy.run_path(str(ROOT / "scripts/score_calibration.py"))["score"]


@pytest.mark.parametrize("file", [
    "codex-calibration-0.171.0-macos.json",
    "codex-calibration-0.172.0-alpha.2-macos.json",
])
def test_pinned_sandbox_runs(file):
    bundle = json.loads((ROOT/"verification"/file).read_text())
    assert all(s["observer_control"] == "protected" for s in bundle["samples"])
    result = score(bundle)
    assert result["methods"]["observer"]["coverage"]["count"] == 3
    assert result["methods"]["observer"]["false_pass_on_missing_control"]["count"] == 0


def test_original_release_policy_passes_missing_fixture():
    bundle = json.loads((ROOT/"verification/calibration-legacy.json").read_text())
    assert score(bundle)["methods"]["released_0.2.0"]["false_pass_on_missing_control"]["count"] == 1


def test_scoring_retains_missing_and_failed_runs():
    for file, coverage in [("calibration-local.json", 3), ("calibration-codex-restricted-host.json", 0)]:
        bundle = json.loads((ROOT/"verification"/file).read_text())
        result = score(bundle)
        assert result["methods"]["observer"]["coverage"]["count"] == coverage
        assert result["samples"] == 4
        assert result["methods"]["observer"]["false_pass_on_missing_control"]["count"] == 0
        if coverage:
            assert result["methods"]["status_only"]["false_pass_on_missing_control"]["count"] == 1
        invalid = copy.deepcopy(bundle)
        invalid["samples"].pop()
        with pytest.raises(ValueError, match="missing"):
            score(invalid)


def test_copy_of_denied_trial_cannot_stand_in_for_a_repeat():
    bundle = json.loads((ROOT / "verification/calibration-local.json").read_text())
    cases = {s["case"]: s for s in bundle["samples"]}
    cases["denied_repeat"]["report"] = copy.deepcopy(cases["denied"]["report"])
    with pytest.raises(ValueError, match="distinct run"):
        score(bundle)


def test_unavailable_runs_keep_detection_denominator_and_leave_error_rates_undefined():
    bundle = json.loads((ROOT / "verification/calibration-codex-restricted-host.json").read_text())
    result = score(bundle)
    for metrics in result["methods"].values():
        assert metrics["change_detection"]["n"] == 1
        assert metrics["unchanged_pair_coverage"]["rate"] == 0
        for key in ("false_alarms", "false_pass_on_missing_control", "false_pass_on_nonpassing_cases"):
            assert metrics[key] == {"count": 0, "n": 0, "rate": None, "wilson95": None}


def test_different_checker_versions_cannot_be_pooled():
    bundle = json.loads((ROOT / "verification/calibration-local.json").read_text())
    bundle["samples"][-1]["report"]["checker_version"] = "other"
    with pytest.raises(ValueError, match="checker version"):
        score(bundle)


def test_installed_reference_inputs_match_originals():
    from agent_boundary_check.calibration import DEFAULT_BUNDLE, REFERENCE

    for filename in ("design.json", "policy.toml"):
        assert (REFERENCE / filename).read_bytes() == (ROOT / "examples/calibration" / filename).read_bytes()
    assert DEFAULT_BUNDLE.read_bytes() == (ROOT / "verification" / DEFAULT_BUNDLE.name).read_bytes()


def test_offline_replay_from_empty_directory(monkeypatch, tmp_path, capsys):
    from agent_boundary_check.cli import main

    monkeypatch.chdir(tmp_path)
    assert main(["replay"]) == 0
    summary = capsys.readouterr().out
    for case, verdict in (("allowed", "VIOLATION"), ("denied", "PASS"),
                          ("missing", "INCONCLUSIVE"), ("denied_repeat", "PASS")):
        assert any(line.split() == ["trial", "1", case, verdict] for line in summary.splitlines())
    assert main(["replay", "--json"]) == 0
    metrics = json.loads(capsys.readouterr().out)["methods"]["observer"]
    assert metrics["intact_case_coverage"]["count"] == metrics["intact_case_coverage"]["n"] == 3
    assert metrics["false_pass_on_missing_control"]["count"] == 0


def test_replay_rejects_incomplete_user_bundle(tmp_path, capsys):
    from agent_boundary_check.cli import main

    bundle = tmp_path / "incomplete.json"
    bundle.write_text('{"samples":[]}', encoding="utf-8")
    assert main(["replay", str(bundle)]) == 2
    output = capsys.readouterr()
    assert "error:" in output.err
    assert not output.out
