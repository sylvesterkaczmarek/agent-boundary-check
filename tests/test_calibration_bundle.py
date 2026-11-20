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
