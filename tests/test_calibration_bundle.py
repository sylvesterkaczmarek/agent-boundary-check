import copy
import json
from pathlib import Path
import runpy

import pytest

ROOT = Path(__file__).resolve().parents[1]
score = runpy.run_path(str(ROOT / "scripts/score_calibration.py"))["score"]


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
