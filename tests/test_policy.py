from pathlib import Path

import pytest

from agent_boundary_check.models import ProbeResult, ProbeStatus
from agent_boundary_check.policy import evaluate_policy, load_policy


def test_policy_detects_forbidden_allow(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text('version = 1\ndeny = ["outside_read"]\nallow = ["workspace_read"]\n')
    policy = load_policy(path)
    violations = evaluate_policy(
        [
            ProbeResult("outside_read", ProbeStatus.ALLOW),
            ProbeResult("workspace_read", ProbeStatus.ALLOW),
        ],
        policy,
    )
    assert violations == ["outside_read: allowed but policy requires deny"]


def test_policy_rejects_overlap(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text('version = 1\ndeny = ["x"]\nallow = ["x"]\n')
    with pytest.raises(ValueError):
        load_policy(path)
