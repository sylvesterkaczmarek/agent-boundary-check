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
    assert violations == ["outside_read: allow but policy requires deny"]


def test_policy_fails_closed_on_unknown_or_skipped():
    policy_path = Path(__file__).parents[1] / "examples" / "strict-policy.toml"
    policy = load_policy(policy_path)
    violations = evaluate_policy(
        [
            ProbeResult("outside_read", ProbeStatus.UNKNOWN),
            ProbeResult("workspace_read", ProbeStatus.SKIPPED),
        ],
        policy,
    )
    assert "outside_read: unknown but policy requires deny" in violations
    assert "workspace_read: skipped but policy requires allow" in violations


def test_policy_accepts_absent_for_denied_optional_resource(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text('version = 1\ndeny = ["docker_socket"]\n')
    policy = load_policy(path)
    assert evaluate_policy([ProbeResult("docker_socket", ProbeStatus.ABSENT)], policy) == []


def test_policy_rejects_overlap(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text('version = 1\ndeny = ["outside_read"]\nallow = ["outside_read"]\n')
    with pytest.raises(ValueError):
        load_policy(path)


def test_policy_rejects_unknown_capability(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text('version = 1\ndeny = ["outside_reed"]\n')
    with pytest.raises(ValueError, match="unknown capabilities"):
        load_policy(path)


def test_policy_rejects_unknown_top_level_field(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_text('version = 1\ndney = ["outside_read"]\n')
    import pytest
    with pytest.raises(ValueError, match="unknown fields"):
        load_policy(path)


def test_policy_rejects_boolean_schema_version(tmp_path):
    path = tmp_path / "policy.toml"
    path.write_text('version = true\n')
    import pytest
    with pytest.raises(ValueError, match="version must be 1"):
        load_policy(path)


@pytest.mark.parametrize("capability", ["outside_read", "outside_write", "home_read", "environment_canary", "network_egress"])
def test_absent_does_not_satisfy_deny_for_required_probe(capability):
    from agent_boundary_check.policy import BoundaryPolicy

    policy = BoundaryPolicy(frozenset({capability}), frozenset())
    assert evaluate_policy([ProbeResult(capability, ProbeStatus.ABSENT)], policy) == [
        f"{capability}: absent but policy requires deny"
    ]


@pytest.mark.parametrize("required", ["allow", "deny"])
def test_duplicate_observations_cannot_hide_policy_failures(required):
    from agent_boundary_check.policy import BoundaryPolicy

    policy = BoundaryPolicy(
        frozenset({"outside_read"}) if required == "deny" else frozenset(),
        frozenset({"outside_read"}) if required == "allow" else frozenset(),
    )
    probes = [ProbeResult("outside_read", ProbeStatus.ERROR), ProbeResult("outside_read", ProbeStatus(required))]
    assert evaluate_policy(probes, policy) == [
        f"outside_read: reported more than once; policy requires {required}"
    ]
