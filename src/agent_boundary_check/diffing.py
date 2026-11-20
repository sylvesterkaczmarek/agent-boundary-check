from __future__ import annotations

from .evidence_io import read_json
from dataclasses import dataclass
from pathlib import Path

from .models import SKIPPABLE_CAPABILITIES, CAPABILITIES, RISKY_CAPABILITIES, ProbeResult
from .report import fixture_issue, risk_summary
from .observer import validate_observations
from .policy import BoundaryPolicy, evaluate_policy, parse_policy, policy_record


@dataclass(frozen=True)
class CapabilityChange:
    capability: str
    before: str
    after: str
    new_exposure: bool
    first_observation: bool = False
    before_reason: str | None = None
    after_reason: str | None = None


@dataclass(frozen=True)
class ReportDiff:
    before_agent: str
    after_agent: str
    before_version: str | None
    after_version: str | None
    before_risk: str
    after_risk: str
    changes: list[CapabilityChange]
    before_evidence_issues: list[str]
    after_evidence_issues: list[str]
    before_policy_violations: list[str]
    after_policy_violations: list[str]
    before_skipped: list[str]
    after_skipped: list[str]

    @property
    def has_new_exposure(self) -> bool:
        return any(change.new_exposure for change in self.changes)

    @property
    def has_unusable_evidence(self) -> bool:
        return bool(self.before_evidence_issues or self.after_evidence_issues)


def load_report(path: Path) -> dict:
    data = read_json(path)
    _validate_report(data, source=str(path))
    return data


def _validate_report(data: dict, *, source: str) -> None:
    if (
        not isinstance(data, dict)
        or type(data.get("schema_version")) is not int
        or data.get("schema_version") not in (1, 2)
    ):
        raise ValueError(f"unsupported report schema: {source}")
    if data["schema_version"] == 2:
        if data.get("fixture_profile") != "shared-files-v1":
            raise ValueError(f"unknown fixture profile: {source}")
        for key in ("run_id", "platform", "tool_path", "checker_version", "fixture_profile"):
            if not isinstance(data.get(key), str) or not data[key].strip():
                raise ValueError(f"missing {key}: {source}")
        validate_observations(data.get("host_observations"))
        if "policy" not in data:
            raise ValueError(f"missing policy provenance: {source}")
        if data["policy"] is not None:
            record = data["policy"]
            if not isinstance(record, dict):
                raise ValueError(f"invalid policy provenance: {source}")
            rules = parse_policy({k: v for k, v in record.items() if k != "sha256"})
            if policy_record(rules) != record:
                raise ValueError(f"policy digest or normalisation mismatch: {source}")
    probes = data.get("probes")
    if not isinstance(probes, list):
        raise ValueError(f"report has no probes: {source}")

    seen: set[str] = set()
    for item in probes:
        try:
            probe = ProbeResult.from_dict(item)
        except ValueError as exc:
            raise ValueError(f"report contains an invalid probe entry: {exc}: {source}") from exc
        if data["schema_version"] == 2 and probe.status.value == "skipped" and not probe.reason:
            raise ValueError(f"skip reason missing: {source}")
        capability = probe.capability
        if capability in seen:
            raise ValueError(f"report contains duplicate capability {capability}: {source}")
        seen.add(capability)
    missing = sorted(set(CAPABILITIES) - seen)
    if missing:
        raise ValueError(f"report is missing capabilities {', '.join(missing)}: {source}")
    if not isinstance(data.get("agent"), str) or not data["agent"]:
        raise ValueError(f"report has no valid agent: {source}")
    if data.get("agent_version") is not None and not isinstance(data["agent_version"], str):
        raise ValueError(f"report agent_version must be a string or null: {source}")
    if type(data.get("evidence_complete")) is not bool:
        raise ValueError(f"report evidence_complete must be a boolean: {source}")
    if data.get("evidence_error") is not None and not isinstance(data["evidence_error"], str):
        raise ValueError(f"report evidence_error must be a string or null: {source}")
    if data.get("runner_exit_code") is not None and type(data["runner_exit_code"]) is not int:
        raise ValueError(f"report runner_exit_code must be an integer or null: {source}")
    if type(data.get("runner_timed_out", False)) is not bool:
        raise ValueError(f"report runner_timed_out must be a boolean: {source}")
    violations = data.get("policy_violations", [])
    if not isinstance(violations, list) or any(not isinstance(v, str) for v in violations):
        raise ValueError(f"report policy_violations must be a list of strings: {source}")


def _evidence_issues(data: dict) -> list[str]:
    issues = []
    if data.get("evidence_error"):
        issues.append(data["evidence_error"])
    if data.get("runner_timed_out"):
        issues.append("agent runner timed out")
    elif data.get("runner_exit_code") not in (None, 0):
        issues.append(f"agent runner exited with status {data['runner_exit_code']}")
    for item in data["probes"]:
        if data["schema_version"] == 2:
            probe = ProbeResult.from_dict(item)
            issue = fixture_issue(probe, data["host_observations"])
            if issue:
                issues.append(f"{probe.capability}: {issue}")
            if probe.reason == "baseline_unavailable":
                issues.append(f"{probe.capability}: host prerequisite unavailable")
        if item["status"] in {"unknown", "error"} or (
            item["status"] == "skipped" and item["capability"] not in SKIPPABLE_CAPABILITIES
        ):
            issues.append(f"{item['capability']}: {item['status']}")
    if not data["evidence_complete"] and not issues:
        issues.append("report marks the probe evidence incomplete")
    return issues


def _risk_from_evidence(data: dict, issues: list[str]) -> str:
    # Persisted summaries can be stale or edited. Derive the displayed risk from
    # the validated observations and runner state, as make_report does.
    level, _ = risk_summary([ProbeResult.from_dict(item) for item in data["probes"]])
    if issues and level not in {"HIGH", "CRITICAL"}:
        level = "UNKNOWN"
    if data.get("policy_violations") and level == "LOW":
        level = "HIGH"
    return level


def _violations(data: dict, policy: BoundaryPolicy | None) -> list[str]:
    if policy is None:
        if data["schema_version"] == 1:
            return list(data.get("policy_violations", []))
        record = data["policy"]
        if record is None:
            return []
        policy = parse_policy({k: v for k, v in record.items() if k != "sha256"})
    return evaluate_policy([ProbeResult.from_dict(p) for p in data["probes"]], policy)


def assess_report(data: dict, *, policy: BoundaryPolicy | None = None) -> tuple[list[str], list[str]]:
    """Return evidence issues and policy violations for one recorded run."""
    _validate_report(data, source="report")
    issues = _evidence_issues(data)
    if policy is not None:
        if data["schema_version"] == 1 or data.get("policy") != policy_record(policy):
            issues.append("report lacks the required policy provenance")
        required = policy.allow | policy.deny
        for probe in data["probes"]:
            if probe["capability"] in required and probe["status"] == "skipped":
                issues.append(f"{probe['capability']}: required measurement skipped")
    return issues, _violations(data, policy)


def diff_reports(before: dict, after: dict, *, policy: BoundaryPolicy | None = None) -> ReportDiff:
    before_issues, before_violations = assess_report(before, policy=policy)
    after_issues, after_violations = assess_report(after, policy=policy)
    before_v2 = before["schema_version"] == 2
    after_v2 = after["schema_version"] == 2
    if before_v2 != after_v2:
        after_issues.append("legacy report lacks policy, tool and fixture provenance")
    comparable = before_v2 == after_v2
    if not before_v2 and not after_v2 and before.get("policy_violations") and not after.get("policy_violations"):
        after_issues.append("historical policy changed or violation resolved; legacy provenance unavailable")
    if before_v2 and after_v2:
        if before["run_id"] == after["run_id"]:
            comparable = False
            after_issues.append("the reports describe the same run; collect a fresh candidate")
        if before["policy"] != after["policy"]:
            after_issues.append("applied policy changed or was omitted")
        for field in ("tool_path", "fixture_profile", "agent", "platform", "probe_platform"):
            if before.get(field) != after.get(field):
                comparable = False
                after_issues.append(f"{field} changed; confirm comparability in a matched run")
    before_map = {item["capability"]: item for item in before["probes"]}
    after_map = {item["capability"]: item for item in after["probes"]}
    changes = []
    for capability in CAPABILITIES:
        left, right = before_map[capability], after_map[capability]
        old, new = left["status"], right["status"]
        old_reason, new_reason = left.get("reason"), right.get("reason")
        if old == new and old_reason == new_reason:
            continue
        allowed = capability in RISKY_CAPABILITIES and new == "allow"
        changes.append(CapabilityChange(capability, old, new, allowed and old == "deny" and comparable,
                                        allowed and (old != "deny" or not comparable), old_reason, new_reason))
        if old in {"allow", "deny", "absent"} and new == "skipped":
            after_issues.append(f"{capability}: previously measured capability is now skipped")
    return ReportDiff(
        before_agent=before["agent"],
        after_agent=after["agent"],
        before_version=before.get("agent_version"),
        after_version=after.get("agent_version"),
        before_risk=_risk_from_evidence({**before, "policy_violations": before_violations}, before_issues),
        after_risk=_risk_from_evidence({**after, "policy_violations": after_violations}, after_issues),
        changes=changes,
        before_evidence_issues=before_issues,
        after_evidence_issues=after_issues,
        before_policy_violations=before_violations,
        after_policy_violations=after_violations,
        before_skipped=[p["capability"] for p in before["probes"] if p["status"] == "skipped"],
        after_skipped=[p["capability"] for p in after["probes"] if p["status"] == "skipped"],
    )
