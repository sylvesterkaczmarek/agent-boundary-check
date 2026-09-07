from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .models import CAPABILITIES, RISKY_CAPABILITIES, ProbeResult
from .report import risk_summary


@dataclass(frozen=True)
class CapabilityChange:
    capability: str
    before: str
    after: str
    new_exposure: bool


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
    data = json.loads(path.read_text(encoding="utf-8"))
    _validate_report(data, source=str(path))
    return data


def _validate_report(data: dict, *, source: str) -> None:
    if (
        not isinstance(data, dict)
        or type(data.get("schema_version")) is not int
        or data.get("schema_version") != 1
    ):
        raise ValueError(f"unsupported report schema: {source}")
    probes = data.get("probes")
    if not isinstance(probes, list):
        raise ValueError(f"report has no probes: {source}")

    seen: set[str] = set()
    for item in probes:
        try:
            probe = ProbeResult.from_dict(item)
        except ValueError as exc:
            raise ValueError(f"report contains an invalid probe entry: {exc}: {source}") from exc
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
        if item["status"] in {"unknown", "error"}:
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


def diff_reports(before: dict, after: dict) -> ReportDiff:
    _validate_report(before, source="before report")
    _validate_report(after, source="after report")
    before_map = {str(item["capability"]): str(item["status"]) for item in before["probes"]}
    after_map = {str(item["capability"]): str(item["status"]) for item in after["probes"]}
    changes: list[CapabilityChange] = []
    for capability in CAPABILITIES:
        old = before_map.get(capability, "missing")
        new = after_map.get(capability, "missing")
        if old == new:
            continue
        new_exposure = capability in RISKY_CAPABILITIES and new == "allow" and old != "allow"
        changes.append(CapabilityChange(capability, old, new, new_exposure))
    before_issues = _evidence_issues(before)
    after_issues = _evidence_issues(after)
    after_issues.extend(
        f"{change.capability}: previously measured capability is now skipped"
        for change in changes
        if change.before in {"allow", "deny", "absent"} and change.after == "skipped"
    )
    return ReportDiff(
        before_agent=str(before.get("agent", "unknown")),
        after_agent=str(after.get("agent", "unknown")),
        before_version=before.get("agent_version"),
        after_version=after.get("agent_version"),
        before_risk=_risk_from_evidence(before, before_issues),
        after_risk=_risk_from_evidence(after, after_issues),
        changes=changes,
        before_evidence_issues=before_issues,
        after_evidence_issues=after_issues,
        before_policy_violations=list(before.get("policy_violations", [])),
        after_policy_violations=list(after.get("policy_violations", [])),
        before_skipped=[p["capability"] for p in before["probes"] if p["status"] == "skipped"],
        after_skipped=[p["capability"] for p in after["probes"] if p["status"] == "skipped"],
    )
