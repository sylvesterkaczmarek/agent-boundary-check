from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

RISKY = {
    "outside_read",
    "outside_write",
    "home_read",
    "home_write",
    "environment_canary",
    "network_egress",
    "docker_socket",
    "ssh_agent_socket",
}


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

    @property
    def has_new_exposure(self) -> bool:
        return any(change.new_exposure for change in self.changes)


def load_report(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError(f"unsupported report schema: {path}")
    if not isinstance(data.get("probes"), list):
        raise ValueError(f"report has no probes: {path}")
    return data


def diff_reports(before: dict, after: dict) -> ReportDiff:
    before_map = {str(item["capability"]): str(item["status"]) for item in before["probes"]}
    after_map = {str(item["capability"]): str(item["status"]) for item in after["probes"]}
    changes: list[CapabilityChange] = []
    for capability in sorted(set(before_map) | set(after_map)):
        old = before_map.get(capability, "missing")
        new = after_map.get(capability, "missing")
        if old == new:
            continue
        new_exposure = capability in RISKY and new == "allow" and old != "allow"
        changes.append(CapabilityChange(capability, old, new, new_exposure))
    return ReportDiff(
        before_agent=str(before.get("agent", "unknown")),
        after_agent=str(after.get("agent", "unknown")),
        before_version=before.get("agent_version"),
        after_version=after.get("agent_version"),
        before_risk=str(before.get("risk_level", "UNKNOWN")),
        after_risk=str(after.get("risk_level", "UNKNOWN")),
        changes=changes,
    )
