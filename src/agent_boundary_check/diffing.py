from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .models import CAPABILITIES, RISKY_CAPABILITIES, ProbeStatus


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
    if (
        not isinstance(data, dict)
        or type(data.get("schema_version")) is not int
        or data.get("schema_version") != 1
    ):
        raise ValueError(f"unsupported report schema: {path}")
    probes = data.get("probes")
    if not isinstance(probes, list):
        raise ValueError(f"report has no probes: {path}")

    seen: set[str] = set()
    for item in probes:
        if not isinstance(item, dict):
            raise ValueError(f"report contains an invalid probe entry: {path}")
        capability = item.get("capability")
        status = item.get("status")
        if not isinstance(capability, str) or capability not in CAPABILITIES:
            raise ValueError(f"report contains an unknown capability {capability!r}: {path}")
        if capability in seen:
            raise ValueError(f"report contains duplicate capability {capability}: {path}")
        seen.add(capability)
        try:
            ProbeStatus(str(status))
        except ValueError as exc:
            raise ValueError(f"report contains invalid status {status!r} for {capability}: {path}") from exc
    missing = sorted(set(CAPABILITIES) - seen)
    if missing:
        raise ValueError(f"report is missing capabilities {', '.join(missing)}: {path}")
    return data


def diff_reports(before: dict, after: dict) -> ReportDiff:
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
    return ReportDiff(
        before_agent=str(before.get("agent", "unknown")),
        after_agent=str(after.get("agent", "unknown")),
        before_version=before.get("agent_version"),
        after_version=after.get("agent_version"),
        before_risk=str(before.get("risk_level", "UNKNOWN")),
        after_risk=str(after.get("risk_level", "UNKNOWN")),
        changes=changes,
    )
