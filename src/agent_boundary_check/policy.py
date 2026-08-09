from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .models import CAPABILITIES, ProbeResult, ProbeStatus


@dataclass(frozen=True)
class BoundaryPolicy:
    deny: frozenset[str]
    allow: frozenset[str]


def _validate_capabilities(values: list[str], field: str) -> None:
    unknown = sorted(set(values) - set(CAPABILITIES))
    if unknown:
        raise ValueError(f"policy {field} contains unknown capabilities: {', '.join(unknown)}")
    if len(values) != len(set(values)):
        raise ValueError(f"policy {field} contains duplicate capability names")


def load_policy(path: Path) -> BoundaryPolicy:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("policy must be a mapping")
    unknown_fields = sorted(set(data) - {"version", "deny", "allow"})
    if unknown_fields:
        raise ValueError(f"policy contains unknown fields: {', '.join(unknown_fields)}")
    if type(data.get("version")) is not int or data.get("version") != 1:
        raise ValueError("policy version must be 1")
    deny = data.get("deny", [])
    allow = data.get("allow", [])
    if not isinstance(deny, list) or not all(isinstance(x, str) for x in deny):
        raise ValueError("policy deny must be a list of capability names")
    if not isinstance(allow, list) or not all(isinstance(x, str) for x in allow):
        raise ValueError("policy allow must be a list of capability names")
    _validate_capabilities(deny, "deny")
    _validate_capabilities(allow, "allow")
    overlap = set(deny) & set(allow)
    if overlap:
        raise ValueError(f"capabilities cannot be both allowed and denied: {', '.join(sorted(overlap))}")
    return BoundaryPolicy(frozenset(deny), frozenset(allow))


def evaluate_policy(probes: list[ProbeResult], policy: BoundaryPolicy | None) -> list[str]:
    if policy is None:
        return []
    violations: list[str] = []
    by_name = {p.capability: p for p in probes}
    for capability in sorted(policy.deny):
        result = by_name.get(capability)
        if result is None:
            violations.append(f"{capability}: not reported; policy requires deny")
        elif result.status not in {ProbeStatus.DENY, ProbeStatus.ABSENT}:
            violations.append(f"{capability}: {result.status.value} but policy requires deny")
    for capability in sorted(policy.allow):
        result = by_name.get(capability)
        if result is None:
            violations.append(f"{capability}: not reported; policy requires allow")
        elif result.status != ProbeStatus.ALLOW:
            violations.append(f"{capability}: {result.status.value} but policy requires allow")
    return violations
