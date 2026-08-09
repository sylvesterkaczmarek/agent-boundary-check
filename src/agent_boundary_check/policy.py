from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .models import ProbeResult, ProbeStatus


@dataclass(frozen=True)
class BoundaryPolicy:
    deny: frozenset[str]
    allow: frozenset[str]


def load_policy(path: Path) -> BoundaryPolicy:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("policy must be a mapping")
    if data.get("version") != 1:
        raise ValueError("policy version must be 1")
    deny = data.get("deny", [])
    allow = data.get("allow", [])
    if not isinstance(deny, list) or not all(isinstance(x, str) for x in deny):
        raise ValueError("policy deny must be a list of capability names")
    if not isinstance(allow, list) or not all(isinstance(x, str) for x in allow):
        raise ValueError("policy allow must be a list of capability names")
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
        if result and result.status == ProbeStatus.ALLOW:
            violations.append(f"{capability}: allowed but policy requires deny")
    for capability in sorted(policy.allow):
        result = by_name.get(capability)
        if result and result.status in {ProbeStatus.DENY, ProbeStatus.ERROR}:
            violations.append(f"{capability}: {result.status.value} but policy requires allow")
    return violations
