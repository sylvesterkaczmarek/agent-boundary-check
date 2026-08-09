from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


CAPABILITIES = (
    "workspace_read",
    "workspace_write",
    "outside_read",
    "outside_write",
    "home_read",
    "home_write",
    "environment_canary",
    "child_process",
    "network_egress",
    "docker_socket",
    "ssh_agent_socket",
)

RISKY_CAPABILITIES = frozenset(
    {
        "outside_read",
        "outside_write",
        "home_read",
        "home_write",
        "environment_canary",
        "network_egress",
        "docker_socket",
        "ssh_agent_socket",
    }
)


class ProbeStatus(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    ABSENT = "absent"
    SKIPPED = "skipped"
    ERROR = "error"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ProbeResult:
    capability: str
    status: ProbeStatus
    detail: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProbeResult":
        if not isinstance(data, dict):
            raise ValueError("probe entry must be an object")
        capability = data.get("capability")
        if not isinstance(capability, str) or capability not in CAPABILITIES:
            raise ValueError(f"unknown probe capability: {capability!r}")
        try:
            status = ProbeStatus(str(data.get("status")))
        except ValueError as exc:
            raise ValueError(f"invalid status for {capability}: {data.get('status')!r}") from exc
        detail = data.get("detail", "")
        if not isinstance(detail, str):
            detail = str(detail)
        return cls(capability=capability, status=status, detail=detail[:1000])


@dataclass
class RunReport:
    schema_version: int
    run_id: str
    agent: str
    agent_version: str | None
    platform: str
    probe_platform: str | None
    probes: list[ProbeResult]
    risk_level: str
    evidence_complete: bool
    evidence_error: str | None = None
    exposures: list[str] = field(default_factory=list)
    policy_violations: list[str] = field(default_factory=list)
    declared_hints: dict[str, Any] = field(default_factory=dict)
    runner_exit_code: int | None = None
    runner_timed_out: bool = False
    runner_output: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["probes"] = [
            {"capability": p.capability, "status": p.status.value, "detail": p.detail}
            for p in self.probes
        ]
        return data
