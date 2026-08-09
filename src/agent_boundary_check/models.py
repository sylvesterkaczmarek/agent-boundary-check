from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


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
        return cls(
            capability=str(data["capability"]),
            status=ProbeStatus(str(data["status"])),
            detail=str(data.get("detail", "")),
        )


@dataclass
class RunReport:
    schema_version: int
    run_id: str
    agent: str
    agent_version: str | None
    platform: str
    probes: list[ProbeResult]
    risk_level: str
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
