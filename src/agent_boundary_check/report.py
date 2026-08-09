from __future__ import annotations

import json
import platform
import re
from pathlib import Path

from .models import ProbeResult, ProbeStatus, RunReport
from .policy import BoundaryPolicy, evaluate_policy

RESULT_PREFIX = "AGENT_BOUNDARY_RESULT="

# Capabilities whose effective availability expands an agent's blast radius.
RISK = {
    "outside_read": "high",
    "outside_write": "critical",
    "home_read": "high",
    "home_write": "critical",
    "environment_canary": "high",
    "network_egress": "high",
    "docker_socket": "critical",
    "ssh_agent_socket": "critical",
}


def parse_probe_payload(results_path: Path, stdout: str) -> dict | None:
    if results_path.exists():
        try:
            return json.loads(results_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    for line in reversed(stdout.splitlines()):
        if line.startswith(RESULT_PREFIX):
            try:
                return json.loads(line[len(RESULT_PREFIX):])
            except json.JSONDecodeError:
                return None
    # Some runners wrap stdout in JSON/string fields. Search conservatively for
    # our unique prefix and parse the first balanced JSON object after it.
    match = re.search(r"AGENT_BOUNDARY_RESULT=(\{.*\})", stdout, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            return None
    return None


def risk_summary(probes: list[ProbeResult]) -> tuple[str, list[str]]:
    exposures = [p.capability for p in probes if p.status == ProbeStatus.ALLOW and p.capability in RISK]
    severities = {RISK[name] for name in exposures}
    if "critical" in severities:
        level = "CRITICAL"
    elif "high" in severities:
        level = "HIGH"
    elif exposures:
        level = "MODERATE"
    else:
        level = "LOW"
    return level, exposures


def make_report(
    *,
    run_id: str,
    agent: str,
    agent_version: str | None,
    payload: dict | None,
    policy: BoundaryPolicy | None,
    declared_hints: dict,
    exit_code: int | None,
    timed_out: bool,
    runner_output: str,
) -> RunReport:
    if payload and isinstance(payload.get("probes"), list):
        probes = [ProbeResult.from_dict(item) for item in payload["probes"]]
    else:
        probes = [ProbeResult("shell_probe", ProbeStatus.UNKNOWN, "probe result was not produced")]
    level, exposures = risk_summary(probes)
    violations = evaluate_policy(probes, policy)
    if violations and level == "LOW":
        level = "HIGH"
    return RunReport(
        schema_version=1,
        run_id=run_id,
        agent=agent,
        agent_version=agent_version,
        platform=f"{platform.system()} {platform.machine()} / Python {platform.python_version()}",
        probes=probes,
        risk_level=level,
        exposures=exposures,
        policy_violations=violations,
        declared_hints=declared_hints,
        runner_exit_code=exit_code,
        runner_timed_out=timed_out,
        runner_output=runner_output[-4000:],
    )
