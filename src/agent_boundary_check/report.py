from __future__ import annotations

import hashlib
import hmac
import json
import platform
import re
from pathlib import Path
from typing import Any

from .models import CAPABILITIES, OPTIONAL_RESOURCE_CAPABILITIES, ProbeResult, ProbeStatus, RunReport
from .policy import BoundaryPolicy, evaluate_policy

RESULT_PREFIX = "AGENT_BOUNDARY_RESULT="

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

_ALLOWED_TOP_LEVEL = {"schema_version", "run_id", "probe_platform", "probes", "attestation"}


def _parse_probe_output(output: str) -> tuple[bool, dict | None]:
    decoder = json.JSONDecoder()
    latest = None
    saw_marker = False
    cursor = 0
    while (index := output.find(RESULT_PREFIX, cursor)) >= 0:
        saw_marker = True
        # Even a malformed current result supersedes older evidence. Falling
        # back to a prior successful result would conceal a failed execution.
        latest = None
        cursor = index + len(RESULT_PREFIX)
        while cursor < len(output) and output[cursor].isspace():
            cursor += 1
        try:
            # Advance past the complete object, so marker text inside a probe
            # detail cannot be mistaken for a newer result.
            data, cursor = decoder.raw_decode(output, cursor)
            if isinstance(data, dict):
                latest = data
        except json.JSONDecodeError:
            continue
    return saw_marker, latest


def parse_probe_payload(results_path: Path, stdout: str, *, stderr: str = "") -> dict | None:
    # The process result belongs to the current execution. A retained result
    # file can belong to an earlier execution, especially when a write failed.
    stdout_marker, stdout_payload = _parse_probe_output(stdout)
    stderr_marker, stderr_payload = _parse_probe_output(stderr)
    if stdout_marker and stderr_marker:
        # Separately captured streams have no shared chronological order.
        # Conflicting or malformed results cannot establish the current state.
        return stdout_payload if stdout_payload == stderr_payload else None
    if stdout_marker:
        return stdout_payload
    if stderr_marker:
        return stderr_payload
    if results_path.exists():
        try:
            data = json.loads(results_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except (OSError, UnicodeError, json.JSONDecodeError):
            pass
    return None


def _canonical_for_attestation(payload: dict[str, Any]) -> bytes:
    body = {key: value for key, value in payload.items() if key != "attestation"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _validate_payload(
    payload: dict | None,
    *,
    expected_run_id: str,
    attestation_key: str | None,
) -> tuple[list[ProbeResult], str | None, str | None]:
    if payload is None:
        return _unknown_probes("probe result was not produced"), None, "probe result was not produced"
    if not isinstance(payload, dict):
        return _unknown_probes("probe payload was invalid"), None, "probe payload must be an object"
    if set(payload) - _ALLOWED_TOP_LEVEL:
        extra = ", ".join(sorted(set(payload) - _ALLOWED_TOP_LEVEL))
        return _unknown_probes("probe payload contained unexpected fields"), None, f"unexpected probe payload fields: {extra}"
    if type(payload.get("schema_version")) is not int or payload.get("schema_version") != 1:
        return _unknown_probes("probe schema did not match"), None, "probe schema version did not match"
    if payload.get("run_id") != expected_run_id:
        return _unknown_probes("probe run identifier did not match"), None, "probe run identifier did not match"

    if attestation_key is not None:
        signature = payload.get("attestation")
        if not isinstance(signature, str):
            return _unknown_probes("probe attestation was missing"), None, "probe attestation was missing"
        if re.fullmatch(r"[0-9a-f]{64}", signature) is None:
            return _unknown_probes("probe attestation did not validate"), None, "probe attestation did not validate"
        expected = hmac.new(
            attestation_key.encode("utf-8"),
            _canonical_for_attestation(payload),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return _unknown_probes("probe attestation did not validate"), None, "probe attestation did not validate"

    raw_probes = payload.get("probes")
    if not isinstance(raw_probes, list):
        return _unknown_probes("probe list was missing"), None, "probe payload has no probe list"

    parsed: dict[str, ProbeResult] = {}
    try:
        for item in raw_probes:
            probe = ProbeResult.from_dict(item)
            if probe.capability in parsed:
                raise ValueError(f"duplicate probe capability: {probe.capability}")
            parsed[probe.capability] = probe
    except (KeyError, TypeError, ValueError) as exc:
        return _unknown_probes("probe payload was invalid"), None, str(exc)

    missing = [name for name in CAPABILITIES if name not in parsed]
    probes = [
        parsed.get(name, ProbeResult(name, ProbeStatus.UNKNOWN, "probe did not report this capability"))
        for name in CAPABILITIES
    ]
    error = f"probe omitted capabilities: {', '.join(missing)}" if missing else None
    probe_platform = payload.get("probe_platform") if isinstance(payload.get("probe_platform"), str) else None
    return probes, probe_platform, error


def _unknown_probes(detail: str) -> list[ProbeResult]:
    return [ProbeResult(name, ProbeStatus.UNKNOWN, detail) for name in CAPABILITIES]


def risk_summary(probes: list[ProbeResult]) -> tuple[str, list[str]]:
    exposures = [p.capability for p in probes if p.status == ProbeStatus.ALLOW and p.capability in RISK]
    severities = {RISK[name] for name in exposures}
    if "critical" in severities:
        return "CRITICAL", exposures
    if "high" in severities:
        return "HIGH", exposures

    by_name = {p.capability: p for p in probes}
    if set(by_name) != set(CAPABILITIES) or len(by_name) != len(probes):
        return "UNKNOWN", exposures
    if any(
        p.status in {ProbeStatus.UNKNOWN, ProbeStatus.ERROR}
        or (p.status == ProbeStatus.ABSENT and p.capability not in OPTIONAL_RESOURCE_CAPABILITIES)
        for p in probes
    ):
        return "UNKNOWN", exposures
    if any(p.status == ProbeStatus.SKIPPED for p in probes):
        return "PARTIAL", exposures
    return "LOW", exposures


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
    attestation_key: str | None = None,
) -> RunReport:
    probes, probe_platform, payload_error = _validate_payload(
        payload,
        expected_run_id=run_id,
        attestation_key=attestation_key,
    )
    errors = [payload_error] if payload_error else []
    if timed_out:
        errors.append("agent runner timed out")
    elif exit_code not in (None, 0):
        errors.append(f"agent runner exited with status {exit_code}")
    if not payload_error:
        unusable = [
            f"{probe.capability} ({probe.status.value})"
            for probe in probes
            if probe.status in {ProbeStatus.UNKNOWN, ProbeStatus.ERROR}
        ]
        if unusable:
            errors.append(f"unusable probe evidence: {', '.join(unusable)}")
    evidence_error = "; ".join(errors) if errors else None

    level, exposures = risk_summary(probes)
    unusable_probe_state = any(
        probe.status in {ProbeStatus.UNKNOWN, ProbeStatus.ERROR} for probe in probes
    )
    if (evidence_error or unusable_probe_state) and level not in {"HIGH", "CRITICAL"}:
        level = "UNKNOWN"

    violations = evaluate_policy(probes, policy)
    if violations and level == "LOW":
        level = "HIGH"
    evidence_complete = evidence_error is None and not unusable_probe_state
    return RunReport(
        schema_version=1,
        run_id=run_id,
        agent=agent,
        agent_version=agent_version,
        platform=f"{platform.system()} {platform.machine()} / Python {platform.python_version()}",
        probe_platform=probe_platform,
        probes=probes,
        risk_level=level,
        evidence_complete=evidence_complete,
        evidence_error=evidence_error,
        exposures=exposures,
        policy_violations=violations,
        declared_hints=declared_hints,
        runner_exit_code=exit_code,
        runner_timed_out=timed_out,
        runner_output=runner_output[-4000:],
    )
