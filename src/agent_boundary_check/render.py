from __future__ import annotations

from .models import ProbeStatus, RunReport


SYMBOL = {
    ProbeStatus.ALLOW: "ALLOW",
    ProbeStatus.DENY: "DENY",
    ProbeStatus.ABSENT: "N/A",
    ProbeStatus.SKIPPED: "SKIP",
    ProbeStatus.ERROR: "ERROR",
    ProbeStatus.UNKNOWN: "UNKNOWN",
}

FRIENDLY = {
    "workspace_read": "Workspace read",
    "workspace_write": "Workspace write",
    "outside_read": "Outside-workspace read",
    "outside_write": "Outside-workspace write",
    "home_read": "Synthetic home read",
    "home_write": "Synthetic home write",
    "environment_canary": "Inherited environment",
    "child_process": "Child process",
    "network_egress": "Network egress",
    "docker_socket": "Docker socket",
    "ssh_agent_socket": "SSH agent socket",
}


def render_report(report: RunReport) -> None:
    print()
    print(f"Agent Boundary Check  {report.risk_level}")
    version = f" · {report.agent_version}" if report.agent_version else ""
    print(f"{report.agent}{version}")
    print(f"Host: {report.platform}")
    if report.probe_platform:
        print(f"Probe: {report.probe_platform}")
    print()

    rows = [(FRIENDLY.get(p.capability, p.capability), SYMBOL[p.status], p.detail) for p in report.probes]
    cap_width = max([len("Capability"), *(len(r[0]) for r in rows)]) if rows else len("Capability")
    state_width = max([len("Effective"), *(len(r[1]) for r in rows)]) if rows else len("Effective")
    print(f"{'Capability':<{cap_width}}  {'Effective':<{state_width}}  Evidence")
    for capability, status, detail in rows:
        print(f"{capability:<{cap_width}}  {status:<{state_width}}  {detail}")

    hints = {k: v for k, v in report.declared_hints.items() if v not in (None, [], {}, "")}
    if hints:
        print("\nDeclared configuration hints")
        for key in sorted(hints):
            print(f"• {key}: {hints[key]}")

    if report.exposures:
        print("\nBlast-radius exposures")
        for item in report.exposures:
            print(f"• {FRIENDLY.get(item, item)}")
    if report.policy_violations:
        print("\nPolicy violations")
        for violation in report.policy_violations:
            print(f"• {violation}")
    if report.runner_timed_out:
        print("\nAgent runner timed out before the probe completed.")
    if report.evidence_error:
        print(f"\nEvidence incomplete: {report.evidence_error}")
