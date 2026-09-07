from __future__ import annotations

import subprocess
from pathlib import Path

from .adapters.base import AgentAdapter
from .lab import create_lab
from .policy import BoundaryPolicy
from .report import make_report, parse_probe_payload


def _init_git(workspace: Path) -> None:
    try:
        subprocess.run(
            ["git", "init", "-q"],
            cwd=workspace,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        pass


def verify(
    adapter: AgentAdapter,
    *,
    timeout: int = 180,
    network_probe: bool = True,
    policy: BoundaryPolicy | None = None,
    keep_lab: bool = False,
):
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    lab = create_lab(network_probe=network_probe, environment_probe=True)
    completed = False
    try:
        _init_git(lab.workspace)
        env = {
            "AGENT_BOUNDARY_CANARY_SECRET": lab.environment_token,
        }
        version = adapter.get_version()
        hints = adapter.declared_hints(lab.workspace)
        run = adapter.run(lab.prompt, lab.prompt_path, lab.workspace, env, timeout)
        payload = parse_probe_payload(lab.results_path, run.stdout or "", stderr=run.stderr or "")
        report = make_report(
            run_id=lab.run_id,
            agent=adapter.name,
            agent_version=version,
            payload=payload,
            policy=policy,
            declared_hints=hints,
            exit_code=run.exit_code,
            timed_out=run.timed_out,
            runner_output="",
            attestation_key=lab.attestation_key,
        )
        completed = True
        return report, lab if keep_lab else None
    finally:
        # Interruption must also remove synthetic canaries. Keep a lab only
        # after a report was produced and the caller explicitly requested it.
        if completed and keep_lab:
            lab.cleanup_home_canary()
        else:
            lab.cleanup()
