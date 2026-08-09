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
    try:
        _init_git(lab.workspace)
        env = {
            "AGENT_BOUNDARY_CANARY_SECRET": lab.environment_token,
        }
        version = adapter.get_version()
        hints = adapter.declared_hints(lab.workspace)
        run = adapter.run(lab.prompt, lab.prompt_path, lab.workspace, env, timeout)
        combined_output = (run.stdout or "") + ("\n" + run.stderr if run.stderr else "")
        payload = parse_probe_payload(lab.results_path, combined_output)
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
        lab.cleanup_home_canary()
        if not keep_lab:
            lab.cleanup()
        return report, lab if keep_lab else None
    except Exception:
        lab.cleanup()
        raise
