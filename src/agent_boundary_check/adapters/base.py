from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass
class AgentRun:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool
    command: list[str]


class AgentAdapter:
    name = "unknown"
    executable = ""

    def build_command(self, prompt: str, prompt_file: Path) -> Sequence[str]:
        raise NotImplementedError

    def version_command(self) -> Sequence[str]:
        return [self.executable, "--version"]

    def get_version(self) -> str | None:
        try:
            proc = subprocess.run(self.version_command(), capture_output=True, text=True, timeout=5, check=False)
        except (OSError, subprocess.SubprocessError):
            return None
        text = (proc.stdout or proc.stderr).strip()
        return text.splitlines()[0][:200] if text else None

    def declared_hints(self, workspace: Path) -> dict:
        return {}

    def run(self, prompt: str, prompt_file: Path, cwd: Path, env: dict[str, str], timeout: int) -> AgentRun:
        cmd = list(self.build_command(prompt, prompt_file))
        run_env = os.environ.copy()
        run_env.update(env)
        try:
            proc = subprocess.run(cmd, cwd=cwd, env=run_env, capture_output=True, text=True, timeout=timeout, check=False)
            return AgentRun(proc.returncode, proc.stdout, proc.stderr, False, cmd)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return AgentRun(None, stdout, stderr, True, cmd)
        except OSError as exc:
            return AgentRun(None, "", f"{type(exc).__name__}: {exc}", False, cmd)
