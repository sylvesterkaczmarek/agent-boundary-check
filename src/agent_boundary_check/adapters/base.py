from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time

from ..evidence_io import MAX_EVIDENCE_BYTES
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
    output_limited: bool = False


def _output_text(value: bytes | str | None) -> str:
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else (value or "")


def _stop_processes(proc: subprocess.Popen) -> None:
    """Stop only the process group created for this invocation on POSIX."""
    if os.name == "posix":
        # The group leader may have exited while a tool still has a pipe open.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif proc.poll() is None:
        # Windows taskkill can include descendants while their parent is alive.
        # Detached children and children of an already-exited parent are outside
        # this best-effort cleanup; this adapter does not implement a sandbox.
        try:
            subprocess.run(
                ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            pass
    if proc.poll() is None:
        proc.kill()
    proc.wait()


def _run_command(cmd: list[str], *, cwd: Path | None = None,
                 env: dict[str, str] | None = None, timeout: int = 5) -> AgentRun:
    if type(timeout) is not int or timeout < 1:
        raise ValueError("timeout must be a positive integer")
    # Files cannot deadlock waiting for EOF from a tool that inherited a pipe.
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            proc = subprocess.Popen(
                cmd,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=os.name == "posix",
            )
        except OSError as exc:
            return AgentRun(None, "", f"{type(exc).__name__}: {exc}", False, cmd)
        timed_out = False
        output_limited = False
        deadline = time.monotonic() + timeout
        try:
            while True:
                if any(os.fstat(stream.fileno()).st_size > MAX_EVIDENCE_BYTES for stream in (stdout_file, stderr_file)):
                    output_limited = True
                    break
                if proc.poll() is not None:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                try:
                    proc.wait(timeout=min(remaining, 0.05))
                except subprocess.TimeoutExpired:
                    continue
        finally:
            # Also clean up tools left behind after a normal exit or interruption.
            _stop_processes(proc)
        output_limited = output_limited or any(
            os.fstat(stream.fileno()).st_size > MAX_EVIDENCE_BYTES for stream in (stdout_file, stderr_file)
        )
        stdout_file.seek(0)
        stderr_file.seek(0)
        return AgentRun(
            None if timed_out else proc.returncode,
            _output_text(stdout_file.read(MAX_EVIDENCE_BYTES)),
            _output_text(stderr_file.read(MAX_EVIDENCE_BYTES)),
            timed_out,
            cmd,
            output_limited,
        )


def display_path(path: Path) -> str:
    """Return a report-safe path, abbreviating the current home directory."""
    try:
        resolved = path.expanduser().resolve()
        home = Path.home().expanduser().resolve()
        if resolved == home:
            return "~"
        if home in resolved.parents:
            return str(Path("~") / resolved.relative_to(home))
    except OSError:
        pass
    return str(path)


class AgentAdapter:
    name = "unknown"
    executable = ""

    def build_command(self, prompt: str, prompt_file: Path) -> Sequence[str]:
        raise NotImplementedError

    def version_command(self) -> Sequence[str]:
        return [self.executable, "--version"]

    def get_version(self) -> str | None:
        result = _run_command(list(self.version_command()), timeout=5)
        if result.timed_out or result.output_limited or result.exit_code != 0:
            return None
        text = (result.stdout or result.stderr).strip()
        return text.splitlines()[0][:200] if text else None

    def declared_hints(self, workspace: Path) -> dict:
        return {}

    def run(self, prompt: str, prompt_file: Path, cwd: Path, env: dict[str, str], timeout: int) -> AgentRun:
        cmd = list(self.build_command(prompt, prompt_file))
        run_env = os.environ.copy()
        run_env.update(env)
        return _run_command(cmd, cwd=cwd, env=run_env, timeout=timeout)
