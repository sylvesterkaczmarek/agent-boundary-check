"""Run the published file-fixture conditions on an unprivileged POSIX host."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from agent_boundary_check.cli import main
from agent_boundary_check.diffing import load_report
from agent_boundary_check.evidence_io import read_json
from agent_boundary_check.lab import create_lab
from agent_boundary_check.report import parse_probe_payload

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "calibration"


def observer_control(prefix, workspace, root, env):
    # Positive and negative write controls run in the same sandbox invocation.
    # Only these two synthetic markers are in scope.
    outside = root / "observer-control-marker"
    inside = workspace / "positive-control-marker"
    script = """import errno, sys
from pathlib import Path
with Path(sys.argv[1]).open('x') as marker:
    marker.write('control')
try:
    with Path(sys.argv[2]).open('x') as marker:
        marker.write('control')
except OSError as exc:
    sys.exit(0 if exc.errno in (errno.EACCES, errno.EPERM, errno.EROFS) else 2)
sys.exit(1)
"""
    args = [*prefix, sys.executable, "-I", "-S", "-c", script, str(inside), str(outside)]
    try:
        result = subprocess.run(args, cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=30)
    except subprocess.TimeoutExpired:
        return "inconclusive"
    if outside.exists():
        return "writable"
    if result.returncode == 0 and inside.is_file() and inside.read_bytes() == b"control":
        return "protected"
    return "inconclusive"


def run_case(case, root, runner, executable, version):
    lab = create_lab(root / "lab", network_probe=False, socket_probe=False, environment_probe=False)
    source = lab.root / "outside" / "outside-canary.txt"
    cmd = [sys.executable, "-I", "-S", ".agent-boundary/probe_driver.py"]
    env = os.environ.copy()
    protection = "shared_principal"
    if runner == "codex-sandbox":
        # Only the fixture workspace is writable by the configured sandbox.
        # Observer files and the output bundle live outside it.
        env["CODEX_HOME"] = str(root / "codex-config")
        Path(env["CODEX_HOME"]).mkdir()
        prefix = [executable, "sandbox", "-c", 'sandbox_mode="workspace-write"', "--"]
        cmd = [*prefix, *cmd]
    try:
        if runner == "codex-sandbox":
            protection = observer_control(prefix, lab.workspace, root, env)
        if case.startswith("denied"):
            source.chmod(0)
        elif case == "missing":
            source.rename(root / "parked-canary")
        try:
            proc = subprocess.run(cmd, cwd=lab.workspace, env=env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
            runner_status = "completed" if proc.returncode == 0 else "runner_failed"
        except subprocess.TimeoutExpired:
            runner_status = "timed_out"
        finally:
            # Restore the host observer's access to the original file.
            if case.startswith("denied"):
                source.chmod(0o600)
        raw = parse_probe_payload(lab.results_path, "")
        path = root / "report.json"
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["collect", str(lab.root), "--tool-path", runner + "/python-driver",
                         "--policy", str(EXAMPLES / "policy.toml"), "--json", str(path)])
        report = load_report(path)
        # Give every captured run an identity, including a failed launcher.
        report.update(agent=runner, agent_version=version)
        if runner_status != "completed":
            report.update(evidence_complete=False, evidence_error=runner_status,
                          runner_exit_code=None if runner_status == "timed_out" else proc.returncode,
                          runner_timed_out=runner_status == "timed_out")
            code = 2
        if runner_status == "completed" and protection in {"inconclusive", "writable"}:
            report.update(evidence_complete=False, evidence_error="observer control " + protection)
            code = 2
        # Absolute paths can occur in diagnostics. Keep only structured states.
        for item in report["probes"]:
            item["detail"] = ""
        original = {p["capability"]: p["status"] for p in raw["probes"]} if raw else {}
        return {"case": case, "observer_control": protection, "runner_status": runner_status, "exit_code": code,
                "driver_status": original, "report": report}
    finally:
        lab.cleanup_home_canary()


def run(out, runner, expected, repeats):
    if os.name != "posix" or os.geteuid() == 0:
        raise ValueError("file-mode controls require an unprivileged POSIX identity")
    if not 1 <= repeats <= 100:
        raise ValueError("repeats must be between 1 and 100")
    design = read_json(EXAMPLES / "design.json")
    executable = shutil.which("codex") if runner == "codex-sandbox" else sys.executable
    if executable is None:
        raise ValueError("Codex CLI is unavailable")
    if runner == "codex-sandbox":
        version = subprocess.check_output([executable, "--version"], text=True, timeout=10).strip()
        if version != expected:
            raise ValueError(f"expected {expected!r}, found {version!r}")
    else:
        version = sys.version.split()[0]
    out.parent.mkdir(parents=True, exist_ok=True)
    samples = []
    for repetition in range(repeats):
        for case in design["cases"]:
            with tempfile.TemporaryDirectory(prefix="boundary-calibration-", dir=Path.home()) as directory:
                record = run_case(case, Path(directory), runner, executable, version)
                samples.append({**record, "repetition": repetition})
    bundle = {"protocol": design["protocol"], "runner": runner, "version": version,
              "repetitions": repeats, "samples": samples}
    with out.open("x", encoding="utf-8") as stream:
        json.dump(bundle, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--runner", choices=["local-posix", "codex-sandbox"], default="local-posix")
    parser.add_argument("--expect-version", help="exact codex --version output, required for Codex")
    parser.add_argument("--repeats", type=int, default=1)
    options = parser.parse_args()
    run(options.out, options.runner, options.expect_version, options.repeats)
