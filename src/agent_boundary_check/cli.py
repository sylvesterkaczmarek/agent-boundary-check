from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from . import __version__
from .adapters import BUILTIN_ADAPTERS, detect_agents, get_adapter
from .adapters.command import CommandAdapter
from .diffing import diff_reports, load_report
from .lab import RUN_ID_RE, cleanup_home_canary_for_run, create_lab
from .models import ProbeStatus
from .policy import load_policy
from .render import render_report, safe_text
from .report import make_report, parse_probe_payload
from .runner import verify


def _error(message: str) -> None:
    print(f"error: {safe_text(message)}", file=sys.stderr)


def _resolve_path(path: Path, *, strict: bool = False) -> Path:
    try:
        return path.expanduser().resolve(strict=strict)
    except RuntimeError as exc:  # Symlink loops on Python 3.11 and 3.12.
        raise ValueError(f"could not resolve path: {path}") from exc


def _validate_output(path: Path | None, protected: tuple[Path, ...] = ()) -> None:
    if path is None:
        return
    path = path.expanduser()
    try:
        resolved = _resolve_path(path, strict=True)
    except FileNotFoundError:
        resolved = _resolve_path(path)
    for source in protected:
        source = source.expanduser()
        if resolved == _resolve_path(source) or (path.exists() and source.exists() and path.samefile(source)):
            raise ValueError(f"report output would overwrite an input file: {source}")


def _write_json(report, path: Path | None, protected: tuple[Path, ...] = ()) -> None:
    if path:
        path = path.expanduser()
        _validate_output(path, protected)
        content = json.dumps(report.to_dict(), indent=2, sort_keys=True, allow_nan=False) + "\n"
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n", dir=path.parent,
                prefix=f".{path.name}.", suffix=".tmp", delete=False,
            ) as stream:
                temporary = Path(stream.name)
                stream.write(content)
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _has_unusable_evidence(report) -> bool:
    runner_failed = report.runner_timed_out or report.runner_exit_code not in (None, 0)
    return runner_failed or not report.evidence_complete or bool(report.evidence_error) or any(
        probe.status in {ProbeStatus.UNKNOWN, ProbeStatus.ERROR} for probe in report.probes
    )


def cmd_agents(args) -> int:
    rows = []
    for name, cls in BUILTIN_ADAPTERS.items():
        path = shutil.which(cls.executable)
        rows.append((name, "yes" if path else "no", path or "-"))
    name_w = max(len("Agent"), *(len(r[0]) for r in rows))
    installed_w = max(len("Installed"), *(len(r[1]) for r in rows))
    print(f"{'Agent':<{name_w}}  {'Installed':<{installed_w}}  Executable")
    for name, installed, path in rows:
        print(f"{name:<{name_w}}  {installed:<{installed_w}}  {path}")
    return 0


def _policy(args):
    return load_policy(Path(args.policy).expanduser()) if getattr(args, "policy", None) else None


def _require_installed_builtin(agent_name: str) -> None:
    adapter_cls = BUILTIN_ADAPTERS.get(agent_name)
    if adapter_cls is None:
        return
    if shutil.which(adapter_cls.executable) is None:
        raise ValueError(
            f"{agent_name} CLI is not installed or not on PATH; "
            "run 'agent-boundary agents' to see detected agents"
        )


def cmd_verify(args) -> int:
    try:
        protected = (Path(args.policy),) if args.policy else ()
        output = Path(args.json) if args.json else None
        _validate_output(output, protected)
        policy = _policy(args)
        agent_name = args.agent
        if agent_name == "auto":
            detected = detect_agents()
            if not detected:
                raise ValueError("no supported coding agent detected; run 'agent-boundary agents' or use manual mode")
            if len(detected) > 1:
                raise ValueError(f"multiple supported agents detected ({', '.join(detected)}); choose one explicitly")
            agent_name = detected[0]
        _require_installed_builtin(agent_name)
        adapter = get_adapter(agent_name, args.command)
        report, lab = verify(
            adapter,
            timeout=args.timeout,
            network_probe=not args.no_network,
            policy=policy,
            keep_lab=args.keep_lab,
        )
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        _error(str(exc))
        return 2
    render_report(report)
    try:
        _write_json(report, output, protected)
    except (ValueError, OSError) as exc:
        _error(str(exc))
        return 2
    if lab:
        print(f"\nLab retained at {lab.root}")
    if _has_unusable_evidence(report):
        return 2
    if report.policy_violations:
        return 1
    return 0


def cmd_demo(args) -> int:
    command = f'"{sys.executable}" .agent-boundary/probe_driver.py'
    adapter = CommandAdapter(command)
    report, _ = verify(adapter, timeout=30, network_probe=False, policy=None, keep_lab=False)
    report.agent = "demo-runner"
    render_report(report)
    try:
        _write_json(report, Path(args.json) if args.json else None)
    except OSError as exc:
        _error(str(exc))
        return 2
    return 2 if _has_unusable_evidence(report) else 0


def cmd_prepare(args) -> int:
    try:
        lab = create_lab(Path(args.output), network_probe=not args.no_network, environment_probe=False)
    except (ValueError, OSError) as exc:
        _error(str(exc))
        return 2
    print(f"Prepared synthetic boundary lab at {lab.root}")
    print(f"Workspace: {lab.workspace}")
    print(f"Prompt: {lab.prompt_path}")
    print("\nOpen the workspace in your coding agent, paste the prompt, then run:")
    print(f"agent-boundary collect {lab.root}")
    return 0


def cmd_collect(args) -> int:
    root = _resolve_path(Path(args.lab))
    manifest_path = root / "workspace" / ".agent-boundary" / "manifest.json"
    results_path = root / "workspace" / ".agent-boundary" / "results.json"
    try:
        protected = tuple(manifest_path.parent / name for name in (
            "manifest.json", "results.json", "probe_driver.py", "PROMPT.txt",
        )) + ((Path(args.policy),) if args.policy else ())
        output = Path(args.json) if args.json else None
        _validate_output(output, protected)
        if not manifest_path.exists():
            raise ValueError("lab manifest not found")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if not isinstance(manifest, dict):
            raise ValueError("lab manifest must be a mapping")
        if type(manifest.get("schema_version")) is not int or manifest.get("schema_version") != 1:
            raise ValueError("lab manifest schema version did not match")
        run_id = manifest.get("run_id")
        if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
            raise ValueError("lab manifest has no valid run identifier")
        attestation_key = manifest.get("attestation_key")
        if not isinstance(attestation_key, str) or not attestation_key:
            raise ValueError("lab manifest has no valid attestation key")
        protected += tuple(
            Path(manifest[key]) for key in (
                "workspace_read_path", "workspace_write_path", "outside_read_path",
                "outside_write_path", "home_read_path", "home_write_path",
            ) if isinstance(manifest.get(key), str)
        )
        _validate_output(output, protected)
        if output is not None:
            canary_directory = _resolve_path(Path.home() / ".agent-boundary-check" / "canaries" / run_id)
            if _resolve_path(output).is_relative_to(canary_directory):
                raise ValueError("report output cannot be inside the home canary directory scheduled for cleanup")
        payload = parse_probe_payload(results_path, "")
        report = make_report(
            run_id=run_id,
            agent="manual",
            agent_version=None,
            payload=payload,
            policy=_policy(args),
            declared_hints={},
            exit_code=None,
            timed_out=False,
            runner_output="",
            attestation_key=attestation_key,
        )
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        _error(str(exc))
        return 2

    render_report(report)
    try:
        _write_json(report, output, protected)
    except (ValueError, OSError) as exc:
        _error(str(exc))
        if not _has_unusable_evidence(report):
            cleanup_home_canary_for_run(run_id, lab_root=root, attestation_key=attestation_key)
        return 2
    if _has_unusable_evidence(report):
        return 2
    cleanup_home_canary_for_run(run_id, lab_root=root, attestation_key=attestation_key)
    if report.policy_violations:
        return 1
    return 0


def cmd_diff(args) -> int:
    try:
        before = load_report(Path(args.before))
        after = load_report(Path(args.after))
        result = diff_reports(before, after)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        _error(str(exc))
        return 2
    print("Agent Boundary Diff")
    print(f"Agent: {safe_text(result.before_agent)} -> {safe_text(result.after_agent)}")
    print(f"Version: {safe_text(result.before_version or '-')} -> {safe_text(result.after_version or '-')}")
    print(f"Risk: {result.before_risk} -> {result.after_risk}")
    for label in ("before", "after"):
        for issue in getattr(result, f"{label}_evidence_issues"):
            print(f"{label} evidence incomplete: {safe_text(issue)}")
        skipped = getattr(result, f"{label}_skipped")
        if skipped:
            print(f"{label} skipped checks: {', '.join(skipped)}")
        for violation in getattr(result, f"{label}_policy_violations"):
            print(f"{label} policy violation: {safe_text(violation)}")
    if not result.changes:
        print("\nNo capability changes.")
    else:
        print("\nCapability changes")
        for change in result.changes:
            suffix = "  NEW EXPOSURE" if change.new_exposure else ""
            print(f"• {change.capability}: {change.before} -> {change.after}{suffix}")
    if result.has_unusable_evidence:
        return 2
    return 1 if result.has_new_exposure or result.after_policy_violations else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-boundary",
        description="Verify the effective execution boundary of AI coding agents using synthetic canaries.",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command_name", required=True)

    agents = sub.add_parser("agents", help="show supported agents detected on this machine")
    agents.set_defaults(func=cmd_agents)

    verify_p = sub.add_parser("verify", help="run a synthetic boundary probe through a coding agent")
    verify_p.add_argument("agent", nargs="?", default="auto", choices=["auto", *BUILTIN_ADAPTERS.keys(), "command"])
    verify_p.add_argument("--command", help="custom command template; supports {prompt} and {prompt_file}")
    verify_p.add_argument("--timeout", type=_positive_int, default=180)
    verify_p.add_argument("--no-network", action="store_true", help="skip the TCP egress probe")
    verify_p.add_argument("--policy", help="optional TOML boundary policy")
    verify_p.add_argument("--json", help="write machine-readable report")
    verify_p.add_argument("--keep-lab", action="store_true", help="retain the synthetic workspace after the run")
    verify_p.set_defaults(func=cmd_verify)

    demo = sub.add_parser("demo", help="run a deterministic local demo without an AI account")
    demo.add_argument("--json", help="write machine-readable report")
    demo.set_defaults(func=cmd_demo)

    prepare = sub.add_parser("prepare", help="prepare a manual lab for unsupported or GUI coding agents")
    prepare.add_argument("--output", required=True, help="empty directory to create")
    prepare.add_argument("--no-network", action="store_true")
    prepare.set_defaults(func=cmd_prepare)

    collect = sub.add_parser("collect", help="collect results from a manually-run boundary lab")
    collect.add_argument("lab")
    collect.add_argument("--policy")
    collect.add_argument("--json")
    collect.set_defaults(func=cmd_collect)

    diff_p = sub.add_parser("diff", help="compare two JSON boundary reports")
    diff_p.add_argument("before")
    diff_p.add_argument("after")
    diff_p.set_defaults(func=cmd_diff)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, OSError, UnicodeError) as exc:
        _error(str(exc))
        return 2
    except KeyboardInterrupt:
        _error("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
