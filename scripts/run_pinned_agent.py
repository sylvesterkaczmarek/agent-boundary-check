"""Collect a file-only report from a pinned, installed coding-agent CLI."""
import argparse
import json
from pathlib import Path

from agent_boundary_check.adapters import BUILTIN_ADAPTERS
from agent_boundary_check.cli import _has_unusable_evidence
from agent_boundary_check.policy import load_policy
from agent_boundary_check.runner import verify


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent", required=True, choices=sorted(BUILTIN_ADAPTERS))
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--expect-version", required=True, help="exact first line of --version")
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()
    adapter = BUILTIN_ADAPTERS[args.agent]()
    adapter.executable = str(args.executable.resolve(strict=True))
    if adapter.get_version() != args.expect_version:
        parser.error("installed CLI differs from the expected version")
    if args.output.exists() or args.output.resolve() == args.policy.resolve():
        parser.error("choose a new report filename")
    report, _ = verify(adapter, policy=load_policy(args.policy), timeout=args.timeout,
                       network_probe=False, socket_probe=False)
    if report.agent_version != args.expect_version:
        parser.error("CLI version changed before measurement")
    # Public bundles omit paths from hints and free-form probe diagnostics.
    data = report.to_dict()
    data["declared_hints"] = {}
    for item in data["probes"]:
        item["detail"] = ""
    if data["evidence_error"]:
        data["evidence_error"] = "insufficient evidence; see structured states and runner status"
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, sort_keys=True, indent=2)
        stream.write("\n")
    return 2 if _has_unusable_evidence(report) else int(bool(report.policy_violations))


if __name__ == "__main__":
    raise SystemExit(main())
