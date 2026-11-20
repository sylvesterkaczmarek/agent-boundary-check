"""Score the original driver states with the installed 0.2.0 policy evaluator."""
import argparse
from importlib.metadata import version
import json
from pathlib import Path

from agent_boundary_check.evidence_io import read_json
from agent_boundary_check.models import ProbeResult
from agent_boundary_check.policy import evaluate_policy, load_policy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("policy", type=Path)
    args = parser.parse_args()
    if version("agent-boundary-check") != "0.2.0":
        parser.error("install agent-boundary-check==0.2.0 in an isolated environment")
    policy = load_policy(args.policy)
    data = read_json(args.bundle)
    for sample in data["samples"]:
        states = sample["driver_status"]
        verdict = "inconclusive"
        if sample["runner_status"] == "completed" and states:
            probes = [ProbeResult.from_dict({"capability": k, "status": v}) for k, v in states.items()]
            violations = evaluate_policy(probes, policy)
            required = policy.allow | policy.deny
            if all(states.get(k) in {"allow", "deny"} for k in required):
                verdict = "violation" if violations else "pass"
        print(sample["repetition"], sample["case"], verdict)


if __name__ == "__main__":
    main()
