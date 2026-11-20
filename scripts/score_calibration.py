"""Score a complete calibration bundle offline against the predeclared design."""
import argparse
from collections import Counter
import json
from pathlib import Path

from agent_boundary_check.diffing import diff_reports
from agent_boundary_check.evidence_io import read_json
from agent_boundary_check.models import CAPABILITIES, ProbeStatus
from agent_boundary_check.policy import load_policy

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "calibration"


def fraction(count, total):
    # Wilson score interval; repetitions on the same host can be correlated.
    if total == 0:
        return {"count": count, "n": total, "rate": None, "wilson95": None}
    z = 1.95996398454
    rate = count / total
    centre = (rate + z*z/(2*total)) / (1 + z*z/total)
    width = z * (rate*(1-rate)/total + z*z/(4*total*total))**0.5 / (1+z*z/total)
    return {"count": count, "n": total, "rate": rate, "wilson95": [max(0, centre-width), min(1, centre+width)]}


def score(bundle):
    design = read_json(EXAMPLES / "design.json")
    policy = load_policy(EXAMPLES / "policy.toml")
    repeats = bundle["repetitions"]
    if bundle["protocol"] != design["protocol"] or type(repeats) is not int or not 1 <= repeats <= 100:
        raise ValueError("unsupported study protocol or repetitions")
    expected = {(r, case) for r in range(repeats) for case in design["cases"]}
    samples = {}
    counts = {"observer": Counter(), "status_only": Counter()}
    for sample in bundle["samples"]:
        key = (sample["repetition"], sample["case"])
        if type(key[0]) is not int or key not in expected or key in samples:
            raise ValueError("unexpected or repeated case")
        report = sample["report"]
        if report["agent"] != bundle["runner"] or report["agent_version"] != bundle["version"]:
            raise ValueError("runner identity mismatch")
        result = diff_reports(report, report, policy=policy)
        status = sample["runner_status"]
        if status not in {"completed", "runner_failed", "timed_out"}:
            raise ValueError("unknown runner outcome")
        control = sample["observer_control"]
        if control not in {"shared_principal", "protected", "inconclusive", "writable"}:
            raise ValueError("unknown observer control outcome")
        protected = control == "protected" if bundle["runner"] == "codex-sandbox" else control == "shared_principal"
        usable = status == "completed" and protected and not result.has_unusable_evidence
        verdict = ("violation" if result.after_policy_violations else "pass") if usable else "inconclusive"
        if sample["exit_code"] != {"pass": 0, "violation": 1, "inconclusive": 2}[verdict]:
            raise ValueError("stored exit code disagrees with evidence")
        driver = sample["driver_status"]
        if driver and (set(driver) != set(CAPABILITIES) or any(v not in set(ProbeStatus) for v in driver.values())):
            raise ValueError("invalid driver evidence")
        raw = driver.get(design["target"])
        baseline = "inconclusive"
        if status == "completed" and raw in ("allow", "deny") and driver.get("workspace_read") == "allow":
            baseline = "violation" if raw == "allow" else "pass"
        samples[key] = (verdict, baseline)
        for name, outcome in zip(counts, samples[key]):
            counter = counts[name]
            counter["conclusive"] += outcome != "inconclusive"
            counter["false_pass"] += design["cases"][key[1]] != "pass" and outcome == "pass"
    if samples.keys() != expected:
        raise ValueError("missing study cases")
    results = {}
    for index, (name, count) in enumerate(counts.items()):
        for repetition in range(repeats):
            for left, right, label in design["pairs"]:
                a, b = samples[(repetition, left)][index], samples[(repetition, right)][index]
                changed = a != b and "inconclusive" not in (a, b)
                if label == "change":
                    count["detected"] += a == "pass" and b == "violation"
                elif label == "unchanged":
                    count["false_alarm"] += changed
                elif label == "invalid_control":
                    count["invalid_pass"] += b == "pass"
        results[name] = {"coverage": fraction(count["conclusive"], len(samples)),
                         "change_detection": fraction(count["detected"], repeats),
                         "false_alarms": fraction(count["false_alarm"], repeats),
                         "false_pass_on_missing_control": fraction(count["invalid_pass"], repeats),
                         "false_pass_on_nonpassing_cases": fraction(count["false_pass"],
                             repeats * sum(v != "pass" for v in design["cases"].values()))}
    return {"protocol": design["protocol"], "runner": bundle["runner"], "version": bundle["version"],
            "samples": len(samples), "methods": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    # Sized for at most 400 small reports; use the bounded strict decoder.
    from agent_boundary_check.safe_files import read_regular_bytes
    from agent_boundary_check.evidence_io import decoder, validate_tree
    bundle = decoder().decode(read_regular_bytes(args.bundle, limit=8*1024*1024, strict_parents=False).decode())
    validate_tree(bundle)
    print(json.dumps(score(bundle), indent=2))


if __name__ == "__main__":
    main()
