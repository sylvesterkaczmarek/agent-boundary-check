"""Score a complete calibration bundle offline against the predeclared design."""
from collections import Counter
import json
from pathlib import Path

from agent_boundary_check.diffing import assess_report
from agent_boundary_check.evidence_io import decoder, read_json, validate_tree
from agent_boundary_check.models import CAPABILITIES, ProbeResult, ProbeStatus
from agent_boundary_check.policy import evaluate_policy, load_policy
from agent_boundary_check.render import safe_text
from agent_boundary_check.safe_files import read_regular_bytes

REFERENCE = Path(__file__).with_name("reference")
DEFAULT_BUNDLE = REFERENCE / "codex-calibration-0.171.0-macos.json"


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
    design = read_json(REFERENCE / "design.json")
    policy = load_policy(REFERENCE / "policy.toml")
    repeats = bundle["repetitions"]
    if bundle["protocol"] != design["protocol"] or type(repeats) is not int or not 1 <= repeats <= 100:
        raise ValueError("unsupported study protocol or repetitions")
    expected = {(r, case) for r in range(repeats) for case in design["cases"]}
    samples = {}
    run_ids = set()
    checker_version = bundle.get("checker_version")
    if bundle["runner"] not in {"local-posix", "codex-sandbox"}:
        raise ValueError("unknown calibration runner")
    legacy = bundle.get("checker_version") == "0.2.0"
    method = "released_0.2.0" if legacy else "observer"
    counts = {method: Counter(), "status_only": Counter()}
    for sample in bundle["samples"]:
        key = (sample["repetition"], sample["case"])
        if type(key[0]) is not int or key not in expected or key in samples:
            raise ValueError("unexpected or repeated case")
        report = sample["report"]
        if report["agent"] != bundle["runner"] or report["agent_version"] != bundle["version"]:
            raise ValueError("runner identity mismatch")
        if report["schema_version"] != (1 if legacy else 2):
            raise ValueError("checker and report schema disagree")
        issues, violations = assess_report(report, policy=None if legacy else policy)
        run_id = report.get("run_id")
        if not isinstance(run_id, str) or not run_id.strip() or run_id in run_ids:
            raise ValueError("each trial requires a distinct run identifier")
        run_ids.add(run_id)
        if not legacy:
            if checker_version is None:
                checker_version = report["checker_version"]
            if report["checker_version"] != checker_version:
                raise ValueError("checker version differs across the bundle")
        if legacy:
            recomputed = evaluate_policy([ProbeResult.from_dict(p) for p in report["probes"]], policy)
            if recomputed != violations:
                raise ValueError("legacy policy outcome differs from study contract")
        status = sample["runner_status"]
        if status not in {"completed", "runner_failed", "timed_out"}:
            raise ValueError("unknown runner outcome")
        control = sample["observer_control"]
        if control not in {"shared_principal", "protected", "inconclusive", "writable"}:
            raise ValueError("unknown observer control outcome")
        protected = control == "protected" if bundle["runner"] == "codex-sandbox" else control == "shared_principal"
        usable = status == "completed" and protected and not issues
        verdict = ("violation" if violations else "pass") if usable else "inconclusive"
        if type(sample["exit_code"]) is not int or sample["exit_code"] != {"pass": 0, "violation": 1, "inconclusive": 2}[verdict]:
            raise ValueError("stored exit code disagrees with evidence")
        driver = sample["driver_status"]
        if not isinstance(driver, dict):
            raise ValueError("invalid driver observations")
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
            measured = status == "completed" and (protected if name == method else bool(driver))
            expected_verdict = design["cases"][key[1]]
            if expected_verdict == "inconclusive":
                counter["measured_invalid"] += measured
            else:
                counter["intact"] += 1
                counter["conclusive_intact"] += outcome != "inconclusive"
            if expected_verdict != "pass":
                counter["measured_nonpassing"] += measured
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
                    count["unchanged_decidable"] += "inconclusive" not in (a, b)
                    count["false_alarm"] += changed
                elif label == "invalid_control":
                    count["invalid_pass"] += b == "pass"
        results[name] = {"coverage": fraction(count["conclusive"], len(samples)),
                         "change_detection": fraction(count["detected"], repeats),
                         "intact_case_coverage": fraction(count["conclusive_intact"], count["intact"]),
                         "unchanged_pair_coverage": fraction(count["unchanged_decidable"], repeats),
                         "false_alarms": fraction(count["false_alarm"], count["unchanged_decidable"]),
                         "false_pass_on_missing_control": fraction(count["invalid_pass"], count["measured_invalid"]),
                         "false_pass_on_nonpassing_cases": fraction(count["false_pass"],
                             count["measured_nonpassing"])}
    return {"protocol": design["protocol"], "runner": bundle["runner"], "version": bundle["version"],
            "samples": len(samples), "methods": results}


def replay(path: Path, *, summary: bool) -> None:
    # Sized for up to 400 reports in the study design.
    try:
        raw = read_regular_bytes(path, limit=8 * 1024 * 1024, strict_parents=False)
        bundle = decoder().decode(raw.decode("utf-8"))
        validate_tree(bundle)
        result = score(bundle)
    except (KeyError, TypeError, IndexError, AttributeError, RecursionError) as exc:
        raise ValueError(f"invalid calibration bundle: {exc}") from exc
    if not summary:
        print(json.dumps(result, indent=2))
        return
    print(f"{result['runner']} ({safe_text(result['version'])}) | {result['samples']} trials")
    verdicts = {0: "PASS", 1: "VIOLATION", 2: "INCONCLUSIVE"}
    for sample in bundle["samples"]:
        print(f"  trial {sample['repetition'] + 1}  {sample['case']:<14} {verdicts[sample['exit_code']]}")
    for name, metrics in result["methods"].items():
        intact = metrics["intact_case_coverage"]
        missed = metrics["false_pass_on_missing_control"]
        false_passes = f"{missed['count']}/{missed['n']}" if missed["n"] else "unmeasured"
        print(f"{name}: intact cases decided {intact['count']}/{intact['n']}, "
              f"false passes on missing fixtures {false_passes}")
