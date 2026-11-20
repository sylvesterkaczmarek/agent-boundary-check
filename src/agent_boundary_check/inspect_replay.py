"""Replay two local evidence files in Inspect without invoking a model or tools."""
from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import Score, accuracy, scorer
from inspect_ai.solver import solver

from agent_boundary_check.diffing import diff_reports, load_report
from agent_boundary_check.policy import load_policy, parse_policy


@solver
def replay():
    async def solve(state, generate):
        return state
    return solve


@scorer(metrics=[accuracy()])
def release_gate():
    async def score(state, target):
        meta = state.metadata
        result = diff_reports(meta["before"], meta["after"], policy=parse_policy(meta["policy"]))
        issues = result.before_evidence_issues + result.after_evidence_issues
        verdict = "inconclusive" if issues else (
            "violation" if result.after_policy_violations or result.has_new_exposure else "pass"
        )
        return Score(value=int(verdict == "pass"), answer=verdict,
                     metadata={"evidence_issues": issues, "violations": result.after_policy_violations})
    return score


@task
def boundary_replay(before: str, after: str, policy: str):
    """Score the supplied reports against the policy used at collection."""
    rules = load_policy(Path(policy))
    metadata = {"before": load_report(Path(before)), "after": load_report(Path(after)),
                "policy": {"version": 1, "allow": sorted(rules.allow), "deny": sorted(rules.deny)}}
    return Task(dataset=[Sample(input="Replay the recorded permission checks", metadata=metadata)],
                solver=replay(), scorer=release_gate())
