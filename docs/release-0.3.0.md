# Agent Boundary Check 0.3.0

Version 0.3.0 fixes a false policy pass that could occur when a test file went missing. The host now checks the fixture before the checker can conclude that access was denied.

## Try the published result

In a fresh Python 3.11 or later environment, run the following commands.

```sh
python -m pip install agent-boundary-check==0.3.0
agent-boundary replay
```

The wheel contains the original four Codex CLI 0.171.0 sandbox trials recorded on hosted macOS. The replay prints a violation for the successful outside read, a pass for each of the two genuine denials and an inconclusive verdict for the missing file. Add `--json` for the scored counts and denominators. Replay reads the saved observations offline.

## What changed

- Reports identify the applied policy, checker version and execution route. A release comparison requires distinct runs and compatible evidence.
- The comparison distinguishes a newly granted permission from access measured for the first time. Incomplete controls produce an inconclusive verdict.
- The calibration scorer rejects duplicated trial identifiers and mixed checker versions. Error rates identify how many cases could actually be measured.
- An optional Inspect task lets evaluators score recorded comparisons in their existing evaluation workflow.

## Evidence and scope

The pilot includes an end-to-end baseline with the published 0.2.0 checker, a Linux control with the development checker and four designed conditions for each of two pinned Codex sandbox versions on hosted macOS. A restricted Linux host also contributed four inconclusive sandbox trials. The new-version reference observations were collected with checker 0.3.0.dev0. This release rescores those original files.

The pilot measures the Codex sandbox command directly. Live model-backed evaluations and independent replications remain open. The four cases per version demonstrate the handling of a known failure and give no estimate of its frequency in deployment.

[Study protocol and data](https://github.com/sylvesterkaczmarek/agent-boundary-check/blob/v0.3.0/docs/file-permission-pilot.md) · [Hosted trial records](https://github.com/sylvesterkaczmarek/agent-boundary-check/actions/runs/44830101830) · [Report interpretation](https://github.com/sylvesterkaczmarek/agent-boundary-check/blob/v0.3.0/docs/report-v2.md) · [Cite this version](https://github.com/sylvesterkaczmarek/agent-boundary-check/blob/v0.3.0/CITATION.cff)

The release assets include the wheel, source distribution, commit identifier, calibration bundle, distribution verification and SHA-256 checksums.
