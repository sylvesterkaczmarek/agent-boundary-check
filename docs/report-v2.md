# Policy-aware release checks

Install the development checkout with `python -m pip install .`. Supply the same TOML policy when collecting the baseline and the candidate, then run:

```sh
agent-boundary diff baseline.json candidate.json --policy team-policy.toml
```

Exit 0 means the candidate satisfies the specified rules and the comparison found no newly granted risky capability. Exit 1 means a policy violation or newly granted risky capability. Exit 2 means the evidence cannot establish the comparison. Both reports are rescored. A release comparison requires two distinct v2 run identifiers. Supplying the same run in both positions returns exit 2. A previously failed baseline can be followed by a passing candidate once its permissions are corrected.

The report includes the normalised policy and its SHA-256 digest. Reordering rules or changing TOML formatting preserves identity. An omitted policy is recorded as null. Different applied policies, execution routes, agent identities, fixture profiles or host/probe platform strings require a matched run for a release verdict. Agent versions may differ. The checker version is recorded for study provenance. Custom commands carry a fingerprint of their argument template. For a GUI collector, supply a stable execution label using `collect --tool-path`. Its default manual label identifies only the Python-driver route.

| Observation | Interpretation |
| --- | --- |
| Risky denial followed by allowance | Newly observed permission change on a comparable route. |
| Skipped, absent or unknown followed by allowance | First observed access. Add `--review-first-access` to request review. Unusable evidence still takes precedence. |
| Host baseline unavailable | The prerequisite failed. A comparison exits 2 even if both probes have status `skipped`. |
| Same intentional skip in both reports | Outside the measured coverage. Explicitly required measurements still have to be usable. |

The host captures read-fixture identity and a digest of the expected contents at preparation. It records write-directory identity and expected marker content. During collection it reads only the expected synthetic paths with the existing safe-file helpers. A matching write marker corroborates a shared write. An absent marker alone cannot prove denial. A read fixture that disappeared, changed contents or was replaced, a changed write parent, and conflicting observations yield incomplete evidence. Positive evidence from a verified marker is retained when a runner reports denial. A sandbox with a private writable overlay can legitimately produce a different host view. This profile leaves that outcome inconclusive.

Manual preparation keeps the baseline beside the workspace. A successful collection records a receipt bound to the baseline, manifest and raw result. It permits rescoring the same run after home-fixture cleanup. An incomplete collection keeps its fixtures for diagnosis. Prepare a fresh lab if a pre-upgrade lab lacks a host baseline. Existing version 1 JSON reports remain readable for descriptive comparisons. Required-policy gates and mixed-version comparisons return inconclusive when historical provenance is missing.

The verifier runs as the calling user. Same-user access to the observer files limits what this evidence establishes about a hostile participant. A manifest digest correlates observations within a run. Independent enforcement requires a separately protected observer. Evidence records describe the requested invocation. A native editor, shell and remote service can have different permissions.

[Machine-readable schema](../examples/calibration/report-v2.schema.json) · [CI step](../examples/calibration/team-ci.yml) · [Study protocol](file-permission-pilot.md)
