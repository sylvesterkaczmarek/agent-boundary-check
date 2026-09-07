# Reproducibility

Each run gets a unique identifier, unique synthetic canary values and a run-local evidence integrity key. The operation set, result schema and risk mapping are deterministic for a given version of Agent Boundary Check.

Agent behavior itself may not be deterministic. To reduce model variance, the generated prompt asks the agent to execute one exact command and the actual capability checks are performed by deterministic local code.

For comparisons across machines or agent versions:

1. use the same Agent Boundary Check version;
2. use the same policy file;
3. record the agent version printed in the JSON report;
4. keep the same network-probe setting;
5. compare host-baseline availability as well as agent results;
6. repeat an unexpected result in a fresh lab before treating it as a regression.

Network and Unix-socket results depend on the host baseline. A `SKIP` caused by a failed host baseline should not be compared as though it were a sandbox denial.

The JSON report is the preferred machine-readable artifact for CI or longitudinal comparisons. Configuration paths under the user's home directory are abbreviated with `~` in report hints to avoid leaking the local account name unnecessarily.

## Comparing runs

Use `agent-boundary diff before.json after.json` to compare effective capability states. A transition from a non-allow state to `allow` for a blast-radius capability is marked as a new exposure. This is useful after agent upgrades, sandbox changes or machine rebuilds.

Diff validates the report envelope and capability observations, then recomputes risk from those observations. A stored risk label cannot hide an exposure. Failed runners, incomplete evidence and policy violations remain visible even when capability states are unchanged.

| Exit code | Comparison outcome |
|---:|---|
| `0` | usable evidence, no new high-risk exposure and no policy violation in the newer report |
| `1` | new high-risk exposure or policy violation in the newer report |
| `2` | invalid/incomplete evidence in either report, failed runner, or loss of previously measured coverage through a new skip |

Unchanged deliberate skips, such as two runs with `--no-network`, are shown explicitly and do not alone cause exit code `2`. A successful comparison therefore does not imply every capability was tested.

## Local validation

The test suite isolates synthetic home directories and stubs host network/socket baselines. Subprocess and command-adapter tests use local synthetic runners, including timeout and child-process cases. CI also tests the installed wheel using tests shipped in the source distribution. These checks validate the tool's own behaviour; they do not establish the boundary of a real installed coding agent or exercise its provider APIs.
