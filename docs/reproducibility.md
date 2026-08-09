# Reproducibility

Each run gets a unique identifier, unique synthetic canary values and a run-local evidence integrity key. The operation set, result schema and risk mapping are deterministic for a given version of Agent Boundary Check.

Agent behavior itself may not be deterministic. To reduce model variance, the generated prompt asks the agent to execute one exact command and the actual capability checks are performed by deterministic local code.

For comparisons across machines or agent versions:

1. use the same Agent Boundary Check version;
2. use the same policy file;
3. record the agent version printed in the JSON report;
4. keep the same network-probe setting;
5. compare host-baseline availability as well as agent results;
6. repeat an unexpected result before treating it as a regression.

Network and Unix-socket results depend on the host baseline. A `SKIP` caused by a failed host baseline should not be compared as though it were a sandbox denial.

The JSON report is the preferred machine-readable artifact for CI or longitudinal comparisons. Configuration paths under the user's home directory are abbreviated with `~` in report hints to avoid leaking the local account name unnecessarily.

## Comparing runs

Use `agent-boundary diff before.json after.json` to compare effective capability states. A transition from a non-allow state to `allow` for a blast-radius capability is marked as a new exposure. This is useful after agent upgrades, sandbox changes or machine rebuilds.
