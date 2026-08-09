# Reproducibility

Each run gets a unique identifier and unique synthetic canary values. The operation set, result schema and risk mapping are deterministic for a given version of Agent Boundary Check.

Agent behavior itself may not be deterministic. To reduce model variance, the generated prompt asks the agent to execute one exact command and the actual capability checks are performed by deterministic local code.

For comparisons across machines or agent versions:

1. use the same Agent Boundary Check version;
2. use the same policy file;
3. record the agent version printed in the JSON report;
4. keep the same network-probe setting;
5. repeat an unexpected result before treating it as a regression.

The JSON report is the preferred machine-readable artifact for CI or longitudinal comparisons.

## Comparing runs

Use `agent-boundary diff before.json after.json` to compare effective capability states. A transition from a non-allow state to `allow` for a blast-radius capability is marked as a new exposure. This is useful after agent upgrades, sandbox changes or machine rebuilds.
