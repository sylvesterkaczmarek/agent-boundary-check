# Agent Boundary Check 0.2.0

This release strengthens boundary-evidence handling and synthetic-probe safety
without changing agent sandbox, approval or trust settings.

## Changes

- Bounded strict JSON parsing and captured runner output, with explicit incomplete results.
- Type-sensitive comparison of stdout and stderr evidence.
- Standalone manifest preflight before any probe side effect.
- Restricted synthetic file access, exclusive markers and explicit socket opt-out.
- Correct distinction between denied creation and failures after creation.
- Offline showcase, expanded regression coverage and verified public distributions.

## Review evidence

The original implementation suite contained 271 passing tests. A separate review
reproduced 16 failures in 39 new checks across three issue groups. All are repaired;
49 separate review cases are now included in a 328-test suite. Original failures
and valid controls remain preserved. All 17 earlier implementation findings were
also rerun before and after correction.

Public wheel and source packages are compared by hash with the verified build
and tested in fresh non-editable installations. See the attached review,
distribution.json, COMMIT.txt and SHA256SUMS.txt for provenance. CI includes
Linux Python 3.11-3.14, macOS and Windows, with explicit platform-specific skips.

## Scope

This release uses synthetic local fixtures. It does not certify any particular
agent sandbox, and no fresh live-agent inference session was performed. The HMAC
key is visible to an agent that controls the lab. Windows concurrent-path and
process-tree limitations, possible spool overshoot and single-path measurement
scope remain documented. Prepare a fresh lab after upgrading.
