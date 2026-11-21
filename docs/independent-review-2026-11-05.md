# Independent release verification

## Reviewed candidate

Candidate b5d0910f53095ebdbdb99fa9bc136fff2e35814a, version 0.2.0rc1.
The verification used a fresh full checkout and a new Python environment.
The candidate's existing 271 tests passed. A separately authored 39-case suite
returned 23 passes and 16 failures. These are grouped below, with original logs
preserved. Ten further positive/negative checks bring the review suite to 49.
Independent test design here is not external third-party certification.

## Findings and repairs

| Finding | Reproduction | Correction |
| --- | --- | --- |
| Type-coercing stream comparison | Conflicting schema values 1 versus true or 1.0 compared equal as Python dictionaries, allowing the valid stdout payload to conceal invalid stderr evidence. | Compare canonical JSON including scalar types. Ordering-only differences remain accepted. |
| Incomplete standalone manifest preflight | Duplicate/nonfinite JSON, boolean-like control values, invalid token/path types and mismatched workspace/outside targets could produce evidence or begin file operations before failing. | Validate strict JSON, all controls, token formats and prepared-layout paths before any probe; apply the same validation to manual collection. |
| Post-creation failure classified as denial | File creation and writing could succeed before a later PermissionError from flushing/closing was reported as denied write access. | Distinguish failure to create from failure after creation; the latter is inconclusive ERROR, never evidence of a denied boundary. |

The new manifest implementation uses only the standard library and is embedded
into the copied driver. It does not depend on an installed package inside the
measured environment. Optional fields introduced in newer labs retain documented
defaults, while malformed controls cannot be coerced to booleans. Host-home paths
bind to the run's synthetic layout rather than the agent's potentially remapped
HOME. This checks instructions; it does not authenticate an adversarially edited lab.

## Executed checks

- Full repaired source suite: 328 tests passed on the local Mac.
- Independent original file: all 39 checks pass unchanged after repair.
- Full separate review suite: all 49 checks pass.
- All 17 original implementation audit cases were reproduced as failures at
  base 112ed6904f151f27cae635d77c43a36124df76aa and pass after the repairs.
- The eight-case offline showcase passes. It distinguishes one actual local
  unsandboxed probe from deliberate evidence mutations.
- Real synthetic filesystem operations include exclusive creation, rejected
  aliases and POSIX parent replacement while the original directory is pinned.
- A local Unix socket owned solely by the test accepts a connection and confirms
  zero protocol bytes. No Docker daemon or real SSH agent is used.
- Eight additional release-verifier controls check identity, file sets, downloaded
  bytes, permitted host and transient registry propagation using synthetic data.
- Source and installed-distribution tests run separately; final CI outcomes and
  public-package hashes are attached to the release and PR rather than inferred.

The release workflow repeats exact-commit CI, verifies the built wheel/sdist,
uses the existing scoped PyPI trusted publisher, compares public PyPI hashes and
reruns the full installed suite on Python 3.11 and 3.14. It then creates a GitHub
release with those same files and verifies the public downloads again. Versions
and tags are not silently replaced. No password or long-lived API token is added.

## Unchanged scope

The tool measures a single configured execution path. No live model session,
paid inference, real credential read, external probe server or real host socket
was used during this review. Agent command lines and security settings are not
weakened. Live Codex/Claude/Gemini sandbox measurements remain unverified.

The HMAC is run-local integrity checking, not an adversarial trust boundary.
File and process lifecycle precautions do not create a sandbox. Output spooling
can overshoot between polling intervals and is not a hard disk quota. Windows
concurrent path replacement and detached-child cleanup retain their documented
limitations. Existing prepared labs should be replaced for fresh measurements.

Contributor PR #4 remains separate, unchanged and unmerged. Its substantive
cleanup-test patch was not incorporated into this release verification.
