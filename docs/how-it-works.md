# How it works

Agent Boundary Check separates **measurement** from **agent reasoning** as much as possible.

The agent receives one instruction: run the generated `probe_driver.py` exactly once. The driver is deterministic Python code copied into a synthetic workspace. Because that process is launched through the agent's normal shell/tool execution path, its observed filesystem, environment, process and network access are evidence about that effective path.

## Lab layout

Automatic runs use a private directory under the user's home directory rather than the operating system temporary directory:

```text
~/.agent-boundary-check/labs/<run>/
├── workspace/
│   ├── .agent-boundary/
│   │   ├── manifest.json
│   │   ├── probe_driver.py
│   │   └── PROMPT.txt
│   └── workspace-canary.txt
└── outside/
    └── outside-canary.txt

~/.agent-boundary-check/canaries/<run>/
├── home-canary.txt
└── ownership.json
```

The sibling `outside/` directory is deliberate. Putting the lab under `/tmp` or another operating-system temporary location can create false positives because some sandboxes grant special access to temporary directories.

Every canary value is random and synthetic. The raw inherited-environment token is not written to the manifest; only its SHA-256 digest is stored there. The manifest contains no host credentials.

## Evidence integrity

Each run has a random integrity key stored with the synthetic lab. `probe_driver.py` signs the canonical result payload with HMAC-SHA256, and automatic collection rejects a missing or invalid signature. Manual collection validates the same marker.

Automatic collection gives current process output precedence over a retained result file. The latest result in each stream is used; conflicting stdout and stderr results are inconclusive because separately captured streams have no shared chronological order. A malformed final result is inconclusive; it cannot fall back to a successful earlier attempt. Duplicate, missing or invalid capability observations also make evidence incomplete.

This is an integrity check for the measurement flow, not a trust boundary against a malicious agent. An agent with workspace read/write access can inspect or modify synthetic lab files. The project therefore does not claim tamper resistance against an adversarial agent.

## Host baselines

Network and Unix-socket checks can otherwise produce misleading denials when the host itself is offline or lacks access. Before the agent starts, the host process therefore checks whether it can:

- open a TCP connection to `example.com:443`;
- connect to the detected Docker Unix socket, if present;
- connect to the configured SSH-agent Unix socket, if present.

The agent-side probe is marked `SKIP` when the corresponding host baseline fails. Socket checks connect and immediately close without sending Docker or SSH-agent protocol data.

## Evidence states

- `allow`: the operation succeeded and was verified where practical
- `deny`: the operation was rejected, hidden or not accessible after any required baseline succeeded
- `absent`: an optional Docker or SSH-agent Unix socket was not configured or present; invalid for mandatory synthetic checks
- `skipped`: the probe was disabled or the host baseline made comparison inconclusive
- `error`: the probe reached an unexpected state or an inconclusive operational failure, including timeout, DNS failure or a refused connection
- `unknown`: usable evidence was not produced

The distinction matters. Missing evidence is never reported as a successful security boundary.

A missing synthetic path records observed invisibility as `deny`, but cannot distinguish sandbox hiding from concurrent deletion. Network and socket baselines can become stale between the host and agent checks, which is why later connection failures are inconclusive.

## File lifecycle

Canary markers and raw results use exclusive creation, preserving existing files and symlink targets. Run each prepared driver once and create a fresh lab for another measurement. Setup failures and interrupted automatic runs remove their own newly created artifacts. Automatic cleanup checks the captured directory identity; manual home-canary cleanup additionally checks a marker binding the run to its lab and integrity key. These checks prevent routine path redirection and mistaken cleanup, but do not add an adversarial trust boundary.

Incomplete manual collection preserves the home canary. Completed collection removes it when ownership is established, while leaving the prepared workspace available for inspection. Older labs without an ownership marker require manual canary cleanup or a fresh preparation.

## Agent adapters

Adapters do only three things:

1. identify an installed CLI;
2. run it non-interactively with the generated prompt;
3. collect narrow, non-secret configuration hints where supported.

Adapters close stdin for non-interactive execution and must not weaken the current sandbox or permission policy merely to make the probe complete.
