# Agent Boundary Check

![Agent Boundary Check](assets/social/github-social-card-agent-boundary-check.png)

[![CI](https://github.com/sylvesterkaczmarek/agent-boundary-check/actions/workflows/ci.yml/badge.svg)](https://github.com/sylvesterkaczmarek/agent-boundary-check/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/agent-boundary-check.svg)](https://pypi.org/project/agent-boundary-check/)
![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

**Your coding agent says it is sandboxed. Is it?**

Agent Boundary Check measures the effective execution boundary of AI coding agents with synthetic canaries. Instead of trusting configuration alone, it asks the agent to run one deterministic probe inside its normal execution path and reports what that process can actually read, write, execute and reach. The core CLI has zero runtime dependencies beyond Python 3.11+.

## At a glance

```bash
agent-boundary verify
```

If exactly one supported CLI is installed, it is selected automatically. Otherwise choose `codex`, `claude` or `gemini` explicitly.

Representative demo output from the checked-in deterministic runner:

```text
Agent Boundary Check  CRITICAL
demo-runner

Capability                 Effective   Evidence
Workspace read             ALLOW       synthetic canary was readable
Workspace write            ALLOW       synthetic marker write succeeded
Outside-workspace read     ALLOW       synthetic canary was readable
Outside-workspace write    ALLOW       synthetic marker write succeeded
Synthetic home read        ALLOW       synthetic canary was readable
Synthetic home write       ALLOW       synthetic marker write succeeded
Inherited environment      ALLOW       synthetic inherited environment value was visible
Child process              ALLOW       child process executed
Network egress             SKIP        network probe disabled
Docker socket              N/A         socket not configured
SSH agent socket           N/A         socket not configured

Blast-radius exposures
• Outside-workspace read
• Outside-workspace write
• Synthetic home read
• Synthetic home write
• Inherited environment
```

The demo is intentionally unsandboxed. It exists to exercise the measurement path, not to characterize any real coding agent.

## What it measures

The probe uses only resources it creates itself. It does **not** read your real SSH keys, cloud credentials, browser data or password stores.

It currently checks:

- read and write access inside the synthetic workspace
- read and write access outside that workspace
- read and write access to a synthetic canary under the user's home directory
- visibility of a synthetic inherited environment value
- child-process execution
- outbound TCP reachability to `example.com:443`, compared with a host-side baseline
- connectability of the Docker Unix socket when the host process can connect to it
- connectability of the configured SSH-agent Unix socket when the host process can connect to it

The network check opens a TCP connection only. Socket checks connect and immediately close without sending protocol data. No canary or credential data is transmitted. Use `--no-network` to skip external network probing.

## Why this is different

Static configuration tells you what a boundary is *supposed* to be. Agent Boundary Check measures one concrete execution path through the installed agent and records evidence from inside that path.

```text
agent config → coding-agent runner → agent shell/tool boundary → synthetic probe → evidence
```

This makes it useful for catching regressions after agent upgrades, comparing machines, validating team policies and checking whether a claimed sandbox boundary matches observed behavior.

## Supported agents

Automatic runners are included for:

- Codex CLI
- Claude Code
- Gemini CLI

The built-in adapters deliberately do not add permission-bypass, sandbox-bypass or YOLO flags. They exercise the agent with its current configuration.

For GUI agents or unsupported CLIs, use the manual `prepare` / `collect` flow. See [`docs/supported-agents.md`](docs/supported-agents.md).

## Install

For a standalone command-line installation, use pipx:

```bash
pipx install agent-boundary-check
```

Or install the package with pip:

```bash
python3 -m pip install agent-boundary-check
```

Then run:

```bash
agent-boundary --version
agent-boundary agents
```

### Install from source

If you prefer to install directly from the repository:

```bash
git clone https://github.com/sylvesterkaczmarek/agent-boundary-check.git
cd agent-boundary-check
python3 -m pip install .
```

Run a boundary measurement:

```bash
agent-boundary verify codex
agent-boundary verify claude
agent-boundary verify gemini
```

Try the deterministic demo without any AI account:

```bash
agent-boundary demo
```

Write a machine-readable report:

```bash
agent-boundary verify codex --json boundary.json
```

Compare reports after an agent upgrade or configuration change:

```bash
agent-boundary diff boundary-before.json boundary-after.json
```

A newly allowed high-risk capability is marked `NEW EXPOSURE` and returns exit code `1`.

Skip the external network probe:

```bash
agent-boundary verify codex --no-network
```

## Manual mode

For Cursor, another GUI coding agent, or any unsupported harness:

```bash
agent-boundary prepare --output ./boundary-lab
```

Open `boundary-lab/workspace` in the agent and paste the generated prompt from:

```text
boundary-lab/workspace/.agent-boundary/PROMPT.txt
```

Then collect the evidence:

```bash
agent-boundary collect ./boundary-lab
```

The prompt instructs the agent to run exactly one checked probe and not to request broader permissions. Manual mode cannot inject a new environment variable into an already-running GUI agent, so the inherited-environment check is reported as `SKIP` rather than incorrectly reported as denied.

## Boundary policies

Turn measurements into CI gates with a small TOML policy:

```toml
version = 1

allow = ["workspace_read", "workspace_write", "child_process"]
deny = [
  "outside_read",
  "outside_write",
  "home_read",
  "home_write",
  "environment_canary",
  "network_egress",
  "docker_socket",
  "ssh_agent_socket",
]
```

Run it with:

```bash
agent-boundary verify codex --policy examples/strict-policy.toml --json boundary.json
```

A policy violation returns exit code `1`. Missing or unusable probe evidence returns `2`.

## Safety model

Agent Boundary Check is designed to test boundaries without touching genuine secrets:

1. it creates unique synthetic canaries;
2. automatic labs live under `~/.agent-boundary-check/labs/`, not the operating system temporary directory, so special temp-directory permissions do not masquerade as normal outside-workspace access;
3. the agent is instructed not to inspect anything else;
4. the probe refers only to synthetic paths and values in the generated manifest; the raw inherited-environment token is represented there only by a one-way hash;
5. result payloads carry a run-local integrity marker and are validated before use;
6. it never uses an agent's dangerous permission-bypass flags;
7. external network and Unix-socket results are compared with host-side reachability before a denial is claimed;
8. home-directory canaries are deleted after automatic verification or collection;
9. raw secret values are not collected from the host.

See [`docs/threat-model.md`](docs/threat-model.md).

## What the result means

An `ALLOW` result means the agent-executed probe process successfully exercised that capability during this run. A `DENY` result means the probe process could not exercise it after any required host baseline succeeded. `N/A`, `SKIP`, `ERROR` and `UNKNOWN` are kept distinct so absence of evidence is not silently turned into a security claim.

`LOW` is used only when risky capabilities were actually denied or absent. `PARTIAL` means at least one risky probe was intentionally or baseline-skipped. `UNKNOWN` means required evidence was missing or invalid.

A high blast-radius rating is **not automatically a vulnerability**. Some users intentionally run agents with broad authority. The report describes effective exposure; a policy determines whether that exposure is acceptable for a particular environment.

## What this repository does not claim

- It does not prove that every tool path exposed by an agent has the same permissions as the tested execution path.
- The run-local integrity marker catches malformed or casually fabricated output, but it is not a cryptographic trust boundary against an adversarial agent that can read and modify its synthetic workspace.
- Automatic mode runs in a synthetic workspace, so project-local agent configuration may differ; use manual mode inside the target project when that configuration is part of the boundary.
- It does not test model alignment, prompt-injection resistance or malware detection.
- It does not read or validate real credentials.
- It does not prove that a sandbox is secure against kernel, container-runtime or agent implementation vulnerabilities.
- A denied probe is evidence for this run and configuration, not a universal guarantee.
- Running a real agent may activate hooks, plugins, MCP servers or other startup integrations already configured for that agent. Agent Boundary Check does not disable them because doing so would change the environment being measured.
- The deterministic probe requires a usable `python3` or `python` executable inside the agent's execution environment. A containerized sandbox without Python will produce insufficient evidence rather than a false deny.
- Docker and SSH-agent socket checks currently cover Unix sockets on macOS/Linux. Windows named pipes are reported as `SKIP`, not as absent or denied.
- Gemini Folder Trust is not bypassed. If it is enabled and the generated headless lab is not already trusted, Gemini can refuse the run; that is reported as incomplete evidence rather than overridden with `--skip-trust`.

## Development

```bash
python3 -m pip install -e '.[dev]'
pytest -q
agent-boundary demo
```

## Repository layout

```text
agent-boundary-check/
├── .github/workflows/       # CI
├── assets/social/           # repository social card
├── docs/                    # method, threat model, policies and agent notes
├── examples/                # example boundary policy
├── src/agent_boundary_check/# CLI, adapters, lab and reporting
├── tests/                   # unit, safety and end-to-end tests
├── CITATION.cff
├── LICENSE
├── Makefile
├── pyproject.toml
└── README.md
```

## Cite this repository

If you use or adapt this repository, please cite:

> Kaczmarek, S. (2026). *Agent Boundary Check*. GitHub. https://github.com/sylvesterkaczmarek/agent-boundary-check

```bibtex
@software{Kaczmarek_2026_Agent_Boundary_Check,
  author = {Sylvester Kaczmarek},
  title  = {{Agent Boundary Check}},
  year   = {2026},
  url    = {https://github.com/sylvesterkaczmarek/agent-boundary-check}
}
```

## License

MIT. See [LICENSE](LICENSE).

© **Sylvester Kaczmarek** · [https://www.sylvesterkaczmarek.com](https://www.sylvesterkaczmarek.com)
