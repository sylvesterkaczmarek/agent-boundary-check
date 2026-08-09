# Supported agents

Agent Boundary Check includes lightweight adapters for three command-line coding agents plus a generic command adapter.

The automatic adapters use each agent's non-interactive mode and close stdin so a CLI cannot accidentally wait for piped input. They do not add permission-bypass or sandbox-bypass flags.

## Codex CLI

```bash
agent-boundary verify codex
```

The adapter invokes `codex exec <prompt>`. It does not add flags that weaken approvals or sandboxing. Configuration hints are read from `$CODEX_HOME/config.toml` when `CODEX_HOME` is set, otherwise `~/.codex/config.toml`. Only narrow boundary metadata is reported, such as sandbox mode, approval policy, default permission profile, workspace-write network access and writable-root count.

## Claude Code

```bash
agent-boundary verify claude
```

The adapter uses Claude Code print mode with a bounded turn count. It never uses `--dangerously-skip-permissions`. It observes managed, user and workspace settings when present and reports only narrow permission/sandbox metadata and rule counts.

## Gemini CLI

```bash
agent-boundary verify gemini
```

The adapter uses non-interactive prompt mode with text output and does not enable `--yolo` or `--skip-trust`. It observes system, user and workspace settings when present and may report sandbox, sandbox-network, allowed-path, tool-sandboxing and folder-trust metadata.

If Gemini Folder Trust is enabled, a brand-new headless lab can be rejected as untrusted. Agent Boundary Check deliberately does not bypass that security gate. Trust the managed `~/.agent-boundary-check` parent explicitly if you want to measure Gemini in trusted-folder mode; otherwise the run returns insufficient evidence rather than silently changing the boundary.

## Generic command adapter

For an executable that accepts a prompt:

```bash
agent-boundary verify command \
  --command 'my-agent --prompt {prompt}'
```

The placeholders `{prompt}` and `{prompt_file}` are supported. If neither is present, the prompt is appended as the final argument. The command is split into arguments and executed directly; it is not passed through a shell.

## GUI and unsupported agents

Use manual mode:

```bash
agent-boundary prepare --output ./boundary-lab
```

Open `boundary-lab/workspace` in the agent, paste `.agent-boundary/PROMPT.txt`, let the agent run the one probe command, then:

```bash
agent-boundary collect ./boundary-lab
```

Manual mode cannot inject a transient environment variable into an already-running GUI agent, so the inherited-environment probe is `SKIP`. Other capabilities remain measurable through the deterministic driver.

## Probe runtime

The generated probe uses only the Python standard library, but a usable `python3` or `python` executable must exist inside the agent's execution environment. If an agent launches tools inside a container without Python, automatic evidence will be incomplete rather than interpreted as a denied capability.
