# Supported agents

Agent Boundary Check includes lightweight adapters for three command-line coding agents plus a generic command adapter.

## Codex CLI

```bash
agent-boundary verify codex
```

The adapter invokes `codex exec` and does not add flags that bypass approvals or sandboxing. If `~/.codex/config.toml` exists, the report includes a narrow set of non-secret boundary hints such as the configured sandbox and approval mode when those fields are present.

## Claude Code

```bash
agent-boundary verify claude
```

The adapter uses Claude Code print mode and a bounded turn count. It never uses `--dangerously-skip-permissions`. Detected settings files are reported, and only narrow permission metadata is extracted.

## Gemini CLI

```bash
agent-boundary verify gemini
```

The adapter uses headless prompt mode and does not enable `--yolo`. When settings are present, the report may include sandbox, sandbox-network and tool-sandboxing hints.

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

This makes the core measurement method usable without building a bespoke adapter first.
