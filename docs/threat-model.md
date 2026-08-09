# Threat model

## Goal

Measure the effective authority available to a coding-agent execution path without using real secrets or destructive actions.

## Protected assets

The tool treats the user's actual credentials, private files, repositories and external accounts as out of scope for active probing. Synthetic stand-ins are used instead.

## Probe constraints

The generated driver may:

- read or write its own synthetic files;
- read or write synthetic files outside the workspace that the tool created for the run;
- read one synthetic environment variable injected by the tool;
- create one short-lived child process;
- make a TCP connection to `example.com:443` without transmitting canary data;
- connect to a host-reachable Docker or SSH-agent Unix socket and immediately close it without sending protocol data.

It must not:

- read SSH private keys;
- read cloud credential files;
- query password stores or keychains;
- use browser sessions;
- call cloud/provider APIs with host credentials;
- send Docker API requests;
- send SSH-agent protocol requests;
- modify agent permissions or sandbox configuration;
- request elevated privileges.

Host-side baseline connections are made only so the tool can distinguish "the host cannot reach this resource" from "the agent execution path cannot reach this resource."

## Agent startup behavior

Running a real coding-agent CLI may activate hooks, plugins, MCP servers or other integrations already configured for that agent. Agent Boundary Check intentionally does not disable those integrations because doing so would change the runtime being measured. Users should therefore run the tool only with agent configurations they are already willing to start normally.

## Interpretation

The tool measures an execution path, not every possible path in an agent runtime. A product may apply different restrictions to native file tools, shell commands, MCP tools and browser/network tools. Those surfaces should be measured separately before making a broad deployment claim.

The run-local HMAC is an evidence-integrity check, not an adversarial security boundary. An agent that can inspect and modify the synthetic workspace can also inspect the synthetic integrity key.

An allowed capability describes exposure, not necessarily a vulnerability. Whether the exposure violates requirements belongs in an explicit policy.
