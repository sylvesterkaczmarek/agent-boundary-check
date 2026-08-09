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
- create one child process;
- make a TCP connection to `example.com:443` without transmitting canary data;
- inspect accessibility metadata for Docker and SSH-agent sockets.

It must not:

- read SSH private keys;
- read cloud credential files;
- query password stores or keychains;
- use browser sessions;
- call cloud/provider APIs with host credentials;
- modify agent permissions or sandbox configuration;
- request elevated privileges;
- connect to Docker or SSH-agent sockets.

## Interpretation

The tool measures an execution path, not every possible path in an agent runtime. A product may apply different restrictions to native file tools, shell commands, MCP tools and browser/network tools. Those surfaces should be measured separately before making a broad deployment claim.

An allowed capability describes exposure, not necessarily a vulnerability. Whether the exposure violates requirements belongs in an explicit policy.
