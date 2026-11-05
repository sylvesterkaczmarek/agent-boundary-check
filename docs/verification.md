# Reproducible verification

## Source checkout

Use Python 3.11 or newer in a fresh virtual environment. From the checkout:

```bash
python -m pip install -e '.[dev]'
python -m pytest -q
python -m ruff check src scripts tests
python scripts/showcase.py --out /tmp/boundary-showcase-new
```

The showcase requires a new output directory. It uses one unsandboxed process
against synthetic fixtures in a temporary home, then applies controlled evidence
mutations. It prints eight outcomes and writes summary.json. It does not invoke
an AI account, query a live service, discover host sockets or characterize a real
agent's sandbox. The first observation shows exposure; the policy case rejects
that exposure; the remaining cases demonstrate evidence-integrity handling.

## Installed package

Build and verify in an environment with Python 3.12 or newer:

```bash
python -m pip install build twine
python -m build
python -m twine check --strict dist/*
python scripts/verify_distribution.py dist/*.whl dist/*.tar.gz --report /tmp/boundary-package-proof.json
```

The verifier compares wheel and source-distribution identity and runtime bytes,
creates an independent environment, installs the wheel non-editably, and runs
the entire source-distribution test suite and showcase outside the checkout.
The runtime still has no third-party dependencies. Test/build tools are separate.

CI exercises Linux on Python 3.11 through 3.14 and portability jobs on macOS and
Windows. The final package job depends on all runtime jobs. Python and operating
system support must be reported from actual job outcomes, including platform
skips, rather than inferred from source compatibility.

## Live-agent measurement

Live sessions remain a separate optional step because starting a real CLI may
activate its existing account, hooks and integrations. After reviewing that
configuration, an operator may run:

```bash
agent-boundary verify codex --no-network --no-sockets --json codex-boundary.json
```

These options disable probe TCP/socket checks, not the agent's own account
traffic. No sandbox, approval or folder-trust settings are changed. An incomplete
result must remain incomplete. Do not add bypass flags to make a test succeed.
A blocked command or absent interpreter does not prove all operations are denied.

Official references checked on 5 November 2026:

- Codex noninteractive execution: https://developers.openai.com/codex/noninteractive/
- Claude Code CLI reference: https://code.claude.com/docs/en/cli-reference
- Gemini headless execution: https://geminicli.com/docs/cli/headless/
- Gemini folder trust: https://geminicli.com/docs/cli/trusted-folders/

The local Codex help supported the existing exec invocation. Claude and Gemini
were assessed with synthetic adapter fixtures and documentation only.
