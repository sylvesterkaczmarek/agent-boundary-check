from pathlib import Path

import pytest

from agent_boundary_check.adapters import get_adapter
from agent_boundary_check.adapters.claude import ClaudeAdapter
from agent_boundary_check.adapters.codex import CodexAdapter
from agent_boundary_check.adapters.command import CommandAdapter
from agent_boundary_check.adapters.gemini import GeminiAdapter


def test_codex_command_does_not_bypass_sandbox():
    cmd = list(CodexAdapter().build_command("hello", Path("p")))
    assert cmd[:2] == ["codex", "exec"]
    joined = " ".join(cmd).lower()
    assert "danger" not in joined
    assert "bypass" not in joined


def test_claude_command_does_not_skip_permissions():
    cmd = list(ClaudeAdapter().build_command("hello", Path("p")))
    joined = " ".join(cmd)
    assert "--dangerously-skip-permissions" not in joined
    assert "-p" in cmd


def test_gemini_command_does_not_use_yolo():
    cmd = list(GeminiAdapter().build_command("hello", Path("p")))
    assert "--yolo" not in cmd
    assert "-p" in cmd


def test_custom_command_substitutes_prompt_and_file():
    adapter = CommandAdapter('runner --prompt "{prompt}" --file {prompt_file}')
    cmd = adapter.build_command("hello world", Path("/tmp/prompt.txt"))
    assert "hello world" in cmd
    assert "/tmp/prompt.txt" in cmd


def test_command_requires_template():
    with pytest.raises(ValueError):
        CommandAdapter("")


def test_get_adapter_requires_custom_command():
    with pytest.raises(ValueError):
        get_adapter("command")
