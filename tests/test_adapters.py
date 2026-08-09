import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_boundary_check.adapters import get_adapter
from agent_boundary_check.adapters.base import AgentAdapter, display_path
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
    assert "--max-turns" in cmd


def test_gemini_command_does_not_use_yolo():
    cmd = list(GeminiAdapter().build_command("hello", Path("p")))
    assert "--yolo" not in cmd
    assert "-p" in cmd
    assert "--output-format" in cmd


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


def test_agent_runner_receives_eof_on_stdin(tmp_path):
    script = tmp_path / "stdin_check.py"
    script.write_text("import sys\nassert sys.stdin.read() == ''\nprint('ok')\n")
    adapter = CommandAdapter(f'"{sys.executable}" "{script}"')
    result = adapter.run("unused", tmp_path / "p", tmp_path, {}, 5)
    assert result.exit_code == 0
    assert result.stdout.strip() == "ok"


def test_codex_respects_codex_home_for_config(tmp_path, monkeypatch):
    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "config.toml").write_text('sandbox_mode = "workspace-write"\napproval_policy = "on-request"\ndefault_permissions = "repo-safe"\n[sandbox_workspace_write]\nnetwork_access = true\nwritable_roots = ["/x"]\n')
    monkeypatch.setenv("CODEX_HOME", str(home))
    hints = CodexAdapter().declared_hints(tmp_path)
    assert hints["config_file"] == str(home / "config.toml")
    assert hints["approval_policy"] == "on-request"
    assert hints["default_permissions"] == "repo-safe"
    assert hints["workspace_write_network_access"] is True
    assert hints["workspace_write_writable_root_count"] == 1


@pytest.mark.skipif(os.name == "nt", reason="fake CLI shim uses a POSIX executable script")
@pytest.mark.parametrize("adapter_cls, executable", [
    (CodexAdapter, "codex"),
    (ClaudeAdapter, "claude"),
    (GeminiAdapter, "gemini"),
])
def test_builtin_adapter_end_to_end_with_cli_shim(tmp_path, monkeypatch, adapter_cls, executable):
    from agent_boundary_check.runner import verify

    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    shim = bin_dir / executable
    shim.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = \"--version\" ]; then echo 'test-cli 1.0'; exit 0; fi\n"
        f"exec '{sys.executable}' .agent-boundary/probe_driver.py\n",
        encoding="utf-8",
    )
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")

    report, retained = verify(adapter_cls(), timeout=10, network_probe=False, keep_lab=False)
    assert retained is None
    assert report.evidence_complete
    assert report.agent == adapter_cls.name
    assert report.agent_version == "test-cli 1.0"
    assert {p.capability: p.status.value for p in report.probes}["environment_canary"] == "allow"


def test_display_path_abbreviates_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    assert display_path(home / ".claude" / "settings.json") == "~/.claude/settings.json"


def test_gemini_honors_configuration_path_overrides(tmp_path, monkeypatch):
    defaults = tmp_path / "defaults.json"
    system = tmp_path / "system.json"
    defaults.write_text('{"tools":{"sandbox":true}}')
    system.write_text('{"security":{"toolSandboxing":true}}')
    custom_home = tmp_path / "gemini-home"
    user = custom_home / ".gemini" / "settings.json"
    user.parent.mkdir(parents=True)
    user.write_text('{"general":{"defaultApprovalMode":"plan"},"security":{"environmentVariableRedaction":{"enabled":true}}}')
    monkeypatch.setenv("GEMINI_CLI_SYSTEM_DEFAULTS_PATH", str(defaults))
    monkeypatch.setenv("GEMINI_CLI_SYSTEM_SETTINGS_PATH", str(system))
    monkeypatch.setenv("GEMINI_CLI_HOME", str(custom_home))
    monkeypatch.setenv("GEMINI_SANDBOX", "docker")
    monkeypatch.setenv("SANDBOX_MOUNTS", "/one:ro,/two:rw")

    hints = GeminiAdapter().declared_hints(tmp_path)
    assert str(defaults) in hints["config_files"]
    assert str(system) in hints["config_files"]
    assert str(user) in hints["config_files"]
    assert hints["environment_sandbox"] == "docker"
    assert hints["sandbox_mount_count"] == 2
    assert any(item.get("default_approval_mode") == "plan" for item in hints["sandbox_settings"])
    assert any(item.get("environment_variable_redaction") is True for item in hints["sandbox_settings"])


def test_claude_counts_additional_directories(tmp_path, monkeypatch):
    home = tmp_path / "home"
    settings = home / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text('{"permissions":{"additionalDirectories":["../shared","/tmp/data"]}}')
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    hints = ClaudeAdapter().declared_hints(tmp_path)
    assert hints["additional_directory_count"] == 2


def test_custom_command_windows_style_quoted_executable(monkeypatch):
    import agent_boundary_check.adapters.command as command_module

    monkeypatch.setattr(command_module.os, "name", "nt")
    adapter = CommandAdapter(r'"C:\Program Files\Python\python.exe" script.py "{prompt}"')
    cmd = adapter.build_command("hello world", Path(r"C:\tmp\prompt.txt"))
    assert cmd[0] == r"C:\Program Files\Python\python.exe"
    assert cmd[1] == "script.py"
    assert cmd[2] == "hello world"


def test_claude_ignores_non_object_and_invalid_utf8_settings(tmp_path, monkeypatch):
    home = tmp_path / "home"
    settings = home / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_bytes(b"\xff\xfe")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    hints = ClaudeAdapter().declared_hints(tmp_path)
    assert hints["config_files"] == ["~/.claude/settings.json"]

    settings.write_text("[]")
    hints = ClaudeAdapter().declared_hints(tmp_path)
    assert "permission_default_modes" not in hints


def test_gemini_ignores_non_object_and_invalid_utf8_settings(tmp_path, monkeypatch):
    home = tmp_path / "home"
    settings = home / ".gemini" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_bytes(b"\xff\xfe")
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    hints = GeminiAdapter().declared_hints(tmp_path)
    assert "~/.gemini/settings.json" in hints["config_files"]

    settings.write_text("[]")
    hints = GeminiAdapter().declared_hints(tmp_path)
    assert "sandbox_settings" not in hints


def test_codex_invalid_utf8_config_is_reported_not_raised(tmp_path, monkeypatch):
    home = tmp_path / "codex-home"
    home.mkdir()
    (home / "config.toml").write_bytes(b"\xff\xfe")
    monkeypatch.setenv("CODEX_HOME", str(home))
    hints = CodexAdapter().declared_hints(tmp_path)
    assert hints["config_parse"] == "failed"
