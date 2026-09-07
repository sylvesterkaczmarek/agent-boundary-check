import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

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
    prompt_file = Path("/tmp/prompt.txt")
    cmd = adapter.build_command("hello world", prompt_file)
    assert "hello world" in cmd
    assert str(prompt_file) in cmd


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
    assert hints["config_file"] == display_path(home / "config.toml")
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
    assert display_path(home / ".claude" / "settings.json") == str(Path("~") / ".claude" / "settings.json")


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
    assert display_path(defaults) in hints["config_files"]
    assert display_path(system) in hints["config_files"]
    assert display_path(user) in hints["config_files"]
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

    monkeypatch.setattr(command_module, "os", SimpleNamespace(name="nt"))
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
    assert hints["config_files"] == [display_path(settings)]

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
    assert display_path(settings) in hints["config_files"]

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


def test_custom_command_preserves_placeholder_text_inside_values():
    adapter = CommandAdapter('runner --prompt={prompt} --file={prompt_file}')
    prompt = 'Keep {prompt_file}, {prompt}, spaces and "quotes" literal'
    path = Path('folder-{prompt}/prompt file.txt')
    assert adapter.build_command(prompt, path) == [
        'runner', '--prompt=' + prompt, '--file=' + str(path),
    ]


@pytest.mark.parametrize('template', ['""', 'runner "unterminated', 'runner\0x'])
def test_custom_command_rejects_invalid_template_before_running(template):
    with pytest.raises(ValueError):
        CommandAdapter(template)


def test_custom_command_windows_preserves_embedded_quotes_and_backslashes(monkeypatch):
    import agent_boundary_check.adapters.command as command_module

    monkeypatch.setattr(command_module, 'os', SimpleNamespace(name='nt'))
    adapter = CommandAdapter(r'runner --path="C:\My Files\\" --label="a \"quote\"" {prompt}')
    assert adapter.build_command('hello', Path('p')) == [
        'runner', '--path=C:\\My Files\\', '--label=a "quote"', 'hello',
    ]


@pytest.mark.parametrize('arguments', [
    ['runner', '', 'hello world', 'tab\tvalue'],
    ['C:\\Program Files\\runner.exe', 'C:\\My Files\\', '\\', '\\\\'],
    ['runner', 'a"b', 'a\\"b', 'a\\\\"b', 'quoted "value" end\\'],
    ['runner', "it's literal", 'x=y z', '{prompt}'],
])
def test_windows_parser_round_trips_python_argument_quoting(arguments):
    from agent_boundary_check.adapters.command import _split_windows_command

    assert _split_windows_command(subprocess.list2cmdline(arguments)) == arguments


def test_agent_output_with_invalid_utf8_is_retained_without_crashing(tmp_path):
    script = tmp_path / 'binary.py'
    script.write_text("import os\nos.write(1, b'out\\xff')\nos.write(2, b'err\\xfe')\n")
    result = CommandAdapter(f'"{sys.executable}" "{script}"').run('unused', tmp_path/'p', tmp_path, {}, 5)
    assert result.exit_code == 0
    assert result.stdout == 'out\ufffd'
    assert result.stderr == 'err\ufffd'


def test_agent_timeout_retains_invalid_utf8_output(tmp_path):
    script = tmp_path / 'binary_timeout.py'
    script.write_text("import os, time\nos.write(1, b'partial\\xff')\ntime.sleep(5)\n")
    result = CommandAdapter(f'"{sys.executable}" "{script}"').run('unused', tmp_path/'p', tmp_path, {}, 1)
    assert result.timed_out
    assert result.exit_code is None
    assert result.stdout == 'partial\ufffd'


@pytest.mark.parametrize('returncode,expected', [(0, 'version\ufffd'), (2, None)])
def test_version_requires_success_and_tolerates_invalid_utf8(tmp_path, returncode, expected):
    script = tmp_path / 'version.py'
    script.write_text(f"import os, sys\nos.write(1, b'version\\xff')\nsys.exit({returncode})\n")

    class StubAdapter(AgentAdapter):
        def version_command(self):
            return [sys.executable, str(script)]

    assert StubAdapter().get_version() == expected


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process-group cleanup')
@pytest.mark.parametrize('timeout_parent', [True, False])
def test_agent_run_stops_its_background_tools(tmp_path, timeout_parent):
    import time

    ready = tmp_path / 'ready'
    marker = tmp_path / 'late-write'
    child = tmp_path / 'child.py'
    child.write_text(
        'import time\nfrom pathlib import Path\n'
        f'Path({str(ready)!r}).touch()\n'
        'time.sleep(2)\n'
        f'Path({str(marker)!r}).touch()\n'
    )
    parent = tmp_path / 'parent.py'
    parent.write_text(
        'import subprocess, sys, time\nfrom pathlib import Path\n'
        f'subprocess.Popen([sys.executable, {str(child)!r}])\n'
        f'while not Path({str(ready)!r}).exists(): time.sleep(0.01)\n'
        + ('time.sleep(5)\n' if timeout_parent else '')
    )
    result = CommandAdapter(f'"{sys.executable}" "{parent}"').run(
        'unused', tmp_path/'p', tmp_path, {}, 1,
    )
    assert ready.exists(), 'The child must start before cleanup is tested'
    assert result.timed_out is timeout_parent
    time.sleep(2.1)
    assert not marker.exists(), 'A background tool wrote after the invocation ended'


def test_claude_honours_user_config_directory_override(tmp_path, monkeypatch):
    home = tmp_path / 'home'
    default = home / '.claude' / 'settings.json'
    default.parent.mkdir(parents=True)
    default.write_text('{"permissions":{"additionalDirectories":["old","unused"]}}')
    custom = tmp_path / 'custom'
    custom.mkdir()
    settings = custom / 'settings.json'
    settings.write_text('{"permissions":{"additionalDirectories":["active"]}}')
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: home))
    monkeypatch.setenv('CLAUDE_CONFIG_DIR', str(custom))
    hints = ClaudeAdapter().declared_hints(tmp_path)
    assert display_path(settings) in hints['config_files']
    assert display_path(default) not in hints['config_files']
    assert hints['additional_directory_count'] == 1


def test_windows_timeout_cleanup_targets_only_owned_child(monkeypatch):
    import agent_boundary_check.adapters.base as base_module

    calls = []

    class Process:
        pid = 73129
        alive = True

        def poll(self):
            return None if self.alive else 1

        def kill(self):
            calls.append('direct-kill')
            self.alive = False

        def wait(self):
            calls.append('wait')
            return 1

    def taskkill(command, **kwargs):
        calls.append(command)
        raise OSError('taskkill unavailable')

    monkeypatch.setattr(base_module, 'os', SimpleNamespace(name='nt'))
    monkeypatch.setattr(base_module.subprocess, 'run', taskkill)
    base_module._stop_processes(Process())
    assert calls == [['taskkill', '/PID', '73129', '/T', '/F'], 'direct-kill', 'wait']
