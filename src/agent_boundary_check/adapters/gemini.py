from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from .base import AgentAdapter, display_path


def _system_settings_paths() -> list[Path]:
    if os.name == "nt":
        base = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "gemini-cli"
    elif sys.platform == "darwin":
        base = Path("/Library/Application Support/GeminiCli")
    else:
        base = Path("/etc/gemini-cli")

    defaults = Path(os.environ["GEMINI_CLI_SYSTEM_DEFAULTS_PATH"]).expanduser() if os.environ.get("GEMINI_CLI_SYSTEM_DEFAULTS_PATH") else base / "system-defaults.json"
    settings = Path(os.environ["GEMINI_CLI_SYSTEM_SETTINGS_PATH"]).expanduser() if os.environ.get("GEMINI_CLI_SYSTEM_SETTINGS_PATH") else base / "settings.json"
    return [defaults, settings]


def _user_settings_path() -> Path:
    root = Path(os.environ.get("GEMINI_CLI_HOME", str(Path.home()))).expanduser()
    return root / ".gemini" / "settings.json"


class GeminiAdapter(AgentAdapter):
    name = "gemini"
    executable = "gemini"

    def build_command(self, prompt: str, prompt_file: Path):
        # Do not use --yolo or other flags that alter the current boundary.
        return [self.executable, "-p", prompt, "--output-format", "text"]

    def declared_hints(self, workspace: Path) -> dict:
        candidates = [*_system_settings_paths(), _user_settings_path(), workspace / ".gemini" / "settings.json"]
        found = [p for p in candidates if p.exists()]
        hints: dict = {"config_files": [display_path(p) for p in found]}

        env_sandbox = os.environ.get("GEMINI_SANDBOX")
        if env_sandbox:
            hints["environment_sandbox"] = env_sandbox[:100]
        sandbox_mounts = os.environ.get("SANDBOX_MOUNTS")
        if sandbox_mounts:
            hints["sandbox_mount_count"] = len([item for item in sandbox_mounts.split(",") if item.strip()])

        observations = []
        for path in found:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            observation: dict = {"source": display_path(path)}
            general = data.get("general")
            if isinstance(general, dict) and isinstance(general.get("defaultApprovalMode"), str):
                observation["default_approval_mode"] = general["defaultApprovalMode"]
            tools = data.get("tools")
            if isinstance(tools, dict):
                if isinstance(tools.get("sandbox"), (str, bool, dict)):
                    sandbox = tools["sandbox"]
                    observation["sandbox"] = sandbox if isinstance(sandbox, (str, bool)) else "configured"
                if isinstance(tools.get("sandboxNetworkAccess"), bool):
                    observation["sandbox_network_access"] = tools["sandboxNetworkAccess"]
                allowed = tools.get("sandboxAllowedPaths")
                if isinstance(allowed, list):
                    observation["sandbox_allowed_path_count"] = len(allowed)
            security = data.get("security")
            if isinstance(security, dict):
                if isinstance(security.get("toolSandboxing"), bool):
                    observation["tool_sandboxing"] = security["toolSandboxing"]
                folder_trust = security.get("folderTrust")
                if isinstance(folder_trust, dict) and isinstance(folder_trust.get("enabled"), bool):
                    observation["folder_trust_enabled"] = folder_trust["enabled"]
                env_redaction = security.get("environmentVariableRedaction")
                if isinstance(env_redaction, dict) and isinstance(env_redaction.get("enabled"), bool):
                    observation["environment_variable_redaction"] = env_redaction["enabled"]
            if len(observation) > 1:
                observations.append(observation)
        if observations:
            hints["sandbox_settings"] = observations
        return hints
