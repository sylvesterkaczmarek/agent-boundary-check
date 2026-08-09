from __future__ import annotations

import json
import os
from pathlib import Path

from .base import AgentAdapter, display_path


def _managed_settings_path() -> Path | None:
    if os.name == "nt":
        program_files = os.environ.get("ProgramFiles")
        return Path(program_files) / "ClaudeCode" / "managed-settings.json" if program_files else None
    if __import__("sys").platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode/managed-settings.json")
    return Path("/etc/claude-code/managed-settings.json")


class ClaudeAdapter(AgentAdapter):
    name = "claude"
    executable = "claude"

    def build_command(self, prompt: str, prompt_file: Path):
        # Print mode is non-interactive. No permission-bypass flag is used.
        return [self.executable, "-p", "--max-turns", "4", prompt]

    def declared_hints(self, workspace: Path) -> dict:
        candidates = [
            _managed_settings_path(),
            Path.home() / ".claude" / "settings.json",
            workspace / ".claude" / "settings.json",
            workspace / ".claude" / "settings.local.json",
        ]
        found = [p for p in candidates if p is not None and p.exists()]
        hints: dict = {"config_files": [display_path(p) for p in found]}
        permission_modes = []
        sandbox_observations = []
        for path in found:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            permissions = data.get("permissions")
            if isinstance(permissions, dict):
                if isinstance(permissions.get("defaultMode"), str):
                    permission_modes.append({"source": display_path(path), "value": permissions["defaultMode"]})
                for key in ("allow", "deny", "ask"):
                    if isinstance(permissions.get(key), list):
                        hints[f"permission_{key}_count"] = hints.get(f"permission_{key}_count", 0) + len(permissions[key])
                if isinstance(permissions.get("additionalDirectories"), list):
                    hints["additional_directory_count"] = (
                        hints.get("additional_directory_count", 0) + len(permissions["additionalDirectories"])
                    )
            sandbox = data.get("sandbox")
            if isinstance(sandbox, dict):
                observation = {"source": display_path(path)}
                for key in ("enabled", "failIfUnavailable", "autoAllowBashIfSandboxed", "allowUnsandboxedCommands"):
                    if isinstance(sandbox.get(key), bool):
                        observation[key] = sandbox[key]
                filesystem = sandbox.get("filesystem")
                if isinstance(filesystem, dict):
                    for key in ("allowWrite", "denyWrite", "allowRead", "denyRead"):
                        if isinstance(filesystem.get(key), list):
                            observation[f"filesystem_{key}_count"] = len(filesystem[key])
                network = sandbox.get("network")
                if isinstance(network, dict):
                    for key in ("allowedDomains", "deniedDomains", "allowUnixSockets"):
                        if isinstance(network.get(key), list):
                            observation[f"network_{key}_count"] = len(network[key])
                sandbox_observations.append(observation)
        if permission_modes:
            hints["permission_default_modes"] = permission_modes
        if sandbox_observations:
            hints["sandbox_settings"] = sandbox_observations
        return hints
