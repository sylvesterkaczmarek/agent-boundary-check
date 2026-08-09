from __future__ import annotations

import json
from pathlib import Path

from .base import AgentAdapter


class GeminiAdapter(AgentAdapter):
    name = "gemini"
    executable = "gemini"

    def build_command(self, prompt: str, prompt_file: Path):
        # Do not use --yolo or other flags that alter the current boundary.
        return [self.executable, "-p", prompt, "--output-format", "text"]

    def declared_hints(self, workspace: Path) -> dict:
        candidates = [Path.home() / ".gemini" / "settings.json", workspace / ".gemini" / "settings.json"]
        found = [p for p in candidates if p.exists()]
        hints: dict = {"config_files": [str(p) for p in found]}
        for path in found:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            tools = data.get("tools")
            if isinstance(tools, dict):
                if isinstance(tools.get("sandbox"), (str, bool)):
                    hints["sandbox"] = tools["sandbox"]
                if isinstance(tools.get("sandboxNetworkAccess"), bool):
                    hints["sandbox_network_access"] = tools["sandboxNetworkAccess"]
                allowed = tools.get("sandboxAllowedPaths")
                if isinstance(allowed, list):
                    hints["sandbox_allowed_path_count"] = len(allowed)
            security = data.get("security")
            if isinstance(security, dict) and isinstance(security.get("toolSandboxing"), bool):
                hints["tool_sandboxing"] = security["toolSandboxing"]
        return hints
