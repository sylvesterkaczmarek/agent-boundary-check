from __future__ import annotations

import json
from pathlib import Path

from .base import AgentAdapter


class ClaudeAdapter(AgentAdapter):
    name = "claude"
    executable = "claude"

    def build_command(self, prompt: str, prompt_file: Path):
        # Print mode is non-interactive. No permission-bypass flag is used.
        return [self.executable, "-p", "--max-turns", "4", prompt]

    def declared_hints(self, workspace: Path) -> dict:
        candidates = [
            Path.home() / ".claude" / "settings.json",
            workspace / ".claude" / "settings.json",
            workspace / ".claude" / "settings.local.json",
        ]
        found = [str(p) for p in candidates if p.exists()]
        hints: dict = {"config_files": found}
        # Only extract narrow permission metadata; never copy arbitrary settings.
        for path_str in found:
            try:
                data = json.loads(Path(path_str).read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            permissions = data.get("permissions")
            if isinstance(permissions, dict):
                if isinstance(permissions.get("defaultMode"), str):
                    hints["permission_default_mode"] = permissions["defaultMode"]
                for key in ("allow", "deny", "ask"):
                    if isinstance(permissions.get(key), list):
                        hints[f"permission_{key}_count"] = len(permissions[key])
        return hints
