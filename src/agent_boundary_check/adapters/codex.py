from __future__ import annotations

import tomllib
from pathlib import Path

from .base import AgentAdapter


class CodexAdapter(AgentAdapter):
    name = "codex"
    executable = "codex"

    def build_command(self, prompt: str, prompt_file: Path):
        # Intentionally do not add flags that weaken approvals or sandboxing.
        return [self.executable, "exec", prompt]

    def declared_hints(self, workspace: Path) -> dict:
        path = Path.home() / ".codex" / "config.toml"
        if not path.exists():
            return {"config_file": None}
        hints: dict = {"config_file": str(path)}
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            hints["config_parse"] = "failed"
            return hints
        for key in ("sandbox_mode", "approval_policy"):
            value = data.get(key)
            if isinstance(value, (str, bool, int, float)):
                hints[key] = value
        sandbox = data.get("sandbox_workspace_write")
        if isinstance(sandbox, dict) and isinstance(sandbox.get("network_access"), bool):
            hints["workspace_write_network_access"] = sandbox["network_access"]
        return hints
