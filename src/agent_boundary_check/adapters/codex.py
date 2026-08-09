from __future__ import annotations

import os
import tomllib
from pathlib import Path

from .base import AgentAdapter, display_path


class CodexAdapter(AgentAdapter):
    name = "codex"
    executable = "codex"

    def build_command(self, prompt: str, prompt_file: Path):
        # Intentionally do not add flags that weaken approvals or sandboxing.
        return [self.executable, "exec", prompt]

    def declared_hints(self, workspace: Path) -> dict:
        codex_home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))).expanduser()
        path = codex_home / "config.toml"
        if not path.exists():
            return {"config_file": None}
        hints: dict = {"config_file": display_path(path)}
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            hints["config_parse"] = "failed"
            return hints
        for key in ("sandbox_mode", "approval_policy", "default_permissions"):
            value = data.get(key)
            if isinstance(value, (str, bool, int, float)):
                hints[key] = value
        sandbox = data.get("sandbox_workspace_write")
        if isinstance(sandbox, dict):
            if isinstance(sandbox.get("network_access"), bool):
                hints["workspace_write_network_access"] = sandbox["network_access"]
            writable_roots = sandbox.get("writable_roots")
            if isinstance(writable_roots, list):
                hints["workspace_write_writable_root_count"] = len(writable_roots)
        return hints
