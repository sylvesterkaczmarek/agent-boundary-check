from __future__ import annotations

import shutil

from .base import AgentAdapter
from .claude import ClaudeAdapter
from .codex import CodexAdapter
from .command import CommandAdapter
from .gemini import GeminiAdapter

BUILTIN_ADAPTERS = {
    "codex": CodexAdapter,
    "claude": ClaudeAdapter,
    "gemini": GeminiAdapter,
}


def get_adapter(name: str, command: str | None = None) -> AgentAdapter:
    if name == "command":
        if not command:
            raise ValueError("--command is required when agent is 'command'")
        return CommandAdapter(command)
    try:
        return BUILTIN_ADAPTERS[name]()
    except KeyError as exc:
        raise ValueError(f"unsupported agent: {name}") from exc


def detect_agents() -> list[str]:
    return [name for name, cls in BUILTIN_ADAPTERS.items() if shutil.which(cls.executable)]
