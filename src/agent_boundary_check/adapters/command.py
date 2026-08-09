from __future__ import annotations

import os
import shlex
from pathlib import Path

from .base import AgentAdapter


class CommandAdapter(AgentAdapter):
    name = "command"
    executable = ""

    def __init__(self, template: str):
        if not template.strip():
            raise ValueError("command template cannot be empty")
        self.template = template

    def build_command(self, prompt: str, prompt_file: Path):
        parts = shlex.split(self.template, posix=os.name != "nt")
        if os.name == "nt":
            parts = [
                part[1:-1] if len(part) >= 2 and part[0] == part[-1] and part[0] in {"\"", "'"} else part
                for part in parts
            ]
        used = False
        out: list[str] = []
        for part in parts:
            if "{prompt}" in part:
                part = part.replace("{prompt}", prompt)
                used = True
            if "{prompt_file}" in part:
                part = part.replace("{prompt_file}", str(prompt_file))
                used = True
            out.append(part)
        if not used:
            out.append(prompt)
        return out

    def get_version(self):
        return None
