from __future__ import annotations

import os
import re
import shlex
from pathlib import Path

from .base import AgentAdapter


def _split_windows_command(template: str) -> list[str]:
    """Split arguments using Windows double-quote and backslash rules."""
    parts: list[str] = []
    index = 0
    while index < len(template):
        while index < len(template) and template[index] in " \t":
            index += 1
        if index == len(template):
            break
        argument: list[str] = []
        quoted = False
        while index < len(template) and (quoted or template[index] not in " \t"):
            slashes = 0
            while index < len(template) and template[index] == "\\":
                slashes += 1
                index += 1
            if index < len(template) and template[index] == '"':
                argument.extend("\\" * (slashes // 2))
                if slashes % 2:
                    argument.append('"')
                elif quoted and index + 1 < len(template) and template[index + 1] == '"':
                    argument.append('"')
                    index += 1
                else:
                    quoted = not quoted
                index += 1
            else:
                argument.extend("\\" * slashes)
                if index < len(template) and (quoted or template[index] not in " \t"):
                    argument.append(template[index])
                    index += 1
        if quoted:
            raise ValueError("command template has an unclosed double quote")
        parts.append("".join(argument))
    return parts


class CommandAdapter(AgentAdapter):
    name = "command"
    executable = ""

    def __init__(self, template: str):
        if not template.strip():
            raise ValueError("command template cannot be empty")
        if "\0" in template:
            raise ValueError("command template cannot contain a NUL byte")
        self.template = template
        self.parts = _split_windows_command(template) if os.name == "nt" else shlex.split(template)
        if not self.parts or not self.parts[0]:
            raise ValueError("command template must name an executable")

    def build_command(self, prompt: str, prompt_file: Path):
        used = False
        out: list[str] = []
        replacements = {"prompt": prompt, "prompt_file": str(prompt_file)}
        pattern = re.compile(r"\{(prompt|prompt_file)\}")
        for part in self.parts:
            if pattern.search(part):
                used = True
                part = pattern.sub(lambda match: replacements[match.group(1)], part)
            out.append(part)
        if not used:
            out.append(prompt)
        return out

    def get_version(self):
        return None
