"""Bounded, unambiguous JSON input. Invalid evidence never becomes a pass."""
import json
import math
from pathlib import Path

from .safe_files import read_regular_bytes

MAX_EVIDENCE_BYTES = 1_048_576
MAX_NESTING = 64


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate JSON key')
        value[key] = item
    return value


def _constant(value):
    raise ValueError('nonfinite JSON constant')


def decoder():
    return json.JSONDecoder(object_pairs_hook=_pairs, parse_constant=_constant)


def validate_tree(value, depth=0):
    if depth > MAX_NESTING:
        raise ValueError('JSON nesting exceeds limit')
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError('JSON object keys must be strings')
            key.encode('utf-8')
            validate_tree(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            validate_tree(child, depth + 1)
    elif isinstance(value, str):
        value.encode('utf-8')
    elif type(value) is float:
        if not math.isfinite(value):
            raise ValueError('nonfinite JSON number')
    elif value is not None and type(value) not in (bool, int):
        raise ValueError('unsupported JSON value')


def check_size(text):
    if len(text) > MAX_EVIDENCE_BYTES or len(text.encode('utf-8')) > MAX_EVIDENCE_BYTES:
        raise ValueError('input exceeds the byte limit')


def loads(text):
    try:
        check_size(text)
        value = decoder().decode(text)
        validate_tree(value)
        return value
    except (RecursionError, UnicodeError) as exc:
        raise ValueError('invalid or excessively nested JSON') from exc


def read_text(path: Path, *, strict_parents=False):
    return read_regular_bytes(path, limit=MAX_EVIDENCE_BYTES, strict_parents=strict_parents).decode('utf-8')


def read_json(path: Path, *, strict_parents=False):
    return loads(read_text(path, strict_parents=strict_parents))
