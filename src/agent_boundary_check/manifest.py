"""Standalone preflight for generated synthetic-probe instructions."""
import json
import math
from pathlib import Path
import re

_MANIFEST_BOOLEANS = (
    'environment_probe', 'network_probe', 'network_host_reachable',
    'unix_socket_probe_supported', 'docker_socket_host_present',
    'docker_socket_host_connectable', 'ssh_agent_socket_host_present',
    'ssh_agent_socket_host_connectable',
)
_MANIFEST_OPTIONAL_BOOLEANS = ('socket_probe', 'docker_transport_supported')
_MANIFEST_FILES = {
    'workspace_read': ('workspace', 'workspace-canary.txt'),
    'workspace_write': ('workspace', 'workspace-write-marker.txt'),
    'outside_read': ('outside', 'outside-canary.txt'),
    'outside_write': ('outside', 'outside-write-marker.txt'),
}


def _unique_manifest_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate manifest key')
        result[key] = value
    return result


def _manifest_constant(value):
    raise ValueError('nonfinite manifest constant')


def _manifest_tree(value, depth=0):
    if depth > 64:
        raise ValueError('manifest nesting exceeds limit')
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError('manifest keys must be strings')
            key.encode('utf-8')
            _manifest_tree(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _manifest_tree(item, depth + 1)
    elif isinstance(value, str):
        value.encode('utf-8')
    elif type(value) is float and not math.isfinite(value):
        raise ValueError('nonfinite manifest value')
    elif value is not None and type(value) not in (bool, int, float):
        raise ValueError('unsupported manifest value')


def validate_manifest(manifest, internal):
    """Validate every probe control and file target before any probe operation.

    Paths bind to the prepared layout, not to the agent's possibly remapped HOME.
    This rejects accidental/corrupt instructions; it is not adversarial attestation.
    """
    _manifest_tree(manifest)
    if not isinstance(manifest, dict):
        raise ValueError('lab manifest must be a mapping')
    if type(manifest.get('schema_version')) is not int or manifest['schema_version'] != 1:
        raise ValueError('lab manifest schema version did not match')
    run_id = manifest.get('run_id')
    if not isinstance(run_id, str) or re.fullmatch('[0-9a-f]{16}', run_id) is None:
        raise ValueError('lab manifest has no valid run identifier')
    key = manifest.get('attestation_key')
    if not isinstance(key, str) or re.fullmatch('[0-9a-f]{64}', key) is None:
        raise ValueError('lab manifest has no valid attestation key')
    for field in _MANIFEST_BOOLEANS:
        if type(manifest.get(field)) is not bool:
            raise ValueError(f'manifest {field} must be a boolean')
    for field in _MANIFEST_OPTIONAL_BOOLEANS:
        if field in manifest and type(manifest[field]) is not bool:
            raise ValueError(f'manifest {field} must be a boolean')
    internal = Path(internal)
    if not internal.is_absolute() or internal.name != '.agent-boundary' or internal.parent.name != 'workspace':
        raise ValueError('manifest is outside the prepared lab layout')
    root = internal.parent.parent
    prefixes = (*_MANIFEST_FILES, 'home_read', 'home_write')
    allowed = {'schema_version', 'run_id', 'attestation_key', 'environment_token_hash',
               'docker_socket_path', 'ssh_agent_socket_path', *_MANIFEST_BOOLEANS, *_MANIFEST_OPTIONAL_BOOLEANS}
    for prefix in prefixes:
        allowed.update({prefix+'_path', prefix+'_token'})
        path, token = manifest.get(prefix+'_path'), manifest.get(prefix+'_token')
        if not isinstance(path, str) or '\x00' in path or not Path(path).is_absolute() or '..' in Path(path).parts:
            raise ValueError(f'manifest {prefix}_path must be an absolute synthetic path')
        if not isinstance(token, str) or re.fullmatch('abc_[0-9a-f]{32}', token) is None:
            raise ValueError(f'manifest {prefix}_token must be a synthetic token')
        if prefix in _MANIFEST_FILES and Path(path) != root.joinpath(*_MANIFEST_FILES[prefix]):
            raise ValueError(f'manifest {prefix}_path does not match the prepared lab')
    home_read, home_write = (Path(manifest[p+'_path']) for p in ('home_read', 'home_write'))
    if (home_read.name != 'home-canary.txt' or home_write.name != 'home-write-marker.txt'
            or home_read.parent != home_write.parent
            or home_read.parent.parts[-3:] != ('.agent-boundary-check', 'canaries', run_id)):
        raise ValueError('home canary paths do not match this synthetic run')
    for field in ('docker_socket_path', 'ssh_agent_socket_path'):
        if not isinstance(manifest.get(field), str) or '\x00' in manifest[field]:
            raise ValueError(f'manifest {field} must be a socket-path string')
    if set(manifest) - allowed:
        raise ValueError('manifest contains unexpected fields')
    for prefix in ('docker_socket', 'ssh_agent_socket'):
        if manifest[prefix+'_host_connectable'] and not manifest[prefix+'_host_present']:
            raise ValueError('manifest socket baseline is contradictory')
    return manifest


def parse_manifest(text, internal):
    try:
        if len(text) > 1048576 or len(text.encode('utf-8')) > 1048576:
            raise ValueError('manifest exceeds byte limit')
        value = json.loads(text, object_pairs_hook=_unique_manifest_pairs, parse_constant=_manifest_constant)
        return validate_manifest(value, internal)
    except (RecursionError, UnicodeError) as exc:
        raise ValueError('invalid or excessively nested manifest') from exc
