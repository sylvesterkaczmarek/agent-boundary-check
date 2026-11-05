"""Independent local synthetic checks. No external services or credential access."""
from copy import deepcopy
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from agent_boundary_check.adapters.base import _run_command
from agent_boundary_check.cli import main
from agent_boundary_check.lab import create_lab
from agent_boundary_check.models import CAPABILITIES, ProbeResult, ProbeStatus
from agent_boundary_check.policy import BoundaryPolicy, evaluate_policy
from agent_boundary_check.probe_script import PROBE_DRIVER_SOURCE
from agent_boundary_check.report import make_report, parse_probe_payload, RESULT_PREFIX
from agent_boundary_check.safe_files import read_regular_bytes, write_new_text


@pytest.fixture(autouse=True)
def isolated_host(tmp_path, monkeypatch):
    home = tmp_path/'review-home'; home.mkdir()
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: home))
    monkeypatch.setattr('agent_boundary_check.lab._tcp_reachable', lambda *a, **k: pytest.fail('external TCP baseline'))
    monkeypatch.setattr('agent_boundary_check.lab._unix_socket_connectable', lambda *a, **k: pytest.fail('host socket baseline'))


def body():
    value = {'schema_version': 1, 'run_id': 'review', 'probe_platform': 'synthetic',
             'probes': [{'capability': n, 'status': 'deny', 'detail': ''} for n in CAPABILITIES]}
    value['attestation'] = hmac.new(b'review-key', json.dumps(value, sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()
    return value


def report(value, **kwargs):
    args = dict(run_id='review', agent='review', agent_version=None, payload=value, policy=None,
                declared_hints={}, exit_code=0, timed_out=False, runner_output='', attestation_key='review-key')
    args.update(kwargs)
    return make_report(**args)


@pytest.mark.parametrize('alias', [True, 1.0])
def test_stream_equality_is_type_sensitive(tmp_path, alias):
    valid = body(); different = deepcopy(valid); different['schema_version'] = alias
    result = parse_probe_payload(tmp_path/'absent', RESULT_PREFIX+json.dumps(valid), stderr=RESULT_PREFIX+json.dumps(different))
    assert result is None, 'numeric equality must not hide conflicting typed evidence'


def test_order_only_stream_difference_is_valid(tmp_path):
    valid = body()
    parsed = parse_probe_payload(tmp_path/'absent', RESULT_PREFIX+json.dumps(valid),
                                 stderr=RESULT_PREFIX+json.dumps(valid, sort_keys=True))
    assert report(parsed).evidence_complete


@pytest.mark.parametrize('damage', ['duplicate', 'nonfinite', 'schema-bool', 'environment-integer',
    'network-string', 'socket-list', 'baseline-integer', 'home-token-list', 'path-null', 'wrong-workspace', 'wrong-outside'])
def test_driver_rejects_malformed_manifest_before_any_probe(tmp_path, damage):
    lab = create_lab(tmp_path/'lab', network_probe=False, socket_probe=False)
    manifest = json.loads(lab.manifest_path.read_text())
    if damage == 'duplicate':
        raw = json.dumps(manifest).replace('"network_probe": false', '"network_probe": true, "network_probe": false')
    else:
        if damage == 'nonfinite': manifest['extra'] = float('nan')
        if damage == 'schema-bool': manifest['schema_version'] = True
        if damage == 'environment-integer': manifest['environment_probe'] = 0
        if damage == 'network-string': manifest['network_probe'] = 'disabled'
        if damage == 'socket-list': manifest['socket_probe'] = []
        if damage == 'baseline-integer': manifest['network_host_reachable'] = 0
        if damage == 'home-token-list': manifest['home_read_token'] = []
        if damage == 'path-null': manifest['home_read_path'] = None
        if damage == 'wrong-workspace': manifest['workspace_read_path'] = str(lab.root/'outside/outside-canary.txt')
        if damage == 'wrong-outside': manifest['outside_write_path'] = str(lab.workspace/'unexpected-marker')
        raw = json.dumps(manifest)
    lab.manifest_path.write_text(raw)
    run = subprocess.run([sys.executable, '-I', '-S', str(lab.manifest_path.parent/'probe_driver.py')],
                         cwd=lab.workspace, capture_output=True, text=True, timeout=10)
    assert run.returncode != 0, 'invalid manifests must not produce completed evidence'
    assert not (lab.workspace/'workspace-write-marker.txt').exists(), 'preflight must precede probe side effects'
    assert not lab.results_path.exists()
    assert 'Traceback' not in run.stderr


@pytest.mark.parametrize('capability', ['workspace_write', 'outside_write', 'home_write'])
def test_post_creation_permission_error_is_not_a_denied_boundary(tmp_path, monkeypatch, capsys, capability):
    lab = create_lab(tmp_path/'lab', network_probe=False, socket_probe=False)
    target = json.loads(lab.manifest_path.read_text())[capability+'_path']
    real_fdopen = os.fdopen
    real_open = os.open
    selected = set()
    def open_file(path, flags, *a, **k):
        fd = real_open(path, flags, *a, **k)
        if Path(path).name == Path(target).name and flags & os.O_CREAT:
            selected.add(fd)
        return fd
    class BadFlush:
        def __init__(self, file): self.file = file
        def __enter__(self): return self
        def fileno(self): return self.file.fileno()
        def write(self, text): self.file.write(text); self.file.flush()
        def __exit__(self, *a):
            self.file.close()
            raise PermissionError(errno.EACCES, 'synthetic post-creation failure')
    def fdopen(fd, *a, **k):
        file = real_fdopen(fd, *a, **k)
        if fd in selected:
            selected.remove(fd)
            return BadFlush(file)
        return file
    monkeypatch.setattr(os, 'open', open_file)
    monkeypatch.setattr(os, 'supports_dir_fd', {*os.supports_dir_fd, open_file})
    monkeypatch.setattr(os, 'fdopen', fdopen)
    monkeypatch.setattr(subprocess, 'run', lambda *a, **k: subprocess.CompletedProcess(a[0], 0, 'AGENT_BOUNDARY_CHILD_OK', ''))
    exec(PROBE_DRIVER_SOURCE, {'__file__': str(lab.manifest_path.parent/'probe_driver.py')})
    payload = parse_probe_payload(lab.results_path, capsys.readouterr().out)
    row = next(x for x in payload['probes'] if x['capability'] == capability)
    assert Path(target).exists()
    assert row['status'] == 'error', 'file creation succeeded; subsequent I/O failure cannot prove denial'


@pytest.mark.parametrize('operation', ['read', 'write'])
def test_parent_replacement_uses_pinned_directory(tmp_path, monkeypatch, operation):
    if os.name != 'posix' or os.open not in os.supports_dir_fd:
        pytest.skip('requires POSIX descriptor-relative operations')
    import agent_boundary_check.safe_files as module
    parent = tmp_path/'original'; parent.mkdir(); (parent/'read').write_text('owned')
    elsewhere = tmp_path/'unrelated'; elsewhere.mkdir(); (elsewhere/'read').write_text('unrelated')
    retained = tmp_path/'retained'
    original_open = module._leaf_open
    def replace(path, directory, flags):
        parent.rename(retained)
        parent.symlink_to(elsewhere, target_is_directory=True)
        return original_open(path, directory, flags)
    monkeypatch.setattr(module, '_leaf_open', replace)
    if operation == 'read': assert read_regular_bytes(parent/'read', limit=30) == b'owned'
    else:
        write_new_text(parent/'write', 'marker')
        assert (retained/'write').read_text() == 'marker'
        assert not (elsewhere/'write').exists()
    assert (elsewhere/'read').read_text() == 'unrelated'


@pytest.mark.parametrize('kind', ['directory', 'fifo', 'symlink', 'hardlink'])
def test_evidence_nonregular_or_aliased_file_rejected_without_blocking(tmp_path, kind):
    path = tmp_path/'evidence'
    if kind == 'directory': path.mkdir()
    elif kind == 'fifo':
        if not hasattr(os, 'mkfifo'): pytest.skip('POSIX FIFO')
        os.mkfifo(path)
    else:
        original = tmp_path/'source'; original.write_text(json.dumps(body()))
        try:
            if kind == 'symlink': path.symlink_to(original)
            else: os.link(original, path)
        except OSError: pytest.skip('filesystem alias unavailable')
    start = time.monotonic()
    assert parse_probe_payload(path, '') is None
    assert time.monotonic()-start < 2


@pytest.mark.parametrize('status', ['allow', 'deny', 'skipped', 'unknown', 'error', 'absent'])
@pytest.mark.parametrize('required', ['allow', 'deny'])
def test_socket_policy_truth_table(status, required):
    policy = BoundaryPolicy(frozenset({'docker_socket'}) if required == 'deny' else frozenset(),
                            frozenset({'docker_socket'}) if required == 'allow' else frozenset())
    violations = evaluate_policy([ProbeResult('docker_socket', ProbeStatus(status))], policy)
    expected = status == 'allow' if required == 'allow' else status in ('deny', 'absent')
    assert bool(violations) is not expected


@pytest.mark.parametrize('channel', [1, 2])
def test_binary_output_overflow_is_incomplete(channel):
    result = _run_command([sys.executable, '-I', '-S', '-c', f'import os;os.write({channel},b"a"*1200000)'], timeout=5)
    assert result.output_limited
    assert not report(body(), output_limited=True).evidence_complete


def test_current_invalid_marker_cannot_recover_old_attested_file(tmp_path):
    path = tmp_path/'evidence'; path.write_text(json.dumps(body()))
    assert parse_probe_payload(path, RESULT_PREFIX+'{broken', stderr=RESULT_PREFIX+json.dumps(body())) is None


def test_full_automatic_probe_uses_only_owned_synthetic_resources(tmp_path, monkeypatch):
    from agent_boundary_check.adapters.command import CommandAdapter
    from agent_boundary_check.runner import verify
    report_value, kept = verify(CommandAdapter(f'"{sys.executable}" -I -S .agent-boundary/probe_driver.py'),
                                timeout=10, network_probe=False, socket_probe=False)
    assert kept is None and report_value.evidence_complete
    assert report_value.risk_level == 'CRITICAL'
    assert {p.capability for p in report_value.probes if p.status == ProbeStatus.SKIPPED} == {'network_egress', 'docker_socket', 'ssh_agent_socket'}
    assert not (Path.home()/'.agent-boundary-check').exists()


def test_manual_collection_accepts_unchanged_generated_manifest(tmp_path, capsys):
    lab = create_lab(tmp_path/'manual', network_probe=False, socket_probe=False, environment_probe=False)
    run = subprocess.run([sys.executable, '-I', '-S', str(lab.manifest_path.parent/'probe_driver.py')],
                         cwd=lab.workspace, capture_output=True, text=True, timeout=10)
    assert run.returncode == 0
    saved = tmp_path/'report.json'
    assert main(['collect', str(lab.root), '--json', str(saved)]) == 0
    value = json.loads(saved.read_text())
    assert value['evidence_complete']
    assert next(p['status'] for p in value['probes'] if p['capability'] == 'environment_canary') == 'skipped'
    assert not lab.home_canary_dir.exists()


@pytest.mark.parametrize('missing', ['socket_probe', 'docker_transport_supported'])
def test_legacy_optional_manifest_flags_are_accepted(tmp_path, missing):
    from agent_boundary_check.manifest import parse_manifest
    lab = create_lab(tmp_path/'lab', network_probe=False, socket_probe=False)
    value = json.loads(lab.manifest_path.read_text()); value.pop(missing)
    assert parse_manifest(json.dumps(value), lab.manifest_path.parent) == value


@pytest.mark.parametrize('damage', ['home-run', 'home-basename', 'nested', 'surrogate', 'socket-conflict', 'oversized'])
def test_preflight_rejects_additional_corruption(tmp_path, damage):
    from agent_boundary_check.manifest import parse_manifest
    lab = create_lab(tmp_path/'lab', network_probe=False, socket_probe=False)
    value = json.loads(lab.manifest_path.read_text())
    if damage == 'home-run': value['home_read_path'] = str(lab.home_canary_dir.with_name('0'*16)/'home-canary.txt')
    if damage == 'home-basename': value['home_write_path'] = str(lab.home_canary_dir/'unrelated')
    if damage == 'surrogate': value['environment_token_hash'] = '\ud800'
    if damage == 'socket-conflict': value['docker_socket_host_connectable'] = True
    if damage == 'oversized': value['extra'] = 'x'*1048576
    raw = '['*1100+'0'+']'*1100 if damage == 'nested' else json.dumps(value)
    with pytest.raises(ValueError): parse_manifest(raw, lab.manifest_path.parent)


def test_synthetic_socket_connection_sends_no_protocol_data(tmp_path):
    import socket
    import tempfile
    if os.name == 'nt' or not hasattr(socket, 'AF_UNIX'):
        pytest.skip('POSIX Unix socket')
    lab = create_lab(tmp_path/'lab', network_probe=False, socket_probe=False)
    # Short path avoids the operating system's small Unix socket path limit.
    with tempfile.TemporaryDirectory(prefix='abc-review-socket-') as short:
        path = str(Path(short)/'owned.sock')
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(path); server.listen(1); server.settimeout(3)
            value = json.loads(lab.manifest_path.read_text())
            value.update(socket_probe=True, unix_socket_probe_supported=True,
                         docker_socket_path=path, docker_socket_host_present=True, docker_socket_host_connectable=True)
            lab.manifest_path.write_text(json.dumps(value))
            run = subprocess.run([sys.executable, '-I', '-S', str(lab.manifest_path.parent/'probe_driver.py')],
                                 cwd=lab.workspace, capture_output=True, text=True, timeout=10)
            assert run.returncode == 0
            connection, _ = server.accept()
            with connection:
                connection.settimeout(3)
                assert connection.recv(1) == b''
            parsed = parse_probe_payload(lab.results_path, run.stdout)
            assert next(p['status'] for p in parsed['probes'] if p['capability'] == 'docker_socket') == 'allow'
