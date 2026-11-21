"""Offline synthetic checks. No real agent, credential or external service use."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_boundary_check.cli import main
from agent_boundary_check.lab import create_lab
from agent_boundary_check.models import CAPABILITIES
from agent_boundary_check.report import parse_probe_payload, make_report


@pytest.fixture(autouse=True)
def isolated_host(tmp_path, monkeypatch):
    home = tmp_path/'synthetic-home'; home.mkdir()
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: home))
    monkeypatch.setattr('agent_boundary_check.lab._tcp_reachable', lambda *a, **k: False)
    monkeypatch.setattr('agent_boundary_check.lab._unix_socket_connectable', lambda *a, **k: False)


def payload():
    return {'schema_version':1, 'run_id':'test', 'probe_platform':'synthetic',
            'probes':[{'capability':n, 'status':'deny', 'detail':''} for n in CAPABILITIES]}


@pytest.mark.parametrize('source', ['stdout','file'])
@pytest.mark.parametrize('damage', ['duplicate','nonfinite','deep','oversized'])
def test_ambiguous_or_excessive_json_cannot_be_evidence(tmp_path, source, damage):
    raw = json.dumps(payload())
    if damage == 'duplicate': raw = raw.replace('"status": "deny"', '"status":"allow","status":"deny"', 1)
    if damage == 'nonfinite': raw = raw.replace('"probe_platform": "synthetic"', '"probe_platform": NaN')
    if damage == 'deep': raw = '{"x":' + '['*1100 + '0' + ']'*1100 + '}'
    if damage == 'oversized': raw = raw.replace('"detail": ""', '"detail": "'+('x'*2_100_000)+'"', 1)
    path = tmp_path/'result.json'
    if source == 'file': path.write_text(raw)
    assert parse_probe_payload(path, 'AGENT_BOUNDARY_RESULT='+raw if source=='stdout' else '') is None


def test_result_symlink_is_not_followed(tmp_path):
    target = tmp_path/'unrelated-synthetic.json'; target.write_text(json.dumps(payload()))
    link = tmp_path/'result.json'
    try: link.symlink_to(target)
    except OSError: pytest.skip('symlinks unavailable')
    assert parse_probe_payload(link, '') is None


@pytest.mark.parametrize('capability', ['workspace_read','outside_read','home_write','child_process'])
def test_mandatory_skipped_probe_cannot_be_complete(capability):
    data = payload()
    next(p for p in data['probes'] if p['capability']==capability)['status']='skipped'
    report = make_report(run_id='test', agent='synthetic', agent_version=None, payload=data,
                         policy=None, declared_hints={}, exit_code=0, timed_out=False, runner_output='')
    assert not report.evidence_complete
    assert report.risk_level=='UNKNOWN'


def test_canary_read_does_not_follow_redirected_file(tmp_path):
    lab = create_lab(tmp_path/'lab', network_probe=False)
    target=tmp_path/'other-synthetic.txt'; target.write_text('unrelated synthetic data')
    canary=lab.workspace/'workspace-canary.txt';canary.unlink()
    try: canary.symlink_to(target)
    except OSError: pytest.skip('symlinks unavailable')
    run=subprocess.run([sys.executable,'-I','-S',str(lab.workspace/'.agent-boundary/probe_driver.py')],cwd=lab.workspace,capture_output=True,text=True,timeout=10)
    data=parse_probe_payload(lab.results_path,run.stdout)
    assert next(p for p in data['probes'] if p['capability']=='workspace_read')['status']=='error'


def test_socket_disabled_transport_is_not_absent(tmp_path, monkeypatch):
    monkeypatch.setenv('DOCKER_HOST','tcp://synthetic.invalid:2376')
    lab=create_lab(tmp_path/'lab',network_probe=False)
    run=subprocess.run([sys.executable,'-I','-S',str(lab.workspace/'.agent-boundary/probe_driver.py')],cwd=lab.workspace,capture_output=True,text=True,timeout=10)
    data=parse_probe_payload(lab.results_path,run.stdout)
    assert next(p for p in data['probes'] if p['capability']=='docker_socket')['status']=='skipped'


def test_default_demo_does_not_probe_live_unix_sockets(monkeypatch):
    calls=[]
    monkeypatch.setattr('agent_boundary_check.lab._docker_socket_path',lambda: calls.append(True) or '')
    assert main(['demo'])==0
    assert not calls


def test_runner_output_is_bounded_and_marked():
    from agent_boundary_check.adapters.base import _run_command
    result=_run_command([sys.executable,'-I','-S','-c','import sys;sys.stdout.write("x"*2200000)'],timeout=5)
    assert len(result.stdout)<=1_048_576
    assert getattr(result,'output_limited',False)
