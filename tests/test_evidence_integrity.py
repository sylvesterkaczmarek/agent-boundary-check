"""Synthetic boundary cases, including valid controls and actual local I/O."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from agent_boundary_check import evidence_io
from agent_boundary_check.adapters.base import AgentRun, _run_command
from agent_boundary_check.cli import main
from agent_boundary_check.diffing import diff_reports, load_report
from agent_boundary_check.lab import create_lab
from agent_boundary_check.models import CAPABILITIES
from agent_boundary_check.policy import BoundaryPolicy, evaluate_policy
from agent_boundary_check.report import RESULT_PREFIX, make_report, parse_probe_payload
from agent_boundary_check.safe_files import read_regular_bytes, write_new_text


def data(run_id='r'):
    return {'schema_version':1, 'run_id':run_id, 'probe_platform':'synthetic',
            'probes':[{'capability':name,'status':'deny','detail':''} for name in CAPABILITIES]}


def report(payload=None, **kwargs):
    args=dict(run_id='r',agent='fixture',agent_version=None,payload=data() if payload is None else payload,
              policy=None,declared_hints={},exit_code=0,timed_out=False,runner_output='')
    args.update(kwargs)
    return make_report(**args)


@pytest.mark.parametrize('raw', [
    '{"x":1,"x":2}', '{"x":{"y":1,"y":2}}', '{"x":NaN}', '{"x":Infinity}',
    '{"x":-Infinity}', '{"x":1e999}', '{"x":"\\ud800"}', '{"\\udfff":1}',
    '['*66+'0'+']'*66, '['*1100+'0'+']'*1100,
])
def test_strict_json_rejects_ambiguous_nonfinite_or_excessive_inputs(raw):
    with pytest.raises(ValueError): evidence_io.loads(raw)


@pytest.mark.parametrize('value', [{}, [True,False,None,0,1.25,'é'], {'a':[{'b':2}]}])
def test_strict_json_valid_controls(value):
    assert evidence_io.loads(json.dumps(value))==value


@pytest.mark.parametrize('bad', ['{incomplete', '{"x":1,"x":2}', '{"x":NaN}'])
def test_malformed_result_cannot_hide_inner_good_marker(tmp_path,bad):
    good=RESULT_PREFIX+json.dumps(data())
    assert parse_probe_payload(tmp_path/'none',good+'\n'+RESULT_PREFIX+bad+'\n'+good) is None


@pytest.mark.parametrize('channel',['stdout','stderr'])
def test_oversize_stream_cannot_fall_back_to_retained_file(tmp_path,channel):
    path=tmp_path/'result.json';path.write_text(json.dumps(data()))
    args={channel:'x'*(evidence_io.MAX_EVIDENCE_BYTES+1)}
    assert parse_probe_payload(path,args.get('stdout',''),stderr=args.get('stderr','')) is None


@pytest.mark.parametrize('entry',['file','parent'])
def test_safe_file_reads_reject_redirection(tmp_path,entry):
    source=tmp_path/'original';source.mkdir(); (source/'evidence').write_text('synthetic')
    link=tmp_path/'alias'
    try:
        link.symlink_to(source if entry=='parent' else source/'evidence',target_is_directory=entry=='parent')
    except OSError: pytest.skip('symlink creation unavailable')
    with pytest.raises((OSError,ValueError)):
        read_regular_bytes(link/'evidence' if entry=='parent' else link,limit=100)


def test_read_refuses_hardlink(tmp_path):
    source=tmp_path/'source';source.write_text('synthetic')
    alias=tmp_path/'alias'
    try: os.link(source,alias)
    except OSError: pytest.skip('hardlinks unavailable')
    with pytest.raises(ValueError): read_regular_bytes(alias,limit=100)


@pytest.mark.skipif(not hasattr(os,'mkfifo'),reason='POSIX FIFO')
def test_fifo_evidence_is_rejected_without_waiting_for_a_writer(tmp_path):
    path=tmp_path/'fifo';os.mkfifo(path)
    assert parse_probe_payload(path,'') is None


def test_canary_prefix_read_is_bounded_and_detects_changed_content(tmp_path):
    path=tmp_path/'synthetic';path.write_bytes(b'x'*100000)
    assert read_regular_bytes(path,limit=35,prefix_only=True)==b'x'*36
    with pytest.raises(ValueError): read_regular_bytes(path,limit=35)


def test_marker_write_rejects_parent_redirect_and_preserves_sentinel(tmp_path):
    source=tmp_path/'target';source.mkdir();sentinel=source/'marker';sentinel.write_text('keep')
    alias=tmp_path/'alias'
    try: alias.symlink_to(source,target_is_directory=True)
    except OSError: pytest.skip('symlinks unavailable')
    with pytest.raises((OSError,ValueError)): write_new_text(alias/'new-marker','data')
    assert sentinel.read_text()=='keep'
    assert not (source/'new-marker').exists()


def test_marker_exclusive_creation_and_read_control(tmp_path):
    path=tmp_path/'marker';write_new_text(path,'safe')
    assert read_regular_bytes(path,limit=4)==b'safe'
    with pytest.raises(FileExistsError): write_new_text(path,'replace')
    assert path.read_text()=='safe'


@pytest.mark.parametrize('capability',['workspace_read','workspace_write','outside_read','outside_write','home_read','home_write','child_process'])
def test_old_report_with_mandatory_skip_is_unusable_even_when_unchanged(capability):
    saved=report().to_dict()
    next(p for p in saved['probes'] if p['capability']==capability)['status']='skipped'
    difference=diff_reports(saved,saved)
    assert difference.has_unusable_evidence
    assert difference.after_risk=='UNKNOWN'


@pytest.mark.parametrize('capability',['environment_canary','network_egress','docker_socket','ssh_agent_socket'])
def test_optional_skip_is_partial_not_denial_and_does_not_satisfy_policy(capability):
    payload=data();next(p for p in payload['probes'] if p['capability']==capability)['status']='skipped'
    checked=report(payload)
    assert checked.evidence_complete and checked.risk_level=='PARTIAL'
    policy=BoundaryPolicy(frozenset({capability}),frozenset())
    assert evaluate_policy(checked.probes,policy)


@pytest.mark.parametrize('channel',[1,2])
def test_captured_output_limit_is_explicit_for_each_stream(channel):
    command=[sys.executable,'-I','-S','-c',f'import os,time;os.write({channel},b"x"*2200000);time.sleep(5)']
    outcome=_run_command(command,timeout=10)
    assert outcome.output_limited and not outcome.timed_out
    assert len(outcome.stdout)<=evidence_io.MAX_EVIDENCE_BYTES
    assert len(outcome.stderr)<=evidence_io.MAX_EVIDENCE_BYTES


def test_output_limit_invalidates_an_otherwise_valid_report():
    checked=report(output_limited=True)
    assert not checked.evidence_complete and checked.risk_level=='UNKNOWN'
    assert 'capture limit' in checked.evidence_error


@pytest.mark.parametrize('timeout',[True,0,-1,float('nan'),float('inf'),.5])
def test_invalid_timeout_rejected_before_spawning(timeout,monkeypatch):
    monkeypatch.setattr(subprocess,'Popen',lambda *a,**k:pytest.fail('must validate before process launch'))
    with pytest.raises(ValueError):_run_command(['unused'],timeout=timeout)


def test_socket_opt_out_does_not_discover_or_connect(tmp_path,monkeypatch):
    def forbidden(*a,**k):pytest.fail('socket discovery or connection attempted')
    monkeypatch.setattr('agent_boundary_check.lab._docker_socket_path',forbidden)
    monkeypatch.setattr('agent_boundary_check.lab._unix_socket_connectable',forbidden)
    monkeypatch.setenv('SSH_AUTH_SOCK','/synthetic/do-not-connect')
    lab=create_lab(tmp_path/'lab',network_probe=False,socket_probe=False)
    manifest=evidence_io.read_json(lab.manifest_path)
    assert not manifest['socket_probe'] and manifest['docker_socket_path']==manifest['ssh_agent_socket_path']==''
    run=subprocess.run([sys.executable,'-I','-S',str(lab.manifest_path.parent/'probe_driver.py')],cwd=lab.workspace,capture_output=True,text=True,timeout=10)
    output=parse_probe_payload(lab.results_path,run.stdout)
    assert all(p['status']=='skipped' for p in output['probes'] if p['capability'].endswith('_socket'))


def test_prepare_cli_accepts_socket_opt_out(tmp_path):
    path=tmp_path/'lab'
    assert main(['prepare','--output',str(path),'--no-network','--no-sockets'])==0
    manifest=evidence_io.read_json(path/'workspace/.agent-boundary/manifest.json')
    assert not manifest['socket_probe'] and not manifest['network_probe']


@pytest.mark.parametrize('command',['collect','diff'])
def test_cli_deep_json_returns_error_without_traceback(tmp_path,capsys,command):
    malformed='['*1100+'0'+']'*1100
    if command=='collect':
        lab=create_lab(tmp_path/'lab',network_probe=False,socket_probe=False)
        lab.manifest_path.write_text(malformed)
        argv=['collect',str(lab.root)]
    else:
        path=tmp_path/'report.json';path.write_text(malformed)
        argv=['diff',str(path),str(path)]
    assert main(argv)==2
    assert 'Traceback' not in capsys.readouterr().err


def test_report_load_rejects_duplicate_keys(tmp_path):
    path=tmp_path/'report.json'
    raw=json.dumps(report().to_dict()).replace('"evidence_complete": true','"evidence_complete": false, "evidence_complete": true')
    path.write_text(raw)
    with pytest.raises(ValueError):load_report(path)


def test_produced_result_file_contains_valid_hmac(tmp_path):
    lab=create_lab(tmp_path/'lab',network_probe=False,socket_probe=False)
    outcome=subprocess.run([sys.executable,'-I','-S',str(lab.manifest_path.parent/'probe_driver.py')],cwd=lab.workspace,capture_output=True,text=True,timeout=10)
    body=parse_probe_payload(lab.results_path,outcome.stdout)
    signature=body.pop('attestation')
    expected=hmac.new(lab.attestation_key.encode(),json.dumps(body,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected,signature)


def test_runner_output_limit_never_recovers_old_valid_file(tmp_path,monkeypatch):
    from agent_boundary_check.runner import verify
    from agent_boundary_check.adapters.base import AgentAdapter
    lab=create_lab(network_probe=False,socket_probe=False)
    payload=data(lab.run_id)
    payload['attestation']=hmac.new(lab.attestation_key.encode(),json.dumps(payload,sort_keys=True,separators=(',',':')).encode(),hashlib.sha256).hexdigest()
    lab.results_path.write_text(json.dumps(payload))
    monkeypatch.setattr('agent_boundary_check.runner.create_lab',lambda **k:lab)
    class Stub(AgentAdapter):
        def get_version(self):return None
        def run(self,*a):return AgentRun(0,'','',False,['synthetic'],output_limited=True)
    checked,_=verify(Stub(),network_probe=False,socket_probe=False)
    assert not checked.evidence_complete and checked.risk_level=='UNKNOWN'
    assert not lab.root.exists()


def test_probe_ancestor_validation_does_not_require_directory_listing(tmp_path):
    if os.name!='posix' or os.geteuid()==0: pytest.skip('requires unprivileged POSIX user')
    directory=tmp_path/'search-only';directory.mkdir()
    canary=directory/'canary';canary.write_text('synthetic')
    directory.chmod(0o100)
    try:
        assert read_regular_bytes(canary,limit=9)==b'synthetic'
    finally:
        directory.chmod(0o700)


def test_missing_result_is_incomplete_without_exceptions(tmp_path):
    assert parse_probe_payload(tmp_path/'missing','normal diagnostics') is None


def test_fixture_directory_replacement_never_reads_other_tree(tmp_path):
    root=tmp_path/'owned';root.mkdir(); (root/'canary').write_text('owned')
    renamed=tmp_path/'retained';root.rename(renamed)
    other=tmp_path/'other';other.mkdir(); (other/'canary').write_text('synthetic unrelated')
    try: root.symlink_to(other,target_is_directory=True)
    except OSError: pytest.skip('symlinks unavailable')
    with pytest.raises((ValueError,OSError)):read_regular_bytes(root/'canary',limit=100)
    assert (other/'canary').read_text()=='synthetic unrelated'


def test_showcase_is_offline_and_rejects_existing_output(tmp_path):
    import runpy
    module=runpy.run_path(str(Path(__file__).parents[1]/'scripts/showcase.py'))
    out=tmp_path/'showcase';summary=module['demonstrate'](out)
    assert summary['passed']==summary['total']==8
    with pytest.raises(FileExistsError):module['demonstrate'](out)


def test_synthetic_child_has_no_site_or_environment_startup_hooks():
    from agent_boundary_check.probe_script import PROBE_DRIVER_SOURCE
    assert '[sys.executable, "-I", "-S", "-c",' in PROBE_DRIVER_SOURCE
