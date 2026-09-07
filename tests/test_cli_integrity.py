import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent_boundary_check.adapters.base import AgentAdapter
from agent_boundary_check.cli import _write_json, main
from agent_boundary_check.lab import create_lab
from agent_boundary_check.models import CAPABILITIES
from agent_boundary_check.render import render_report
from agent_boundary_check.report import make_report
from agent_boundary_check.runner import verify


def _report():
    return make_report(
        run_id='0123456789abcdef', agent='synthetic', agent_version='1.0',
        payload={'schema_version': 1, 'run_id': '0123456789abcdef', 'probes': [
            {'capability': name, 'status': 'deny', 'detail': 'permission denied'}
            for name in CAPABILITIES
        ]}, policy=None, declared_hints={}, exit_code=0, timed_out=False, runner_output='',
    )


@pytest.mark.parametrize('change', ['timeout', 'unknown', 'skipped', 'policy'])
def test_diff_returns_failure_for_lost_evidence_or_existing_policy_failure(tmp_path, capsys, change):
    before = _report().to_dict()
    after = _report().to_dict()
    if change == 'timeout':
        after['runner_timed_out'] = True
        after['evidence_complete'] = False
    elif change in {'unknown', 'skipped'}:
        after['probes'][0]['status'] = change
    else:
        after['policy_violations'] = ['workspace_write: denied but policy requires allow']
    paths = [tmp_path / 'before.json', tmp_path / 'after.json']
    for path, data in zip(paths, [before, after]):
        path.write_text(json.dumps(data), encoding='utf-8')
    assert main(['diff', *map(str, paths)]) == (1 if change == 'policy' else 2)
    output = capsys.readouterr().out
    assert ('policy violation' if change == 'policy' else 'evidence incomplete') in output


def test_incomplete_collect_preserves_canaries_until_probe_can_run(tmp_path):
    lab = create_lab(tmp_path / 'manual', network_probe=False, environment_probe=False)
    assert main(['collect', str(lab.root)]) == 2
    assert lab.home_canary_dir.is_dir()
    proc = subprocess.run([sys.executable, '.agent-boundary/probe_driver.py'], cwd=lab.workspace, capture_output=True)
    assert proc.returncode == 0
    assert main(['collect', str(lab.root)]) == 0
    assert not lab.home_canary_dir.exists()


@pytest.mark.parametrize('filename', ['manifest.json', 'results.json', 'probe_driver.py', 'PROMPT.txt'])
def test_collect_report_cannot_overwrite_lab_inputs(tmp_path, filename):
    lab = create_lab(tmp_path / 'manual', network_probe=False, environment_probe=False)
    subprocess.run([sys.executable, '.agent-boundary/probe_driver.py'], cwd=lab.workspace, check=True, capture_output=True)
    output = lab.manifest_path.parent / filename
    before = output.read_bytes()
    assert main(['collect', str(lab.root), '--json', str(output)]) == 2
    assert output.read_bytes() == before
    assert lab.home_canary_dir.exists()


@pytest.mark.parametrize('alias', [False, True])
def test_verify_rejects_policy_output_collision_before_running(tmp_path, monkeypatch, alias):
    policy = tmp_path / 'policy.toml'
    policy.write_text('version = 1\ndeny = ["outside_write"]\n', encoding='utf-8')
    output = tmp_path / 'report.json' if alias else policy
    if alias:
        os.link(policy, output)
    before = policy.read_bytes()
    called = []
    monkeypatch.setattr('agent_boundary_check.cli.verify', lambda *a, **kw: called.append(True))
    assert main(['verify', 'command', '--command', 'unused', '--policy', str(policy), '--json', str(output)]) == 2
    assert called == []
    assert policy.read_bytes() == before


def test_failed_atomic_output_preserves_old_report(tmp_path, monkeypatch):
    output = tmp_path / 'report.json'
    output.write_text('previous report', encoding='utf-8')

    def fail_replace(*args):
        raise OSError('disk failure')

    monkeypatch.setattr('agent_boundary_check.cli.os.replace', fail_replace)
    with pytest.raises(OSError, match='disk failure'):
        _write_json(_report(), output)
    assert output.read_text() == 'previous report'
    assert list(tmp_path.glob('.report.json.*')) == []


@pytest.mark.parametrize('keep_lab', [False, True])
def test_interrupted_verify_cleans_its_owned_lab(tmp_path, monkeypatch, keep_lab):
    lab = create_lab(network_probe=False)
    monkeypatch.setattr('agent_boundary_check.runner.create_lab', lambda **kwargs: lab)

    class InterruptedAdapter(AgentAdapter):
        def get_version(self):
            return None

        def run(self, *args):
            raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        verify(InterruptedAdapter(), network_probe=False, keep_lab=keep_lab)
    assert not lab.root.exists()
    assert not lab.home_canary_dir.exists()


def test_terminal_metadata_cannot_clear_or_forge_report_lines(capsys):
    report = _report()
    report.agent_version = '\x1b[2J\nFORGED'
    report.evidence_error = 'failure\rPASS'
    render_report(report)
    text = capsys.readouterr().out
    assert '\x1b' not in text
    assert '\r' not in text
    assert '\\x1b[2J\\nFORGED' in text
    assert 'failure\\rPASS' in text


def test_demo_setup_error_returns_clean_cli_error(monkeypatch, capsys):
    def fail(*args, **kwargs):
        raise OSError('synthetic setup failure')

    monkeypatch.setattr('agent_boundary_check.cli.verify', fail)
    assert main(['demo']) == 2
    assert 'synthetic setup failure' in capsys.readouterr().err


@pytest.mark.parametrize('inside_cleanup_directory', [False, True])
def test_collect_preserves_canaries_and_durable_report_destination(tmp_path, inside_cleanup_directory):
    lab = create_lab(tmp_path / 'manual', network_probe=False, environment_probe=False)
    subprocess.run([sys.executable, '.agent-boundary/probe_driver.py'], cwd=lab.workspace, check=True, capture_output=True)
    output = lab.home_canary_dir / 'report.json' if inside_cleanup_directory else lab.workspace / 'workspace-canary.txt'
    before = output.read_bytes() if output.exists() else None
    assert main(['collect', str(lab.root), '--json', str(output)]) == 2
    assert (output.read_bytes() if output.exists() else None) == before
    assert lab.home_canary_dir.exists()


def test_collect_looping_lab_path_returns_input_error(tmp_path):
    loop = tmp_path / 'loop'
    try:
        loop.symlink_to(loop, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f'Filesystem does not permit symlinks: {exc}')
    assert main(['collect', str(loop)]) == 2
