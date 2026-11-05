"""Offline boundary-evidence demonstration using only owned synthetic resources."""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path
import sys
import tempfile
from unittest.mock import patch

from agent_boundary_check.adapters.command import CommandAdapter
from agent_boundary_check.diffing import diff_reports
from agent_boundary_check.policy import BoundaryPolicy, evaluate_policy
from agent_boundary_check.report import make_report, parse_probe_payload, RESULT_PREFIX
from agent_boundary_check.runner import verify


def demonstrate(out: Path):
    out.mkdir(parents=True, exist_ok=False)
    checks = []
    with tempfile.TemporaryDirectory(prefix='boundary-showcase-') as directory:
        home = Path(directory).resolve()/'home'; home.mkdir()
        with patch.object(Path, 'home', return_value=home):
            adapter = CommandAdapter(f'"{sys.executable}" -I -S .agent-boundary/probe_driver.py')
            observed, lab = verify(adapter, network_probe=False, socket_probe=False, keep_lab=True)
            payload = parse_probe_payload(lab.results_path, '')
            def record(name, ok, evidence_kind):
                checks.append({'case': name, 'passed': bool(ok), 'evidence_kind': evidence_kind})
            def resign(value):
                value = deepcopy(value)
                value.pop('attestation', None)
                canonical = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
                value['attestation'] = hmac.new(lab.attestation_key.encode(), canonical, hashlib.sha256).hexdigest()
                return value
            def interpret(value, **kwargs):
                args = dict(run_id=lab.run_id, agent='synthetic-evidence-fixture', agent_version=None,
                            payload=value, policy=None, declared_hints={}, exit_code=0, timed_out=False,
                            runner_output='', attestation_key=lab.attestation_key)
                args.update(kwargs)
                return make_report(**args)
            record('local_unsandboxed_exposure', observed.evidence_complete and observed.risk_level=='CRITICAL', 'actual local synthetic file/process probe')
            policy = BoundaryPolicy(frozenset({'outside_read','outside_write'}), frozenset())
            record('strict_policy_rejection', len(evaluate_policy(observed.probes, policy))==2, 'policy applied to actual local observation')
            raw = json.dumps(payload).replace('"schema_version": 1', '"schema_version": 0, "schema_version": 1')
            record('duplicate_json_rejected', parse_probe_payload(Path(directory)/'missing', RESULT_PREFIX+raw) is None, 'synthetic evidence corruption')
            changed = deepcopy(payload); changed['attestation'] = '0'*64
            record('invalid_signature_rejected', not interpret(changed).evidence_complete, 'synthetic evidence corruption')
            record('cross_run_replay_rejected', not interpret(payload, run_id='other-run').evidence_complete, 'synthetic identity mismatch')
            changed = deepcopy(payload); changed['probes'][0]['status']='skipped'
            record('mandatory_skip_incomplete', not interpret(resign(changed)).evidence_complete, 'synthetic missing measurement')
            record('output_limit_incomplete', not interpret(payload, output_limited=True).evidence_complete, 'synthetic capture limit')
            before=observed.to_dict(); after=deepcopy(before)
            next(p for p in after['probes'] if p['capability']=='outside_read')['status']='unknown'
            record('lost_observation_inconclusive', diff_reports(before, after).has_unusable_evidence, 'synthetic report comparison')
    summary = {'status':'PASS' if all(c['passed'] for c in checks) else 'FAIL', 'cases':checks,
               'passed':sum(c['passed'] for c in checks), 'total':len(checks),
               'scope':'One actual unsandboxed local synthetic probe plus controlled evidence mutations. No coding-agent inference, external network, host socket discovery or real credentials. This does not certify an agent sandbox.'}
    (out/'summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True)+'\n')
    for check in checks:
        print(f'{check["case"]:34} {"PASS" if check["passed"] else "FAIL"}')
    print(summary['scope'])
    if summary['status']!='PASS': raise RuntimeError('showcase did not meet expected outcomes')
    return summary


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    demonstrate(args.out)
