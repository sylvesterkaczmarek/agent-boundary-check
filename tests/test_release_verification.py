"""Public-download verifier controls use synthetic bytes, not live registry calls."""
import hashlib
import io
import json
from pathlib import Path
import runpy
from urllib.error import HTTPError

import pytest


def fixture(tmp_path):
    expected = tmp_path/'expected'; expected.mkdir()
    bodies = {'example.whl': b'synthetic wheel', 'example.tar.gz': b'synthetic source'}
    for name, data in bodies.items(): (expected/name).write_bytes(data)
    metadata = {'info': {'name': 'agent-boundary-check', 'version': '0.2.0'}, 'urls': [
        {'filename': name, 'url': 'https://files.pythonhosted.org/'+name,
         'digests': {'sha256': hashlib.sha256(data).hexdigest()}} for name, data in bodies.items()]}
    module = runpy.run_path(str(Path(__file__).parents[1]/'scripts/verify_pypi_files.py'))
    return expected, bodies, metadata, module['verify']


@pytest.mark.parametrize('damage', ['name', 'version', 'digest', 'host', 'file-set', 'content'])
def test_public_download_rejects_wrong_identity_or_bytes(tmp_path, monkeypatch, damage):
    expected, bodies, metadata, verify = fixture(tmp_path)
    if damage == 'name': metadata['info']['name'] = 'unrelated'
    if damage == 'version': metadata['info']['version'] = '1.0.0'
    if damage == 'digest': metadata['urls'][0]['digests']['sha256'] = '0'*64
    if damage == 'host': metadata['urls'][0]['url'] = 'https://unrelated.invalid/file.whl'
    if damage == 'file-set': metadata['urls'].pop()
    if damage == 'content': bodies['example.whl'] += b'changed'
    def fake(url, **kwargs):
        if 'pypi.org/pypi/' in url: return io.BytesIO(json.dumps(metadata).encode())
        assert url.startswith('https://files.pythonhosted.org/')
        return io.BytesIO(bodies[url.rsplit('/', 1)[1]])
    monkeypatch.setitem(verify.__globals__, 'urlopen', fake)
    with pytest.raises(ValueError): verify(expected, tmp_path/'download', '0.2.0')


def test_public_download_valid_control_preserves_exact_bytes(tmp_path, monkeypatch):
    expected, bodies, metadata, verify = fixture(tmp_path)
    def fake(url, **kwargs):
        return io.BytesIO(json.dumps(metadata).encode() if 'pypi.org/pypi/' in url else bodies[url.rsplit('/', 1)[1]])
    monkeypatch.setitem(verify.__globals__, 'urlopen', fake)
    verify(expected, tmp_path/'download', '0.2.0')
    assert {p.name:p.read_bytes() for p in (tmp_path/'download').iterdir()} == bodies


def test_public_metadata_retry_handles_registry_propagation(tmp_path, monkeypatch):
    expected, bodies, metadata, verify = fixture(tmp_path)
    calls = []
    def fake(url, **kwargs):
        if 'pypi.org/pypi/' in url:
            calls.append(url)
            if len(calls) == 1: raise HTTPError(url, 404, 'synthetic propagation', {}, None)
            return io.BytesIO(json.dumps(metadata).encode())
        return io.BytesIO(bodies[url.rsplit('/', 1)[1]])
    monkeypatch.setitem(verify.__globals__, 'urlopen', fake)
    monkeypatch.setattr(verify.__globals__['time'], 'sleep', lambda _: None)
    verify(expected, tmp_path/'download', '0.2.0')
    assert len(calls) == 2
