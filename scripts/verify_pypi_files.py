"""Compare public PyPI downloads with the exact verified release distributions."""
import argparse
import hashlib
import json
from pathlib import Path
import time
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import urlopen


def verify(expected, output, version):
    expected = Path(expected); output = Path(output)
    files = sorted(expected.iterdir())
    if len(files) != 2 or {p.suffix for p in files} != {'.whl', '.gz'}:
        raise ValueError('expected one wheel and one source distribution')
    endpoint = f'https://pypi.org/pypi/agent-boundary-check/{version}/json'
    for attempt in range(12):
        try:
            with urlopen(endpoint, timeout=30) as response:
                metadata = json.loads(response.read(2*1024*1024))
            break
        except HTTPError as exc:
            if exc.code != 404 or attempt == 11:
                raise
            time.sleep(10)
    if metadata['info']['name'] != 'agent-boundary-check' or metadata['info']['version'] != version:
        raise ValueError('public package identity mismatch')
    registry = {item['filename']: item for item in metadata['urls']}
    if registry.keys() != {p.name for p in files}:
        raise ValueError('public file set differs from the reviewed build')
    output.mkdir(parents=True, exist_ok=False)
    proof = []
    for path in files:
        entry = registry[path.name]
        expected_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if entry['digests']['sha256'] != expected_hash:
            raise ValueError('public package digest differs from reviewed build')
        url = urlparse(entry['url'])
        if url.scheme != 'https' or url.hostname != 'files.pythonhosted.org':
            raise ValueError('unexpected public package file host')
        with urlopen(entry['url'], timeout=30) as response:
            data = response.read(50*1024*1024 + 1)
        if len(data) > 50*1024*1024 or hashlib.sha256(data).hexdigest() != expected_hash:
            raise ValueError('downloaded package digest mismatch')
        (output/path.name).write_bytes(data)
        proof.append({'name': path.name, 'sha256': expected_hash, 'bytes': len(data)})
    print(json.dumps({'status': 'PASS', 'version': version, 'files': proof}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    verify(args.expected, args.out, args.version)
