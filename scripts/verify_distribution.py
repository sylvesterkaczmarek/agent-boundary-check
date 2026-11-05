"""Verify wheel/source identity and run the complete suite in a clean installation."""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import venv
import zipfile


def identity(raw, name, version):
    meta=BytesParser().parsebytes(raw)
    if meta.get_all('Name')!=[name] or meta.get_all('Version')!=[version]:
        raise ValueError('distribution identity mismatch or ambiguous metadata')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('wheel',type=Path)
    parser.add_argument('sdist',type=Path)
    parser.add_argument('--report',type=Path,required=True)
    args=parser.parse_args()
    wheel,sdist=args.wheel.resolve(strict=True),args.sdist.resolve(strict=True)
    env={k:v for k,v in os.environ.items() if k not in {'PYTHONPATH','PYTHONHOME'}}
    env['PYTHONNOUSERSITE']='1'
    with tempfile.TemporaryDirectory(prefix='boundary-installed-') as directory:
        root=Path(directory);source=root/'source';source.mkdir()
        with tarfile.open(sdist) as archive:
            members=archive.getmembers()
            if len(members)>10000 or sum(m.size for m in members)>50*1024*1024:
                raise ValueError('distribution exceeds size limits')
            archive.extractall(source,filter='data')
        roots=list(source.iterdir())
        if len(roots)!=1 or not roots[0].is_dir():raise ValueError('expected one source distribution root')
        project=roots[0]
        metadata=tomllib.loads((project/'pyproject.toml').read_text(encoding='utf-8'))['project']
        name,version=metadata['name'],metadata['version']
        identity((project/'PKG-INFO').read_bytes(),name,version)
        package=project/'src/agent_boundary_check'
        expected={'agent_boundary_check/'+p.relative_to(package).as_posix():p.read_bytes() for p in package.rglob('*.py')}
        with zipfile.ZipFile(wheel) as archive:
            records=[n for n in archive.namelist() if n.endswith('.dist-info/METADATA')]
            if len(records)!=1:raise ValueError('ambiguous wheel metadata')
            identity(archive.read(records[0]),name,version)
            actual={n:archive.read(n) for n in archive.namelist() if n.startswith('agent_boundary_check/') and n.endswith('.py')}
            if actual!=expected:raise ValueError('wheel/source runtime bytes differ')
        environment=root/'venv';venv.EnvBuilder(with_pip=True).create(environment)
        python=environment/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
        home=root/'synthetic-home';home.mkdir()
        # Tests and smoke demonstrations use only synthetic local homes and no sockets.
        env.update(HOME=str(home),USERPROFILE=str(home))
        def run(argv):
            subprocess.run([str(python),*argv],cwd=project,env=env,check=True,timeout=180)
        run(['-m','pip','install','--disable-pip-version-check',str(wheel),'pytest>=8,<10'])
        run(['-m','pip','check'])
        run(['-c','import pathlib,sys,importlib.metadata as m,agent_boundary_check as a; p=pathlib.Path(a.__file__).resolve(); assert pathlib.Path(sys.prefix).resolve() in p.parents; assert a.__version__==m.version(sys.argv[1])==sys.argv[2]; print("Installed runtime",p)',name,version])
        run(['-m','pytest','-q'])
        run(['scripts/showcase.py','--out',str(root/'showcase')])
        run(['-m','agent_boundary_check.cli','demo','--json',str(root/'demo.json')])
        report={'status':'PASS','distribution':name,'version':version,'runtime_files_matched':len(expected),
                'installation':'fresh non-editable wheel outside source checkout',
                'runtime_dependencies':metadata['dependencies'],
                'wheel_sha256':hashlib.sha256(wheel.read_bytes()).hexdigest(),
                'sdist_sha256':hashlib.sha256(sdist.read_bytes()).hexdigest()}
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
