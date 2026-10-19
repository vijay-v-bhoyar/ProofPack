"""A wheel must not accept an absent or internally incomplete frontend."""
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT=Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('kind',['absent','missing_reference'])
def test_incomplete_frontend_is_rejected_before_wheel_packaging(tmp_path,kind):
    for name in ('setup.py','pyproject.toml','requirements.txt','MANIFEST.in'):shutil.copyfile(ROOT/name,tmp_path/name)
    source=tmp_path/'services/api/proofpack';source.mkdir(parents=True);(source/'__init__.py').write_text('',encoding='utf-8')
    if kind=='missing_reference':
        web=tmp_path/'apps/web/dist';(web/'assets').mkdir(parents=True)
        (web/'index.html').write_text('<!doctype html><script type="module" src="/assets/missing.js"></script>',encoding='utf-8')
        (web/'assets/other.js').write_text('console.log("synthetic fixture");',encoding='utf-8')
    result=subprocess.run([sys.executable,'setup.py','build_py','--build-lib',str(tmp_path/'out')],cwd=tmp_path,
        capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
    assert result.returncode!=0,'incomplete HTML references must not produce an installable frontend'
    assert 'Build the complete bounded frontend' in result.stdout+result.stderr
