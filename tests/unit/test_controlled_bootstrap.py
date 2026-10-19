"""A Windows spawn re-import must reach the worker's own resource setup first."""
from pathlib import Path
import subprocess
import sys


def test_importing_controlled_cli_does_not_preload_worker_dependencies():
    cli=Path(__file__).resolve().parents[2]/'scripts/evaluate_controlled.py'
    probe="""
import runpy,sys
runpy.run_path(sys.argv[1],run_name='__mp_main__')
prefixes=('cv2','numpy','pydantic','boto3','botocore','proofpack')
loaded=sorted(name for name in sys.modules if any(name==p or name.startswith(p+'.') for p in prefixes))
assert not loaded, 'Dependencies imported before worker limits: '+repr(loaded)
"""
    result=subprocess.run([sys.executable,'-I','-c',probe,str(cli)],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stdout+result.stderr
