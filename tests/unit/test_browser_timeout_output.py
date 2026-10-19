"""Retain actual child diagnostics without changing timeout or process outcomes."""
from pathlib import Path
from subprocess import TimeoutExpired
import importlib
import pytest

@pytest.mark.parametrize('output,expected',[(b'partial\n\xff',b'partial\n\xff'),('partial \u03b1\n','partial \u03b1\n'.encode()),(None,b'')])
def test_timeout_retains_exact_available_stdout(monkeypatch,tmp_path,output,expected):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'integration'))
    module=importlib.import_module('test_owner_review_browser')
    error=TimeoutExpired(['synthetic-child'],60,output=output)
    path=tmp_path/'partial.log'
    module.retain_timeout_output(error,path)
    assert path.read_bytes()==expected
    assert error.timeout==60 and error.output is output

def test_timeout_retention_is_best_effort_and_does_not_mask_cleanup(monkeypatch,tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'integration'))
    module=importlib.import_module('test_owner_review_browser')
    error=TimeoutExpired(['synthetic-child'],60,output=b'partial')
    def denied(*args,**kwargs):raise OSError('synthetic unwritable evidence destination')
    monkeypatch.setattr(Path,'write_bytes',denied)
    assert module.retain_timeout_output(error,tmp_path/'partial.log') is False
    assert error.output==b'partial' and error.timeout==60

def test_preexisting_diagnostics_are_never_overwritten(monkeypatch,tmp_path):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'integration'))
    module=importlib.import_module('test_owner_review_browser')
    path=tmp_path/'partial.log';path.write_bytes(b'original')
    assert module.retain_timeout_output(TimeoutExpired(['synthetic-child'],60,output=b'later'),path) is False
    assert path.read_bytes()==b'original'

def test_actual_child_timeout_retains_emitted_output(monkeypatch,tmp_path):
    import subprocess,sys
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'integration'))
    module=importlib.import_module('test_owner_review_browser')
    command=[sys.executable,'-c',"import time; print('synthetic diagnostic before timeout',flush=True); time.sleep(10)"]
    with pytest.raises(TimeoutExpired) as caught:
        subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=3)
    path=tmp_path/'actual-child.partial.log'
    assert module.retain_timeout_output(caught.value,path) is True
    assert path.read_bytes()==caught.value.output
    assert path.read_bytes().splitlines()==[b'synthetic diagnostic before timeout']
