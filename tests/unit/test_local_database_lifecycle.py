"""Owned emulator resource isolation, without Java, a socket server or AWS."""
import json
from pathlib import Path
import sys
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
import dynamodb_local as local


@pytest.fixture
def sandbox(tmp_path,monkeypatch):
    workspace=tmp_path/'workspace';workspace.mkdir()
    state=tmp_path/'os-temp';state.mkdir();marker=state/'unrelated.txt';marker.write_text('preserve')
    monkeypatch.setattr(local,'ROOT',workspace);monkeypatch.setattr(local,'CACHE',workspace/'distribution-cache')
    monkeypatch.setattr(local,'verify_distribution',lambda:{'expected_version':'fixture','zip_sha256':'a'*64})
    monkeypatch.setattr(local.shutil,'which',lambda name:'synthetic-java')
    monkeypatch.setattr(local.tempfile,'gettempdir',lambda:str(state))
    calls=[]
    class Process:
        pid=12345
        def __init__(self):self.code=None
        @property
        def returncode(self):return self.code
        def poll(self):return self.code
        def terminate(self):self.code=0
        def wait(self,timeout):return self.code
        def kill(self):self.code=-1
    def popen(command,*,cwd,stdout,stderr):
        owned=Path(command[command.index('-dbPath')+1]);assert owned==cwd and owned.is_dir()
        (owned/'local.sqlite').write_text('synthetic');stdout.write(b'synthetic emulator diagnostics\n');stdout.flush()
        process=Process();calls.append((owned,process));return process
    monkeypatch.setattr(local.subprocess,'Popen',popen)
    class Client:
        def list_tables(self,**kwargs):return {}
    monkeypatch.setattr(local.boto3,'client',lambda *args,**kwargs:Client())
    return workspace,state,marker,calls


@pytest.mark.parametrize('body_failure',[False,True])
def test_emulator_state_is_private_os_temp_and_cleanup_preserves_unrelated_files(sandbox,body_failure):
    workspace,state,marker,calls=sandbox
    def execute():
        with local.local_database() as endpoint:
            assert endpoint.startswith('http://127.0.0.1:')
            owned=calls[0][0]
            assert owned.parent==state and owned.name.startswith('proofpack-dynamodb-check-')
            assert not owned.is_relative_to(workspace)
            if body_failure:raise RuntimeError('synthetic caller failure')
    if body_failure:
        with pytest.raises(RuntimeError,match='synthetic caller failure'):execute()
    else:execute()
    receipt=json.loads((workspace/'evidence/local/dynamodb-local.json').read_text())
    assert receipt['terminated'] and receipt['state_removed'] and receipt['state_location']=='os_temporary_directory'
    assert not calls[0][0].exists() and calls[0][1].code==0 and marker.read_text()=='preserve'
    assert (workspace/'evidence/local/dynamodb-server.log').read_text()=='synthetic emulator diagnostics\n'


def test_emulator_startup_exit_still_cleans_only_owned_state_and_records_diagnostics(sandbox,monkeypatch):
    workspace,state,marker,calls=sandbox;original=local.subprocess.Popen
    def stopped(*args,**kwargs):
        process=original(*args,**kwargs);process.code=9;return process
    monkeypatch.setattr(local.subprocess,'Popen',stopped)
    with pytest.raises(RuntimeError,match='exited during startup'):
        with local.local_database():raise AssertionError('failed startup cannot serve tests')
    receipt=json.loads((workspace/'evidence/local/dynamodb-local.json').read_text())
    assert receipt['terminated'] and receipt['state_removed'] and receipt['process_exit_code']==9
    assert not calls[0][0].exists() and marker.read_text()=='preserve'
