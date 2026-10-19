"""Pinned local emulator setup and a short-lived owned test server. No AWS credentials."""
import argparse
from contextlib import contextmanager
from datetime import datetime,timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import tempfile
import time
import zipfile

import boto3
from botocore.config import Config
import httpx

ROOT=Path(__file__).resolve().parents[1]
CACHE=ROOT/'.runtime/dynamodb'
SOURCE='https://d1ni2b6xgvw0s0.cloudfront.net/v2.x/dynamodb_local_latest.zip'


def lock_data():
    lock=json.loads((ROOT/'tools/dynamodb-local.lock.json').read_text(encoding='utf-8'))
    if lock['source_url']!=SOURCE or not re.fullmatch(r'[a-f0-9]{64}',lock['zip_sha256']):
        raise RuntimeError('unrecognized emulator lock')
    return lock


def verify_distribution():
    lock=lock_data();target=(CACHE/'distribution').resolve()
    for item in lock['files']:
        path=(target/item['path']).resolve()
        if not path.is_relative_to(target) or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest()!=item['sha256']:
            raise RuntimeError('Pinned DynamoDB Local is missing or changed. Run scripts/dynamodb_local.py --install.')
    return lock


def install():
    lock=lock_data();CACHE.mkdir(parents=True,exist_ok=True);archive=CACHE/'distribution.zip'
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest()!=lock['zip_sha256']:
        with httpx.Client(timeout=120,follow_redirects=False) as client:
            checksum=client.get(lock['checksum_url']);checksum.raise_for_status()
            if lock['zip_sha256'] not in checksum.text.lower():
                raise RuntimeError('Upstream distribution changed; review/version the lock before downloading.')
            with client.stream('GET',SOURCE) as response:
                response.raise_for_status();size=0
                with archive.open('wb') as output:
                    for chunk in response.iter_bytes():
                        size+=len(chunk)
                        if size>128*1024*1024:raise RuntimeError('emulator archive exceeds bound')
                        output.write(chunk)
    if hashlib.sha256(archive.read_bytes()).hexdigest()!=lock['zip_sha256']:raise RuntimeError('emulator checksum mismatch')
    target=(CACHE/'distribution').resolve();target.mkdir(exist_ok=True)
    expected={item['path']:item['sha256'] for item in lock['files']}
    with zipfile.ZipFile(archive) as bundle:
        files=[item for item in bundle.infolist() if not item.is_dir()]
        if sum(item.file_size for item in files)>512*1024*1024 or {item.filename for item in files}!=set(expected):
            raise RuntimeError('unexpected emulator archive inventory')
        for item in files:
            path=(target/item.filename).resolve()
            if not path.is_relative_to(target) or stat.S_ISLNK(item.external_attr>>16):raise RuntimeError('unsafe emulator archive entry')
            payload=bundle.read(item)
            if hashlib.sha256(payload).hexdigest()!=expected[item.filename]:raise RuntimeError('emulator member checksum mismatch')
            if path.exists() and hashlib.sha256(path.read_bytes()).hexdigest()!=expected[item.filename]:
                raise RuntimeError('existing emulator cache differs; do not overwrite it implicitly')
            path.parent.mkdir(parents=True,exist_ok=True)
            if not path.exists():path.write_bytes(payload)
    verify_distribution()
    print('PASS: pinned DynamoDB Local distribution verified.')


@contextmanager
def local_database():
    lock=verify_distribution();java=shutil.which('java')
    if not java:raise RuntimeError('Java 17+ is required for DynamoDB Local.')
    # SQLite run state is disposable and must not share a synced source tree.
    # The checksum-pinned distribution remains in the workspace cache.
    runs=Path(tempfile.gettempdir()).resolve();prefix='proofpack-dynamodb-check-'
    owned=Path(tempfile.mkdtemp(prefix=prefix,dir=runs)).resolve()
    if owned.parent!=runs or not owned.name.startswith(prefix):raise RuntimeError('unsafe test directory')
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1',0));port=reservation.getsockname()[1]
    target=CACHE/'distribution'
    command=[java,'-Djava.awt.headless=true',f'-Djava.library.path={target/"DynamoDBLocal_lib"}','-Xmx512m',
        '-jar',str(target/'DynamoDBLocal.jar'),'-sharedDb','-dbPath',str(owned),'-port',str(port),'-disableTelemetry',
        '-cors',f'http://127.0.0.1:{port}']
    output=ROOT/'evidence/local';output.mkdir(parents=True,exist_ok=True)
    receipt={'scope':'temporary_local_emulator_only','expected_version':lock['expected_version'],'pid':None,
        'endpoint':f'http://127.0.0.1:{port}','source_zip_sha256':lock['zip_sha256'],'command':command,
        'started_at':datetime.now(timezone.utc).isoformat(),'terminated':False,'aws_resources_created':False,
        'state_location':'os_temporary_directory','state_removed':False}
    process=None;log_created=False
    try:
        with (output/'dynamodb-server.log').open('wb') as log:
            log_created=True
            process=subprocess.Popen(command,cwd=owned,stdout=log,stderr=subprocess.STDOUT)
            receipt['pid']=process.pid
            client=boto3.client('dynamodb',endpoint_url=receipt['endpoint'],region_name='us-east-1',
                aws_access_key_id='localtest',aws_secret_access_key='localtest',
                config=Config(connect_timeout=.5,read_timeout=1,retries={'max_attempts':0}))
            deadline=time.monotonic()+15
            while True:
                if process.poll() is not None:raise RuntimeError('owned DynamoDB Local process exited during startup')
                try:
                    client.list_tables(Limit=1)
                    if process.poll() is None:break
                except Exception:
                    if time.monotonic()>=deadline:raise RuntimeError('DynamoDB Local startup timed out')
                    time.sleep(.1)
            yield receipt['endpoint']
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
            receipt['terminated']=process.poll() is not None
            receipt['process_exit_code']=process.returncode
        # Only this newly created run directory is removed, after the owned process stops.
        try:
            if owned.resolve().parent==runs and owned.name.startswith(prefix):shutil.rmtree(owned)
        finally:
            receipt['state_removed']=not owned.exists()
            receipt['server_log_sha256']=hashlib.sha256((output/'dynamodb-server.log').read_bytes()).hexdigest() if log_created else None
            receipt['ended_at']=datetime.now(timezone.utc).isoformat()
            (output/'dynamodb-local.json').write_text(json.dumps(receipt,indent=2)+'\n',encoding='utf-8')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--install',action='store_true');args=parser.parse_args()
    if args.install:install()
    else:
        verify_distribution();print('PASS: emulator hashes match the pinned lock.')
