"""Pytest process evidence for exact full-suite coverage; no application authority."""
import json
import os
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
_data={'phase':'RUNNING','nodeids':[],'outcomes':[],'exit_code':None}


def _write():
    path=Path(os.environ['PROOFPACK_PYTEST_EVIDENCE_PATH']).resolve()
    if not path.is_relative_to(ROOT/'evidence/local') or path.suffix!='.json':
        raise ValueError('owned local evidence destination required')
    path.write_text(json.dumps(_data,indent=2)+'\n',encoding='utf-8')


def pytest_sessionstart(session):_write()


def pytest_collection_finish(session):
    _data.update(phase='COLLECTED',nodeids=[item.nodeid for item in session.items]);_write()


def pytest_runtest_logreport(report):
    _data['outcomes'].append({'nodeid':report.nodeid,'phase':report.when,'outcome':report.outcome,'duration_seconds':report.duration})


def pytest_sessionfinish(session,exitstatus):
    _data.update(phase='COMPLETE',exit_code=int(exitstatus));_write()
