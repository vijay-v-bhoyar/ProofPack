import hashlib
import importlib.util
import json
from pathlib import Path

import cv2
import numpy as np
import pytest

from proofpack.vision.fixtures import CONDITIONS,make_fixture,write_corpus


def test_deterministic_and_counterfactual_truth():
    for condition in CONDITIONS:
        a,truth=make_fixture(0,condition,seed=3);b,other=make_fixture(0,condition,seed=3)
        assert np.array_equal(a,b) and truth==other
        assert truth['data_origin']=='synthetic' and not truth['actual_packing_operator']
        if condition in {'missing','post_pass_removal'}:assert truth['actual_counts']['washer']==0


def test_complete_corpus_provenance_and_no_overwrite(tmp_path):
    data=write_corpus(tmp_path/'corpus')
    assert len(data['records'])==144
    assert len({r['independent_setup_group'] for r in data['records']})==24
    assert {r['condition'] for r in data['records']}==set(CONDITIONS)
    assert all(r['data_origin']=='synthetic' and not r['physical_specimens'] for r in data['records'])
    for record in data['records']:
        assert hashlib.sha256((tmp_path/'corpus'/record['image']).read_bytes()).hexdigest()==record['sha256']
    with pytest.raises(FileExistsError):write_corpus(tmp_path/'corpus')


def test_corpus_verification_rejects_path_provenance_and_content_tampering(tmp_path):
    spec=importlib.util.spec_from_file_location('fixture_verifier',Path(__file__).resolve().parents[2]/'scripts/generate_fixtures.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    target=tmp_path/'corpus';write_corpus(target)
    path=target/'manifest.json';original=path.read_bytes()
    assert len(module.verify_corpus(target)['records'])==144
    for mutation in ('path','origin','calibration_origin'):
        data=json.loads(original)
        if mutation=='path':data['records'][0]['image']='../outside.png'
        elif mutation=='origin':data['records'][0]['data_origin']='physical'
        else:data['calibration_profile']['data_origin']='physical'
        path.write_text(json.dumps(data),encoding='utf-8')
        with pytest.raises(ValueError):module.verify_corpus(target)
    path.write_bytes(original)
    first=target/json.loads(original)['records'][0]['image']
    first.write_bytes(b'forged fixture')
    with pytest.raises(ValueError,match='hash mismatch'):module.verify_corpus(target)
