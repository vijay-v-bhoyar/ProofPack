from pathlib import Path
import json,shutil
import pytest

from test_controlled_contracts import configuration
from proofpack.vision.controlled_fixtures import ControlledBundle,generate_bundle


@pytest.fixture(scope='module')
def generated(tmp_path_factory):
    target=tmp_path_factory.mktemp('controlled-inputs')/'bundle';generate_bundle(target);return target


def test_generated_bundle_has_disjoint_synthetic_groups_and_correct_observability_truth(generated):
    bundle=ControlledBundle(generated,configuration());data=bundle.metadata
    assert len(bundle.episodes)==144 and data['setup_groups']==24 and len(data['images'])==144
    assert all(e['seed']>=1000 for e in bundle.episodes)
    assert len({e['setup_group'] for e in bundle.episodes})==24
    assert not data['physical_truth_verified'] and not data['independent_benchmark_qualified'] and data['split']=='DEVELOPMENT'
    glare=next(e for e in bundle.episodes if e['condition']=='glare');name=glare['states']['initial']['image']
    payload,truth=bundle.image(name);assert payload.startswith(b'\x89PNG') and truth['truth_complete']
    truth['ground_truth_counts']['washer']=999
    assert bundle.image(name)[1]['ground_truth_counts']['washer']!=999
    glare['states'].clear();assert bundle.episodes[4]['states']
    with pytest.raises(FileExistsError):generate_bundle(generated)


@pytest.mark.parametrize('fault',['origin','truth','path','duplicate','bytes','extra','missing'])
def test_modified_inventory_metadata_or_pixels_are_rejected(generated,tmp_path,fault):
    target=tmp_path/'copy';shutil.copytree(generated,target);manifest=target/'manifest.json';data=json.loads(manifest.read_text())
    name=next(iter(data['images']))
    if fault=='origin':data['data_origin']='physical'
    elif fault=='truth':data['images'][name]['truth_complete']=not data['images'][name]['truth_complete']
    elif fault=='path':data['episodes'][0]['states']['initial']['image']='../../private.png'
    elif fault=='bytes':(target/name).write_bytes(b'corrupted')
    elif fault=='extra':(target/'unexpected.png').write_bytes(b'not-an-input')
    elif fault=='missing':(target/name).unlink()
    if fault=='duplicate':manifest.write_text('{"schema_version":1,"schema_version":1}')
    elif fault in {'origin','truth','path'}:manifest.write_text(json.dumps(data))
    with pytest.raises((ValueError,OSError)):ControlledBundle(target,configuration())
