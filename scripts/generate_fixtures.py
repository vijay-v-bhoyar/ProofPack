"""Create an immutable, labeled development corpus; verify existing versions without replacement."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/api'))
from proofpack.vision.fixtures import CONDITIONS,write_corpus
from proofpack.recipes.models import Origin,Recipe
from proofpack.vision.calibration import CalibrationProfile


def verify_corpus(target: Path) -> dict:
    payload=(target/'manifest.json').read_bytes()
    if len(payload)>1024*1024:raise ValueError('manifest limit exceeded')
    manifest=json.loads(payload)
    records=manifest['records']
    if manifest['data_origin']!='synthetic' or len(records)!=144:
        raise ValueError('expected 144 explicitly synthetic development episodes')
    profile=CalibrationProfile.model_validate_json(json.dumps(manifest['calibration_profile']))
    recipes=[Recipe.model_validate_json(json.dumps(r)) for r in manifest['recipes']]
    if (profile.data_origin!=Origin.SYNTHETIC or len(recipes)!=3
            or {r.recipe_id for r in recipes}!={'synthetic-1','synthetic-2','synthetic-3'}
            or any(r.data_origin!=Origin.SYNTHETIC or r.calibration_profile_id!=profile.profile_id for r in recipes)):
        raise ValueError('recipe/calibration origins and bindings must remain synthetic')
    expected={f'r{recipe}-{condition}-{setup}.png' for recipe in range(1,4) for condition in CONDITIONS for setup in range(8)}
    if len({r['image'] for r in records})!=144 or {r['image'] for r in records}!=expected:
        raise ValueError('missing, duplicate or unsafe fixture paths')
    for record in records:
        if (record['data_origin']!='synthetic' or record['split']!='DEVELOPMENT'
                or record['actual_packing_operator'] or record['physical_specimens'] or record['reviewer_independent']):
            raise ValueError('fixture provenance cannot be relabeled as physical/human evidence')
        path=(target/record['image']).resolve()
        if not path.is_relative_to(target.resolve()):raise ValueError('fixture path escapes corpus')
        if hashlib.sha256(path.read_bytes()).hexdigest()!=record['sha256']:
            raise ValueError('fixture content hash mismatch')
    return manifest


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--version',default='v1')
    parser.add_argument('--verify',action='store_true')
    args=parser.parse_args()
    if not re.fullmatch(r'v[1-9][0-9]*',args.version):raise SystemExit('version must be v1, v2, ...')
    root=(ROOT/'fixtures/synthetic').resolve()
    target=(root/args.version).resolve()
    if not target.is_relative_to(root):raise SystemExit('corpus path outside fixture root')
    if args.verify:data=verify_corpus(target)
    else:data=write_corpus(target)
    print(json.dumps({'status':'PASS','data_origin':'synthetic','episodes':len(data['records']),
        'setup_groups':len({r['independent_setup_group'] for r in data['records']}),'path':str(target)}))


if __name__=='__main__':main()
