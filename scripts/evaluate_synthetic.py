"""Development-only single-frame findings; not a baseline advantage or hardware qualification."""
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import sys
import time

import cv2
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/api'))
from generate_fixtures import verify_corpus
from proofpack.recipes.models import Recipe
from proofpack.vision.calibration import CalibrationProfile,rectify
from proofpack.vision.pipeline import decode_image,measure
from proofpack.verifier.core import Finding


def main():
    target=ROOT/'fixtures/synthetic/v1'
    data=verify_corpus(target)
    profile=CalibrationProfile.model_validate_json(json.dumps(data['calibration_profile']))
    recipes={r['recipe_id']:Recipe.model_validate_json(json.dumps(r)) for r in data['recipes']}
    rows=[]
    for record in data['records']:
        started=time.monotonic()
        frame=decode_image((target/record['image']).read_bytes())
        rectified,envelope=rectify(frame,profile)
        result=measure(rectified,recipes[record['recipe_id']],envelope)
        satisfied=result.quality_ok and not result.unknown_regions and all(f==Finding.SATISFIED for f in result.findings)
        rows.append({'case_id':record['id'],'condition':record['condition'],'findings':[f.value for f in result.findings],
            'all_visible_constraints_satisfied':satisfied,'expected_satisfaction':record['expected_pass_allowed'],
            'unknown_regions':result.unknown_regions,'reason_codes':result.reason_codes,
            'elapsed_component_ms':(time.monotonic()-started)*1000,
            'outcome_matches_development_oracle':satisfied==record['expected_pass_allowed']})
    failed=[r['case_id'] for r in rows if not r['outcome_matches_development_oracle']]
    report={'scope':'synthetic_development_single_frame_only','status':'FAIL' if failed else 'PASS',
        'recorded_at':datetime.now(timezone.utc).isoformat(),'opencv_version':cv2.__version__,
        'manifest_sha256':hashlib.sha256((target/'manifest.json').read_bytes()).hexdigest(),
        'controls_sha256':hashlib.sha256((ROOT/'docs/controls.yaml').read_bytes()).hexdigest(),
        'episodes':len(rows),'setup_groups':data['setup_groups'],'failures':failed,'rows':rows,
        'limitations':['Development data, not untouched holdout or physical/operator evidence.',
            'No comparative throughput, network latency, durable pass or learning-advantage claim.',
            'Glare/wrong-variant cases use disclosed synthetic occluder/silhouette models.']}
    output=ROOT/'evidence/local/synthetic-evaluation.json'
    output.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({key:report[key] for key in ('status','scope','episodes','setup_groups','failures')}))
    raise SystemExit(1 if failed else 0)


if __name__=='__main__':main()
