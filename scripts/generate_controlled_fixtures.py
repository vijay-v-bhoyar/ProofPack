"""Generate or verify the fixed, non-independent controlled synthetic bundle."""
import argparse,json,sys
from pathlib import Path
import yaml
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/api'))
from proofpack.review.controlled_models import ControlledConfig
from proofpack.vision.controlled_fixtures import ControlledBundle,generate_bundle


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    target=ROOT/'fixtures/synthetic/controlled-v1'
    config=ControlledConfig(**yaml.safe_load((ROOT/'docs/controls.yaml').read_text())['controlled_baselines'])
    if not args.verify:generate_bundle(target)
    bundle=ControlledBundle(target,config)
    print(json.dumps({'status':'PASS','scope':'designer-authored synthetic bundle only','episodes':len(bundle.episodes),
        'setup_groups':24,'manifest_sha256':bundle.manifest_sha256,'physical_truth_verified':False,'independent_benchmark_qualified':False}))


if __name__=='__main__':main()
