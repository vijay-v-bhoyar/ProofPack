"""Designer-authored action responses, never observed physical interventions."""
import hashlib,json
from pathlib import Path
import cv2

from proofpack.calibrations.dependencies import canonical,digest
from proofpack.planner.policy import DEFAULT_PRIORITY
from proofpack.review.controlled_models import bounded_read,strict_json
from proofpack.vision import fixtures
from proofpack.vision.calibration import CalibrationProfile
from proofpack.recipes.models import Recipe

RESPONSE_MODEL={'version':'rendered-response-v1','effects':{'overlap':{'SEPARATE_REGION':'complete'},'glare':{'RECAPTURE':'complete'}},
    'other_actions':'no_change','unresolvable':['missing','wrong_visible_variant','post_pass_removal'],
    'scope':'authored synthetic assumptions; not observed counterfactual or human effects'}
PNG_BYTES=2097152


def build_metadata(sink=None):
    images={};episodes=[];profile=fixtures.synthetic_profile();response_model=json.loads(canonical(RESPONSE_MODEL))
    for ri in range(3):
        for condition in fixtures.CONDITIONS:
            for setup in range(8):
                seed=1000+ri*100+setup;name=f'r{ri+1}-{condition}-{setup}.png'
                frame,truth=fixtures.make_fixture(ri,condition,seed=seed);ok,encoded=cv2.imencode('.png',frame)
                if not ok:raise ValueError('controlled fixture encoding failed')
                payload=encoded.tobytes()
                if not 0<len(payload)<=PNG_BYTES:raise ValueError('controlled image exceeds input bound')
                images[name]={'sha256':hashlib.sha256(payload).hexdigest(),'truth_complete':not truth['known_incomplete'],
                    'ground_truth_counts':truth['actual_counts'],'data_origin':'synthetic'}
                if sink is not None:sink(name,payload)
    for ri in range(3):
        for condition in fixtures.CONDITIONS:
            for setup in range(8):
                initial=f'r{ri+1}-{condition}-{setup}.png';complete=f'r{ri+1}-complete-{setup}.png'
                states={'initial':{'image':initial}}
                if condition in response_model['effects']:states['clear']={'image':complete}
                edges={name:{kind.value:name for kind in DEFAULT_PRIORITY} for name in states}
                for kind in response_model['effects'].get(condition,{}):edges['initial'][kind]='clear'
                episodes.append({'id':f'controlled-r{ri+1}-{condition}-{setup}','recipe_index':ri,'setup':setup,'seed':1000+ri*100+setup,
                    'setup_group':f'controlled-synthetic-{ri}-{setup}','condition':condition,'initial_state':'initial','states':states,'edges':edges})
    return {'schema_version':1,'data_origin':'synthetic','split':'DEVELOPMENT','frozen_for_reproducibility':True,
        'independent_benchmark_qualified':False,'physical_truth_verified':False,'reviewer_independent':False,
        'license':'OWNER_PUBLICATION_DECISION_REQUIRED','generation_seed_scheme':'1000+recipe_index*100+setup',
        'generator_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'base_generator_sha256':hashlib.sha256(Path(fixtures.__file__).read_bytes()).hexdigest(),
        'opencv_version':cv2.__version__,'response_model':response_model,'response_model_sha256':digest(response_model),
        'episodes':episodes,'episode_count':len(episodes),'setup_groups':24,'images':images,
        'calibration_profile':profile.model_dump(mode='json'),'recipes':[fixtures.demo_recipe(i).model_dump(mode='json') for i in range(3)]}


def generate_bundle(target):
    target=Path(target)
    if target.exists() or target.is_symlink():raise FileExistsError('refuse to replace an existing controlled bundle')
    target.mkdir(parents=True)
    metadata=build_metadata(lambda name,payload:(target/name).write_bytes(payload))
    (target/'manifest.json').write_text(canonical(metadata)+'\n',encoding='utf-8')
    return metadata


class ControlledBundle:
    def __init__(self,target,config):
        source=Path(target)
        if source.is_symlink():raise ValueError('unlinked controlled bundle required')
        self.root=source.resolve();self.config=config;self.path=self.root/'manifest.json'
        payload=bounded_read(self.path,config.max_manifest_bytes);parsed=strict_json(payload,config.max_json_depth)
        expected=build_metadata()
        if canonical(parsed)!=canonical(expected) or len(expected['episodes'])>config.max_episodes:
            raise ValueError('exact generated controlled manifest required')
        if any(len(e['states'])>config.max_response_states_per_episode for e in expected['episodes']):raise ValueError('controlled state budget insufficient')
        self._text=canonical(parsed);self.manifest_sha256=hashlib.sha256(payload).hexdigest()
        self._images=parsed['images'];self._names=frozenset((*self._images,'manifest.json'))
        self.profile=CalibrationProfile.model_validate_json(canonical(parsed['calibration_profile']))
        self.recipes=tuple(Recipe.model_validate_json(canonical(r)) for r in parsed['recipes'])
        self.assert_current(all_images=True)

    @property
    def metadata(self):return json.loads(self._text)

    @property
    def episodes(self):return self.metadata['episodes']

    def image(self,name):
        if name not in self._images:raise ValueError('admitted controlled image required')
        path=self.root/name
        if path.is_symlink() or path.resolve().parent!=self.root:raise ValueError('scoped controlled image required')
        payload=bounded_read(path,PNG_BYTES)
        if hashlib.sha256(payload).hexdigest()!=self._images[name]['sha256']:raise ValueError('controlled source bytes changed')
        return payload,json.loads(canonical(self._images[name]))

    def assert_current(self,*,all_images=False):
        if hashlib.sha256(bounded_read(self.path,self.config.max_manifest_bytes)).hexdigest()!=self.manifest_sha256:
            raise ValueError('controlled manifest changed')
        if frozenset(p.name for p in self.root.iterdir())!=self._names:raise ValueError('controlled inventory changed')
        if all_images:
            for name in self._images:self.image(name)
