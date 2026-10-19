"""Installed analytic synthetic cases; never physical or independent truth.

Keep heavy CV imports lazy so Windows worker bootstrap applies resource bounds
before importing OpenCV. This is distinct from controlled-v1 development data.
"""
from collections import Counter
from dataclasses import dataclass
import hashlib,json,time
from pathlib import Path

from proofpack.calibrations.dependencies import canonical,digest
from proofpack.evidence.repository import StoreUnavailable
from proofpack.planner.candidates import PolicyDraft
from proofpack.planner.policy import choose_action

RUNNER='policy_golden_v1'
FLAGS={'physical_truth_verified':False,'independent_benchmark_qualified':False,'operator_effort_measured':False}
CLASSES=('washer','nut','bolt','flat_bracket')
CASE_IDS=('complete',*(f'missing-{c}' for c in CLASSES),*(f'extra-{c}' for c in CLASSES),'blank-roi','unsupported-variant','clipped-roi')


@dataclass(frozen=True)
class GoldenInput:
    id:str
    payload:bytes
    recipe_json:str
    profile_json:str
    expected_json:str


@dataclass(frozen=True)
class GoldenPlan:
    manifest_json:str
    inputs:tuple[GoldenInput,...]

    @property
    def sha256(self):return hashlib.sha256(self.manifest_json.encode()).hexdigest()


def implementation_sha256():
    from proofpack.vision import fixtures
    return digest({'runner':RUNNER,'source':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'shared_renderer':hashlib.sha256(Path(fixtures.__file__).read_bytes()).hexdigest()})


def build_plan():
    import cv2
    from proofpack.vision import fixtures
    from proofpack.recipes.models import Constraint,Recipe,PartClass,Origin
    if not cv2.__version__.startswith('5.'):raise StoreUnavailable('actual OpenCV 5 required for golden plan')
    profile=fixtures.synthetic_profile().model_copy(update={'profile_id':'policy-golden-mat-v1'})
    recipe=Recipe(recipe_id='policy-golden-v1',revision=1,name='Installed analytic synthetic golden kit',kit_sku='golden-paper-v1',
        constraints=tuple(Constraint(constraint_id=c,part_class_id=PartClass(c),expected_count=1,required_visibility='Analytic synthetic top silhouette') for c in CLASSES),
        reference_asset_ids=('installed-generated-golden-v1',),calibration_profile_id=profile.profile_id,data_origin=Origin.SYNTHETIC)
    centers=((180,180),(330,190),(480,180),(630,190));inputs=[];manifest=[]
    for ident in CASE_IDS:
        image=fixtures.blank_mat();counts={c:1 for c in CLASSES};findings=['SATISFIED']*4;reasons=[];quality=True;selected=recipe
        missing=ident.removeprefix('missing-') if ident.startswith('missing-') else None
        extra=ident.removeprefix('extra-') if ident.startswith('extra-') else None
        for index,(name,center) in enumerate(zip(CLASSES,centers,strict=True)):
            if ident=='blank-roi':continue
            if name==missing:counts[name]=0;findings[index]='VIOLATED';continue
            fixtures._draw(image,PartClass(name),(100,180) if ident=='clipped-roi' and index==0 else center)
            if name==extra:fixtures._draw(image,PartClass(name),(center[0],300));counts[name]=2;findings[index]='VIOLATED'
        if missing is not None:reasons=['missing']
        if extra is not None:reasons=['extra']
        if ident=='unsupported-variant':
            selected=recipe.model_copy(update={'constraints':(recipe.constraints[0].model_copy(update={'permitted_variant_ids':('unenrolled-visible-variant',)}),*recipe.constraints[1:])})
            findings[0]='UNOBSERVABLE';reasons=['unsupported_variant']
        if ident in {'blank-roi','clipped-roi'}:
            counts={c:0 for c in CLASSES};findings=['UNOBSERVABLE']*4;quality=False;reasons=['blur' if ident=='blank-roi' else 'clipped_roi']
        action=None if ident=='complete' else 'RECAPTURE' if missing is not None or extra is not None or ident=='blank-roi' else 'REVIEW'
        expected={'findings':findings,'counts':counts,'quality_ok':quality,'unknown_regions':0,'reason_codes':reasons,'action':action}
        encoded,png=cv2.imencode('.png',image,[cv2.IMWRITE_PNG_COMPRESSION,9])
        if not encoded or not 0<len(png)<=2097152:raise StoreUnavailable('bounded generated golden image required')
        value=GoldenInput(ident,png.tobytes(),selected.model_dump_json(),profile.model_dump_json(),canonical(expected));inputs.append(value)
        manifest.append({'id':ident,'image_sha256':hashlib.sha256(value.payload).hexdigest(),'recipe_sha256':hashlib.sha256(value.recipe_json.encode()).hexdigest(),
            'profile_sha256':profile.content_hash,'expected':expected})
    record={'runner':RUNNER,'purpose':'synthetic_demo_qualification_only','data_origin':'synthetic','implementation_sha256':implementation_sha256(),
        'opencv_version':cv2.__version__,'cases':manifest,'case_count':12,'truth_basis':'analytic renderer specification; shared generator/calibration and same-author expectations',
        'controlled_v1_reused':False,**FLAGS}
    return GoldenPlan(canonical(record),tuple(inputs))


def measure_case(plan,index,spec,registry,runtime_id,*,gate,max_case_ms,tick_ns=None):
    from proofpack.recipes.models import Recipe
    from proofpack.vision.calibration import CalibrationProfile
    if (not isinstance(plan,GoldenPlan) or type(index) is not int or not 0<=index<12 or len(plan.inputs)!=12
            or not isinstance(spec,PolicyDraft) or not callable(gate) or type(max_case_ms) is not int or not 1000<=max_case_ms<=15000):
        raise ValueError('complete installed golden plan and bounded execution required')
    tick=tick_ns or time.monotonic_ns;started=tick()
    if type(started) is not int or started<0:raise StoreUnavailable('trusted golden monotonic clock required')
    definition=canonical(spec.model_dump(mode='json'));manifest=json.loads(plan.manifest_json);item=plan.inputs[index]
    original_implementation=manifest['implementation_sha256'];profile=CalibrationProfile.model_validate_json(item.profile_json);recipe=Recipe.model_validate_json(item.recipe_json)
    def final_guard():
        gate()
        if (implementation_sha256()!=original_implementation or canonical(spec.model_dump(mode='json'))!=definition
                or manifest['cases'][index]['id']!=item.id or item.id!=CASE_IDS[index]
                or manifest['cases'][index]['image_sha256']!=hashlib.sha256(item.payload).hexdigest()
                or manifest['cases'][index]['recipe_sha256']!=hashlib.sha256(item.recipe_json.encode()).hexdigest()
                or manifest['cases'][index]['profile_sha256']!=profile.content_hash
                or canonical(manifest['cases'][index]['expected'])!=item.expected_json):raise StoreUnavailable('golden plan or implementation changed')
        now=tick()
        if type(now) is not int or not 0<=now-started<max_case_ms*1000000:raise StoreUnavailable('original golden case window expired')
    final_guard()
    with registry.diagnostic(runtime_id=runtime_id) as worker:
        final_guard();result=worker.analyze(item.payload,recipe,profile,sequence=index+1,inspection_id='policy-golden-v1');final_guard()
    counts=Counter(c.part_class.value for c in result.candidates if c.part_class is not None)
    actual={'findings':[x.value for x in result.findings],'counts':{c:counts[c] for c in CLASSES},'quality_ok':result.quality_ok,
        'unknown_regions':result.unknown_regions,'reason_codes':list(result.reason_codes),
        'action':None if all(x.value=='SATISFIED' for x in result.findings) else choose_action(tuple(result.reason_codes),priority=spec.priority).value}
    if result.source_sha256!=manifest['cases'][index]['image_sha256'] or result.calibration_hash!=profile.content_hash:raise StoreUnavailable('golden worker provenance mismatch')
    expected=json.loads(item.expected_json)
    content={'phase':'installed_golden','case_id':item.id,'manifest_sha256':plan.sha256,'source_sha256':result.source_sha256,
        'recipe_sha256':manifest['cases'][index]['recipe_sha256'],'calibration_sha256':profile.content_hash,'expected':expected,'actual':actual,
        'passed':actual==expected,'new_pixel_measurement':True,**FLAGS}
    if len(canonical(content).encode())>32768:raise StoreUnavailable('golden case report exceeds bound')
    final_guard();return content,final_guard
