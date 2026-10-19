"""Authorized original-frame CV comparisons; no live state or promotion writer."""
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import time
from typing import Literal,Callable
from pydantic import Field,model_validator

from proofpack.auth.policy import Denied,Role
from proofpack.calibrations.dependencies import canonical,digest
from proofpack.evidence.originals import original_profile
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable
from proofpack.planner.candidates import PolicyDraft
from proofpack.recipes.models import Recipe
from proofpack.recipes.service import catalog_key,revision_key
from proofpack.review.evaluation_models import EvaluationRequest,replay_decision
from proofpack.review.labels import UUIDText
from proofpack.runtime.control import integer,sha
from proofpack.vision.registry import WorkerRegistry
from proofpack.vision.worker_result import WorkerResult


class VisionReplayRequest(EvaluationRequest):
    runner:Literal['vision_replay_v1']
    candidate_recipe_id:UUIDText
    candidate_recipe_revision:int=Field(ge=1,le=9007199254740991)
    candidate_recipe_state_version:int=Field(ge=1,le=9007199254740991)
    candidate_recipe_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    vision_measurement_acknowledged:bool

    @model_validator(mode='after')
    def measurement_ack(self):
        if self.vision_measurement_acknowledged is not True:raise ValueError('explicit original-frame measurement acknowledgment required')
        return self


@dataclass(frozen=True)
class VisionReplayConfig:
    max_case_ms:int=15000
    max_report_bytes:int=32768

    def __post_init__(self):
        if (type(self.max_case_ms) is not int or not 1<=self.max_case_ms<=60000
                or type(self.max_report_bytes) is not int or not 1<=self.max_report_bytes<=32768):
            raise ValueError('bounded vision measurement window and report required')


@dataclass(frozen=True)
class MeasuredReplayCase:
    value:dict
    checks:tuple
    source_expires_at_ms:int
    execution_deadline_ms:int
    final_guard:Callable[[],None]


class VisionReprocessor:
    def __init__(self,evaluations,registry,config,*,tick_ns=None):
        from proofpack.review.evaluations import PolicyEvaluations
        if (not isinstance(evaluations,PolicyEvaluations) or not isinstance(registry,WorkerRegistry)
                or not isinstance(config,VisionReplayConfig) or config.max_case_ms>evaluations.config.lease_ms):
            raise ValueError('shared evaluation/worker services and window within original lease required')
        self.evaluations=evaluations;self.datasets=evaluations.datasets;self.assets=self.datasets.improvement.assets
        self.registry=registry;self.config=config;self.access=evaluations.access;self.repository=evaluations.repository
        self.runtime=evaluations.runtime;self.tick=tick_ns or time.monotonic_ns
        self.configuration=digest({'runner':'vision_replay_v1','window_ms':config.max_case_ms,'report_bytes':config.max_report_bytes,
            'worker_limits':vars(registry.pool.limits),'evaluation':evaluations.configuration})

    def _candidate(self,request):
        hkey=catalog_key(request.candidate_recipe_id);rkey=revision_key(request.candidate_recipe_id,request.candidate_recipe_revision)
        rows=self.repository.snapshot((hkey,rkey));head=rows[hkey];revision=rows[rkey]
        try:
            if (head is None or revision is None or revision.revision!=1 or head.data['retired'] is not False
                    or head.revision!=request.candidate_recipe_state_version or integer(head.data['latest_revision'])!=request.candidate_recipe_revision
                    or hashlib.sha256(revision.data['recipe_json'].encode()).hexdigest()!=request.candidate_recipe_sha256
                    or revision.data['sha256']!=request.candidate_recipe_sha256):raise ValueError()
            value=Recipe.model_validate_json(revision.data['recipe_json'])
            if value.recipe_id!=request.candidate_recipe_id or value.revision!=request.candidate_recipe_revision:raise ValueError()
            return value,tuple(rows.values())
        except (KeyError,TypeError,ValueError,AttributeError) as exc:raise StoreUnavailable('current exact candidate recipe required') from exc

    @staticmethod
    def _measurement(result,original,truth,classes):
        counts=Counter(item.part_class.value for item in result.candidates if item.part_class is not None)
        observable=result.quality_ok and result.unknown_regions==0 and all(item.part_class is not None for item in result.candidates)
        return {'observation_id':original['observation_id'],'original_asset_id':original['asset_id'],'source_sha256':result.source_sha256,
            'calibration_sha256':result.calibration_hash,'findings':[x.value for x in result.findings],
            'reason_codes':list(result.reason_codes),'quality_ok':result.quality_ok,'unknown_regions':result.unknown_regions,
            'candidates':[x.model_dump(mode='json') for x in result.candidates],
            'class_counts':{c:counts[c] for c in classes},'declared_truth_counts':{c:truth[c] for c in classes},
            'count_comparison_observable':observable,'counts_match_declared_truth':all(counts[c]==truth[c] for c in classes) if observable else None,
            'physical_truth_verified':False,'dimension_truth_accuracy_measured':False}

    def measure(self,actor,*,request,index,execution_gate=None,consumer_id=None):
        result=self.measure_case(actor,request=request,index=index,execution_gate=execution_gate,consumer_id=consumer_id)
        return result.value,result.checks,result.execution_deadline_ms

    def measure_case(self,actor,*,request,index,execution_gate=None,consumer_id=None):
        if not isinstance(request,VisionReplayRequest):raise ValueError('typed exact vision replay request required')
        if execution_gate is not None and not callable(execution_gate):raise ValueError('trusted execution checkpoint required')
        actor=self.access._fresh(actor,Role.REVIEWER);started=self.tick()
        if type(started) is not int or started<0:raise StoreUnavailable('trusted measurement time required')
        actor,checks,policy,manifest,sealed=self.evaluations._inputs(actor,request)
        candidate,rows=self._candidate(request);checks=self.datasets._merge((*checks.values(),*rows))
        source_expiry=min(integer(actor.session.data['expires_at_ms']),integer(sealed.data['expires_at_ms']))
        deadline=min(source_expiry,self.access.now()+self.config.max_case_ms)
        def gate():
            if execution_gate is not None:execution_gate()
            self.access._fresh(actor,Role.REVIEWER)
            tick=self.tick()
            if type(tick) is not int or not 0<=tick-started<self.config.max_case_ms*1000000 or self.access.now()>=deadline:
                raise StoreUnavailable('vision case window expired')
            current=self.repository.snapshot(tuple(checks))
            if any(current[k]!=row for k,row in checks.items()):raise StoreConflict('vision source or authority changed')
        content,label,entry,source_rows,expires=self.datasets.source_case(actor,manifest,sealed,index,gate)
        checks=self.datasets._merge((*checks.values(),*source_rows.values()));source_expiry=min(source_expiry,expires);deadline=min(deadline,source_expiry)
        source=label['source_context'];rkey=revision_key(source['recipe_id'],integer(source['recipe_revision']))
        revision=self.repository.snapshot((rkey,))[rkey]
        try:
            if (revision is None or revision.revision!=1 or revision.data['sha256']!=source['recipe_sha256']
                    or hashlib.sha256(revision.data['recipe_json'].encode()).hexdigest()!=source['recipe_sha256']):raise ValueError()
            baseline=Recipe.model_validate_json(revision.data['recipe_json'])
            if (baseline.recipe_id!=source['recipe_id'] or baseline.revision!=integer(source['recipe_revision'])
                    or candidate.kit_sku!=baseline.kit_sku or candidate.data_origin!=baseline.data_origin
                    or candidate.calibration_profile_id!=baseline.calibration_profile_id):raise ValueError()
        except (KeyError,TypeError,ValueError,AttributeError) as exc:raise StoreUnavailable('same-kit immutable baseline/candidate recipe binding required') from exc
        checks=self.datasets._merge((*checks.values(),revision));classes=sorted({x.part_class_id.value for r in (baseline,candidate) for x in r.constraints})
        truth={x['part_class']:integer(x['count']) for x in label['ground_truth_counts']}
        if not set(classes)<=truth.keys():raise StoreUnavailable('explicit truth counts required for every compared class')
        originals=[x for x in source['sources'] if x.get('derivation')=='original_transmitted_frame']
        observations=source['observations']
        if not 1<=len(observations)<=2 or len(originals)!=len(observations):raise StoreUnavailable('original geometry-bearing input required for every observation')
        by_observation={x['observation_id']:x for x in originals}
        if len(by_observation)!=len(originals) or set(by_observation)!={x['observation_id'] for x in observations}:raise StoreUnavailable('exact ordered original tuple required')
        self.datasets._access(actor,manifest,tuple(checks.values()),'vision_measurement_case_admitted',index,index,deadline=deadline,consumer_id=consumer_id)
        gate();frames=[];profile=None
        for observed in observations:
            original=by_observation[observed['observation_id']];gate()
            actor,scope,asset,_,_,receipt,expires,binding=self.assets._snapshot(actor,original['asset_id'],binary=True)
            if asset.revision!=integer(original['asset_version']) or receipt.source_sha256!=original['sha256']:raise StoreConflict('original replay asset changed')
            geometry=original_profile(asset)
            if geometry.content_hash!=observed['calibration_sha256'] or geometry.profile_id!=baseline.calibration_profile_id:raise StoreUnavailable('exact source geometry required')
            if profile is not None and profile.content_hash!=geometry.content_hash:raise StoreUnavailable('same geometry required for ordered observations')
            profile=geometry;checks=self.datasets._merge((*checks.values(),*scope.values()));source_expiry=min(source_expiry,expires);deadline=min(deadline,source_expiry)
            payload,actual,version,actual_binding,_=self.assets.read(actor,original['asset_id'],binary=True)
            if actual!=receipt or version!=asset.revision or actual_binding!=binding:raise StoreConflict('original byte receipt changed')
            gate();frames.append((original,observed,payload))
        spec=PolicyDraft.model_validate_json(canonical(policy.data['spec']));sides={}
        with self.registry.diagnostic(runtime_id=self.runtime.instance_id) as worker:
            gate()
            for side,recipe in (('baseline',baseline),('candidate',candidate)):
                measured=[];decisions=[];context_id=digest({'request':request.model_dump(mode='json'),'index':index,'side':side})
                for sequence,(original,observed,payload) in enumerate(frames,1):
                    gate();result=worker.analyze(payload,recipe,profile,sequence=sequence,inspection_id=context_id)
                    if (not isinstance(result,WorkerResult) or result.source_sha256!=hashlib.sha256(payload).hexdigest()
                            or result.calibration_hash!=profile.content_hash or len(result.findings)!=len(recipe.constraints)):
                        raise StoreUnavailable('replay worker provenance mismatch')
                    gate();measured.append(self._measurement(result,original,truth,classes))
                    decisions.append({'observation_id':observed['observation_id'],'sequence':integer(observed['sequence']),
                        'findings':[x.value for x in result.findings],'reason_codes':list(result.reason_codes),'quality_ok':result.quality_ok,
                        'unknown_regions':result.unknown_regions,'calibration_sha256':result.calibration_hash})
                replay_label={**label,'source_context':{**source,'observations':decisions}}
                historical=replay_decision(replay_label,spec)[side]
                sides[side]={**historical,'measurements':measured,'recipe_sha256':source['recipe_sha256'] if side=='baseline' else request.candidate_recipe_sha256}
        gate()
        value={'schema_version':1,'runner':'vision_replay_v1','dataset_example_sha256':entry['content_sha256'],
            'label_id':content['label_id'],'label_revision':content['label_revision'],'label_sha256':content['label_sha256'],
            'source_context_sha256':content['source_context_sha256'],'split':content['split'],'data_origin':content['data_origin'],
            'policy_revision_sha256':policy.data['sha256'],'source_artifact_sha256':source['artifact_sha256'],
            'execution_artifact_sha256':self.runtime.artifact_sha256,'calibration_sha256':profile.content_hash,
            'original_frames':len(frames),'measurement_count':len(frames)*2,'comparison_classes':classes,
            'declared_review_duration_ms':integer(label['duration_ms']),'case_elapsed_ms':(self.tick()-started)//1000000,
            'baseline':sides['baseline'],'candidate':sides['candidate'],'pixel_measurement_performed':True,
            'historical':True,'machine_pass':False,'diagnostic_only':True,'independent_benchmark_qualified':False,
            'promotion_eligible':False,'operator_effort_measured':False,'physical_truth_verified':False}
        encoded=canonical(value)
        if len(encoded.encode())>self.config.max_report_bytes:raise StoreUnavailable('vision case report exceeds bound')
        gate();return MeasuredReplayCase(json.loads(encoded),tuple(checks.values()),source_expiry,deadline,gate)
