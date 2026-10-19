"""Four equal-opportunity arms in a disclosed synthetic response model."""
from collections import Counter
import hashlib,time
from uuid import uuid4

from proofpack.calibrations.dependencies import canonical,digest
from proofpack.planner.candidates import PolicyDraft
from proofpack.planner.policy import ActionKind
from proofpack.review.controlled_models import ARMS,OUTCOMES,FLAGS,ControlledConfig,arm_order,outcome,select_action,verdict
from proofpack.vision.controlled_fixtures import ControlledBundle
from proofpack.vision.registry import WorkerRegistry
from proofpack.vision.worker import WorkerUnavailable
from proofpack.vision.worker_result import WorkerResult


class ControlledHeld(RuntimeError):
    def __init__(self,reason):self.reason=reason;super().__init__(reason)


class ControlledExperiment:
    def __init__(self,bundle,definition,candidate_sha256,registry,config,*,checkpoint=None,progress=None,tick_ns=None,started_ns=None):
        if (not isinstance(bundle,ControlledBundle) or not isinstance(definition,PolicyDraft) or not isinstance(config,ControlledConfig)
                or bundle.config!=config or not isinstance(registry,WorkerRegistry)):
            raise ValueError('typed shared controlled experiment inputs required')
        if len(candidate_sha256)!=64 or any(c not in '0123456789abcdef' for c in candidate_sha256):raise ValueError('exact candidate file hash required')
        self.bundle=bundle;self.definition=definition;self.candidate_sha256=candidate_sha256;self.registry=registry;self.config=config
        self.checkpoint=checkpoint or (lambda:None);self.progress=progress or (lambda value:None);self.tick=tick_ns or time.monotonic_ns
        self.started=self.tick() if started_ns is None else started_ns
        if type(self.started) is not int or self.started<0:raise ValueError('trusted monotonic start required')
        self.runtime_id=str(uuid4());self.seen=set();self.reserved=0;self.last_case=None

    def _elapsed(self,start):
        now=self.tick()
        if type(now) is not int or not now>=start>=self.started:raise ControlledHeld('TRUSTED_TIME_UNAVAILABLE')
        return (now-start)/1000000

    def _gate(self,start):
        if self.checkpoint() is False:raise ControlledHeld('CANCELLED')
        self.bundle.assert_current()
        if self._elapsed(self.started)>=self.config.max_run_ms or self._elapsed(start)>=self.config.max_case_ms:
            raise ControlledHeld('DEADLINE_EXCEEDED')

    def _emit(self,value):
        encoded=canonical(value)
        if len(encoded.encode())+1>self.config.max_case_report_bytes:raise ControlledHeld('CASE_REPORT_TOO_LARGE')
        # Callbacks get owned JSON, never a mutable alias to counters or truth.
        import json
        self.progress(json.loads(encoded))

    def case(self,index):
        episodes=self.bundle.episodes
        if type(index) is not int or not 0<=index<len(episodes) or index in self.seen:raise ValueError('new admitted episode index required')
        self.seen.add(index);episode=episodes[index];recipe=self.bundle.recipes[episode['recipe_index']];start=self.tick()
        _,truth=self.bundle.image(episode['states'][episode['initial_state']]['image'])
        value={'index':index,'case_id':episode['id'],'setup_group':episode['setup_group'],'condition':episode['condition'],
            'status':'IN_PROGRESS','execution_runtime_id':self.runtime_id,'manifest_sha256':self.bundle.manifest_sha256,'episode_sha256':digest(episode),
            'candidate_file_sha256':self.candidate_sha256,'candidate_definition_sha256':digest(self.definition.model_dump(mode='json')),
            'recipe_sha256':digest(recipe.model_dump(mode='json')),'calibration_sha256':self.bundle.profile.content_hash,
            'data_origin':'synthetic','ground_truth_method':'generator_parameters','truth_complete':truth['truth_complete'],
            'arm_order':list(arm_order(index)),'worker_start_ms':0,'reserved_measurements':0,'arms':{
                arm:{'outcome':'not_run','stop_reason':None,'reserved_measurements':0,'observations':[],'actions':[],
                     'input_preparation_ms':0,'measurement_component_ms':0,'unused_action_budget':self.config.max_actions_per_arm,
                     'unused_observation_opportunities':self.config.max_observations_per_arm} for arm in ARMS},**FLAGS}
        self.last_case=value;active=None
        try:
            self._gate(start);self._emit(value);warming=self.tick()
            with self.registry.diagnostic(runtime_id=self.runtime_id) as worker:
                value['worker_start_ms']=self._elapsed(warming);self._gate(start)
                for arm in arm_order(index):
                    active=arm;record=value['arms'][arm];state=episode['initial_state']
                    context=digest({'runtime_id':self.runtime_id,'case_id':episode['id'],'arm':arm})
                    record['tracking_context_sha256']=context
                    for sequence in range(1,self.config.max_observations_per_arm+1):
                        self._gate(start);loading=self.tick();name=episode['states'][state]['image'];payload,info=self.bundle.image(name)
                        record['input_preparation_ms']+=self._elapsed(loading);self._gate(start)
                        if (self.reserved>=self.config.max_measurements_per_run or value['reserved_measurements']>=self.config.max_measurements_per_episode):
                            raise ControlledHeld('MEASUREMENT_BUDGET_EXHAUSTED')
                        self.reserved+=1;value['reserved_measurements']+=1;record['reserved_measurements']+=1
                        record['unused_observation_opportunities']-=1;record['outcome']='technical_failure';self._emit(value)
                        measuring=self.tick();result=worker.analyze(payload,recipe,self.bundle.profile,sequence=sequence,inspection_id=context)
                        duration=self._elapsed(measuring)
                        if (not isinstance(result,WorkerResult) or result.source_sha256!=hashlib.sha256(payload).hexdigest()
                                or result.calibration_hash!=self.bundle.profile.content_hash or len(result.findings)!=len(recipe.constraints)):
                            raise ControlledHeld('WORKER_PROVENANCE_MISMATCH')
                        self._gate(start);self.bundle.image(name);self._gate(start)
                        observed=result.model_dump(mode='json',exclude={'evidence_jpeg_base64','evidence_sha256'})
                        observed.update(sequence=sequence,state_id=state,image=name,elapsed_component_ms=duration,
                            class_counts={part:sum(c.part_class is not None and c.part_class.value==part for c in result.candidates) for part in info['ground_truth_counts']},
                            declared_truth_counts=info['ground_truth_counts'],truth_complete=info['truth_complete'])
                        record['observations'].append(observed);record['measurement_component_ms']+=duration
                        record['outcome']=outcome(result,info['truth_complete']);self._emit(value)
                        if verdict(result)=='satisfied':record['stop_reason']='VISIBLE_CONSTRAINTS_SATISFIED';break
                        if arm=='single_frame_v1':record['stop_reason']='SINGLE_FRAME_LIMIT';break
                        if len(record['actions'])>=self.config.max_actions_per_arm:record['stop_reason']='ACTION_BUDGET_EXHAUSTED';break
                        action=select_action(arm,result,self.definition)
                        if action is None or action==ActionKind.REVIEW:record['stop_reason']='MANUAL_REVIEW';break
                        next_state=episode['edges'][state][action.value]
                        record['actions'].append({'kind':action.value,'from_state':state,'to_state':next_state,
                            'transition_sha256':digest({'episode_sha256':value['episode_sha256'],'from_state':state,'action':action.value,'to_state':next_state})})
                        record['unused_action_budget']-=1;state=next_state;self._gate(start)
                    if record['stop_reason'] is None:raise ControlledHeld('INCOMPLETE_ARM')
                    self._emit(value)
            active=None;self._gate(start)
            if any(not r['observations'] or r['outcome'] not in OUTCOMES for r in value['arms'].values()):raise ControlledHeld('INCOMPLETE_CASE')
            if value['reserved_measurements']!=sum(r['reserved_measurements'] for r in value['arms'].values()):raise ControlledHeld('CASE_BUDGET_MISMATCH')
            value.update(status='COMPLETE',case_elapsed_before_final_output_ms=self._elapsed(start));self._emit(value)
            self._gate(start);return value
        except (ControlledHeld,WorkerUnavailable,ValueError,OSError,KeyError) as exc:
            value['status']='HELD';value['error']=exc.reason if isinstance(exc,ControlledHeld) else 'WORKER_UNAVAILABLE' if isinstance(exc,WorkerUnavailable) else 'SOURCE_OR_OUTPUT_UNAVAILABLE'
            if active is not None:value['arms'][active].update(outcome='technical_failure',stop_reason=value['error'])
            raise ControlledHeld(value['error']) from exc


def summarize(episodes,cases,images):
    """All planned denominators remain, including missing/failed arm outcomes."""
    if len({c['index'] for c in cases})!=len(cases):raise ValueError('distinct controlled case results required')
    by_index={c['index']:c for c in cases};totals={arm:{key:0 for key in OUTCOMES} for arm in ARMS};groups={};paired=[]
    complete=sum(images[e['states'][e['initial_state']]['image']]['truth_complete'] for e in episodes)
    counters={arm:{'actions_used':0,'reserved_measurements':0,'validated_measurements':0} for arm in ARMS}
    for index,episode in enumerate(episodes):
        row=by_index.get(index);group=groups.setdefault(episode['setup_group'],{arm:{key:0 for key in OUTCOMES} for arm in ARMS})
        for arm in ARMS:
            item=None if row is None else row['arms'][arm];key='not_run' if item is None else item['outcome']
            if key not in OUTCOMES:raise ValueError('installed final outcome required')
            totals[arm][key]+=1;group[arm][key]+=1
            if item is not None:
                counters[arm]['actions_used']+=len(item['actions']);counters[arm]['reserved_measurements']+=item['reserved_measurements']
                counters[arm]['validated_measurements']+=len(item['observations'])
        if row is not None and row['status']=='COMPLETE':
            candidate=row['arms']['candidate_priority_v1']
            paired.append({'case_id':episode['id'],**{arm:{'correct_satisfaction_difference':int(candidate['outcome']=='correct_satisfaction')-int(row['arms'][arm]['outcome']=='correct_satisfaction'),
                'actions_used_difference':len(candidate['actions'])-len(row['arms'][arm]['actions'])} for arm in ARMS if arm!='candidate_priority_v1'}})
    def rate(numerator,denominator,incomplete):
        reason='INCOMPLETE_ARM' if incomplete else 'ZERO_DENOMINATOR' if not denominator else None
        return {'numerator':numerator,'denominator':denominator,'value':None if reason else numerator/denominator,'undefined_reason':reason}
    result={}
    for arm,counts in totals.items():
        if sum(counts.values())!=len(episodes):raise ValueError('every planned episode must remain in its denominator')
        incomplete=bool(counts['not_run'] or counts['technical_failure'])
        result[arm]={'outcomes':counts,**counters[arm],
            'incorrect_satisfaction_rate':rate(counts['incorrect_satisfaction'],len(episodes)-complete,incomplete),
            'incorrect_rejection_rate':rate(counts['incorrect_rejection'],complete,incomplete),'unresolved_rate':rate(counts['unresolved'],len(episodes),incomplete)}
    return {'arms':result,'episodes':len(episodes),'truth_complete':complete,'truth_incomplete':len(episodes)-complete,
        'groups':groups,'paired_differences':paired,'candidate_advantage_proved':False,
        'uncertainty':{'method':'descriptive_only','reason':'Fixed designer-authored response cases and seed groups are not a random independent human/physical sample; raw group results and paired differences are retained.'}}
