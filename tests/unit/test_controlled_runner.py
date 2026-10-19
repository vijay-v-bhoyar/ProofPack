from contextlib import contextmanager
from dataclasses import replace
import hashlib,importlib.util,json,shutil
from pathlib import Path
import pytest,yaml

from test_controlled_contracts import configuration,proposal
from test_controlled_fixtures import generated
from proofpack.review.controlled import ControlledExperiment,ControlledHeld,summarize
from proofpack.calibrations.dependencies import canonical
from proofpack.vision.controlled_fixtures import ControlledBundle
from proofpack.vision.registry import WorkerRegistry
from proofpack.vision.worker_limits import WorkerLimits
from proofpack.vision.worker import WorkerUnavailable
from proofpack.vision.worker_result import WorkerResult

ROOT=Path(__file__).resolve().parents[2]


def fake_registry(bundle,monkeypatch,after=None):
    limits=WorkerLimits.from_controls(yaml.safe_load((ROOT/'docs/controls.yaml').read_text()))
    registry=WorkerRegistry(limits,max_processes=1);calls=[]
    images={v['sha256']:(k,v) for k,v in bundle.metadata['images'].items()}
    class Worker:
        def analyze(self,payload,recipe,profile,**kwargs):
            source=hashlib.sha256(payload).hexdigest();name,truth=images[source];calls.append((source,kwargs))
            unknown='overlap' in name or 'glare' in name
            reasons=['overlap','missing'] if 'overlap' in name else ['glare'] if 'glare' in name else ['missing'] if not truth['truth_complete'] else []
            candidates=[{'part_class':part,'box':[10,10,20,20],'dimension_interval_mm':[1.,2.]} for part,count in truth['ground_truth_counts'].items() for _ in range(count)]
            findings=['UNOBSERVABLE' if unknown else 'SATISFIED' if truth['truth_complete'] else 'VIOLATED']*len(recipe.constraints)
            result=WorkerResult.model_validate_json(json.dumps({'candidates':candidates,'findings':findings,'reason_codes':reasons,'quality_ok':True,
                'unknown_regions':1 if unknown else 0,'scene_generation':kwargs['sequence'],'scene_changed':kwargs['sequence']>1,
                'source_sha256':source,'calibration_hash':profile.content_hash}))
            if after:after()
            return result
    @contextmanager
    def diagnostic(**kwargs):yield Worker()
    monkeypatch.setattr(registry,'diagnostic',diagnostic)
    return registry,calls


def test_four_arms_use_identical_starting_pixels_separate_contexts_and_nonrefundable_counts(generated,monkeypatch):
    bundle=ControlledBundle(generated,configuration());registry,calls=fake_registry(bundle,monkeypatch)
    experiment=ControlledExperiment(bundle,proposal(),'c'*64,registry,configuration());value=experiment.case(24)
    assert value['status']=='COMPLETE' and len(value['arms'])==4 and not value['machine_pass']
    arms=value['arms'];assert len({r['observations'][0]['source_sha256'] for r in arms.values()})==1
    assert arms['single_frame_v1']['outcome']=='unresolved' and arms['single_frame_v1']['unused_action_budget']==2
    assert arms['rule_priority_v1']['outcome']=='correct_satisfaction' and len(arms['rule_priority_v1']['actions'])==1
    assert arms['fixed_recapture_v1']['outcome']==arms['candidate_priority_v1']['outcome']=='unresolved'
    assert len({kw['inspection_id'] for _,kw in calls})==4
    assert {r['tracking_context_sha256'] for r in arms.values()}=={kw['inspection_id'] for _,kw in calls}
    assert experiment.reserved==value['reserved_measurements']==len(calls)
    with pytest.raises(ValueError):experiment.case(24)
    assert experiment.reserved==len(calls)
    assert 'evidence_jpeg_base64' not in json.dumps(value)


@pytest.mark.parametrize('fault',['worker','source','cancel','deadline','budget'])
def test_failed_or_canceled_case_never_retries_or_refunds(generated,tmp_path,monkeypatch,fault):
    target=tmp_path/'bundle';shutil.copytree(generated,target);config=configuration()
    if fault=='budget':config=replace(config,max_measurements_per_episode=4)
    bundle=ControlledBundle(target,config);clock=[0];cancel=[False]
    def after():
        if fault=='worker':raise WorkerUnavailable('synthetic worker failure')
        if fault=='source':(target/'manifest.json').write_text('{}')
        if fault=='cancel':cancel[0]=True
        if fault=='deadline':clock[0]=config.max_case_ms*1000000
    registry,calls=fake_registry(bundle,monkeypatch,after)
    experiment=ControlledExperiment(bundle,proposal(),'c'*64,registry,config,tick_ns=lambda:clock[0],checkpoint=lambda:not cancel[0])
    with pytest.raises(ControlledHeld):experiment.case(24)
    assert experiment.last_case['status']=='HELD' and 1<=experiment.reserved<=4
    assert experiment.reserved==len(calls) and any(r['outcome']=='not_run' for r in experiment.last_case['arms'].values())
    with pytest.raises(ValueError):experiment.case(24)


def test_slow_final_output_callback_cannot_complete_after_case_deadline(generated,monkeypatch):
    bundle=ControlledBundle(generated,configuration());clock=[0];registry,_=fake_registry(bundle,monkeypatch)
    def output(value):
        if value['status']=='COMPLETE':clock[0]=configuration().max_case_ms*1000000
    experiment=ControlledExperiment(bundle,proposal(),'c'*64,registry,configuration(),tick_ns=lambda:clock[0],progress=output)
    with pytest.raises(ControlledHeld,match='DEADLINE'):experiment.case(0)
    assert experiment.last_case['status']=='HELD' and experiment.reserved==4


def test_partial_summary_keeps_every_planned_denominator_and_group(generated,monkeypatch):
    bundle=ControlledBundle(generated,configuration());registry,_=fake_registry(bundle,monkeypatch)
    value=ControlledExperiment(bundle,proposal(),'c'*64,registry,configuration()).case(0)
    summary=summarize(bundle.episodes,[value],bundle.metadata['images'])
    assert summary['episodes']==144 and summary['truth_complete']==summary['truth_incomplete']==72 and len(summary['groups'])==24
    for arm in summary['arms'].values():assert sum(arm['outcomes'].values())==144 and arm['outcomes']['not_run']==143
    for arm in summary['arms'].values():
        assert arm['incorrect_satisfaction_rate']['value'] is None and arm['incorrect_satisfaction_rate']['denominator']==72
        assert arm['incorrect_satisfaction_rate']['undefined_reason']=='INCOMPLETE_ARM'
    assert not summary['candidate_advantage_proved'] and summary['uncertainty']['method']=='descriptive_only'


@pytest.mark.parametrize('fault',['not_run','technical_failure'])
def test_incomplete_arm_rates_are_unknown_without_hiding_other_arms(generated,monkeypatch,fault):
    bundle=ControlledBundle(generated,configuration());registry,_=fake_registry(bundle,monkeypatch)
    value=ControlledExperiment(bundle,proposal(),'c'*64,registry,configuration()).case(0)
    value['arms']['candidate_priority_v1']['outcome']=fault
    summary=summarize(bundle.episodes[:1],[value],bundle.metadata['images'])
    affected=summary['arms']['candidate_priority_v1']
    for metric in ('incorrect_satisfaction_rate','incorrect_rejection_rate','unresolved_rate'):
        assert affected[metric]['value'] is None and affected[metric]['undefined_reason']=='INCOMPLETE_ARM'
    assert affected['outcomes'][fault]==1
    for name,arm in summary['arms'].items():
        if name=='candidate_priority_v1':continue
        assert arm['incorrect_satisfaction_rate']['value'] is None
        assert arm['incorrect_satisfaction_rate']['undefined_reason']=='ZERO_DENOMINATOR'
        assert arm['incorrect_rejection_rate']['value']==0.0 and arm['unresolved_rate']['value']==0.0
        assert arm['incorrect_rejection_rate']['denominator']==1


def load_cli():
    spec=importlib.util.spec_from_file_location('controlled_cli',ROOT/'scripts/evaluate_controlled.py')
    cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli);return cli


def test_case_output_bound_includes_the_written_newline(generated,tmp_path,monkeypatch):
    config=configuration();bundle=ControlledBundle(generated,config);registry,_=fake_registry(bundle,monkeypatch)
    sample=ControlledExperiment(bundle,proposal(),'c'*64,registry,config,tick_ns=lambda:0).case(0)
    # The on-disk record requires one additional byte, not present in bare canonical JSON.
    config=replace(config,max_case_report_bytes=len(canonical(sample).encode()))
    tight=ControlledBundle(generated,config);registry,_=fake_registry(tight,monkeypatch)
    journal=load_cli().Journal(tmp_path/'output',config)
    experiment=ControlledExperiment(tight,proposal(),'c'*64,registry,config,tick_ns=lambda:0,progress=journal.case)
    with pytest.raises(ControlledHeld,match='CASE_REPORT'):experiment.case(0)
    assert experiment.last_case['status']=='HELD'


def test_changed_output_journal_cannot_publish_complete_result(generated,tmp_path,monkeypatch):
    config=configuration();bundle=ControlledBundle(generated,config);registry,_=fake_registry(bundle,monkeypatch)
    value=ControlledExperiment(bundle,proposal(),'c'*64,registry,config).case(0)
    journal=load_cli().Journal(tmp_path/'output',config);journal.write({'status':'IN_PROGRESS','complete':False});journal.case(value)
    journal.paths[0].write_text('{}')
    with pytest.raises(ControlledHeld,match='JOURNAL_CHANGED'):journal.write({'status':'COMPLETE','complete':True},final=True)
    assert json.loads((journal.output/'controlled-baselines.json').read_text())['status']=='IN_PROGRESS'


@pytest.mark.parametrize('fault',['close','final_write'])
def test_cli_final_publication_rechecks_candidate_after_cleanup_and_output_preparation(generated,tmp_path,monkeypatch,fault):
    spec=importlib.util.spec_from_file_location('controlled_cli',ROOT/'scripts/evaluate_controlled.py');cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
    candidate=tmp_path/'candidate.json';candidate.write_text(proposal().model_dump_json());output=tmp_path/'output'
    bundle=ControlledBundle(generated,configuration());registry,_=fake_registry(bundle,monkeypatch)
    monkeypatch.setattr(cli,'make_registry',lambda *args,**kwargs:registry)
    if fault=='close':
        close=registry.close
        def changed():close();candidate.write_text(candidate.read_text()+' ')
        monkeypatch.setattr(registry,'close',changed)
    else:
        atomic=cli.atomic_json
        def changed(path,value,limit,*args,**kwargs):
            if value.get('complete') is True:candidate.write_text(candidate.read_text()+' ')
            return atomic(path,value,limit,*args,**kwargs)
        monkeypatch.setattr(cli,'atomic_json',changed)
    assert cli.run(candidate,output=output,bundle_path=generated)==1
    result=json.loads((output/'controlled-baselines.json').read_text())
    assert result['status']=='HELD' and not result['complete'] and not result['promotion_eligible']
