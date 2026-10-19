from dataclasses import asdict,replace
from itertools import permutations
from pathlib import Path
import json
import pytest,yaml

from proofpack.calibrations.dependencies import canonical
from proofpack.planner import contract_registry,contract_suite,policy
from proofpack.planner.candidates import PolicyDraft
from proofpack.planner.contract_suite import ContractSuiteConfig,ContractSuiteHeld,PolicyContractSuite
from proofpack.verifier import core


def configuration():return ContractSuiteConfig(256,15000,8192,1048576)
def definition(priority=('SEPARATE_REGION','PLACE_FLAT','RECAPTURE')):
    return PolicyDraft.model_validate_json(json.dumps({'name':'Software contract candidate','algorithm':'reason_priority_v1','priority':priority}))


@pytest.mark.parametrize('priority',tuple(permutations(('SEPARATE_REGION','PLACE_FLAT','RECAPTURE'))))
def test_every_installed_ordering_executes_complete_contract_inventory(priority):
    emitted=[];suite=PolicyContractSuite(definition(priority),configuration(),progress=emitted.append)
    result=suite.run();cases=contract_registry.installed_cases()
    assert result['status']=='PASS' and result['complete'] is True and result['counts']=={'PASS':len(cases)}
    assert len(cases)==170 and len({c.id for c in cases})==170
    assert [r['id'] for r in result['cases']]==[c.id for c in cases] and result['reserved_attempts']==170
    assert all(result[key] is False for key in ('qualification_eligible','promotion_eligible','physical_truth_verified','independent_benchmark_qualified'))
    assert all(not record['complete'] for record in emitted)
    assert result['implementation_sha256']==contract_suite.implementation_sha256()


def test_independent_literal_oracle_detects_wrong_production_reason_mapping(monkeypatch):
    monkeypatch.setitem(policy.REASON_ACTIONS,'overlap',policy.ActionKind.RECAPTURE)
    result=PolicyContractSuite(definition(),configuration()).run()
    assert result['complete'] is True and result['status']=='FAIL' and result['counts']['FAIL']>0
    assert next(c for c in result['cases'] if c['id']=='eligibility-032')['status']=='FAIL'


def test_unsafe_verifier_mutation_fails_software_safety_cases(monkeypatch):
    original=core.verify
    def unsafe(*args,**kwargs):return replace(original(*args,**kwargs),state=core.State.PASSED_CURRENT)
    monkeypatch.setattr(core,'verify',unsafe)
    result=PolicyContractSuite(definition(),configuration()).run()
    assert result['status']=='FAIL' and next(c for c in result['cases'] if c['id']=='observation-quality')['status']=='FAIL'


def test_case_exception_is_retained_as_failed_case_without_omitting_remaining_cases(monkeypatch):
    original=contract_registry.execute_case
    def failed(case,spec):
        if case.id=='eligibility-001':raise RuntimeError('private implementation details')
        return original(case,spec)
    monkeypatch.setattr(contract_registry,'execute_case',failed)
    result=PolicyContractSuite(definition(),configuration()).run()
    assert result['status']=='FAIL' and result['complete'] and len(result['cases'])==170
    assert result['cases'][1]['reason']=='CASE_EXECUTION_ERROR' and 'private implementation' not in canonical(result)


def test_snapshot_mutation_cannot_drop_required_cases_or_add_approval():
    def changed(report):report['cases'].clear();report['promotion_eligible']=True
    suite=PolicyContractSuite(definition(),configuration(),progress=changed)
    result=suite.run();result['cases'].clear();copy=suite.last_report;copy['cases'].pop()
    assert len(suite.last_report['cases'])==170 and suite.last_report['promotion_eligible'] is False
    with pytest.raises(ValueError):suite.run()


@pytest.mark.parametrize('field',tuple(ContractSuiteConfig.__dataclass_fields__))
@pytest.mark.parametrize('bad',[True,0,1.5])
def test_configuration_requires_explicit_bounded_integers(field,bad):
    with pytest.raises(ValueError):ContractSuiteConfig(**{**asdict(configuration()),field:bad})


def test_installed_configuration_rejects_missing_or_authorizing_settings():
    controls=yaml.safe_load((Path(__file__).resolve().parents[2]/'docs/controls.yaml').read_text())
    assert ContractSuiteConfig.from_controls(controls)==configuration()
    for key in controls['policy_contract_suite']:
        missing=json.loads(json.dumps(controls));missing['policy_contract_suite'].pop(key)
        with pytest.raises(ValueError):ContractSuiteConfig.from_controls(missing)
    controls['policy_contract_suite']['promotion_eligible']=True
    with pytest.raises(ValueError):ContractSuiteConfig.from_controls(controls)


@pytest.mark.parametrize('fault',['case_budget','report_bytes','case_bytes','deadline','clock_reverse','cancel','source','candidate','configuration','clock_error'])
def test_incomplete_execution_never_returns_a_complete_report_or_refunds_attempts(monkeypatch,fault):
    config=configuration();clock=[1000];emitted=[];suite=None
    if fault=='case_budget':config=replace(config,max_cases=169)
    if fault=='report_bytes':config=replace(config,max_report_bytes=1)
    if fault=='case_bytes':config=replace(config,max_case_report_bytes=1)
    def progress(report):
        emitted.append(report)
        if report['reserved_attempts']:
            if fault=='deadline':clock[0]+=configuration().max_duration_ms*1000000
            if fault=='clock_reverse':clock[0]-=1
            if fault=='candidate':suite.definition=definition(('RECAPTURE','PLACE_FLAT','SEPARATE_REGION'))
            if fault=='configuration':suite.config=replace(config,max_cases=255)
    def checkpoint():return False if fault=='cancel' and emitted else None
    def tick():
        if fault=='clock_error':raise RuntimeError('unavailable trusted clock')
        return clock[0]
    if fault=='source':
        calls=[0]
        def changed():calls[0]+=1;return ('a' if calls[0]==1 else 'b')*64
        monkeypatch.setattr(contract_suite,'implementation_sha256',changed)
    suite=PolicyContractSuite(definition(),config,progress=progress,tick_ns=tick,checkpoint=checkpoint)
    with pytest.raises(ContractSuiteHeld):suite.run()
    report=suite.last_report
    assert report['status']=='HELD' and not report['complete'] and len(report['cases'])==170
    assert report['reserved_attempts']==sum(row['status']!='NOT_RUN' for row in report['cases'])
    assert all(not event['complete'] for event in emitted)
    if fault=='case_bytes':assert not emitted
    with pytest.raises(ValueError):suite.run()


def test_final_progress_time_is_counted_before_completion():
    clock=[0]
    def progress(report):
        if report['cases'][-1]['status']=='PASS':clock[0]=15000000000
    suite=PolicyContractSuite(definition(),configuration(),progress=progress,tick_ns=lambda:clock[0])
    with pytest.raises(ContractSuiteHeld,match='DEADLINE'):suite.run()
    assert suite.last_report['status']=='HELD' and suite.last_report['reserved_attempts']==170


@pytest.mark.parametrize('fault',['interrupt','source_time','registry','cancel'])
def test_final_boundary_cannot_publish_after_interruption_mutation_or_time_loss(monkeypatch,fault):
    clock=[0];ended=[False];suite=None;original=contract_suite.implementation_sha256;calls=[0];observed_completion=[]
    def fingerprint():
        calls[0]+=1
        if fault=='source_time' and calls[0]==3:clock[0]=15000000000
        return original()
    monkeypatch.setattr(contract_suite,'implementation_sha256',fingerprint)
    def progress(report):
        if report['cases'][-1]['status']=='PASS':
            ended[0]=True
            if fault=='registry':monkeypatch.setattr(contract_registry,'EXPECTED_ACTIONS',('REVIEW',)*7)
    def checkpoint():
        if ended[0] and calls[0]==2:
            observed_completion.append(suite.last_report['complete'])
            if fault=='interrupt':raise KeyboardInterrupt()
        return False if ended[0] and fault=='cancel' else None
    suite=PolicyContractSuite(definition(),configuration(),progress=progress,checkpoint=checkpoint,tick_ns=lambda:clock[0])
    with pytest.raises((ContractSuiteHeld,KeyboardInterrupt)):suite.run()
    assert suite.last_report['status']=='HELD' and suite.last_report['complete'] is False
    assert suite.last_report['reserved_attempts']==170 and len(suite.last_report['cases'])==170
    assert not any(observed_completion)
