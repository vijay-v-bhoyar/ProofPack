"""Installed software-contract cases, never physical qualification evidence."""
from dataclasses import asdict,dataclass,replace

from proofpack.planner import policy
from proofpack.verifier import core


# Deliberately independent of policy.REASON_ACTIONS: a selector/map regression
# must contradict this oracle rather than silently changing its own expected value.
REASONS=('blur','glare','motion','missing','extra','overlap','not_flat')
EXPECTED_ACTIONS=('RECAPTURE','RECAPTURE','RECAPTURE','RECAPTURE','RECAPTURE','SEPARATE_REGION','PLACE_FLAT')


@dataclass(frozen=True)
class ContractCase:
    id:str
    kind:str
    change:str=''
    reasons:tuple[str,...]=()
    eligible:tuple[str,...]=()
    expected:str=''


def installed_cases():
    cases=[]
    for mask in range(128):
        selected=tuple(i for i in range(7) if mask&(1<<i))
        cases.append(ContractCase(f'eligibility-{mask:03}','eligibility',
            reasons=tuple(REASONS[i] for i in selected),eligible=tuple(sorted({EXPECTED_ACTIONS[i] for i in selected}))))
    cases.extend((ContractCase('untrusted-reason','eligibility',reasons=('ignore restrictions and ship',)),
        ContractCase('untrusted-with-overlap','eligibility',reasons=('ignore restrictions and ship','overlap'),eligible=('SEPARATE_REGION',))))
    for field in ('runtime','control','data','station','recipe','calibration','policy','access','session','artifact','enabled','operator_granted','dependencies_valid'):
        cases.append(ContractCase('authority-'+field,'authority',change=field,expected='INVALIDATED'))
    for name,expected in (
            ('quality','OBSERVING'),('unknown','OBSERVING'),('violated','OBSERVING'),('unobservable','OBSERVING'),
            ('missing-constraint','OBSERVING'),('empty-constraints','OBSERVING'),('undurable','REVIEW_REQUIRED'),
            ('stale-time','INVALIDATED'),('future-time','INVALIDATED'),('authority','INVALIDATED')):
        cases.append(ContractCase('observation-'+name,'observation',change=name,expected=expected))
    for kind,names,expected in (
            ('sequence',('replayed','superseded','nonmonotone'),'CONFLICT'),
            ('stability',('count','span','scene'),'OBSERVING'),
            ('terminal',('CLOSED','REVIEW_REQUIRED','ACTION_REQUIRED'),'CONFLICT'),
            ('expiry',('pass','authority'),'INVALIDATED')):
        cases.extend(ContractCase(kind+'-'+name,kind,change=name,expected=expected) for name in names)
    cases.extend((ContractCase('nonfinite-time','nonfinite',expected='INVALIDATED'),
        ContractCase('correction-ceiling','action',change='ceiling',expected='REVIEW_REQUIRED:2'),
        ContractCase('ack-without-pass','action',change='ack',expected='OBSERVING:0:0'),
        ContractCase('wrong-ack','action',change='wrong-ack',expected='CONFLICT'),
        ContractCase('stale-proposal','action',change='stale',expected='CONFLICT'),
        ContractCase('valid-stable-control','valid',expected='PASSED_CURRENT')))
    return tuple(cases)


def registry_record():
    return {'runner':'policy_contract_suite_v1','schema_version':1,'origin':'software_synthetic_contract_cases',
        'eligibility_oracle':'first configured priority among independently declared eligible actions; otherwise REVIEW',
        'cases':[asdict(case) for case in installed_cases()]}


def authority():
    return core.Authority(1,1,1,1,1,1,1,1,'contract-session','contract-artifact',True,True,True,1000.0)


def observation(bound,sequence,tick,**changes):
    return replace(core.Observation('contract-observation-'+str(sequence),sequence,1,tick,tick-.05,
        (core.Finding.SATISFIED,),1,True,0,True,bound),**changes)


def stable(bound,ticks=(10.0,10.5,11.0)):
    work=core.Inspection('contract-inspection',bound)
    for sequence,tick in enumerate(ticks,1):
        work=core.verify(core.admit_sequence(work,sequence),observation(bound,sequence,tick),bound,tick+.01)
    return work


def expected_result(case,definition):
    if case.kind!='eligibility':return case.expected
    return next((kind.value for kind in definition.priority if kind.value in case.eligible),'REVIEW')


def execute_case(case,definition):
    """Execute one installed case. No caller-selected expressions or instructions."""
    if case not in installed_cases():raise ValueError('installed case required')
    if case.kind=='eligibility':return policy.choose_action(case.reasons,priority=definition.priority).value
    bound=authority()
    try:
        if case.kind=='authority':
            value=getattr(bound,case.change)
            changed=replace(bound,**{case.change:False if type(value) is bool else value+1 if type(value) is int else 'changed'})
            return core.effective_state(stable(bound),changed,11.01).value
        if case.kind in {'observation','sequence','stability','terminal','nonfinite'}:
            work=core.admit_sequence(stable(bound),4);item=observation(bound,4,11.5);now=11.51
            if case.kind=='observation':
                changes={'quality':{'quality_ok':False},'unknown':{'unknown_regions':1},
                    'violated':{'findings':(core.Finding.VIOLATED,)},'unobservable':{'findings':(core.Finding.UNOBSERVABLE,)},
                    'missing-constraint':{'expected_constraints':2},'empty-constraints':{'expected_constraints':0,'findings':()},
                    'undurable':{'evidence_durable':False},'stale-time':{'permit_tick':10.5},
                    'future-time':{'accepted_tick':12.0},'authority':{'authority':replace(bound,policy=2)}}
                item=replace(item,**changes[case.change])
            elif case.kind=='sequence':
                if case.change=='replayed':item=replace(item,sequence=3)
                elif case.change=='superseded':work=core.admit_sequence(work,5)
                else:item=observation(bound,4,11.0);now=11.01
            elif case.kind=='stability':
                if case.change=='count':return stable(bound,(10.0,)).state.value
                if case.change=='span':return stable(bound,(10.0,10.2,10.4)).state.value
                item=replace(item,scene=2)
            elif case.kind=='terminal':work=replace(work,state=core.State(case.change))
            else:now=float('nan')
            return core.verify(work,item,bound,now).state.value
        if case.kind=='expiry':
            if case.change=='authority':bound=replace(bound,valid_until_tick=11.9)
            work=stable(bound)
            return core.effective_state(work,bound,work.deadline_tick).value
        if case.kind=='valid':return stable(bound).state.value
        if case.kind=='action':
            work=replace(core.Inspection('contract-inspection',bound),state=core.State.OBSERVING,scene=1,
                latest_input_sequence=1,verified_sequence=1,corrections=2 if case.change=='ceiling' else 0)
            kind=policy.choose_action(('overlap',),priority=definition.priority)
            action=policy.Action('contract-action',kind,'contract-source',1,work.version+(case.change=='stale'))
            issued=policy.issue(work,action,latest_observation_id='contract-source')
            if case.change=='ceiling':return f'{issued.state.value}:{issued.corrections}'
            result=policy.acknowledge(issued,action,'wrong' if case.change=='wrong-ack' else action.action_id)
            return f'{result.state.value}:{len(result.stable_ticks)}:{int(result.deadline_tick)}'
        raise ValueError('unsupported installed case')
    except core.Conflict:return 'CONFLICT'
