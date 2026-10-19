"""Pure provenance construction; no SDK transport, authorization or deletion claims."""
from decimal import Decimal
import hashlib
import json

import pytest

from proofpack.evidence.repository import Key, Row, Write, StoreConflict
from proofpack.evidence.resource_bindings import prepare,prepare_linked


def test_exact_versions_digest_and_deterministic_order_without_payload_disclosure():
    key=Key('state','inspection#two');old=Row(key,2,{'count':0})
    a=Write(key,2,{'count':Decimal('1')});b=Write(Key('events','record#one'),None,{'private':'NEVER_INCLUDE_PAYLOAD'})
    writes,checks,binding=prepare('deployment','record',(a,b),(old,old))
    assert len(writes)==2 and checks==(old,)
    assert binding['writes'][0]['table']=='events' and binding['writes'][1]=={
        'table':'state','resource':key.resource,'previous_revision':2,'revision':3,
        'sha256':hashlib.sha256(b'{"count":1}').hexdigest()}
    assert binding['checks']==[{'table':'state','resource':key.resource,'revision':2,'sha256':hashlib.sha256(b'{"count":0}').hexdigest()}]
    assert 'NEVER_INCLUDE_PAYLOAD' not in json.dumps(binding)
    assert prepare('deployment','record',(b,a),(old,))[2]==binding


def test_freezes_nested_writes_and_checked_data_and_consumes_iterables_once():
    data={'nested':['original']};prior={'old':['before']};key=Key('state','row')
    writes,checks,binding=prepare('deployment','record',(w for w in (Write(key,1,data),)),(r for r in (Row(key,1,prior),)))
    data['nested'].append('later');prior['old'].append('later')
    assert writes[0].data=={'nested':['original']} and checks[0].data=={'old':['before']}
    assert binding==prepare('deployment','record',writes,checks)[2]


def test_checked_acknowledgment_does_not_require_a_fake_business_mutation():
    row=Row(Key('state','purpose#existing'),4,{'read_denied':True})
    writes,checks,binding=prepare('deployment','purpose-withdraw',(),(row,))
    assert writes==() and checks==(row,) and binding['writes']==[] and len(binding['checks'])==1


def test_full_existing_shared_transaction_capacity_is_preserved():
    writes=tuple(Write(Key('state','item#'+str(i)),1,{}) for i in range(98))
    checks=tuple(Row(w.key,1,{}) for w in writes)
    frozen,dependencies,binding=prepare('deployment','record',writes,checks)
    assert len(frozen)==len(dependencies)==len(binding['writes'])==len(binding['checks'])==98
    with pytest.raises(ValueError,match='bound'):
        prepare('deployment','record',writes,(Row(Key('state','extra'),1,{}),))


@pytest.mark.parametrize('case',['duplicate-write','foreign-table','empty-key','long-key','write-bool','write-zero',
    'write-overflow','check-bool','check-zero','check-overflow','untyped-write','untyped-check','no-scope',
    'float','fractional-decimal','binary','non-map','empty-deployment','long-operation'])
def test_invalid_input_never_produces_provenance(case):
    key=Key('state','row');writes=(Write(key,None,{}),);checks=();deployment='deployment';operation='record'
    if case=='duplicate-write':writes=(*writes,*writes)
    elif case in {'foreign-table','empty-key','long-key'}:
        writes=(Write(Key('other' if case=='foreign-table' else 'state','' if case=='empty-key' else 'x'*257 if case=='long-key' else 'row'),None,{}),)
    elif case.startswith('write-'):writes=(Write(key,{'write-bool':True,'write-zero':0,'write-overflow':2**63-1}[case],{}),)
    elif case.startswith('check-'):checks=(Row(Key('state','other'),{'check-bool':True,'check-zero':0,'check-overflow':2**63}[case],{}),)
    elif case=='untyped-write':writes=(None,)
    elif case=='untyped-check':checks=(None,)
    elif case=='no-scope':writes=()
    elif case in {'float','fractional-decimal','binary'}:
        writes=(Write(key,None,{'value':{'float':1.5,'fractional-decimal':Decimal('1.5'),'binary':b'private'}[case]}),)
    elif case=='non-map':writes=(Write(key,None,[]),)
    elif case=='empty-deployment':deployment=''
    elif case=='long-operation':operation='x'*513
    with pytest.raises(ValueError):prepare(deployment,operation,writes,checks)


@pytest.mark.parametrize('case',['conflicting-version','conflicting-payload','wrong-prior','create-over-existing'])
def test_conflicting_duplicate_dependencies_and_written_prior_are_rejected(case):
    key=Key('state','row');writes=(Write(key,1,{}),);checks=(Row(key,1,{}),)
    if case=='conflicting-version':checks=(*checks,Row(key,2,{}))
    elif case=='conflicting-payload':checks=(*checks,Row(key,1,{'changed':True}))
    elif case=='wrong-prior':writes=(Write(key,2,{}),)
    else:writes=(Write(key,None,{}),)
    with pytest.raises(StoreConflict):prepare('deployment','record',writes,checks)


def test_single_direct_event_preserves_ninety_nine_other_transaction_items():
    business=tuple(Write(Key('state','resource#'+str(i)),None,{}) for i in range(99))
    event=Write(Key('events','event#one'),None,{'kind':'record'})
    writes,checks=prepare_linked('deployment','record',(*business,event),())
    assert len(writes)==100 and checks==()
    assert len(writes[-1].data['resource_bindings']['writes'])==99
    with pytest.raises(ValueError,match='bound'):
        prepare_linked('deployment','record',(*business,Write(Key('state','overflow'),None,{}),event),())


def test_nested_events_and_updated_replay_share_links_without_output_self_references():
    root=Write(Key('state','inspection#one'),2,{'status':'done'})
    prior={'body_hash':'a'*64,'result':{'id':'one'},'at_ms':1,'resource_bindings':{'historical':'retained in earlier event'}}
    replay=Write(Key('state','idempotency#one'),1,prior)
    events=(Write(Key('events','a'),None,{}),Write(Key('events','b'),None,{'kind':'nested'}))
    writes,checks=prepare_linked('deployment','record',(root,replay,*events),(Row(root.key,2,{'status':'before'}),Row(replay.key,1,prior)))
    outputs=[value for value in writes if value.key in {replay.key,events[0].key,events[1].key}]
    binding=outputs[0].data['resource_bindings']
    assert all(value.data['resource_bindings']==binding for value in outputs)
    assert [value['resource'] for value in binding['writes']]==[root.key.resource]
    assert [value['resource'] for value in binding['checks']]==[root.key.resource]
    assert len(checks)==2 and outputs[0].expected_revision==1 and outputs[0].data['body_hash']=='a'*64
    prior['result']['id']='changed'
    assert outputs[0].data['result']=={'id':'one'}
    outputs[0].data['resource_bindings']['operation']='mutated-local-copy'
    assert outputs[1].data['resource_bindings']['operation']=='record'


@pytest.mark.parametrize('reserved',[None,False,True,0,-1,100,'1'])
def test_invalid_reserved_output_count_cannot_change_transaction_capacity(reserved):
    with pytest.raises(ValueError):prepare('deployment','record',(Write(Key('state','row'),None,{}),),(),reserved_items=reserved)


def test_encoded_envelope_bound_is_enforced_for_valid_large_unicode_resource_keys():
    writes=tuple(Write(Key('state','é'*240+str(i)),1,{}) for i in range(98))
    checks=tuple(Row(value.key,1,{}) for value in writes)
    with pytest.raises(ValueError,match='envelope exceeds bound'):prepare('deployment','record',writes,checks)


@pytest.mark.parametrize('case',['missing-output','duplicate-output','existing-event','prebound-event','inconsistent-output-check'])
def test_invalid_linked_output_contract_is_rejected(case):
    root=Write(Key('state','root'),None,{});event=Write(Key('events','event'),None,{})
    writes=(root,event);checks=()
    if case=='missing-output':writes=(root,)
    elif case=='duplicate-output':writes=(root,event,event)
    elif case=='existing-event':writes=(root,Write(event.key,1,{}))
    elif case=='prebound-event':writes=(root,Write(event.key,None,{'resource_bindings':{}}))
    else:checks=(Row(event.key,1,{}),)
    with pytest.raises((ValueError,StoreConflict)):prepare_linked('deployment','record',writes,checks)
