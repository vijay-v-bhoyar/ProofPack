"""Source-written v2 startup histories; all identities/releases are synthetic."""
from copy import deepcopy
from dataclasses import replace
from decimal import Decimal
import pytest

from test_restore_runtime import setup, runtime, item
from restore_consumer_model import sdk_world
from test_access_context import complete, read as read_access
from test_runtime_context import read as read_runtime
from test_auth_history_consumption import read as read_auth
from test_capture_lineage import DEPLOYMENT, uid
from proofpack.auth.service import AccessService, AuthConfig
from proofpack.runtime.control import RuntimeControl, RUNTIME, DATA, ALLOCATION
from proofpack.runtime.startup_schema import restore_startup, valid_data_write, MAXIMUM, LEGACY_FIELDS
from proofpack.evidence.repository import Key, StoreUnavailable
from proofpack.evidence.runtime_lineage import discover, RuntimeLineageLimits, RuntimeLineageHeld
from proofpack.evidence.resource_bindings import _payload_sha256


def source_family(existing):
    access,fence,client,ids,clock=setup()
    if existing:runtime(access).start()
    current=runtime(access);current.start()
    event=next(Key('events',key) for (_,_,key),value in client.items.items()
        if key.startswith('runtime#') and value['data']['M']['instance_id']=={'S':current.instance_id})
    marker=Key('state','runtime-start#'+current.instance_id)
    rows=access.repository.snapshot((event,marker,RUNTIME,ALLOCATION,DATA))
    return rows[event],rows[marker],rows[RUNTIME],None if existing else rows[ALLOCATION],rows[DATA]


def lineage(family):
    event,marker,state,allocation,data=family
    return discover(event,marker,state,deployment='synthetic',now_ms=2000,
        created_allocation=allocation,created_data=data,limits=RuntimeLineageLimits(8,100000,10000,100000),
        deadline_ns=1000,tick=lambda:1,checkpoint=lambda:None)


@pytest.mark.parametrize('existing',[False,True],ids=['initial-DATA','conditional-DATA'])
def test_lineage_consumes_real_fenced_startup_writer_without_cleanup_authority(existing):
    family=source_family(existing);before=deepcopy(family);result=lineage(family)
    assert family==before and result.read_only is True and result.can_confirm_cleanup is False
    assert result.policy=='runtime-startup-provenance-v1'
    assert len(result.records)==(4 if existing else 5)
    assert family[4].data['epoch']==(2 if existing else 1)


def test_legacy_marker_cannot_authorize_conditional_data_even_with_matching_marker_digest():
    event,marker,state,allocation,data=source_family(True)
    marker=replace(marker,data={k:v for k,v in marker.data.items() if k in LEGACY_FIELDS})
    body=deepcopy(event.data)
    for reference in body['resource_bindings']['writes']:
        if reference['resource']==marker.key.resource:reference['sha256']=_payload_sha256(marker.data)
    event=replace(event,data=body)
    with pytest.raises(RuntimeLineageHeld):lineage((event,marker,state,allocation,data))


def context_family(monkeypatch):
    reader,owner,_,rows,_=complete(monkeypatch)
    repo,fence,client,ids=sdk_world(deployment=DEPLOYMENT,artifact_sha256='e'*64)
    remove={key for key,value in rows.items() if key.resource.startswith('runtime-start#')
        or key.table=='events' and value.data.get('kind')=='runtime_started'}
    for key,value in rows.items():
        if key in remove or key in (RUNTIME,DATA,ALLOCATION):continue
        encoded=repo.key(key)|{'revision':{'N':str(value.revision)},'data':repo.serialize.serialize(value.data)}
        client.items[client.identity(repo.tables[key.table],encoded)]=encoded
    # A copied isolated bootstrap state permits the genuine protected writer to
    # produce the same origin/runtime identity as the untouched capture fixture.
    initial=repo.key(RUNTIME)|{'revision':{'N':'1'},'data':repo.serialize.serialize(
        {'runtime_epoch':0,'control_version':1,'inspection_enabled':False})}
    client.items[client.identity(repo.tables['state'],initial)]=initial
    access=AccessService(repo,AuthConfig(DEPLOYMENT,'https://identity.example.test',b'x'*32),clock_ms=lambda:3)
    current=RuntimeControl(access,instance_id=uid(4),artifact_sha256='e'*64,controls_sha256='b'*64,environment='test')
    current.start()
    event_keys=[Key('events',key) for (_,_,key),value in client.items.items()
        if key.startswith('runtime#') and value['data']['M']['instance_id']=={'S':uid(4)}]
    marker=Key('state','runtime-start#'+uid(4))
    generated=repo.snapshot((RUNTIME,DATA,ALLOCATION,marker,*event_keys))
    assert generated[marker].data['startup_schema_version']==2
    for key in remove:rows.pop(key)
    rows.update(generated)
    return reader,owner,rows


@pytest.mark.parametrize('read',[read_runtime,read_access,read_auth],ids=['runtime-context','origin-context','complete-auth'])
def test_full_held_readers_consume_v2_runtime_marker_without_writes_or_new_rights(monkeypatch,read):
    reader,owner,rows=context_family(monkeypatch);before=deepcopy(rows)
    result=read(reader);context=result.corpus.runtime_context
    assert context.read_only is True and context.can_confirm_cleanup is False
    assert context.policy=='runtime-maintenance-context-v1'
    assert any(record.reference.key.resource.startswith('runtime-start#') for record in context.records)
    assert rows==before and owner.wait_for_drain(0)


@pytest.mark.parametrize('bad',[True,False,2.0,'2',None,Decimal('NaN'),Decimal('sNaN'),Decimal('Infinity'),Decimal('2.1')])
def test_startup_version_is_an_exact_finite_integer_discriminator(bad):
    data=dict.fromkeys(LEGACY_FIELDS)
    data.update(startup_schema_version=bad,restore_generation_sha256='a'*64,previous_data_epoch=0,data_epoch=1)
    with pytest.raises((ValueError,ArithmeticError)):restore_startup(data)


@pytest.mark.parametrize('value',[2,Decimal('2'),Decimal('2.0')])
def test_lossless_dynamo_version_and_legacy_shapes_are_preserved(value):
    legacy=dict.fromkeys(LEGACY_FIELDS)
    assert restore_startup(legacy) is None
    assert restore_startup(legacy|dict(startup_schema_version=value,restore_generation_sha256='a'*64,
        previous_data_epoch=Decimal('3'),data_epoch=Decimal('4')))==('a'*64,3,4)


def test_data_revision_range_keeps_the_existing_last_valid_conditional_update():
    assert valid_data_write(('a'*64,3,4),MAXIMUM,MAXIMUM+1) is True
    assert valid_data_write(('a'*64,3,4),MAXIMUM+1,MAXIMUM+2) is False
    assert valid_data_write(None,1,2) is False


@pytest.mark.parametrize('fault',['marker_revision','missing_allocation','allocation_extra','data_before_start_time'])
def test_exact_retry_requires_intact_heads_and_original_immutable_marker(fault):
    access,fence,client,ids,clock=setup();first=runtime(access);first.start()
    if fault=='marker_revision':item(access.repository,client,Key('state','runtime-start#'+first.instance_id))['revision']={'N':'2'}
    elif fault=='missing_allocation':client.items.pop(client.identity(access.repository.tables['state'],access.repository.key(ALLOCATION)))
    elif fault=='allocation_extra':item(access.repository,client,ALLOCATION)['data']['M']['unreviewed']={'BOOL':True}
    else:item(access.repository,client,DATA)['data']['M']['changed_at_ms']={'N':'0'}
    before=deepcopy(client.items);retry=runtime(access,instance=first.instance_id)
    with pytest.raises(StoreUnavailable):retry.start()
    assert retry.handle is None and client.items==before


def test_clock_backwards_after_commit_withholds_handle_without_rewriting_committed_state():
    access,fence,client,ids,clock=setup();first=runtime(access);original=client.transact_write_items
    def backwards(**kwargs):
        result=original(**kwargs);clock[0]-=1;return result
    client.transact_write_items=backwards
    with pytest.raises(StoreUnavailable):first.start()
    assert first.handle is None and item(access.repository,client,DATA)['data']['M']['epoch']=={'N':'1'}
