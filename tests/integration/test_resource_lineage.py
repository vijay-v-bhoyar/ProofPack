"""Owned-emulator regression for missing shared-writer provenance, not an exposure claim."""
from test_access_lifecycle import repository_factory,world
from proofpack.auth.policy import Role
from proofpack.auth.service import invitation_key
from proofpack.calibrations.dependencies import digest


def test_shared_writer_atomically_links_event_and_idempotency_to_exact_created_resource(world):
    service,repo,clock,uid,credentials,owner=world
    arguments=dict(target_subject='lineage-synthetic-user',target_email='lineage@example.invalid',
        roles=(Role.OPERATOR,),ttl_seconds=60,idempotency_key='lineage-original')
    result=service.create_invitation(owner,**arguments)
    replays,cursor=repo.query(prefix='idempotency#',limit=100)
    assert cursor is None and len(replays)==1
    events,cursor=repo.query(prefix='access#',table='events',limit=100)
    selected=[row for row in events if row.data.get('kind')=='invite']
    assert cursor is None and len(selected)==1
    assert 'resource_bindings' in replays[0].data,'shared idempotency result lacks typed cleanup resource bindings'
    bindings=replays[0].data['resource_bindings']
    assert selected[0].data['resource_bindings']==bindings
    assert bindings['schema_version']==1 and bindings['deployment']==repo.deployment and bindings['operation']=='invite'
    key=invitation_key(result['id']);source=repo.snapshot((key,))[key]
    links=[item for item in bindings['writes'] if item['table']==key.table and item['resource']==key.resource]
    assert links==[{'table':key.table,'resource':key.resource,'previous_revision':None,'revision':1,'sha256':digest(source.data)}]
    assert isinstance(bindings['checks'],list) and bindings['checks']
    replay=service.create_invitation(owner,**arguments)
    assert replay==result and len(repo.query(prefix='idempotency#',limit=100)[0])==1
    assert len([row for row in repo.query(prefix='access#',table='events',limit=100)[0] if row.data.get('kind')=='invite'])==1


def test_stale_dependency_aborts_business_event_and_idempotency_atomically(world,monkeypatch):
    import pytest
    from proofpack.evidence.repository import StoreConflict,Write
    service,repo,clock,uid,credentials,owner=world
    commit=service._commit
    def race(writes,checks=()):
        current=repo.snapshot((owner.member.key,))[owner.member.key]
        repo.transact((Write(current.key,current.revision,current.data),))
        return commit(writes,checks)
    monkeypatch.setattr(service,'_commit',race)
    with pytest.raises(StoreConflict):
        service.create_invitation(owner,target_subject='lineage-race-user',target_email='race@example.invalid',
            roles=(Role.OPERATOR,),ttl_seconds=60,idempotency_key='lineage-race')
    assert repo.query(prefix='invitation#',limit=100)[0]==[]
    assert repo.query(prefix='idempotency#',limit=100)[0]==[]
    assert not [row for row in repo.query(prefix='access#',table='events',limit=100)[0] if row.data.get('kind')=='invite']


def test_final_callback_cannot_change_payload_after_bindings_are_prepared(world):
    from uuid import uuid4
    from proofpack.evidence.repository import Key,Write
    service,repo,clock,uid,credentials,owner=world
    key=Key('state','lineage-effect#'+str(uuid4()));data={'nested':['original']}
    idem,body_hash,prior=service._idempotency(owner,'lineage-freeze','lineage-freeze',{'effect':key.resource})
    service._record(owner,'lineage-freeze',idem,body_hash,{'id':key.resource},(Write(key,None,data),),
        before_commit=lambda:data['nested'].append('changed-after-preparation'))
    current=repo.snapshot((key,idem));assert current[key].data=={'nested':['original']}
    binding=current[idem].data['resource_bindings']['writes'][0]
    assert binding['resource']==key.resource and binding['sha256']==digest(current[key].data)
    assert data=={'nested':['original','changed-after-preparation']}


def test_session_expiring_during_provenance_preparation_cannot_commit(world,monkeypatch):
    from uuid import uuid4
    import pytest
    import proofpack.auth.service as access_module
    from proofpack.auth.policy import Denied
    from proofpack.evidence.repository import Key,Write
    service,repo,clock,uid,credentials,owner=world
    key=Key('state','lineage-expiry#'+str(uuid4()))
    idem,body_hash,prior=service._idempotency(owner,'lineage-expiry','lineage-expiry',{'effect':key.resource})
    prepare=access_module.prepare_resource_bindings
    def expire(*args,**kwargs):
        value=prepare(*args,**kwargs);clock.value=int(owner.session.data['expires_at_ms']);return value
    monkeypatch.setattr(access_module,'prepare_resource_bindings',expire)
    with pytest.raises(Denied):service._record(owner,'lineage-expiry',idem,body_hash,{'id':key.resource},(Write(key,None,{}),))
    assert repo.snapshot((key,idem))=={key:None,idem:None}
    assert not [row for row in repo.query(prefix='access#',table='events',limit=100)[0] if row.data.get('kind')=='lineage-expiry']
