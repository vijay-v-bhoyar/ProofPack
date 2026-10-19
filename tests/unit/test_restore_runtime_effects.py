"""Bounded downstream guards and allocation effects; no complete user trial."""
from copy import deepcopy
from types import SimpleNamespace
from uuid import uuid4
import pytest

from restore_consumer_model import auth_world
from test_restore_runtime import setup, runtime
from proofpack.evidence.repository import Key, Row, Write, StoreConflict, StoreUnavailable
from proofpack.evidence.purposes import DataPurposes
from proofpack.review.manifests import DatasetManifests
from proofpack.runtime.control import ALLOCATION, DATA


def test_new_incarnation_preserves_occupied_allocation_while_advancing_data():
    access,fence,client,ids,clock=setup();runtime(access).start()
    repo=access.repository;head=repo.snapshot((ALLOCATION,))[ALLOCATION]
    occupied={str(uuid4()):str(uuid4())}
    repo.transact((Write(ALLOCATION,head.revision,{'slots':occupied}),))
    before=repo.snapshot((ALLOCATION,))[ALLOCATION]
    runtime(access).start();after=repo.snapshot((ALLOCATION,DATA))
    assert after[ALLOCATION]==before and after[ALLOCATION].data['slots']==occupied
    assert after[DATA].data['epoch']==2


def test_actual_dataset_guard_rejects_old_data_binding_even_with_current_runtime_and_fresh_actor():
    access,fence,client,ids,proof,clock=auth_world()
    actor=access.resolve(access.login(proof).cookie)
    access.change_access(actor,user_id=actor.member.data['id'],roles=['owner','reviewer'],enabled=True,
        expected_version=int(actor.member.data['access_version']),idempotency_key='fixture-reviewer-role')
    actor=access.resolve(access.login(proof).cookie)
    first=runtime(access);first.start()
    # This is a guard unit with a supplied row, not a prepared/sealed dataset or
    # adoption claim. Authentication, runtime and DATA readers are actual source.
    holder=SimpleNamespace(access=access,repository=access.repository,runtime=first,
        purposes=DataPurposes(access,first,max_lifetime_ms=60000),configuration='synthetic-guard-unit')
    holder._runtime=lambda:DatasetManifests._runtime(holder)
    supplied=Row(Key('state','job#'+str(uuid4())),1,dict(configuration=holder.configuration,
        artifact_sha256=first.artifact_sha256,controls_sha256=first.controls_sha256,environment=first.environment,
        data_epoch=1,created_at_ms=clock[0],expires_at_ms=61000,effective_deadline_ms=61000))
    assert DatasetManifests._guard(holder,actor,supplied)[2].data['epoch']==1
    current=runtime(access);current.start()
    holder.runtime=current;holder.purposes=DataPurposes(access,current,max_lifetime_ms=60000)
    before=deepcopy(client.items)
    with pytest.raises(StoreConflict,match='dataset binding or lifetime changed'):
        DatasetManifests._guard(holder,actor,supplied)
    assert client.items==before


def test_clock_change_after_link_preparation_denies_before_any_startup_write():
    access,fence,client,ids,clock=setup();before=deepcopy(client.items);original=access._prepare_linked
    def backwards(*args,**kwargs):
        result=original(*args,**kwargs);clock[0]-=1;return result
    access._prepare_linked=backwards;first=runtime(access);client.calls.clear()
    with pytest.raises(StoreUnavailable):first.start()
    assert first.handle is None and client.items==before
    assert not any(name=='transact_write_items' for name,_ in client.calls)
