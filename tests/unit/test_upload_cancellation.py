"""Route dispatch ownership under cancellation; auth/CV covered separately."""
import asyncio
from threading import Event
from uuid import uuid4
import pytest
from starlette.requests import Request
from proofpack.evidence.repository import StoreUnavailable
import proofpack.capture.http as module
from proofpack.capture.observations import ObservationService
from proofpack.stations.service import StationRateLimited
from proofpack.evidence.repository import StoreConflict


@pytest.mark.parametrize('phase',['begin','process','process_failure'])
def test_cancelled_request_retains_capacity_until_owned_thread_finishes(monkeypatch,phase):
    started=Event();finish=Event();released=Event()
    class Service:
        def begin_upload(self,*args):
            if phase=='begin':started.set();assert finish.wait(3)
            return 'owned-server-ticket'
        def upload(self,*args,**kwargs):
            started.set();assert finish.wait(3)
            if phase=='process_failure':raise StoreUnavailable('synthetic failure')
            return {'safe':'result'}
        def end_upload(self,token):assert token=='owned-server-ticket';released.set()
    async def image(request):return object()
    monkeypatch.setattr(module,'write_guard',lambda *args:None)
    monkeypatch.setattr(module,'receive_upload',image)
    async def scenario():
        errors=[];asyncio.get_running_loop().set_exception_handler(lambda loop,context:errors.append(context))
        headers=[(name.encode(),b'value') for name in ('origin','x-csrf-token','idempotency-key','if-match')]
        request=Request({'type':'http','method':'POST','headers':headers})
        task=asyncio.create_task(module.upload(uuid4(),request,'idempotent','1',current=object(),service=Service()))
        try:
            async with asyncio.timeout(2):
                while not started.is_set():await asyncio.sleep(.001)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):await task
            assert not released.is_set()
        finally:finish.set()
        async with asyncio.timeout(2):
            while not released.is_set():await asyncio.sleep(.001)
        await asyncio.sleep(.01)
        assert not errors
    asyncio.run(scenario())


def test_upload_capacity_is_two_total_one_per_station_and_only_owned_tickets_release():
    from threading import Lock
    from types import SimpleNamespace
    # Scope/auth is exercised by HTTP integration; isolate the resource gate here.
    service=object.__new__(ObservationService);service._upload_lock=Lock();service._uploads={}
    service._upload_scope=lambda actor,ident:(actor,SimpleNamespace(data={'station_id':ident}))
    first=service.begin_upload(object(),'station-one');second=service.begin_upload(object(),'station-two')
    with pytest.raises(StoreConflict):service.begin_upload(object(),'station-one')
    with pytest.raises(StationRateLimited):service.begin_upload(object(),'station-three')
    service.end_upload('not-owned');assert len(service._uploads)==2
    service.end_upload(first);third=service.begin_upload(object(),'station-three')
    assert len(service._uploads)==2 and third not in {first,second}
    service.end_upload(first);assert len(service._uploads)==2
    service.end_upload(second);service.end_upload(third);assert service._uploads=={}
