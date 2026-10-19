"""Owner reference intake with private intent before storage and atomic linking."""
from dataclasses import asdict,dataclass,field
import hashlib
import json
from threading import BoundedSemaphore,Lock
from uuid import uuid4

from pydantic import Field

from proofpack.calibrations.dependencies import digest as record_digest
from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,ResourceUnavailable
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.evidence.objects import ReferenceObjects,ObjectReceipt
from proofpack.recipes.models import Contract,Identifier,Origin
from proofpack.runtime.control import DATA,integer,uuid
from proofpack.vision.worker import WorkerBusy,WorkerUnavailable


class ReferenceRateLimited(RuntimeError):pass


class ReferenceRequest(Contract):
    purpose_id:str=Field(pattern=r'^[a-f0-9-]{36}$')
    source_permission_reference:Identifier
    data_origin:Origin
    expires_at_ms:int=Field(gt=0,le=9007199254740991)


@dataclass(frozen=True)
class ReferenceTicket:
    id:str
    user_id:str
    session_id:str
    access_version:int
    runtime:object=field(repr=False)
    data:object=field(repr=False)
    worker:object=field(repr=False)
    lease:object=field(repr=False)


class ReferenceAssets:
    def __init__(self,purposes,objects,registry,*,max_uploads_per_minute):
        if (not isinstance(objects,ReferenceObjects) or objects.config.deployment!=purposes.repository.deployment or type(max_uploads_per_minute) is not int
                or not 1<=max_uploads_per_minute<=100):raise ValueError('shared deployment and explicit bounded intake allowance required')
        self.purposes=purposes;self.access=purposes.access;self.runtime=purposes.runtime;self.repository=purposes.repository
        self.objects=objects;self.registry=registry;self.max_uploads_per_minute=max_uploads_per_minute
        self._capacity=BoundedSemaphore(2);self._lock=Lock();self._tickets={};self._closed=False

    def _scope(self,actor,ticket):
        if not isinstance(ticket,ReferenceTicket):raise Denied('owned reference intake required')
        with self._lock:
            if self._closed or self._tickets.get(ticket.id) is not ticket:raise Denied('owned reference intake required')
        actor=self.access._fresh(actor,Role.OWNER)
        if (actor.member.data['id']!=ticket.user_id or actor.session.data['id']!=ticket.session_id
                or integer(actor.member.data['access_version'])!=ticket.access_version):raise Denied('reference intake authority changed')
        return actor

    def begin(self,actor):
        actor=self.access._fresh(actor,Role.OWNER)
        if not self._capacity.acquire(blocking=False):raise ReferenceRateLimited('reference intake busy')
        lease=None
        try:
            with self._lock:
                if self._closed:raise StoreUnavailable('reference intake closed')
            data=self.purposes.head();runtime=self.repository.snapshot((RUNTIME,))[RUNTIME]
            if not self.runtime.matches(runtime):raise Denied('current runtime required')
            quota_key=Key('state','reference-quota#'+actor.scope);quota=self.repository.snapshot((quota_key,))[quota_key]
            minute=self.access.now()//60000
            if quota is not None and integer(quota.data['minute'])>minute:raise StoreUnavailable('reference allowance clock moved backwards')
            count=0 if quota is None or integer(quota.data['minute'])!=minute else integer(quota.data['count'])
            if count>=self.max_uploads_per_minute:raise ReferenceRateLimited('reference intake allowance exhausted')
            self.access._fresh(actor,Role.OWNER)
            self.repository.transact((Write(quota_key,None if quota is None else quota.revision,{'minute':minute,'count':count+1}),),
                (*actor.rows,runtime,data))
            lease=self.registry.diagnostic(runtime_id=self.runtime.instance_id);worker=lease.__enter__()
            actor=self.access._fresh(actor,Role.OWNER)
            ticket=ReferenceTicket(str(uuid4()),actor.member.data['id'],actor.session.data['id'],integer(actor.member.data['access_version']),runtime,data,worker,lease)
            with self._lock:
                if self._closed:raise StoreUnavailable('reference intake closed')
                self._tickets[ticket.id]=ticket
            return ticket
        except BaseException as exc:
            if lease is not None:lease.__exit__(None,None,None)
            self._capacity.release()
            if isinstance(exc,WorkerBusy):raise ReferenceRateLimited('shared decoder capacity exhausted') from exc
            if isinstance(exc,WorkerUnavailable):raise StoreUnavailable('reference decoder unavailable') from exc
            raise

    def end(self,ticket):
        if not isinstance(ticket,ReferenceTicket):return
        with self._lock:
            if self._tickets.get(ticket.id) is not ticket:return
            self._tickets.pop(ticket.id)
        try:ticket.lease.__exit__(None,None,None)
        finally:self._capacity.release()

    def close(self):
        with self._lock:
            self._closed=True
            for ticket in self._tickets.values():ticket.worker.close()

    def _result(self,actor,row):
        self.access._fresh(actor,Role.OWNER)
        result=row.data['result']
        if result['status']=='committed':return {**self.get(actor,result['id']),'operation_status':'committed','replayed':True}
        return {**result,'operation_status':result['status'],'replayed':True,'requires_reconciliation':True}

    def _fail(self,operation_key,intent_key):
        try:
            rows=self.repository.snapshot((operation_key,intent_key));operation,intent=rows[operation_key],rows[intent_key]
            if operation is None or intent is None or operation.data['result']['status']!='processing' or intent.data['status']=='linked':return
            self.access._commit_linked('reference_failed',(Write(operation_key,operation.revision,{**operation.data,'result':{**operation.data['result'],'status':'failed'}}),
                Write(intent_key,intent.revision,{**intent.data,'status':'needs_reconciliation'})))
        except (StoreConflict,StoreUnavailable,ValueError):pass

    def upload(self,actor,*,ticket,request:ReferenceRequest,payload,content_type,idempotency_key):
        actor=self._scope(actor,ticket)
        if not isinstance(request,ReferenceRequest) or not isinstance(payload,bytes) or not 0<len(payload)<=2097152 or content_type not in {'image/jpeg','image/png'}:
            raise ValueError('typed bounded reference upload required')
        uuid(request.purpose_id)
        body={**request.model_dump(mode='json'),'source_sha256':hashlib.sha256(payload).hexdigest(),'byte_length':len(payload),'content_type':content_type}
        operation,body_hash,replay=self.access._idempotency(actor,'reference-upload',idempotency_key,body)
        if replay is not None:return self._result(actor,replay)
        objects=self.objects;client=objects.client;storage_binding=record_digest(asdict(objects.config))
        endpoint=client.meta.endpoint_url;region=client.meta.region_name
        def storage_fresh():
            if (self.objects is not objects or objects.client is not client
                    or record_digest(asdict(objects.config))!=storage_binding
                    or client.meta.endpoint_url!=endpoint or client.meta.region_name!=region):
                raise StoreUnavailable('original reference storage target required')
        storage_fresh()
        purpose=self.purposes.permitted(request.purpose_id,source_permission_reference=request.source_permission_reference,expires_at_ms=request.expires_at_ms)
        context=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        ident=str(uuid4());intent_key=Key('state','reference-intent#'+ident)
        intent={'id':ident,'kind':'reference','status':'reserved','asset_id':ident,'key':objects.key(ident),
            'history_version':2,'storage_binding_sha256':storage_binding,
            'purpose_id':request.purpose_id,'source_sha256':body['source_sha256'],'context_sha256':context,
            'owner_user_id':ticket.user_id,'session_id':ticket.session_id,'runtime_epoch':integer(ticket.runtime.data['runtime_epoch']),
            'data_epoch':integer(ticket.data.data['epoch']),'created_at_ms':self.access.now()}
        reserved=self.access._record(actor,'reference-upload',operation,body_hash,{'id':ident,'status':'processing'},
            (Write(intent_key,None,intent),),(purpose,ticket.runtime,ticket.data))
        if reserved['id']!=ident:
            replay=self.repository.snapshot((operation,))[operation]
            if replay is None:raise StoreUnavailable('reference operation unavailable')
            return self._result(actor,replay)
        try:
            storage_fresh()
            metadata,canonical=ticket.worker.reference(payload,content_type=content_type)
            actor=self._scope(actor,ticket)
            current_purpose=self.purposes.permitted(request.purpose_id,source_permission_reference=request.source_permission_reference,expires_at_ms=request.expires_at_ms)
            if current_purpose!=purpose:raise StoreConflict('purpose changed during reference verification')
            rows=self.repository.snapshot((operation,intent_key,RUNTIME,DATA))
            op,intentrow=rows[operation],rows[intent_key]
            if (rows[RUNTIME]!=ticket.runtime or rows[DATA]!=ticket.data or op is None or intentrow is None
                    or op.data['result']['status']!='processing' or intentrow.data!=intent):
                raise StoreConflict('reference authority changed')
            writing={**intentrow.data,'status':'writing','stored_sha256':metadata.stored_sha256,'stored_byte_length':metadata.byte_length}
            self.access._fresh(actor,Role.OWNER)
            self.access._commit((Write(intent_key,intentrow.revision,writing),),(*actor.rows,purpose,ticket.runtime,ticket.data,op))
            storage_fresh()
            before_storage=self.repository.snapshot((intent_key,))[intent_key]
            if before_storage is None or before_storage.data!=writing:raise StoreUnavailable('original reference intent target required')
            storage_fresh()
            receipt=objects.put(asset_id=ident,payload=canonical,content_type='image/jpeg',context_sha256=context)
            storage_fresh()
            if (receipt.asset_id!=ident or receipt.key!=intent['key'] or receipt.source_sha256!=metadata.stored_sha256 or receipt.context_sha256!=context
                    or receipt.byte_length!=metadata.byte_length or receipt.content_type!='image/jpeg'):
                raise StoreUnavailable('reference storage provenance mismatch')
            actor=self._scope(actor,ticket)
            if self.purposes.permitted(request.purpose_id,source_permission_reference=request.source_permission_reference,expires_at_ms=request.expires_at_ms)!=purpose:
                raise StoreConflict('reference purpose changed during storage')
            current=self.repository.snapshot((operation,intent_key,RUNTIME,DATA));op,current_intent=current[operation],current[intent_key]
            if (current[RUNTIME]!=ticket.runtime or current[DATA]!=ticket.data or op is None or current_intent is None
                    or op.data['body_hash']!=body_hash or op.data['result']['status']!='processing'
                    or current_intent.data!=writing):raise StoreConflict('reference publication authority changed')
            asset={'storage_binding_sha256':storage_binding,'id':ident,'kind':'reference','status':'committed','read_denied':False,'sha256':metadata.stored_sha256,
                'source_sha256':metadata.source_sha256,'width':metadata.width,'height':metadata.height,'byte_length':metadata.byte_length,
                'content_type':'image/jpeg','object_receipt':asdict(receipt),'purpose_id':request.purpose_id,
                'source_permission_reference':request.source_permission_reference,'data_origin':request.data_origin.value,
                'origin_basis':'owner_declaration','physical_truth_verified':False,'expires_at_ms':request.expires_at_ms,
                'owner_user_id':ticket.user_id,'created_at_ms':self.access.now()}
            def final():
                storage_fresh()
                self._scope(actor,ticket)
                if self.purposes.permitted(request.purpose_id,source_permission_reference=request.source_permission_reference,expires_at_ms=request.expires_at_ms)!=purpose:
                    raise StoreConflict('reference purpose changed before publication')
                storage_fresh()
            self.access._commit_linked('reference_committed',(Write(Key('state','asset#'+ident),None,asset),self.purposes.advance(ticket.data),
                Write(operation,op.revision,{**op.data,'result':{'id':ident,'status':'committed'}}),
                Write(intent_key,current_intent.revision,{**writing,'status':'linked','object_receipt':asdict(receipt)}),
                Write(Key('events','reference#'+str(uuid4())),None,{'kind':'reference_committed','asset_id':ident,
                    'purpose_id':request.purpose_id,'actor_scope':actor.scope,'at_ms':self.access.now()})),
                (*actor.rows,purpose,ticket.runtime,ticket.data,op,current_intent),before_commit=final)
            return {**self.get(actor,ident),'operation_status':'committed','replayed':False}
        except BaseException as exc:
            self._fail(operation,intent_key)
            if isinstance(exc,WorkerUnavailable):raise StoreUnavailable('reference media verification unavailable') from exc
            raise

    def get(self,actor,ident):
        actor=self.purposes.candidate(actor);key=Key('state','asset#'+uuid(ident));first=self.repository.snapshot((key,))[key]
        if first is None or first.data.get('kind')!='reference':raise ResourceUnavailable('reference unavailable')
        purpose=self.purposes.permitted(first.data['purpose_id'],source_permission_reference=first.data['source_permission_reference'],expires_at_ms=integer(first.data['expires_at_ms']))
        expected={row.key:row for row in (*actor.rows,first,purpose)};final=self.repository.snapshot(tuple(expected))
        if any(final[key]!=row for key,row in expected.items()):raise StoreConflict('reference changed during read')
        self.purposes.candidate(actor)
        if self.access.now()>=integer(first.data['expires_at_ms']) or first.data.get('read_denied') is not False or first.data.get('status')!='committed':
            raise StoreUnavailable('reference no longer permitted')
        public={'id','kind','status','read_denied','sha256','source_sha256','width','height','byte_length','content_type','purpose_id',
            'source_permission_reference','data_origin','origin_basis','physical_truth_verified','expires_at_ms','owner_user_id','created_at_ms'}
        return {name:(integer(value) if name in {'width','height','byte_length','expires_at_ms','created_at_ms'} else value)
            for name,value in first.data.items() if name in public} | {'state_version':first.revision}

    def snapshot(self,actor,ident):
        """Internal scoped reference snapshot; never an unauthenticated byte capability."""
        view=self.get(actor,ident);key=Key('state','asset#'+uuid(ident));asset=self.repository.snapshot((key,))[key]
        if asset is None or asset.revision!=view['state_version']:raise StoreConflict('reference changed')
        purpose=self.purposes.permitted(asset.data['purpose_id'],source_permission_reference=asset.data['source_permission_reference'],expires_at_ms=integer(asset.data['expires_at_ms']))
        try:
            receipt=ObjectReceipt(**{**asset.data['object_receipt'],'byte_length':integer(asset.data['object_receipt']['byte_length'])})
            if receipt.asset_id!=ident or receipt.source_sha256!=asset.data['sha256'] or receipt.byte_length!=integer(asset.data['byte_length']):raise ValueError()
        except (TypeError,ValueError,KeyError) as exc:raise StoreUnavailable('reference receipt unavailable') from exc
        rows={asset.key:asset,purpose.key:purpose};final=self.repository.snapshot(tuple(rows))
        if any(final[key]!=row for key,row in rows.items()):raise StoreConflict('reference changed during snapshot')
        return rows,asset,receipt,min(integer(asset.data['expires_at_ms']),integer(purpose.data['expires_at_ms']))
