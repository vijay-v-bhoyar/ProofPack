"""Versioned operational-use attestations, not independent rights certification."""
from uuid import uuid4

from pydantic import Field,model_validator
from proofpack.evidence.originals import ORIGINAL_NOTICE_VERSION,ORIGINAL_NOTICE_TEXT,ORIGINAL_NOTICE_SHA256,original_capture_enabled

from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,ResourceUnavailable,digest
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.recipes.models import Contract,Identifier
from proofpack.runtime.control import DATA,integer,uuid


class PurposeRequest(Contract):
    notice_version:str=Field(min_length=1,max_length=128)
    notice_sha256:str=Field(pattern=r'^[a-f0-9]{64}$')
    source_permission_reference:Identifier
    operational_use_acknowledged:bool
    expires_at_ms:int=Field(gt=0,le=9007199254740991)
    original_capture_retention_acknowledged:bool=False
    original_capture_notice_sha256:str|None=Field(default=None,pattern=r'^[a-f0-9]{64}$')

    @model_validator(mode='after')
    def original_scope(self):
        if self.original_capture_retention_acknowledged:
            if self.original_capture_notice_sha256!=ORIGINAL_NOTICE_SHA256:raise ValueError('exact original retention notice acknowledgment required')
        elif self.original_capture_notice_sha256 is not None:raise ValueError('original notice requires separate acknowledgment')
        return self


def purpose_key(ident):return Key('state','purpose#'+uuid(ident))


class DataPurposes:
    def __init__(self,access,runtime,*,max_lifetime_ms):
        if runtime.access is not access or type(max_lifetime_ms) is not int or not 1<=max_lifetime_ms<=31536000000:
            raise ValueError('shared authority and explicit bounded purpose lifetime required')
        self.access=access;self.runtime=runtime;self.repository=access.repository;self.max_lifetime_ms=max_lifetime_ms

    def candidate(self,actor):
        actor=self.access._fresh(actor)
        return self.access._fresh(actor,Role.REVIEWER if Role.REVIEWER in actor.principal.roles else Role.OWNER)

    def head(self):
        row=self.repository.snapshot((DATA,))[DATA]
        try:
            if row is None or integer(row.data['epoch'])<1 or integer(row.data.get('changed_at_ms',0))>self.access.now():raise ValueError()
        except (TypeError,ValueError,KeyError,AttributeError) as exc:raise StoreUnavailable('current data authority required') from exc
        return row

    def advance(self,row):
        if integer(row.data.get('changed_at_ms',0))>self.access.now():raise StoreUnavailable('data authority clock moved backwards')
        return Write(DATA,row.revision,{**row.data,'epoch':integer(row.data['epoch'])+1,'changed_at_ms':self.access.now()})

    @staticmethod
    def public(row):
        original=row.data.get('original_capture_retention_allowed',False)
        if (type(original) is not bool or (original and (row.data.get('original_capture_notice_version')!=ORIGINAL_NOTICE_VERSION
                or row.data.get('original_capture_notice_sha256')!=ORIGINAL_NOTICE_SHA256 or row.data.get('original_capture_notice_text')!=ORIGINAL_NOTICE_TEXT))):
            raise StoreUnavailable('intact original-capture attestation metadata required')
        return {'id':row.data['id'],'state_version':row.revision,'allowed_uses':list(row.data['allowed_uses']),
            'withdrawn':row.data['withdrawn'],'expires_at_ms':integer(row.data['expires_at_ms']),
            'source_permission_reference':row.data['source_permission_reference'],
            'notice_version':row.data['notice_version'],'notice_sha256':row.data['notice_sha256'],
            'authority_basis':'owner_attestation','rights_independently_verified':False,
            'optional_improvement':False,'optional_publicity':False,
            'original_capture_retention_allowed':original,
            'original_capture_notice_sha256':row.data.get('original_capture_notice_sha256')}

    def create(self,actor,*,request:PurposeRequest,idempotency_key):
        access,runtime_service,repository,lifetime=self.access,self.runtime,self.repository,self.max_lifetime_ms
        actor=self.access._fresh(actor,Role.OWNER)
        if not isinstance(request,PurposeRequest):raise ValueError('typed operational purpose required')
        if request.operational_use_acknowledged is not True:raise Denied('explicit operational use acknowledgment required')
        notice=self.access.operational_notice(actor)
        if request.notice_version!=notice['version'] or request.notice_sha256!=notice['sha256']:
            raise Denied('current operational notice required')
        body=request.model_dump(mode='json')
        if not request.original_capture_retention_acknowledged:
            body.pop('original_capture_retention_acknowledged');body.pop('original_capture_notice_sha256')
        idem,body_hash,replay=self.access._idempotency(actor,'purpose-create',idempotency_key,body)
        if replay is not None:return self.get(actor,replay.data['result']['id'])
        now=self.access.now()
        if (type(lifetime) is not int or not 1<=lifetime<=31536000000
                or not now<request.expires_at_ms<=now+lifetime):raise ValueError('explicit bounded purpose expiry required')
        expires=request.expires_at_ms;notice_binding=(notice['version'],notice['sha256'])
        data=self.head();runtime=self.repository.snapshot((RUNTIME,))[RUNTIME]
        if not self.runtime.matches(runtime):raise Denied('current runtime required')
        ident=str(uuid4());key=purpose_key(ident)
        record={'id':ident,'allowed_uses':['operation'],'withdrawn':False,'expires_at_ms':request.expires_at_ms,
            'source_permission_reference':request.source_permission_reference,'notice_version':notice['version'],
            'notice_sha256':notice['sha256'],'authority_basis':'owner_attestation','rights_independently_verified':False,
            'owner_user_id':actor.member.data['id'],'owner_access_version':integer(actor.member.data['access_version']),
            'created_at_ms':now,'optional_improvement':False,'optional_publicity':False}
        if request.original_capture_retention_acknowledged:
            record.update(original_capture_retention_allowed=True,original_capture_notice_version=ORIGINAL_NOTICE_VERSION,
                original_capture_notice_sha256=ORIGINAL_NOTICE_SHA256,original_capture_notice_text=ORIGINAL_NOTICE_TEXT)
        def final():
            if (self.access is not access or self.runtime is not runtime_service or self.repository is not repository
                    or runtime_service.access is not access or access.repository is not repository
                    or type(self.max_lifetime_ms) is not int or self.max_lifetime_ms!=lifetime):
                raise StoreConflict('original purpose creation configuration changed')
            current_notice=access.operational_notice(actor)
            if ((current_notice['version'],current_notice['sha256'])!=notice_binding
                    or not runtime_service.matches(runtime)):
                raise Denied('original purpose notice and runtime required')
            access._fresh(actor,Role.OWNER)
            if not now<=access.now()<expires:raise Denied('original purpose creation deadline expired')
        result=self.access._record(actor,'purpose-create',idem,body_hash,{'id':ident},
            (Write(key,None,record),self.advance(data)),(runtime,data),before_commit=final,
            event_details={'purpose_id':ident,'notice_sha256':notice['sha256']})
        return self.get(actor,result['id'])

    def options(self,actor):
        actor=self.access._fresh(actor,Role.OWNER);notice=self.access.operational_notice(actor)
        self.access._fresh(actor,Role.OWNER)
        return {'max_lifetime_ms':self.max_lifetime_ms,'server_time_ms':self.access.now(),'notice':notice,
            'original_capture_notice':{'version':ORIGINAL_NOTICE_VERSION,'sha256':ORIGINAL_NOTICE_SHA256,'text':ORIGINAL_NOTICE_TEXT}}

    def list(self,actor,*,limit=20,cursor=None):
        actor=self.candidate(actor)
        if type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded purpose page required')
        start=None if cursor is None else purpose_key(cursor).resource
        rows,last=self.repository.query(prefix='purpose#',limit=limit,start_resource=start)
        result=[self.get(actor,row.data['id']) for row in rows if row.data.get('authority_basis')=='owner_attestation']
        self.candidate(actor)
        return {'purposes':result,'next_cursor':None if last is None else last[len('purpose#'):]}

    def get(self,actor,ident):
        actor=self.candidate(actor);key=purpose_key(ident);row=self.repository.snapshot((key,))[key]
        if row is None:raise ResourceUnavailable('purpose unavailable')
        expected={item.key:item for item in (*actor.rows,row)};final=self.repository.snapshot(tuple(expected))
        if any(final[key]!=value for key,value in expected.items()):raise StoreConflict('purpose authority changed')
        self.candidate(actor)
        try:return self.public(row)
        except (TypeError,ValueError,KeyError,AttributeError) as exc:raise StoreUnavailable('purpose record unavailable') from exc

    def withdraw(self,actor,*,ident,expected_version,idempotency_key):
        actor=self.access._fresh(actor,Role.OWNER)
        if type(expected_version) is not int or expected_version<1:raise ValueError('positive purpose version required')
        key=purpose_key(ident);body={'id':ident,'expected_version':expected_version}
        idem,body_hash,replay=self.access._idempotency(actor,'purpose-withdraw',idempotency_key,body)
        if replay is not None:return self.get(actor,ident)
        row=self.repository.snapshot((key,))[key]
        if row is None:raise ResourceUnavailable('purpose unavailable')
        if row.revision!=expected_version:raise StoreConflict('purpose changed')
        if row.data['withdrawn'] is True:
            self.access._record(actor,'purpose-withdraw',idem,body_hash,{'id':ident},(),(row,),event_details={'purpose_id':ident,'already_withdrawn':True})
            return self.get(actor,ident)
        data=self.head()
        self.access._record(actor,'purpose-withdraw',idem,body_hash,{'id':ident},
            (Write(key,row.revision,{**row.data,'withdrawn':True,'withdrawn_at_ms':self.access.now()}),self.advance(data)),
            (row,data),event_details={'purpose_id':ident})
        return self.get(actor,ident)

    def permitted(self,ident,*,source_permission_reference=None,expires_at_ms=None):
        key=purpose_key(ident);row=self.repository.snapshot((key,))[key]
        try:
            if (row is None or row.data['withdrawn'] is not False or row.data['allowed_uses']!=['operation']
                    or row.data['authority_basis']!='owner_attestation' or row.data['rights_independently_verified'] is not False
                    or row.data['optional_improvement'] is not False or row.data['optional_publicity'] is not False
                    or self.access.config.notice_version!=row.data['notice_version']
                    or digest(self.access.config.notice_text)!=row.data['notice_sha256']
                    or self.access.now()>=integer(row.data['expires_at_ms'])
                    or (source_permission_reference is not None and source_permission_reference!=row.data['source_permission_reference'])
                    or (expires_at_ms is not None and not self.access.now()<expires_at_ms<=integer(row.data['expires_at_ms']))):
                raise ValueError()
        except (TypeError,KeyError,ValueError,AttributeError) as exc:raise StoreUnavailable('permitted operational purpose required') from exc
        original_capture_enabled(row,self.access)
        return row
