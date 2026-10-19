"""Immutable installed policy drafts. No evaluation, promotion or live mutation."""
from dataclasses import dataclass, asdict
import json
from typing import Literal
from uuid import uuid4
from pydantic import Field, model_validator
from proofpack.auth.policy import Denied, Role
from proofpack.auth.service import RUNTIME, ResourceUnavailable
from proofpack.calibrations.dependencies import canonical, digest
from proofpack.evidence.repository import Key, Write, StoreConflict, StoreUnavailable
from proofpack.planner.policy import ActionKind, DEFAULT_PRIORITY, REASON_ACTIONS
from proofpack.recipes.models import Contract
from proofpack.runtime.control import integer, uuid


class PolicyLimited(RuntimeError): pass


@dataclass(frozen=True)
class PolicyCatalogConfig:
    writes_per_minute: int
    reads_per_minute: int
    max_revisions: int

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= hi for v, hi in (
                (self.writes_per_minute,100),(self.reads_per_minute,120),(self.max_revisions,1000))):
            raise ValueError('explicit bounded policy catalog configuration required')


class PolicyDraft(Contract):
    name: str = Field(min_length=1,max_length=80)
    algorithm: Literal['reason_priority_v1']
    priority: tuple[ActionKind,...] = Field(min_length=3,max_length=3)

    @model_validator(mode='after')
    def valid(self):
        if not self.name.strip() or any(ord(c)<32 or ord(c)==127 for c in self.name):
            raise ValueError('bounded plain policy name required')
        if set(self.priority)!=set(DEFAULT_PRIORITY):raise ValueError('exact installed action permutation required')
        return self


INSTALLED = {'algorithm':'reason_priority_v1','eligible_reasons':{k:v.value for k,v in REASON_ACTIONS.items()},
    'default_priority':[x.value for x in DEFAULT_PRIORITY],'fallback':'REVIEW','schema_version':1}


def head_key(ident):return Key('state','policy-candidate#'+uuid(ident))
def revision_key(ident,revision):return Key('state','policy-revision#'+uuid(ident)+'#'+str(integer(revision)))


class PolicyCandidates:
    def __init__(self,access,runtime,config):
        if runtime.access is not access or not isinstance(config,PolicyCatalogConfig):
            raise ValueError('shared policy authority and explicit bounds required')
        self.access=access;self.runtime=runtime;self.repository=access.repository;self.config=config
        self.installed_sha256=digest(INSTALLED)
        self.configuration=digest({'bounds':asdict(config),'installed_sha256':self.installed_sha256})

    def _reader(self,actor):
        actor=self.access._fresh(actor)
        return self.access._fresh(actor,Role.REVIEWER if Role.REVIEWER in actor.principal.roles else Role.OWNER)

    def _runtime(self):
        row=self.repository.snapshot((RUNTIME,))[RUNTIME]
        if not self.runtime.matches(row):raise StoreUnavailable('current policy runtime required')
        return row

    def _quota(self,actor,kind):
        key=Key('state','policy-'+kind+'-quota#'+actor.scope);row=self.repository.snapshot((key,))[key]
        minute=self.access.now()//60000
        if row is not None and integer(row.data['minute'])>minute:raise StoreUnavailable('policy allowance clock moved backwards')
        count=0 if row is None or integer(row.data['minute'])!=minute else integer(row.data['count'])
        limit=self.config.writes_per_minute if kind=='write' else self.config.reads_per_minute
        if count>=limit:raise PolicyLimited('policy catalog allowance exhausted')
        return Write(key,None if row is None else row.revision,{'minute':minute,'count':count+1})

    def _binding(self):
        return {'configuration':self.configuration,'installed_sha256':self.installed_sha256,
            'artifact_sha256':self.runtime.artifact_sha256,'controls_sha256':self.runtime.controls_sha256,'environment':self.runtime.environment}

    def _load(self,ident,number=None):
        key=head_key(ident);head=self.repository.snapshot((key,))[key]
        if head is None:raise ResourceUnavailable('policy candidate unavailable')
        try:
            latest=integer(head.data['latest_revision']);number=latest if number is None else integer(number)
            if (head.data['id']!=ident or head.data['status']!='draft' or not 1<=number<=latest<=1000):raise ValueError()
            keys=(revision_key(ident,number),) if number==1 else (revision_key(ident,number),revision_key(ident,number-1))
            rows=self.repository.snapshot(keys);record=rows[keys[0]]
            def intact(row,n):
                if (row is None or row.revision!=1 or row.data['id']!=ident or integer(row.data['revision'])!=n
                        or digest({k:v for k,v in row.data.items() if k!='sha256'})!=row.data['sha256']):raise ValueError()
                spec=PolicyDraft.model_validate_json(canonical(row.data['spec']))
                if digest({'algorithm':spec.algorithm,'priority':[x.value for x in spec.priority]})!=row.data['behavior_sha256']:raise ValueError()
                if row.data['binding']!=head.data['binding']:raise ValueError()
            intact(record,number)
            if number==latest and record.data['sha256']!=head.data['latest_sha256']:raise ValueError()
            if number==1:
                if record.data['previous_sha256'] is not None:raise ValueError()
            else:
                intact(rows[keys[1]],number-1)
                if record.data['previous_sha256']!=rows[keys[1]].data['sha256']:raise ValueError()
            return head,record,(head,*rows.values())
        except (KeyError,TypeError,ValueError,AttributeError) as exc:raise StoreUnavailable('intact policy revision and lineage required') from exc

    def _public(self,head,record,*,reviewer):
        current=head.data['binding']==self._binding()
        return {'id':head.data['id'],'state_version':head.revision,'latest_revision':integer(head.data['latest_revision']),
            'revision':integer(record.data['revision']),'revision_sha256':record.data['sha256'],'previous_sha256':record.data['previous_sha256'],
            'behavior_sha256':record.data['behavior_sha256'],'spec':json.loads(canonical(record.data['spec'])),
            'binding':json.loads(canonical(record.data['binding'])),'created_at_ms':integer(record.data['created_at_ms']),
            'status':'draft','evaluation_status':'NOT_VERIFIED','promotion_available':False,'live_effect':'none_from_draft_write',
            'binding_current':current,'can_revise':bool(reviewer and current and integer(record.data['revision'])==integer(head.data['latest_revision'])
                and integer(head.data['latest_revision'])<self.config.max_revisions)}

    def _finish_read(self,actor,rows,*,kind,ident):
        quota=self._quota(actor,'read');fresh=self._reader(actor)
        if fresh.rows!=actor.rows:raise StoreConflict('policy reader changed')
        expected={row.key:row for row in (*rows,*actor.rows)}
        event=Write(Key('events','policy-read#'+str(uuid4())),None,{'kind':kind,'policy_id':ident,
            'user_id':actor.member.data['id'],'at_ms':self.access.now()})
        def final():
            self._reader(actor)
            if self.access.now()>=integer(actor.session.data['expires_at_ms']):raise Denied('current policy reader required')
        self.access._commit_linked(kind,(quota,event),tuple(expected.values()),before_commit=final)
        fresh=self._reader(actor)
        if any(expected.get(r.key)!=r for r in fresh.rows):raise StoreConflict('policy reader changed')
        current=self.repository.snapshot(tuple(expected))
        if any(current[k]!=r for k,r in expected.items()):raise StoreConflict('policy metadata changed')
        if Role.REVIEWER not in fresh.principal.roles:self.access._recent_mfa(fresh)
        if self.access.now()>=integer(fresh.session.data['expires_at_ms']):raise Denied('policy delivery session expired')

    def get(self,actor,ident,*,revision=None):
        actor=self._reader(actor);runtime=self._runtime();head,record,rows=self._load(uuid(ident),revision)
        value=self._public(head,record,reviewer=Role.REVIEWER in actor.principal.roles)
        self._finish_read(actor,(*rows,runtime),kind='policy_revision_read',ident=ident)
        return value

    def list(self,actor,*,limit=20,cursor=None):
        actor=self._reader(actor);runtime=self._runtime()
        if type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded policy catalog page required')
        rows,last=self.repository.query(prefix='policy-catalog#',limit=limit,start_resource=None if cursor is None else 'policy-catalog#'+uuid(cursor))
        checks=[runtime];values=[]
        for catalog in rows:
            head,record,binding=self._load(uuid(catalog.data['id']));checks.extend((catalog,*binding))
            values.append(self._public(head,record,reviewer=Role.REVIEWER in actor.principal.roles))
        self._finish_read(actor,checks,kind='policy_catalog_read',ident=None)
        return {'policies':values,'next_cursor':None if last is None else last.split('#',1)[1]}

    def write(self,actor,*,request,idempotency_key,ident=None,expected_version=None):
        actor=self.access._fresh(actor,Role.REVIEWER)
        if not isinstance(request,PolicyDraft):raise ValueError('typed installed policy draft required')
        if ident is not None and (type(expected_version) is not int or not 1<=expected_version<=9007199254740991):raise ValueError('exact policy head version required')
        if ident is None and expected_version is not None:raise ValueError('new policy has no prior version')
        body={'spec':request.model_dump(mode='json'),'id':ident,'expected_version':expected_version}
        operation='policy-create' if ident is None else 'policy-revise:'+uuid(ident)
        idem,body_hash,prior=self.access._idempotency(actor,operation,idempotency_key,body)
        if prior is not None:return self.get(actor,prior.data['result']['id'],revision=integer(prior.data['result']['revision']))
        runtime=self._runtime();checks=[runtime];previous=None;number=1
        if ident is not None:
            head,record,rows=self._load(ident);checks.extend(rows)
            if head.revision!=expected_version or head.data['binding']!=self._binding():raise StoreConflict('current policy head and build binding required')
            number=integer(head.data['latest_revision'])+1;previous=record.data['sha256']
            if number>self.config.max_revisions:raise PolicyLimited('policy revision capacity exhausted')
        else:ident=str(uuid4());head=None
        spec=request.model_dump(mode='json');record={'id':ident,'revision':number,'spec':spec,'previous_sha256':previous,
            'binding':self._binding(),'behavior_sha256':digest({'algorithm':request.algorithm,'priority':[x.value for x in request.priority]}),
            'created_by':actor.member.data['id'],'created_at_ms':self.access.now()}
        record['sha256']=digest(record)
        writes=[Write(head_key(ident),None if head is None else head.revision,{'id':ident,'latest_revision':number,
            'latest_sha256':record['sha256'],'status':'draft','binding':self._binding()}),Write(revision_key(ident,number),None,record),self._quota(actor,'write')]
        if head is None:writes.append(Write(Key('state','policy-catalog#'+ident),None,{'id':ident}))
        def deadline():
            if self.access.now()>=integer(actor.session.data['expires_at_ms']):raise Denied('current policy writer required')
        committed=self.access._record(actor,operation,idem,body_hash,{'id':ident,'revision':number},tuple(writes),tuple(checks),required_role=Role.REVIEWER,before_commit=deadline,
            event_details={'policy_id':ident,'revision':number,'revision_sha256':record['sha256'],'active_change':False})
        return self.get(actor,committed['id'],revision=integer(committed['revision']))
