"""Durable access lifecycle. IdentityProof is accepted only from a trusted OIDC adapter.

No password, token decoding, first-visitor bootstrap or provider side effect lives
here. HTTP request bodies must never be converted directly into IdentityProof.
"""
from dataclasses import dataclass,field
from decimal import Decimal
import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from uuid import UUID,uuid4

from proofpack.auth.policy import Denied,Principal,Role,require
from proofpack.evidence.repository import Key,Row,StoreConflict,StoreUnavailable,Write,DynamoRepository
from proofpack.evidence.resource_bindings import prepare_linked as prepare_resource_bindings
from proofpack.auth.session_schema import session_generation

HEAD=Key('state','access-head')
RUNTIME=Key('state','runtime')


class ResourceUnavailable(LookupError):
    pass


def digest(value: str) -> str:return hashlib.sha256(value.encode()).hexdigest()


def canonical_email(value: str) -> str:
    if not isinstance(value,str) or len(value)>254 or value!=value.strip() or value.count('@')!=1:
        raise ValueError('valid target email required')
    local,domain=value.split('@')
    if not local or not domain or not re.fullmatch(r'[\x21-\x7e]+',value) or any(c in value for c in '<>"\\'):
        raise ValueError('valid target email required')
    # Never broaden a target by folding the local part or stripping plus tags.
    return local+'@'+domain.lower()


def identity_key(issuer: str,subject: str) -> Key:return Key('state','identity#'+digest(issuer+'\0'+subject))


def user_key(ident: str) -> Key:
    try:UUID(ident)
    except (ValueError,TypeError,AttributeError) as exc:raise ValueError('opaque UUID required') from exc
    return Key('state','user#'+ident)


def invitation_key(ident: str) -> Key:
    user_key(ident)
    return Key('state','invitation#'+ident)


@dataclass(frozen=True)
class IdentityProof:
    issuer: str
    subject: str
    email: str
    email_verified: bool
    mfa_verified: bool
    auth_time_ms: int
    expires_at_ms: int
    display_name: str


@dataclass(frozen=True)
class BootstrapApproval:
    issuer: str
    subject: str
    receipt_sha256: str


@dataclass(frozen=True)
class AuthConfig:
    deployment: str
    issuer: str
    capability_key: bytes = field(repr=False)
    initial_owner_subject: str | None = None
    bootstrap_receipt_sha256: str | None = None
    notice_version: str | None = None
    notice_text: str | None = field(default=None,repr=False)
    session_ttl_seconds: int = 3600
    invitation_ttl_seconds: int = 86400
    transfer_ttl_seconds: int = 600
    mfa_grant_max_age_seconds: int = 600
    max_accounts: int = 5

    def __post_init__(self):
        if ((self.notice_version is None)!=(self.notice_text is None)
                or (self.notice_version is not None and (not 1<=len(self.notice_version)<=128 or not 1<=len(self.notice_text)<=16384))):
            raise ValueError('versioned operational notice required')
        if (not self.deployment or not self.issuer.startswith('https://')
                or not isinstance(self.capability_key,bytes) or len(self.capability_key)<32
                or type(self.max_accounts) is not int or self.max_accounts!=5):
            raise ValueError('explicit identity/deployment/key configuration required')
        for name,maximum in (('session_ttl_seconds',3600),('invitation_ttl_seconds',604800),
                             ('transfer_ttl_seconds',600),('mfa_grant_max_age_seconds',600)):
            value=getattr(self,name)
            if type(value) is not int or not 1<=value<=maximum:raise ValueError('bounded authentication lifetime required')


@dataclass(frozen=True)
class Credentials:
    cookie: str = field(repr=False)
    csrf: str = field(repr=False)
    session_id: str
    expires_at_ms: int
    restricted: bool


@dataclass(frozen=True)
class Actor:
    cookie: Row
    session: Row
    member: Row | None
    head: Row
    principal: Principal | None

    @property
    def scope(self):return digest(self.session.data['issuer']+'\0'+self.session.data['subject'])

    @property
    def rows(self):return tuple(row for row in (self.cookie,self.session,self.member,self.head) if row is not None)


class AccessService:
    def __init__(self,repository,config: AuthConfig,*,clock_ms=None):
        if repository.deployment!=config.deployment:raise ValueError('repository deployment mismatch')
        self.repository=repository
        self.config=config
        self.clock_ms=clock_ms or (lambda:int(time.time()*1000))

    def now(self):
        value=self.clock_ms()
        if type(value) is not int or value<0:raise StoreUnavailable('trusted server time unavailable')
        return value

    def _token(self,purpose: str,ident: str) -> str:
        value=hmac.new(self.config.capability_key,(self.config.deployment+'|'+purpose+'|'+ident).encode(),hashlib.sha256).digest()
        return base64.urlsafe_b64encode(value).decode().rstrip('=')

    def _identity(self,proof: IdentityProof,*,mfa=False):
        now=self.now()
        if (not isinstance(proof,IdentityProof) or proof.issuer!=self.config.issuer
                or type(proof.email_verified) is not bool or not proof.email_verified
                or type(proof.mfa_verified) is not bool or not isinstance(proof.subject,str) or not 1<=len(proof.subject)<=256
                or type(proof.auth_time_ms) is not int or type(proof.expires_at_ms) is not int
                or proof.auth_time_ms<0 or proof.auth_time_ms>now or now>=proof.expires_at_ms
                or not isinstance(proof.display_name,str) or not 1<=len(proof.display_name)<=100
                or any(ord(c)<32 for c in proof.display_name)):
            raise Denied('verified provider identity required')
        if mfa and (not proof.mfa_verified or now-proof.auth_time_ms>self.config.mfa_grant_max_age_seconds*1000):
            raise Denied('recent verified MFA required')
        return digest(canonical_email(proof.email))

    def _head(self,row: Row | None):
        if row is None:raise StoreUnavailable('access bootstrap required')
        try:
            if (type(row)is not Row or type(row.key)is not Key or row.key!=HEAD
                    or type(row.revision)is not int or not 1<=row.revision<2**63):raise ValueError()
            data=row.data
            fields={'schema_version','enabled_user_ids','owner_ids','pending_invitation_ids',
                    'bootstrap_scope','bootstrap_receipt','bootstrap_user_id'}
            if type(data)is not dict or len(data)!=len(fields) or set(data)!=fields:raise ValueError()
            version=data['schema_version']
            valid_version=((type(version)is int and version==1)
                           or (type(version)is Decimal and version.is_finite() and version==1))
            members=data['enabled_user_ids'];owners=data['owner_ids'];pending=data['pending_invitation_ids']
            if (not valid_version or any(type(ids)is not list or len(ids)>self.config.max_accounts for ids in (members,owners,pending))
                    or len(members)+len(pending)>self.config.max_accounts):raise ValueError()
            for ident in (*members,*owners,*pending,data['bootstrap_user_id']):
                if type(ident)is not str or len(ident)!=36 or str(UUID(ident))!=ident:raise ValueError()
            if (len(set(members))!=len(members) or len(set(owners))!=len(owners) or len(set(pending))!=len(pending)
                    or not owners or not set(owners)<=set(members)):
                raise ValueError()
            if any(type(data[key])is not str or re.fullmatch('[a-f0-9]{64}',data[key])is None
                   for key in ('bootstrap_scope','bootstrap_receipt')):raise ValueError()
        except (KeyError,ValueError,TypeError) as exc:raise StoreUnavailable('access head inconsistent') from exc
        return {**data,'enabled_user_ids':list(members),'owner_ids':list(owners),'pending_invitation_ids':list(pending)}

    def bootstrap(self,approval: BootstrapApproval,proof: IdentityProof,*,before_commit=None) -> str:
        if before_commit is not None and not callable(before_commit):
            raise ValueError('bootstrap precommit validation must be callable')
        configuration,repository=self.config,self.repository
        email_hash=self._identity(proof,mfa=True)
        if (proof.issuer!=approval.issuer or proof.subject!=approval.subject
                or self.config.initial_owner_subject!=approval.subject
                or self.config.bootstrap_receipt_sha256!=approval.receipt_sha256
                or not re.fullmatch(r'[a-f0-9]{64}',approval.receipt_sha256)):
            raise Denied('target-bound bootstrap approval required')
        index=identity_key(proof.issuer,proof.subject)
        rows=self.repository.snapshot((HEAD,RUNTIME,index))
        if rows[HEAD] is not None:
            head=self._head(rows[HEAD])
            if head['bootstrap_scope']!=digest(proof.issuer+'\0'+proof.subject) or head['bootstrap_receipt']!=approval.receipt_sha256:
                raise StoreConflict('bootstrap already established')
            return head['bootstrap_user_id']  # Historical result, never a grant/re-enable.
        if rows[index] is not None:raise StoreConflict('identity already provisioned')
        runtime=rows[RUNTIME]
        if runtime is not None and runtime.data.get('inspection_enabled') is not False:
            raise Denied('bootstrap requires inspections disabled')
        uid=str(uuid4());now=self.now()
        member=self._member(uid,proof,email_hash,roles=[Role.OWNER.value])
        head={'schema_version':1,'enabled_user_ids':[uid],'owner_ids':[uid],'pending_invitation_ids':[],
              'bootstrap_scope':digest(proof.issuer+'\0'+proof.subject),'bootstrap_receipt':approval.receipt_sha256,
              'bootstrap_user_id':uid}
        writes=[Write(HEAD,None,head),Write(user_key(uid),None,member),Write(index,None,{'user_id':uid})]
        checks=[]
        if runtime is None:writes.append(Write(RUNTIME,None,{'runtime_epoch':0,'control_version':1,'inspection_enabled':False}))
        else:checks.append(runtime)
        writes.append(Write(Key('events','access#'+str(uuid4())),None,{'kind':'bootstrap','actor_id':uid,'at_ms':now,'receipt':approval.receipt_sha256}))
        writes,checks=self._prepare_linked('bootstrap',writes,checks)
        self._identity(proof,mfa=True)
        # The browser setup binds additional original-flow and provider inputs.
        # Revalidate them after store reads, immediately before the atomic effect.
        if before_commit is not None:before_commit()
        if self.config is not configuration or self.repository is not repository:
            raise Denied('bootstrap configuration changed; start again')
        self.repository.transact(writes,checks)
        return uid

    def _member(self,uid,proof,email_hash,*,roles):
        return {'id':uid,'issuer':proof.issuer,'subject':proof.subject,'email_hash':email_hash,
            'display_name':proof.display_name,'roles':roles,'enabled':True,'invited':True,
            'access_version':1,'session_epoch':1,'last_mfa_ms':proof.auth_time_ms if proof.mfa_verified else None,
            'created_at_ms':self.now()}

    def _restore_generation(self):
        if not isinstance(self.repository, DynamoRepository):
            return None  # Existing isolated protocol adapters have no restore authority.
        fence = self.repository._check_data_fence()
        return None if fence is None else fence.generation_sha256()

    def _session_writes(self,proof,*,member=None,invitation=None):
        now=self.now();sid=str(uuid4());raw=secrets.token_urlsafe(32);csrf=self._token('csrf',sid)
        expiry=min(now+self.config.session_ttl_seconds*1000,proof.expires_at_ms)
        if invitation is not None:expiry=min(expiry,int(invitation.data['expires_at_ms']))
        data={'id':sid,'issuer':proof.issuer,'subject':proof.subject,'email_hash':digest(canonical_email(proof.email)),
            'display_name':proof.display_name,
            'created_at_ms':now,
            'active':True,'expires_at_ms':expiry,'mfa_verified':proof.mfa_verified,'auth_time_ms':proof.auth_time_ms,
            'csrf_hash':digest(csrf),'user_id':None if member is None else member.data['id'],
            'access_version':None if member is None else int(member.data['access_version']),
            'session_epoch':None if member is None else int(member.data['session_epoch']),
            'restricted_invitation_id':None if invitation is None else invitation.data['id']}
        generation = self._restore_generation()
        if generation is not None:
            data.update(session_schema_version=2, restore_generation_sha256=generation)
        cookie=Write(Key('state','cookie#'+digest(raw)),None,{'session_id':sid,'user_id':data['user_id']})
        session=Write(Key('state','session#'+sid),None,data)
        return (cookie,session),Credentials(raw,csrf,sid,expiry,invitation is not None)

    def login(self,proof: IdentityProof,*,invitation_id: str | None=None) -> Credentials:
        self._identity(proof)
        index=identity_key(proof.issuer,proof.subject)
        first=self.repository.snapshot((index,))[index]
        if first is None:
            if invitation_id is None:raise Denied('invited membership required')
            key=invitation_key(invitation_id)
            rows=self.repository.snapshot((HEAD,key))
            self._head(rows[HEAD]);invitation=rows[key]
            self._check_invitee(invitation,proof)
            writes,credentials=self._session_writes(proof,invitation=invitation)
            self.repository.transact(writes,(rows[HEAD],invitation))
            return credentials
        uid=first.data['user_id'];key=user_key(uid)
        rows=self.repository.snapshot((HEAD,index,key))
        head=self._head(rows[HEAD]);member=rows[key]
        if (rows[index] is None or rows[index].data.get('user_id')!=uid or member is None
                or member.data.get('enabled') is not True or uid not in head['enabled_user_ids']):
            raise Denied('enabled invited membership required')
        if member.data['issuer']!=proof.issuer or member.data['subject']!=proof.subject:
            raise Denied('identity binding mismatch')
        writes,credentials=self._session_writes(proof,member=member)
        extra=[]
        if proof.mfa_verified:
            extra.append(Write(key,member.revision,{**member.data,'last_mfa_ms':proof.auth_time_ms}))
        self._commit((*writes,*extra),tuple(row for row in rows.values() if row is not None))
        return credentials

    def _check_invitee(self,invitation,proof):
        if (invitation is None or invitation.data.get('status')!='pending'
                or self.now()>=int(invitation.data['expires_at_ms']) or invitation.data['issuer']!=proof.issuer
                or invitation.data['target_subject']!=proof.subject
                or invitation.data['target_email_hash']!=digest(canonical_email(proof.email))):
            raise Denied('valid identity-bound invitation required')

    def resolve(self,raw_cookie: str,*,allow_invitee=False) -> Actor:
        if not isinstance(raw_cookie,str) or not re.fullmatch(r'[A-Za-z0-9_-]{40,128}',raw_cookie):
            raise Denied('session required')
        return self._resolve_key(Key('state','cookie#'+digest(raw_cookie)),allow_invitee=allow_invitee)

    def _resolve_key(self,cookie_key,*,allow_invitee=False):
        first=self.repository.snapshot((cookie_key,))[cookie_key]
        if first is None:raise Denied('session required')
        sid=first.data['session_id'];user_key(sid)
        session_key=Key('state','session#'+sid)
        uid=first.data['user_id']
        keys=(cookie_key,session_key,HEAD) if uid is None else (cookie_key,session_key,HEAD,user_key(uid))
        rows=self.repository.snapshot(keys)
        cookie=rows[cookie_key];session=rows[session_key];head_row=rows[HEAD]
        head=self._head(head_row)
        if (cookie is None or cookie.data!=first.data or session is None or session.data.get('active') is not True
                or self.now()>=int(session.data['expires_at_ms']) or session.data.get('user_id')!=uid
                or self.now()<int(session.data['created_at_ms'])
                or session.data['issuer']!=self.config.issuer):raise Denied('current session required')
        generation = self._restore_generation()
        actual = None
        if 'session_schema_version' in session.data or 'restore_generation_sha256' in session.data:
            try: actual = session_generation(session.data)
            except ValueError as exc: raise Denied('current restore-bound session required') from exc
        if actual != generation:
            raise Denied('current protected release session required')
        member=None;principal=None
        if uid is None:
            if not allow_invitee or not session.data.get('restricted_invitation_id'):raise Denied('membership activation required')
        else:
            member=rows[user_key(uid)]
            if (member is None or member.data.get('enabled') is not True or member.data.get('invited') is not True
                    or uid not in head['enabled_user_ids'] or member.data['subject']!=session.data['subject']
                    or member.data['issuer']!=session.data['issuer']
                    or int(member.data['access_version'])!=int(session.data['access_version'])
                    or int(member.data['session_epoch'])!=int(session.data['session_epoch'])):
                raise Denied('current membership grant required')
            principal=Principal(member.data['subject'],self.config.deployment,
                frozenset(Role(role) for role in member.data['roles']),True,True,int(member.data['access_version']),
                sid,int(session.data['expires_at_ms'])/1000,session.data['mfa_verified'] is True)
        return Actor(cookie,session,member,head_row,principal)

    def _fresh(self,actor: Actor,role=None,*,invitee=False):
        fresh=self._resolve_key(actor.cookie.key,allow_invitee=invitee)
        if fresh.session.data['id']!=actor.session.data['id']:raise Denied('session identity changed')
        if not invitee or fresh.principal is not None:
            require(fresh.principal,role,deployment=self.config.deployment,now=self.now()/1000)
            if role==Role.OWNER:self._recent_mfa(fresh)
        return fresh

    def _commit(self,writes,checks=()):
        keys={write.key for write in writes}
        distinct={row.key:row for row in checks if row is not None and row.key not in keys}
        self.repository.transact(tuple(writes),tuple(distinct.values()))

    def _prepare_linked(self,operation,writes,checks=()):
        return prepare_resource_bindings(self.repository.deployment,operation,writes,checks)

    def _commit_linked(self,operation,writes,checks=(),*,before_commit=None):
        if before_commit is not None and not callable(before_commit):raise ValueError('trusted final commit checkpoint required')
        writes,checks=self._prepare_linked(operation,writes,checks)
        if before_commit is not None:before_commit()
        self._commit(writes,checks)

    def _idempotency(self,actor,operation,key,body):
        if not isinstance(key,str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}',key):raise ValueError('idempotency key required')
        ident=Key('state','idempotency#'+digest(actor.scope+'|'+operation+'|'+key))
        body_hash=digest(json.dumps(body,sort_keys=True,separators=(',',':'),allow_nan=False))
        row=self.repository.snapshot((ident,))[ident]
        if row is not None and row.data['body_hash']!=body_hash:raise StoreConflict('idempotency key reused with different input')
        return ident,body_hash,row

    def _record(self,actor,operation,idem,body_hash,result,writes,checks=(),*,event_details=None,required_role=Role.OWNER,before_commit=None):
        self._fresh(actor,None if operation in {'accept-invite','decline-invite','accept-transfer'} else required_role,
                    invitee=operation in {'accept-invite','decline-invite'})
        event_data={'kind':operation,'actor_scope':actor.scope,'at_ms':self.now(),'session_id':actor.session.data['id']}
        if event_details is not None:event_data['details']=event_details
        event=Write(Key('events','access#'+str(uuid4())),None,event_data)
        replay=Write(idem,None,{'body_hash':body_hash,'result':result,'at_ms':self.now()})
        writes,checks=self._prepare_linked(operation,(*writes,replay,event),(*actor.rows,*checks))
        committed_result=next(value.data['result'] for value in writes if value.key==idem)
        self._fresh(actor,None if operation in {'accept-invite','decline-invite','accept-transfer'} else required_role,
                    invitee=operation in {'accept-invite','decline-invite'})
        if before_commit is not None:before_commit()
        try:self._commit(writes,checks)
        except StoreConflict:
            existing=self.repository.snapshot((idem,))[idem]
            if existing is None or existing.data['body_hash']!=body_hash:raise
            self._fresh(actor,None if operation in {'accept-invite','decline-invite','accept-transfer'} else required_role,
                        invitee=operation in {'accept-invite','decline-invite'})
            return existing.data['result']
        return committed_result

    @staticmethod
    def public_user(member: Row):
        return {'id':member.data['id'],'display_name':member.data['display_name'],
            'roles':list(member.data['roles']),'enabled':member.data['enabled'],
            'access_version':int(member.data['access_version'])}

    def me(self,actor):
        actor=self._fresh(actor)
        return {**self.public_user(actor.member),'session_id':actor.session.data['id'],
            'csrf_token':self._token('csrf',actor.session.data['id'])}

    def session_view(self,actor):
        actor=self._fresh(actor,invitee=True)
        if actor.member is not None:return {'status':'member',**self.me(actor)}
        return {'status':'invitation_pending','invitation_id':actor.session.data['restricted_invitation_id'],
            'session_id':actor.session.data['id'],'csrf_token':self._token('csrf',actor.session.data['id'])}

    def read_transfer(self,actor,transfer_id):
        actor=self._fresh(actor);key=Key('state','owner-transfer#'+str(UUID(transfer_id)))
        first=self.repository.snapshot((key,))[key]
        if first is None:raise ResourceUnavailable('transfer unavailable')
        ident=actor.member.data['id']
        if ident==first.data['source_id']:actor=self._fresh(actor,Role.OWNER)
        elif ident!=first.data['target_id']:raise ResourceUnavailable('transfer unavailable')
        sourcekey=user_key(first.data['source_id']);targetkey=user_key(first.data['target_id'])
        keys=tuple(dict.fromkeys((key,HEAD,sourcekey,targetkey,*(item.key for item in actor.rows))))
        rows=self.repository.snapshot(keys)
        if rows[key]!=first or any(rows[item.key]!=item for item in actor.rows):raise StoreConflict('transfer authority changed')
        source,target=rows[sourcekey],rows[targetkey]
        unchanged=(source is not None and target is not None and rows[HEAD] is not None
            and source.data['enabled'] is True and target.data['enabled'] is True
            and source.data['id'] in rows[HEAD].data['owner_ids']
            and int(source.data['access_version'])==int(first.data['source_version'])
            and int(target.data['access_version'])==int(first.data['target_version']))
        actor=self._fresh(actor,Role.OWNER if ident==first.data['source_id'] else None);recent=True
        try:self._recent_mfa(actor)
        except Denied:recent=False
        remaining=max(0,int(first.data['expires_at_ms'])-self.now())
        pending=first.data['status']=='pending' and remaining>0
        return {'id':transfer_id,'source_id':first.data['source_id'],'target_id':first.data['target_id'],
            'source_name':None if source is None else source.data['display_name'],'target_name':None if target is None else target.data['display_name'],
            'source_version':int(first.data['source_version']),'target_version':int(first.data['target_version']),
            'status':'expired' if first.data['status']=='pending' and not remaining else first.data['status'],
            'remaining_validity_ms':remaining,'eligible_for_accept':bool(pending and unchanged and ident==first.data['target_id'] and recent),
            'requires_recent_mfa':not recent}

    def _resource_page(self,actor,*,prefix,purpose,serialize,limit,cursor):
        actor=self._fresh(actor,Role.OWNER)
        start=None
        if cursor is not None:
            if (not isinstance(cursor,str) or len(cursor)>2048
                    or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}',cursor)):
                raise ValueError('invalid user cursor')
            encoded,signature=cursor.split('.')
            if not hmac.compare_digest(signature,self._token(purpose,encoded)):raise Denied('invalid cursor')
            try:content=json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
            except (ValueError,UnicodeError) as exc:raise ValueError('invalid user cursor') from exc
            if (not isinstance(content,dict) or content.get('scope')!=actor.scope
                    or content.get('prefix')!=prefix or self.now()>=int(content['expires_at_ms'])
                    or not content.get('last','').startswith(prefix)):raise Denied('expired or wrong-scope cursor')
            user_key(content['last'][len(prefix):]);start=content['last']
        rows,last=self.repository.query(prefix=prefix,limit=limit,start_resource=start)
        result=[serialize(row) for row in rows]
        self._fresh(actor,Role.OWNER)
        next_cursor=None
        if last:
            encoded=base64.urlsafe_b64encode(json.dumps({'scope':actor.scope,'prefix':prefix,'last':last,
                'expires_at_ms':self.now()+600000},separators=(',',':')).encode()).decode().rstrip('=')
            next_cursor=encoded+'.'+self._token(purpose,encoded)
        return result,next_cursor

    def list_users(self,actor,*,limit=100,cursor=None):
        result,next_cursor=self._resource_page(actor,prefix='user#',purpose='user-cursor',serialize=self.public_user,limit=limit,cursor=cursor)
        return {'users':result,'next_cursor':next_cursor}

    def public_invitation(self,row):
        status=row.data['status']
        if status=='revoked' and row.data.get('revocation_reason')=='declined_by_target':status='declined'
        if status=='pending' and self.now()>=int(row.data['expires_at_ms']):status='expired'
        return {'id':row.data['id'],'target_subject':row.data['target_subject'],'roles':list(row.data['roles']),
            'status':status,'expires_at_ms':int(row.data['expires_at_ms']),'state_version':row.revision,
            'delivery_status':row.data['delivery_status']}

    def operational_notice(self,actor):
        self._fresh(actor,invitee=True)
        if self.config.notice_version is None:raise StoreUnavailable('operational notice is not configured')
        return {'version':self.config.notice_version,'text':self.config.notice_text,
            'sha256':digest(self.config.notice_text),'optional_improvement_default':False,'optional_publicity_default':False}

    def list_invitations(self,actor,*,limit=100,cursor=None):
        result,next_cursor=self._resource_page(actor,prefix='invitation#',purpose='invitation-cursor',
            serialize=self.public_invitation,limit=limit,cursor=cursor)
        return {'invitations':result,'next_cursor':next_cursor}

    def read_invitation(self,actor,*,invitation_id):
        actor=self._fresh(actor,invitee=True)
        row=self.repository.snapshot((invitation_key(invitation_id),))[invitation_key(invitation_id)]
        if row is None:raise ResourceUnavailable('invitation unavailable')
        owner=actor.principal is not None and Role.OWNER in actor.principal.roles
        if owner:self._fresh(actor,Role.OWNER)
        elif (row.data['issuer']!=actor.session.data['issuer'] or row.data['target_subject']!=actor.session.data['subject']
                or row.data['target_email_hash']!=actor.session.data['email_hash']
                or (actor.member is None and actor.session.data['restricted_invitation_id']!=invitation_id)):
            raise ResourceUnavailable('invitation unavailable')
        self._fresh(actor,Role.OWNER if owner else None,invitee=not owner)
        return self.public_invitation(row)

    def create_invitation(self,actor,*,target_subject,target_email,roles,ttl_seconds,idempotency_key):
        actor=self._fresh(actor,Role.OWNER)
        email_hash=digest(canonical_email(target_email))
        role_values=sorted({Role(role).value for role in roles})
        if (not isinstance(target_subject,str) or not 1<=len(target_subject)<=256 or type(ttl_seconds) is not int
                or not 1<=ttl_seconds<=self.config.invitation_ttl_seconds):raise ValueError('bounded invitation required')
        body={'target_subject':target_subject,'target_email_hash':email_hash,'roles':role_values,'ttl_seconds':ttl_seconds}
        idem,body_hash,replay=self._idempotency(actor,'invite',idempotency_key,body)
        if replay:
            self._fresh(actor,Role.OWNER)
            result=replay.data['result']
            return {**result,'capability':self._token('invitation',result['id'])}
        initial=self._head(actor.head);pending=initial['pending_invitation_ids']
        keys=(HEAD,identity_key(self.config.issuer,target_subject),*(invitation_key(i) for i in pending))
        rows=self.repository.snapshot(keys)
        if rows[HEAD].revision!=actor.head.revision:raise StoreConflict('access capacity changed')
        target_index=rows[identity_key(self.config.issuer,target_subject)]
        if target_index:
            raise StoreConflict('existing identity requires access management, not another invitation')
        head=self._head(rows[HEAD]);writes=[];remaining=[]
        for ident in pending:
            row=rows[invitation_key(ident)]
            if row is None or row.data['status']!='pending':raise StoreUnavailable('invitation capacity inconsistent')
            if self.now()>=int(row.data['expires_at_ms']):writes.append(Write(row.key,row.revision,{**row.data,'status':'expired'}))
            else:
                remaining.append(ident)
                if row.data['target_subject']==target_subject:raise StoreConflict('target already has a pending invitation')
        if len(head['enabled_user_ids'])+len(remaining)>=self.config.max_accounts:raise StoreConflict('account capacity exhausted')
        ident=str(uuid4());created_at=self.now();expiry=created_at+ttl_seconds*1000;capability=self._token('invitation',ident)
        data={'id':ident,'issuer':self.config.issuer,'target_subject':target_subject,'target_email_hash':email_hash,
            'roles':role_values,'expires_at_ms':expiry,'status':'pending','capability_hash':digest(capability),
            'created_by':actor.member.data['id'],'delivery_status':'NOT_SENT',
            'history_schema_version':1,'created_at_ms':created_at,'ttl_seconds':ttl_seconds}
        head['pending_invitation_ids']=[*remaining,ident]
        writes.extend((Write(HEAD,actor.head.revision,head),Write(invitation_key(ident),None,data)))
        result={'id':ident,'expires_at_ms':expiry,'delivery_status':'NOT_SENT'}
        committed=self._record(actor,'invite',idem,body_hash,result,writes,tuple(row for row in rows.values() if row is not None))
        return {**committed,'capability':self._token('invitation',committed['id'])}

    def accept_invitation(self,actor,*,invitation_id,capability,idempotency_key,notice_version,notice_sha256):
        actor=self._fresh(actor,invitee=True)
        idem,body_hash,replay=self._idempotency(actor,'accept-invite',idempotency_key,
            {'id':invitation_id,'capability_hash':digest(capability),'notice_version':notice_version,'notice_sha256':notice_sha256})
        if replay:
            self._fresh(actor,invitee=True)
            return replay.data['result']
        if actor.session.data['restricted_invitation_id']!=invitation_id:raise Denied('bound invitee session required')
        if (self.config.notice_version is None or notice_version!=self.config.notice_version
                or not hmac.compare_digest(digest(self.config.notice_text),notice_sha256)):
            raise Denied('acknowledgment of the current operational notice required')
        key=invitation_key(invitation_id);index=identity_key(self.config.issuer,actor.session.data['subject'])
        rows=self.repository.snapshot((HEAD,key,index))
        invitation=rows[key];head=self._head(rows[HEAD])
        if rows[HEAD].revision!=actor.head.revision:raise StoreConflict('access capacity changed')
        if (invitation is None or invitation.data['status']!='pending' or self.now()>=int(invitation.data['expires_at_ms'])
                or invitation.data['target_subject']!=actor.session.data['subject']
                or invitation.data['target_email_hash']!=actor.session.data['email_hash']
                or not hmac.compare_digest(invitation.data['capability_hash'],digest(capability))
                or invitation_id not in head['pending_invitation_ids']):raise Denied('valid unused invitation required')
        if Role.OWNER.value in invitation.data['roles']:self._recent_mfa(actor)
        old_index=rows[index]
        if old_index is not None:raise StoreConflict('existing identity requires owner access recovery')
        uid=str(uuid4())
        member={'id':uid,'issuer':self.config.issuer,'subject':actor.session.data['subject'],
            'email_hash':actor.session.data['email_hash'],'display_name':actor.session.data['display_name'],'roles':invitation.data['roles'],
            'enabled':True,'invited':True,'access_version':1,'session_epoch':1,
            'last_mfa_ms':actor.session.data['auth_time_ms'] if actor.session.data['mfa_verified'] else None,'created_at_ms':self.now()}
        member.update({'notice_version':notice_version,'notice_sha256':notice_sha256,'notice_acknowledged_at_ms':self.now(),
                       'improvement_reuse':False,'publicity_reuse':False})
        head['pending_invitation_ids'].remove(invitation_id);head['enabled_user_ids'].append(uid)
        if Role.OWNER.value in member['roles']:head['owner_ids'].append(uid)
        accepted={**invitation.data,'status':'accepted','accepted_user_id':uid}
        history_version=invitation.data.get('history_schema_version')
        versioned=((type(history_version)is int and history_version==1)
                   or (type(history_version)is Decimal and history_version.is_finite() and history_version==1))
        if versioned:accepted.update(notice_version=notice_version,notice_sha256=notice_sha256)
        writes=(Write(HEAD,actor.head.revision,head),Write(key,invitation.revision,accepted),
            Write(index,None,{'user_id':uid}),Write(user_key(uid),None,member),
            Write(actor.session.key,actor.session.revision,{**actor.session.data,'active':False}))
        # No privilege upgrade on the restricted cookie: sign in through OIDC again.
        return self._record(actor,'accept-invite',idem,body_hash,{'user_id':uid,'sign_in_required':True},writes,
                            tuple(row for row in rows.values() if row is not None))

    def revoke_invitation(self,actor,*,invitation_id,expected_revision,idempotency_key):
        actor=self._fresh(actor,Role.OWNER)
        idem,body_hash,replay=self._idempotency(actor,'revoke-invite',idempotency_key,{'id':invitation_id,'version':expected_revision})
        if replay:
            self._fresh(actor,Role.OWNER)
            return replay.data['result']
        key=invitation_key(invitation_id);row=self.repository.snapshot((key,))[key]
        if row is None:raise ResourceUnavailable('invitation unavailable')
        if row.revision!=expected_revision:raise StoreConflict('invitation version changed')
        if row.data['status']=='accepted':raise StoreConflict('accepted membership must be revoked through user access')
        head=self._head(actor.head)
        if invitation_id in head['pending_invitation_ids']:head['pending_invitation_ids'].remove(invitation_id)
        result={'id':invitation_id,'status':'revoked'}
        return self._record(actor,'revoke-invite',idem,body_hash,result,
            (Write(HEAD,actor.head.revision,head),Write(key,row.revision,{**row.data,'status':'revoked'})),(row,))

    def decline_invitation(self,actor,*,invitation_id,idempotency_key):
        actor=self._fresh(actor,invitee=True)
        idem,body_hash,replay=self._idempotency(actor,'decline-invite',idempotency_key,{'id':invitation_id})
        if replay:
            self._fresh(actor,invitee=True)
            return replay.data['result']
        if actor.session.data['restricted_invitation_id']!=invitation_id:raise ResourceUnavailable('invitation unavailable')
        key=invitation_key(invitation_id);row=self.repository.snapshot((key,))[key]
        if (row is None or row.data['target_subject']!=actor.session.data['subject']
                or row.data['target_email_hash']!=actor.session.data['email_hash']):raise ResourceUnavailable('invitation unavailable')
        if row.data['status']!='pending' or self.now()>=int(row.data['expires_at_ms']):raise StoreConflict('invitation no longer pending')
        head=self._head(actor.head)
        if invitation_id not in head['pending_invitation_ids']:raise StoreConflict('invitation reservation changed')
        head['pending_invitation_ids'].remove(invitation_id)
        return self._record(actor,'decline-invite',idem,body_hash,{'id':invitation_id,'status':'declined'},
            (Write(HEAD,actor.head.revision,head),Write(key,row.revision,{**row.data,'status':'revoked','revocation_reason':'declined_by_target'}),
             Write(actor.session.key,actor.session.revision,{**actor.session.data,'active':False})),(row,))

    def _recent_mfa(self,actor):
        if (actor.session.data['mfa_verified'] is not True
                or not 0<=self.now()-int(actor.session.data['auth_time_ms'])<=self.config.mfa_grant_max_age_seconds*1000):
            raise Denied('recent target MFA required')

    def change_access(self,actor,*,user_id,roles,enabled,expected_version,idempotency_key):
        actor=self._fresh(actor,Role.OWNER)
        role_values=sorted({Role(role).value for role in roles})
        if type(enabled) is not bool:raise ValueError('explicit enabled flag required')
        body={'id':user_id,'roles':role_values,'enabled':enabled,'version':expected_version}
        idem,body_hash,replay=self._idempotency(actor,'change-access',idempotency_key,body)
        if replay:
            self._fresh(actor,Role.OWNER)
            return replay.data['result']
        row=self.repository.snapshot((user_key(user_id),))[user_key(user_id)]
        if row is None:raise ResourceUnavailable('user unavailable')
        if int(row.data['access_version'])!=expected_version:raise StoreConflict('access version changed')
        head=self._head(actor.head)
        owners=[uid for uid in head['owner_ids'] if uid!=user_id]
        if enabled and Role.OWNER.value in role_values:
            last_mfa=row.data['last_mfa_ms']
            if last_mfa is None or not 0<=self.now()-int(last_mfa)<=self.config.mfa_grant_max_age_seconds*1000:
                raise Denied('target requires recent verified MFA before owner grant')
            owners.append(user_id)
        if not owners:raise Denied('last enabled owner cannot be removed')
        members=[uid for uid in head['enabled_user_ids'] if uid!=user_id]
        if enabled:
            if len(members)+len(head['pending_invitation_ids'])>=self.config.max_accounts:raise StoreConflict('account capacity exhausted')
            members.append(user_id)
        head['owner_ids']=owners;head['enabled_user_ids']=members
        updated={**row.data,'enabled':enabled,'roles':role_values,'access_version':int(row.data['access_version'])+1,
                 'session_epoch':int(row.data['session_epoch'])+1}
        result={'user_id':user_id,'access_version':updated['access_version'],'enabled':enabled,'roles':role_values}
        return self._record(actor,'change-access',idem,body_hash,result,
            (Write(HEAD,actor.head.revision,head),Write(row.key,row.revision,updated)),(row,))

    def revoke_sessions(self,actor,*,user_id,expected_version,idempotency_key):
        actor=self._fresh(actor,Role.OWNER)
        idem,body_hash,replay=self._idempotency(actor,'revoke-sessions',idempotency_key,{'id':user_id,'version':expected_version})
        if replay:
            self._fresh(actor,Role.OWNER)
            return replay.data['result']
        row=self.repository.snapshot((user_key(user_id),))[user_key(user_id)]
        if row is None:raise ResourceUnavailable('user unavailable')
        if int(row.data['access_version'])!=expected_version:raise StoreConflict('access version changed')
        updated={**row.data,'access_version':int(row.data['access_version'])+1,'session_epoch':int(row.data['session_epoch'])+1}
        return self._record(actor,'revoke-sessions',idem,body_hash,{'user_id':user_id,'access_version':updated['access_version']},
                            (Write(row.key,row.revision,updated),),(row,))

    def begin_transfer(self,actor,*,target_id,expected_target_version,idempotency_key):
        actor=self._fresh(actor,Role.OWNER)
        idem,body_hash,replay=self._idempotency(actor,'begin-transfer',idempotency_key,
            {'target_id':target_id,'target_version':expected_target_version})
        if replay:
            self._fresh(actor,Role.OWNER)
            return replay.data['result']
        target=self.repository.snapshot((user_key(target_id),))[user_key(target_id)]
        if (target is None or target.data.get('enabled') is not True
                or int(target.data['access_version'])!=expected_target_version
                or target_id==actor.member.data['id']):raise StoreConflict('enabled distinct target with current grant required')
        ident=str(uuid4());expires=self.now()+self.config.transfer_ttl_seconds*1000
        data={'id':ident,'source_id':actor.member.data['id'],'source_version':int(actor.member.data['access_version']),
            'target_id':target_id,'target_version':expected_target_version,'status':'pending','expires_at_ms':expires}
        return self._record(actor,'begin-transfer',idem,body_hash,{'id':ident,'expires_at_ms':expires},
            (Write(Key('state','owner-transfer#'+ident),None,data),),(target,))

    def accept_transfer(self,actor,*,transfer_id,idempotency_key):
        actor=self._fresh(actor)
        self._recent_mfa(actor)
        user_key(transfer_id);key=Key('state','owner-transfer#'+transfer_id)
        idem,body_hash,replay=self._idempotency(actor,'accept-transfer',idempotency_key,{'id':transfer_id})
        if replay:
            self._fresh(actor)
            return replay.data['result']
        first=self.repository.snapshot((key,))[key]
        if first is None or first.data['target_id']!=actor.member.data['id']:raise Denied('transfer belongs to another target')
        source_key=user_key(first.data['source_id']);target_key=actor.member.key
        rows=self.repository.snapshot((HEAD,key,source_key,target_key))
        transfer=rows[key];source=rows[source_key];target=rows[target_key];head=self._head(rows[HEAD])
        if rows[HEAD].revision!=actor.head.revision:raise StoreConflict('access head changed')
        if (transfer is None or transfer.data!=first.data or transfer.data['status']!='pending'
                or self.now()>=int(transfer.data['expires_at_ms']) or source is None or target is None
                or source.data.get('enabled') is not True or target.data.get('enabled') is not True
                or source.data['id'] not in head['owner_ids']
                or int(source.data['access_version'])!=int(transfer.data['source_version'])
                or int(target.data['access_version'])!=int(transfer.data['target_version'])):
            raise StoreConflict('transfer authority changed or expired')
        source_data={**source.data,'roles':[role for role in source.data['roles'] if role!=Role.OWNER.value],
            'access_version':int(source.data['access_version'])+1,'session_epoch':int(source.data['session_epoch'])+1}
        target_data={**target.data,'roles':sorted(set(target.data['roles'])|{Role.OWNER.value}),
            'access_version':int(target.data['access_version'])+1,'session_epoch':int(target.data['session_epoch'])+1}
        head['owner_ids']=[uid for uid in head['owner_ids'] if uid!=source.data['id']]
        if target.data['id'] not in head['owner_ids']:head['owner_ids'].append(target.data['id'])
        result={'owner_id':target.data['id'],'sign_in_required':True}
        writes=(Write(HEAD,actor.head.revision,head),Write(key,transfer.revision,{**transfer.data,'status':'accepted'}),
                Write(source.key,source.revision,source_data),Write(target.key,target.revision,target_data))
        return self._record(actor,'accept-transfer',idem,body_hash,result,writes,
                            tuple(row for row in rows.values() if row is not None))

    def logout(self,raw_cookie: str,csrf: str) -> None:
        if not isinstance(raw_cookie,str) or not re.fullmatch(r'[A-Za-z0-9_-]{40,128}',raw_cookie):return
        key=Key('state','cookie#'+digest(raw_cookie));cookie=self.repository.snapshot((key,))[key]
        if cookie is None:return
        session_key=Key('state','session#'+cookie.data['session_id'])
        rows=self.repository.snapshot((key,session_key));session=rows[session_key]
        if session is None:return
        if not isinstance(csrf,str) or not hmac.compare_digest(session.data['csrf_hash'],digest(csrf)):
            raise Denied('logout CSRF proof required')
        if session.data['active'] is not True:return
        self._commit((Write(session.key,session.revision,{**session.data,'active':False}),),(rows[key],))
