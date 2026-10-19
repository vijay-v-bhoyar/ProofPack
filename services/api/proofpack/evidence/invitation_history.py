"""Supplied versioned invitation lifecycle; no access, retention or cleanup grant."""
from copy import deepcopy
from dataclasses import asdict, dataclass, field
import hashlib
import re

from proofpack.auth.policy import Role
from proofpack.auth.service import HEAD, identity_key, digest
from proofpack.evidence.inventory import _encoded, _private_payload_size
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode, InvalidResourceBindings, MissingResourceBindings
from proofpack.evidence.replay_lineage import discover as replay_discover, ReplayHistoryHeld
from proofpack.evidence.transfer_history import _number, _sha, _body, TransferHistoryHeld
from proofpack.runtime.control import uuid

MAXIMUM = 2**63-1
POLICY = 'invitation-history-v1'
BASE = frozenset('id issuer target_subject target_email_hash roles expires_at_ms status capability_hash created_by delivery_status history_schema_version created_at_ms ttl_seconds'.split())


class InvitationHistoryHeld(RuntimeError): pass


@dataclass(frozen=True)
class InvitationHistoryLimits:
    max_records: int
    max_payload_bytes: int
    max_dependencies: int
    max_work: int
    max_summary_bytes: int

    def __post_init__(self):
        if any(type(v) is not int or not 1 <= v <= MAXIMUM for v in (
                self.max_records,self.max_payload_bytes,self.max_dependencies,self.max_work,self.max_summary_bytes)):
            raise ValueError('independent explicit finite invitation history limits required')


@dataclass(frozen=True)
class InvitationRecord:
    key: Key
    revision: int
    sha256: str


@dataclass(frozen=True)
class InvitationDependency:
    key: Key
    revision: int
    sha256: str
    kind: str


@dataclass(frozen=True)
class InvitationHistory:
    policy: str
    families: int
    states: tuple[tuple[str,str], ...] = field(repr=False)
    roots: tuple[InvitationRecord, ...] = field(repr=False)
    records: tuple[InvitationRecord, ...] = field(repr=False)
    dependencies: tuple[InvitationDependency, ...] = field(repr=False)
    payload_bytes: int
    work: int
    summary_bytes: int
    summary_sha256: str
    historical: bool = True
    read_only: bool = True
    grants_current_access: bool = False
    can_confirm_cleanup: bool = False


def _hold():raise InvitationHistoryHeld('intact complete versioned invitation history required')


def discover(roots, rows, *, deployment, limits, deadline_ns, tick, checkpoint):
    """Validate closed supplied families; inventory, source authority and policy are external."""
    if (type(roots)is not tuple or not roots or type(rows)is not tuple or type(limits)is not InvitationHistoryLimits
            or type(deployment)is not str or re.fullmatch('[A-Za-z0-9][A-Za-z0-9_-]{0,127}',deployment)is None
            or type(deadline_ns)is not int or not 1<=deadline_ns<=MAXIMUM or not callable(tick) or not callable(checkpoint)):
        raise ValueError('exact bounded invitation inputs and original execution fence required')
    work=0;last=-1
    def checked_tick():
        nonlocal last
        now=tick()
        if type(now)is not int or not 0<=now<deadline_ns or now<last:
            raise InvitationHistoryHeld('original invitation history deadline or clock invalid')
        last=now
    def check(cost=0):
        nonlocal work
        work+=cost
        if work>limits.max_work:raise InvitationHistoryHeld('invitation history work bound exhausted')
        checkpoint();checked_tick();checkpoint();checked_tick()
    try:
        check()
        if len(roots)+len(rows)>limits.max_records:raise InvitationHistoryHeld('invitation history record bound exhausted')
        copies={};references={};payload_bytes=0
        for row in (*roots,*rows):
            check(1)
            if (type(row)is not Row or type(row.key)is not Key or type(row.data)is not dict
                    or type(row.key.table)is not str or row.key.table not in {'state','events'}
                    or type(row.key.resource)is not str or not 1<=len(row.key.resource)<=256
                    or type(row.revision)is not int or not 1<=row.revision<=MAXIMUM or row.key in copies):_hold()
            references[row.key]=InvitationRecord(row.key,row.revision,_payload_sha256(row.data))
            payload_bytes+=_private_payload_size(row.data)
            if payload_bytes>limits.max_payload_bytes:raise InvitationHistoryHeld('invitation history payload bound exhausted')
            copies[row.key]=deepcopy(row)
        families={};initials={};changes={}
        for original in roots:
            check(1);root=copies[original.key];data=root.data
            state=data['status'];extra=set()
            if state=='accepted':extra={'accepted_user_id','notice_version','notice_sha256'}
            elif state=='revoked' and 'revocation_reason' in data:
                extra={'revocation_reason'}
                if data['revocation_reason']!='declined_by_target':_hold()
            if set(data)!=BASE|extra or state not in {'pending','accepted','expired','revoked'}:_hold()
            ident=uuid(data['id']);uuid(data['created_by'])
            if (root.key!=Key('state','invitation#'+ident) or _number(data['history_schema_version'],1)!=1
                    or type(data['issuer'])is not str or not data['issuer'].startswith('https://') or len(data['issuer'])>2048
                    or type(data['target_subject'])is not str or not 1<=len(data['target_subject'])<=256
                    or data['delivery_status']!='NOT_SENT' or type(data['roles'])is not list or len(data['roles'])>len(Role)
                    or any(type(role)is not str or role not in {r.value for r in Role} for role in data['roles'])
                    or data['roles']!=sorted(set(data['roles']))):_hold()
            _sha(data['target_email_hash']);_sha(data['capability_hash'])
            created=_number(data['created_at_ms']);ttl=_number(data['ttl_seconds'],1);expires=_number(data['expires_at_ms'],1)
            if ttl>604800 or expires!=created+ttl*1000:_hold()
            if state=='accepted':
                uuid(data['accepted_user_id']);_sha(data['notice_sha256'])
                if type(data['notice_version'])is not str or not 1<=len(data['notice_version'])<=128:_hold()
            initial={k:v for k,v in data.items() if k in BASE}|{'status':'pending'}
            families[root.key]=root;initials[root.key]=initial;changes[root.key]=[]
        groups={}
        for original in rows:
            check(1);row=copies[original.key];binding=decode(row,deployment=deployment)
            if binding.operation not in {'invite','accept-invite','decline-invite','revoke-invite'}:_hold()
            token=hashlib.sha256(_encoded(asdict(binding))).hexdigest()
            if token not in groups:groups[token]=(binding,[],[])
            prior,events,replays=groups[token]
            if binding!=prior:_hold()
            if row.key.table=='events' and re.fullmatch('access#[a-f0-9-]{36}',row.key.resource):
                uuid(row.key.resource.split('#')[1]);events.append(row)
            elif row.key.table=='state' and re.fullmatch('idempotency#[a-f0-9]{64}',row.key.resource):replays.append(row)
            else:_hold()
        dependencies=set()
        def transition(key,before,after,data,at,replay_at,kind):
            check(1)
            if key not in families or after.key!=key or after.sha256!=_payload_sha256(data):_hold()
            if before is None:
                if after.previous_revision is not None or after.revision!=1:_hold()
            elif after.previous_revision!=before.revision:_hold()
            changes[key].append((after.revision,before,after,data['status'],at,replay_at,kind))
        for binding,events,replays in groups.values():
            check(1)
            if len(events)!=1 or len(replays)!=1:_hold()
            event,replay=events[0],replays[0]
            replay_discover(replay,(event,),deployment=deployment,max_records=limits.max_records,max_payload_bytes=limits.max_payload_bytes)
            e=event.data;result=replay.data['result']
            if set(e)!={'kind','actor_scope','session_id','at_ms','resource_bindings'}:_hold()
            _sha(e['actor_scope']);session=Key('state','session#'+uuid(e['session_id']))
            at=_number(e['at_ms']);replay_at=_number(replay.data['at_ms'])
            written={ref.key:ref for ref in binding.writes};checked={ref.key:ref for ref in binding.checks}
            cookies=[k for k in checked if k.table=='state' and re.fullmatch('cookie#[a-f0-9]{64}',k.resource)]
            users=[k for k in checked if k.table=='state' and k.resource.startswith('user#')]
            if len(cookies)!=1 or HEAD not in checked or session not in checked:_hold()
            authority={HEAD,session,cookies[0]}
            if binding.operation in {'invite','revoke-invite'}:
                if len(users)!=1:_hold()
                uuid(users[0].resource[len('user#'):]);authority.add(users[0])
            elif users:_hold()
            if HEAD not in written or written[HEAD].previous_revision!=checked[HEAD].revision:_hold()
            if binding.operation=='invite':
                if set(result)!={'id','expires_at_ms','delivery_status'} or result['delivery_status']!='NOT_SENT':_hold()
                key=Key('state','invitation#'+uuid(result['id']))
                if key not in families:_hold()
                initial=initials[key];created=_number(initial['created_at_ms']);expires=_number(initial['expires_at_ms'])
                body={name:initial[name] for name in ('target_subject','roles','ttl_seconds')}
                body['ttl_seconds']=_number(body['ttl_seconds'],1);body['target_email_hash']=initial['target_email_hash']
                pending=set(checked)-authority
                if (users[0]!=Key('state','user#'+initial['created_by']) or key in checked or key not in written
                        or _number(result['expires_at_ms'],1)!=expires or replay.data['body_hash']!=_body(body) or at<created
                        or any(k not in families for k in pending) or not set(written)<={HEAD,key}|pending):_hold()
                transition(key,None,written[key],initial,at,replay_at,'create')
                for pending_key in pending:
                    check(1);prior=checked[pending_key];old=initials[pending_key]
                    if prior.revision!=1 or prior.sha256!=_payload_sha256(old) or _number(old['created_at_ms'])>created:_hold()
                    if pending_key in written:
                        if _number(old['expires_at_ms'])>created:_hold()
                        transition(pending_key,prior,written[pending_key],{**old,'status':'expired'},at,replay_at,'expire')
            else:
                affected=[k for k in written if k in families]
                if len(affected)!=1:_hold()
                key=affected[0];root=families[key];initial=initials[key];ident=initial['id']
                prior=checked.get(key)
                if prior is None or set(checked)!=authority|{key} or at<_number(initial['created_at_ms']):_hold()
                if binding.operation=='accept-invite':
                    uid=uuid(root.data['accepted_user_id']);member=Key('state','user#'+uid)
                    identity=identity_key(initial['issuer'],initial['target_subject'])
                    body={'id':ident,'capability_hash':initial['capability_hash'],
                        'notice_version':root.data['notice_version'],'notice_sha256':root.data['notice_sha256']}
                    if (set(result)!={'user_id','sign_in_required'} or result['user_id']!=uid or result['sign_in_required']is not True
                            or set(written)!={HEAD,key,session,member,identity} or prior.revision!=1
                            or prior.sha256!=_payload_sha256(initial) or at>=_number(initial['expires_at_ms'])
                            or e['actor_scope']!=digest(initial['issuer']+'\0'+initial['target_subject'])
                            or any(written[k].previous_revision is not None or written[k].revision!=1 for k in (member,identity))
                            or written[identity].sha256!=_payload_sha256({'user_id':uid})
                            or written[session].previous_revision!=checked[session].revision):_hold()
                    data={**initial,'status':'accepted','accepted_user_id':uid,
                        'notice_version':body['notice_version'],'notice_sha256':body['notice_sha256']}
                elif binding.operation=='decline-invite':
                    body={'id':ident}
                    if (set(result)!={'id','status'} or result!={'id':ident,'status':'declined'}
                            or set(written)!={HEAD,key,session} or prior.revision!=1 or prior.sha256!=_payload_sha256(initial)
                            or at>=_number(initial['expires_at_ms']) or written[session].previous_revision!=checked[session].revision
                            or e['actor_scope']!=digest(initial['issuer']+'\0'+initial['target_subject'])):_hold()
                    data={**initial,'status':'revoked','revocation_reason':'declined_by_target'}
                else:
                    body={'id':ident,'version':prior.revision}
                    if set(result)!={'id','status'} or result!={'id':ident,'status':'revoked'} or set(written)!={HEAD,key}:_hold()
                    data={**initial,'status':'revoked'}
                    if 'revocation_reason' in root.data:data['revocation_reason']=root.data['revocation_reason']
                if replay.data['body_hash']!=_body(body):_hold()
                transition(key,prior,written[key],data,at,replay_at,binding.operation)
            for kind,refs in (('write',binding.writes),('check',binding.checks)):
                for ref in refs:
                    check(1)
                    if ref.key in families:continue
                    dependencies.add(InvitationDependency(ref.key,ref.revision,ref.sha256,kind))
                    if len(dependencies)>limits.max_dependencies:raise InvitationHistoryHeld('invitation dependency bound exhausted')
        states=[]
        for key,root in families.items():
            check(1);chain=sorted(changes[key],key=lambda item:item[0]);previous=None;status=None;end=0
            if not chain or chain[0][6]!='create':_hold()
            for revision,prior,after,new_status,at,replay_at,kind in chain:
                check(1)
                if previous is not None:
                    if (revision!=previous.revision+1 or prior is None or prior.revision!=previous.revision
                            or prior.sha256!=previous.sha256 or at<end or status=='accepted'
                            or kind=='create' or status!='pending' and kind!='revoke-invite'):_hold()
                elif revision!=1 or prior is not None:_hold()
                previous=after;status=new_status;end=replay_at
            if previous.revision!=root.revision or previous.sha256!=references[key].sha256 or status!=root.data['status']:_hold()
            states.append((root.data['id'],'declined' if root.data.get('revocation_reason')=='declined_by_target' else status))
        records=tuple(references[k] for k in sorted(references,key=lambda k:(k.table,k.resource)))
        root_refs=tuple(references[k] for k in sorted(families,key=lambda k:(k.table,k.resource)))
        deps=tuple(sorted(dependencies,key=lambda r:(r.key.table,r.key.resource,r.revision,r.sha256,r.kind)))
        states=tuple(sorted(states));check(len(records)+len(deps))
        summary=_encoded({'policy':POLICY,'deployment':deployment,'states':states,
            'records':[asdict(r) for r in records],'dependencies':[asdict(r) for r in deps]})
        if len(summary)>limits.max_summary_bytes:raise InvitationHistoryHeld('invitation history summary bound exhausted')
        summary_sha256=hashlib.sha256(summary).hexdigest();check(len(records))
        for original in (*roots,*rows):
            if (original.key not in references or original.revision!=references[original.key].revision
                    or _payload_sha256(original.data)!=references[original.key].sha256):_hold()
        checked_tick()
        return InvitationHistory(POLICY,len(roots),states,root_refs,records,deps,payload_bytes,work,len(summary),summary_sha256)
    except (TransferHistoryHeld, ReplayHistoryHeld, InvalidResourceBindings, MissingResourceBindings,
            ValueError,TypeError,KeyError,AttributeError,ArithmeticError,RecursionError):
        raise InvitationHistoryHeld('intact complete supported invitation history unavailable') from None
