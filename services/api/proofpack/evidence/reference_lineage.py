"""Strict retained reference-upload history; no inspection ownership or cleanup grant."""
from copy import deepcopy
from dataclasses import dataclass, field
import re

from pydantic import TypeAdapter
from proofpack.auth.service import HEAD, RUNTIME
from proofpack.evidence.capture_lineage import CaptureRecord, MediaTarget, _n, _shape, _text
from proofpack.evidence.inventory import _private_payload_size, InventoryHeld
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode, MissingResourceBindings, InvalidResourceBindings
from proofpack.recipes.models import Identifier, Origin
from proofpack.runtime.control import DATA, uuid, sha
from proofpack.vision.reference import ReferenceMetadata

POLICY='reference-upload-history-v1'
BASE=frozenset('id kind status asset_id key purpose_id source_sha256 context_sha256 owner_user_id session_id runtime_epoch data_epoch created_at_ms'.split())
TARGET=frozenset(('history_version','storage_binding_sha256'))
STORED=frozenset(('stored_sha256','stored_byte_length'))
ASSET=frozenset('storage_binding_sha256 id kind status read_denied sha256 source_sha256 width height byte_length content_type object_receipt purpose_id source_permission_reference data_origin origin_basis physical_truth_verified expires_at_ms owner_user_id created_at_ms'.split())
RECEIPT=frozenset('asset_id key version_id source_sha256 context_sha256 byte_length content_type'.split())
ACCESS=frozenset('kind actor_scope at_ms session_id resource_bindings'.split())
COMMITTED=frozenset('kind asset_id purpose_id actor_scope at_ms resource_bindings'.split())
REPLAY=frozenset('body_hash result at_ms resource_bindings'.split())


class ReferenceHistoryHeld(RuntimeError):pass


@dataclass(frozen=True)
class ReferenceLimits:
    max_records:int
    max_payload_bytes:int
    max_dependencies:int
    max_work:int

    def __post_init__(self):
        if any(type(v) is not int or not 1<=v<=2**63-1 for v in (
                self.max_records,self.max_payload_bytes,self.max_dependencies,self.max_work)):
            raise ValueError('independent finite reference-history limits required')


@dataclass(frozen=True)
class ReferenceFamily:
    policy:str
    state:str
    intent:CaptureRecord=field(repr=False)
    asset:CaptureRecord|None=field(repr=False)
    records:tuple[CaptureRecord,...]=field(repr=False)
    dependencies:tuple[CaptureRecord,...]=field(repr=False)
    media:tuple[MediaTarget,...]=field(repr=False)
    obligations:tuple[str,...]
    payload_bytes:int
    work:int


def discover(intent,rows,*,deployment,limits,deadline_ns,tick,checkpoint):
    if (type(rows) is not tuple or type(limits) is not ReferenceLimits or type(deployment) is not str
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}',deployment) is None
            or type(deadline_ns) is not int or not 1<=deadline_ns<=2**63-1
            or not callable(tick) or not callable(checkpoint)):
        raise ValueError('exact bounded private reference family, target and original deadline required')
    if len(rows)+1>limits.max_records:raise ReferenceHistoryHeld('reference record bound exhausted')
    work=0;last=-1;size=0
    def check(cost=0):
        nonlocal work,last
        work+=cost
        if work>limits.max_work:raise ReferenceHistoryHeld('reference work bound exhausted')
        checkpoint();now=tick()
        if type(now) is not int or not 0<=now<deadline_ns or now<last:
            raise ReferenceHistoryHeld('original reference deadline or monotonic clock invalid')
        last=now;checkpoint()
    def record(row):return CaptureRecord(row.key,row.revision,_payload_sha256(row.data))
    def match(ref,row,previous=None):
        if (ref.key!=row.key or ref.revision!=row.revision or ref.sha256!=_payload_sha256(row.data)
                or (hasattr(ref,'previous_revision') and ref.previous_revision!=previous)):
            raise ValueError()
    try:
        check();selected={}
        for original in (intent,*rows):
            check(1)
            if (type(original) is not Row or type(original.key) is not Key or type(original.data) is not dict
                    or type(original.revision) is not int or not 1<=original.revision<=2**63-1
                    or original.key.table not in {'state','events'} or type(original.key.resource) is not str
                    or not 1<=len(original.key.resource)<=256 or original.key in selected):raise ValueError()
            row=deepcopy(original);_payload_sha256(row.data);size+=_private_payload_size(row.data)
            if size>limits.max_payload_bytes:raise ReferenceHistoryHeld('reference payload bound exhausted')
            selected[row.key]=row
        root=selected[intent.key];value=root.data;ident=uuid(value['id']);state=value['status']
        if root.key!=Key('state','reference-intent#'+ident) or value['kind']!='reference' or value['asset_id']!=ident:raise ValueError()
        if state not in {'reserved','writing','linked','needs_reconciliation'}:raise ValueError()
        stored=STORED&value.keys()
        target=TARGET&value.keys()
        if target:
            if target!=TARGET or _n(value['history_version'])!=2:raise ValueError()
            sha(value['storage_binding_sha256'])
        if stored and stored!=STORED:raise ValueError()
        if state=='reserved':expected=BASE;revision=1
        elif state=='writing':expected=BASE|STORED;revision=2
        elif state=='linked':expected=BASE|STORED|{'object_receipt'};revision=3
        else:expected=BASE|(STORED if stored else set());revision=3 if stored else 2
        _shape(value,expected|target)
        if root.revision!=revision:raise ValueError()
        object_key='deployments/'+deployment+'/references/'+ident
        if value['key']!=object_key:raise ValueError()
        purpose=Key('state','purpose#'+uuid(value['purpose_id']))
        user=Key('state','user#'+uuid(value['owner_user_id']));session=Key('state','session#'+uuid(value['session_id']))
        created=_n(value['created_at_ms']);_n(value['runtime_epoch'],positive=True);_n(value['data_epoch'],positive=True)
        sha(value['source_sha256']);sha(value['context_sha256'])
        if stored:
            sha(value['stored_sha256'])
            if not 1<=_n(value['stored_byte_length'])<=2097152:raise ValueError()
        asset=None;access=None;event=None;operation=None
        for row in selected.values():
            check(1)
            if row.key==root.key:continue
            prefix=row.key.resource.split('#',1)[0]
            if row.key.table=='state' and row.key==Key('state','asset#'+ident):
                if asset is not None:raise ValueError()
                asset=row
            elif row.key.table=='state' and re.fullmatch(r'idempotency#[a-f0-9]{64}',row.key.resource):
                if operation is not None:raise ValueError()
                operation=row
            elif row.key.table=='events' and prefix=='access':
                uuid(row.key.resource.split('#',1)[1])
                if access is not None or row.revision!=1:raise ValueError()
                _shape(row.data,ACCESS)
                if row.data['kind']!='reference-upload' or row.data['session_id']!=value['session_id']:raise ValueError()
                sha(row.data['actor_scope']);access=row
            elif row.key.table=='events' and prefix=='reference':
                uuid(row.key.resource.split('#',1)[1])
                if event is not None or row.revision!=1:raise ValueError()
                _shape(row.data,COMMITTED)
                if (row.data['kind']!='reference_committed' or row.data['asset_id']!=ident
                        or row.data['purpose_id']!=value['purpose_id']):raise ValueError()
                event=row
            else:raise ValueError()
        if operation is None or access is None:raise ValueError()
        _shape(operation.data,REPLAY);_shape(operation.data['result'],frozenset(('id','status')))
        if operation.data['result']['id']!=ident or operation.data['body_hash']!=value['context_sha256']:raise ValueError()
        admitted=_n(access.data['at_ms']);saved=_n(operation.data['at_ms'])
        if not created<=admitted<=saved:raise ValueError()
        reservation=decode(access,deployment=deployment);check()
        if reservation.operation!='reference-upload':raise ValueError()
        writes={r.key:r for r in reservation.writes};checks={r.key:r for r in reservation.checks}
        if set(writes)!={root.key}:raise ValueError()
        cookies=[k for k in checks if k.table=='state' and re.fullmatch(r'cookie#[a-f0-9]{64}',k.resource)]
        if len(cookies)!=1:raise ValueError()
        contexts={HEAD,RUNTIME,DATA,purpose,user,session,cookies[0]}
        if set(checks)!=contexts:raise ValueError()
        reserved={k:v for k,v in value.items() if k in BASE|target};reserved['status']='reserved'
        match(writes[root.key],Row(root.key,1,reserved))
        dependencies=set()
        def remember(binding):
            for ref in (*binding.checks,*(r for r in binding.writes if r.key not in selected)):
                check(1);dependencies.add(CaptureRecord(ref.key,ref.revision,ref.sha256))
                if len(dependencies)>limits.max_dependencies:raise ReferenceHistoryHeld('reference dependency bound exhausted')
        remember(reservation)
        current=decode(operation,deployment=deployment);check()
        media=[];obligations=['INSPECTION_ORIGIN_NOT_RECORDED','REQUEST_PREIMAGE_NOT_RETAINED']
        if not target:obligations.append('STORAGE_TARGET_NOT_RECORDED')
        if state in {'reserved','writing'}:
            if (operation.revision!=1 or operation.data['result']['status']!='processing' or current!=reservation
                    or asset is not None or event is not None):raise ValueError()
            obligations.append('STORAGE_RECONCILIATION_REQUIRED')
        elif state=='needs_reconciliation':
            if (operation.revision!=2 or operation.data['result']['status']!='failed' or current.operation!='reference_failed'
                    or current.checks or asset is not None or event is not None):raise ValueError()
            final={r.key:r for r in current.writes}
            if set(final)!={root.key}:raise ValueError()
            match(final[root.key],root,root.revision-1);obligations.append('STORAGE_RECONCILIATION_REQUIRED')
        else:
            if (operation.revision!=2 or operation.data['result']['status']!='committed' or asset is None
                    or event is None or current.operation!='reference_committed' or decode(event,deployment=deployment)!=current):raise ValueError()
            _shape(asset.data,ASSET);a=asset.data
            if (asset.revision!=1 or a['id']!=ident or a['kind']!='reference' or a['status']!='committed'
                    or a['read_denied'] is not False or a['origin_basis']!='owner_declaration' or a['physical_truth_verified'] is not False
                    or a['owner_user_id']!=value['owner_user_id'] or a['purpose_id']!=value['purpose_id']
                    or a['source_sha256']!=value['source_sha256'] or a['sha256']!=value['stored_sha256']
                    or _n(a['byte_length'])!=_n(value['stored_byte_length'])):raise ValueError()
            sha(a['storage_binding_sha256'])
            if target and a['storage_binding_sha256']!=value['storage_binding_sha256']:raise ValueError()
            if type(a['data_origin']) is not str:raise ValueError()
            Origin(a['data_origin'])
            TypeAdapter(Identifier).validate_python(a['source_permission_reference'],strict=True)
            ReferenceMetadata.model_validate({'width':_n(a['width']),'height':_n(a['height']),
                'byte_length':_n(a['byte_length']),'source_sha256':a['source_sha256'],'stored_sha256':a['sha256'],
                'content_type':a['content_type']},strict=True)
            when=_n(a['created_at_ms']);finished=_n(event.data['at_ms']);expires=_n(a['expires_at_ms'],positive=True)
            if not created<=when<=finished or finished<admitted or not when<expires<=9007199254740991:raise ValueError()
            if event.data['actor_scope']!=access.data['actor_scope']:raise ValueError()
            receipt=a['object_receipt'];_shape(receipt,RECEIPT)
            _n(receipt['byte_length'],positive=True)
            if receipt!=value['object_receipt'] or receipt!={'asset_id':ident,'key':object_key,
                    'version_id':_text(receipt['version_id'],1024,version=True),'source_sha256':a['sha256'],
                    'context_sha256':value['context_sha256'],'byte_length':_n(a['byte_length']),'content_type':'image/jpeg'}:raise ValueError()
            written={r.key:r for r in current.writes};checked={r.key:r for r in current.checks}
            if set(written)!={asset.key,root.key,DATA} or set(checked)!=contexts|{root.key}:raise ValueError()
            writing={k:v for k,v in value.items() if k!='object_receipt'};writing['status']='writing'
            match(checked[root.key],Row(root.key,2,writing));match(written[root.key],root,2);match(written[asset.key],asset)
            if written[DATA].revision!=checked[DATA].revision+1:raise ValueError()
            media.append(MediaTarget(asset.key,ident,a['storage_binding_sha256'],object_key,receipt['version_id'],'committed'))
        remember(current);check()
        order=lambda r:(r.key.table,r.key.resource,r.revision,r.sha256)
        result=ReferenceFamily(POLICY,state,record(root),record(asset) if asset else None,
            tuple(record(r) for k,r in sorted(selected.items(),key=lambda item:(item[0].table,item[0].resource)) if k!=root.key),
            tuple(sorted(dependencies,key=order)),tuple(media),tuple(obligations),size,work)
        check();return result
    except ReferenceHistoryHeld:raise
    except (KeyError,ValueError,TypeError,AttributeError,InventoryHeld,MissingResourceBindings,InvalidResourceBindings):
        raise ReferenceHistoryHeld('intact complete supported reference-upload history required') from None
