"""Complete private ownership classification; never an executable removal grant."""
from dataclasses import dataclass,field,asdict,replace
import hashlib,re
from itertools import chain
from proofpack.evidence.corpus_accounting import (
    account,AccountingLimits,CorpusAccounting,AccountedRecord,AccountingLink,
    POLICY as ACCOUNTING_POLICY,DISPOSITIONS,CaptureRecord,SupportRecord,
    ReplayRecord,AdmissionReference,CorpusReference,
)
from proofpack.evidence.inventory import InventoryPass,InventoryEntry,_encoded
from proofpack.evidence.repository import Key
from proofpack.evidence.privacy_admission import DrainProof
from proofpack.evidence.replay_corpus import ReplayCorpus
from proofpack.evidence.runtime_context import RuntimeContext,validate as validate_runtime_context, RETENTION as RUNTIME_RETENTION
from proofpack.evidence.corpus_accounting import RUNTIME_POLICY as RUNTIME_ACCOUNTING_POLICY
from proofpack.evidence.purpose_corpus import PurposeCorpus,validate as validate_purpose_corpus,CONTEXT_POLICY as PURPOSE_CONTEXT_POLICY,RETENTION_REASON as PURPOSE_RETENTION_REASON
from proofpack.evidence.corpus_accounting import PURPOSE_POLICY as PURPOSE_ACCOUNTING_POLICY

from proofpack.evidence.access_context import AccessContext,validate as validate_access_context, CONTEXT_POLICY as ACCESS_CONTEXT_POLICY, RETENTION_REASON as ACCESS_RETENTION_REASON
from proofpack.evidence.corpus_accounting import ACCESS_POLICY as ACCESS_ACCOUNTING_POLICY

from proofpack.evidence.auth_history import AuthHistory,validate as validate_auth_history
from proofpack.evidence.corpus_accounting import AUTH_POLICY as AUTH_ACCOUNTING_POLICY

MAXIMUM=2**63-1
POLICY='whole-scope-family-ownership-v1'
RUNTIME_POLICY='whole-scope-family-ownership-v2'
PURPOSE_POLICY='whole-scope-family-ownership-v3'
ACCESS_POLICY='whole-scope-family-ownership-v4'
AUTH_POLICY='whole-scope-family-ownership-v5'
CONTENT=frozenset(('CAPTURE_CONTENT','HUMAN_CONTENT','SUPPORT_CONTENT','LABEL_CONTENT',
    'OPTIONAL_PERMISSION_CONTENT','DATASET_ARTIFACT_CONTENT','REPLAY_RESULT_CONTENT'))
RETENTION={'EXACT_DRAIN_CONTEXT':'retained_original_maintenance_fence',
    'VALIDATED_LABEL_CONTEXT':'retained_original_recipe_or_purpose_for_interpretation'}
REFERENCES=(CaptureRecord,SupportRecord,ReplayRecord,AdmissionReference,CorpusReference)
class ClassificationHeld(RuntimeError):pass

@dataclass(frozen=True)
class ClassificationLimits:
    max_records:int
    max_edges:int
    max_work:int
    max_summary_bytes:int
    def __post_init__(self):
        if any(type(v)is not int or not 1<=v<=MAXIMUM for v in
            (self.max_records,self.max_edges,self.max_work,self.max_summary_bytes)):
            raise ValueError('independent finite classification limits required')

@dataclass(frozen=True)
class ClassificationEntry:
    reference:InventoryEntry=field(repr=False)
    disposition:str
    reason:str
    inspection_ids:tuple[str,...]=field(repr=False)
    policies:tuple[str,...]
    retention_reasons:tuple[str,...]

@dataclass(frozen=True)
class OwnershipClassification:
    policy:str
    inventory_sha256:str
    scope_sha256:str
    accounting_sha256:str
    summary_sha256:str
    requested_inspections:tuple[str,...]=field(repr=False)
    entries:tuple[ClassificationEntry,...]=field(repr=False)
    relationships:tuple[AccountingLink,...]=field(repr=False)
    accounting:CorpusAccounting=field(repr=False)
    counts:tuple[tuple[str,int],...]
    work:int
    summary_bytes:int
    historical:bool=True
    read_only:bool=True
    can_confirm_cleanup:bool=False
    erasure_complete:bool=False
    request_fulfilled:bool=False

def _check_accounting_digest(a,inventory,requested_inspections,*,max_summary_bytes,check,
        runtime_context=None,purpose_corpus=None,access_context=None,auth_history=None):
    """Independent framed-byte check only; never source or cleanup authority."""
    if (type(a)is not CorpusAccounting or type(inventory)is not InventoryPass
            or type(requested_inspections)is not tuple or a.requested_inspections!=requested_inspections
            or a.inventory_sha256!=inventory.summary_sha256 or type(a.entries)is not tuple or type(a.relationships)is not tuple
            or type(inventory.summary_sha256)is not str or re.fullmatch('[a-f0-9]{64}',inventory.summary_sha256)is None
            or type(max_summary_bytes)is not int or not 1<=max_summary_bytes<=MAXIMUM or not callable(check)
            or type(a.summary_bytes)is not int or not 0<a.summary_bytes<=max_summary_bytes
            or type(a.summary_sha256)is not str or re.fullmatch('[a-f0-9]{64}',a.summary_sha256)is None
            or (purpose_corpus is not None and runtime_context is None)
            or (access_context is not None and runtime_context is None)
            or (auth_history is not None and (runtime_context is None or access_context is None))):
        raise ClassificationHeld('original versioned accounting digest inputs required')
    policy=ACCOUNTING_POLICY;digests=[];contexts=[]
    for context,kind,version in ((runtime_context,RuntimeContext,RUNTIME_ACCOUNTING_POLICY),
            (purpose_corpus,PurposeCorpus,PURPOSE_ACCOUNTING_POLICY),
            (access_context,AccessContext,ACCESS_ACCOUNTING_POLICY),
            (auth_history,AuthHistory,AUTH_ACCOUNTING_POLICY)):
        if context is not None:
            if (type(context)is not kind or type(context.summary_sha256)is not str
                    or re.fullmatch('[a-f0-9]{64}',context.summary_sha256)is None):
                raise ClassificationHeld('original typed accounting context digest required')
            policy=version;digests.append(context.summary_sha256);contexts.append(context)
    if a.policy!=policy:raise ClassificationHeld('original accounting policy version required')
    header=(policy,inventory.summary_sha256,requested_inspections,*digests)
    entries,relationships,counts,inventory_entries=a.entries,a.relationships,a.counts,inventory.entries
    expected_size,expected_sha,inventory_sha=a.summary_bytes,a.summary_sha256,inventory.summary_sha256
    def fields():
        return tuple((type(v),v) for v in (a.policy,a.inventory_sha256,a.requested_inspections,
            a.summary_bytes,a.summary_sha256,a.work))
    fixed=fields()
    def same():
        try:
            valid=(fields()==fixed and a.entries is entries and a.relationships is relationships
                and a.counts is counts and inventory.entries is inventory_entries
                and type(inventory.summary_sha256)is str and inventory.summary_sha256==inventory_sha
                and all(type(c.summary_sha256)is str and c.summary_sha256==sha for c,sha in zip(contexts,digests)))
        except (AttributeError,TypeError,ValueError):valid=False
        if not valid:raise ClassificationHeld('original accounting verification inputs changed')
    def guard(cost=0):
        same();check(cost);same()
    guard()
    hashed=hashlib.sha256();size=0
    for value in chain((header,),entries,relationships):
        guard(1)
        if value is header:payload=_encoded(value)
        elif type(value)in (AccountedRecord,AccountingLink):payload=_encoded(asdict(value))
        else:raise ClassificationHeld('original typed accounting frame required')
        frame=str(len(payload)).encode()+b':'+payload;size+=len(frame)
        if size>max_summary_bytes:raise ClassificationHeld('accounting summary bound exhausted')
        hashed.update(frame)
    guard()
    if size!=expected_size or hashed.hexdigest()!=expected_sha:
        raise ClassificationHeld('original accounting digest mismatch')

def classify(selection,inventory,proof,*,requested_inspections,scope_sha256,
             accounting_limits,limits,deadline_ns,tick,checkpoint,reference_corpus=None,runtime_context=None,purpose_corpus=None,access_context=None,auth_history=None):
    if access_context is not None and runtime_context is None:
        raise ClassificationHeld('explicit original runtime context required with access context')
    if purpose_corpus is not None and runtime_context is None:
        raise ClassificationHeld('explicit original runtime context required with purpose context')
    if (type(limits)is not ClassificationLimits or type(accounting_limits)is not AccountingLimits
        or type(inventory)is not InventoryPass or type(selection)is not ReplayCorpus or type(proof)is not DrainProof or type(deadline_ns)is not int
        or not 1<=deadline_ns<=MAXIMUM or not callable(tick) or not callable(checkpoint)):
        raise ValueError('exact private classification inputs and original finite execution bounds required')
    work=0;last=-1
    def checked_tick():
        nonlocal last
        now=tick()
        if type(now)is not int or not 0<=now<deadline_ns or now<last:
            raise ClassificationHeld('original classification deadline or clock invalid')
        last=now;return now
    def check(cost=0):
        nonlocal work
        work+=cost
        if work>limits.max_work:raise ClassificationHeld('classification work bound exhausted')
        checkpoint();checked_tick();checkpoint()
    def sha(v):return type(v)is str and re.fullmatch('[a-f0-9]{64}',v)is not None
    def ordered(values,cap):
        return type(values)is tuple and len(values)<=cap and all(type(v)is str for v in values) and values==tuple(sorted(set(values)))
    check()
    retention_policies=RETENTION
    policy=POLICY;accounting_policy=ACCOUNTING_POLICY
    if runtime_context is not None:
        validate_runtime_context(runtime_context,inventory,proof,scope_sha256=scope_sha256,requested_inspections=requested_inspections,checkpoint=check)
        check(runtime_context.work)
        retention_policies=RETENTION|RUNTIME_RETENTION
        policy=RUNTIME_POLICY;accounting_policy=RUNTIME_ACCOUNTING_POLICY
    if purpose_corpus is not None:
        validate_purpose_corpus(purpose_corpus,inventory,proof,scope_sha256=scope_sha256,requested_inspections=requested_inspections,checkpoint=check)
        check(purpose_corpus.work)
        retention_policies=retention_policies|{PURPOSE_CONTEXT_POLICY:PURPOSE_RETENTION_REASON}
        policy=PURPOSE_POLICY;accounting_policy=PURPOSE_ACCOUNTING_POLICY
    if access_context is not None:
        validate_access_context(access_context,inventory,proof,scope_sha256=scope_sha256,requested_inspections=requested_inspections,checkpoint=check)
        check(access_context.work)
        retention_policies=retention_policies|{ACCESS_CONTEXT_POLICY:ACCESS_RETENTION_REASON}
        policy=ACCESS_POLICY;accounting_policy=ACCESS_ACCOUNTING_POLICY
    if auth_history is not None:
        if access_context is None or runtime_context is None: raise ClassificationHeld('original auth/access/runtime required')
        validate_auth_history(auth_history,inventory,proof,scope_sha256=scope_sha256,requested_inspections=requested_inspections,checkpoint=check)
        check(auth_history.work)
        policy=AUTH_POLICY;accounting_policy=AUTH_ACCOUNTING_POLICY
    if type(inventory.entries)is not tuple or len(inventory.entries)>limits.max_records:
        raise ClassificationHeld('classification record bound exhausted')
    index={};previous=None
    for entry in inventory.entries:
        check(1)
        if type(entry)is not InventoryEntry or type(entry.key)is not Key:
            raise ClassificationHeld('exact original classification references required')
        k=entry.key;identity=(k.table,k.resource)
        if (type(k.table)is not str or k.table not in ('state','events') or type(k.resource)is not str
            or not 1<=len(k.resource)<=256 or type(entry.revision)is not int or not 1<=entry.revision<=MAXIMUM
            or entry.kind!='live' or not sha(entry.payload_sha256) or entry.reference_sha256 is not None
            or entry.resource_sha256 is not None or (previous is not None and identity<=previous)):
            raise ClassificationHeld('intact ordered live inventory and journal reconciliation required')
        previous=identity;index[k]=entry
    remaining_work=limits.max_work-work
    if remaining_work<1:raise ClassificationHeld('classification work exhausted before accounting')
    effective=replace(accounting_limits,max_records=min(accounting_limits.max_records,limits.max_records),
        max_relationships=min(accounting_limits.max_relationships,limits.max_edges),
        max_work=min(accounting_limits.max_work,remaining_work))
    # Only this fresh derivation supplies ownership; no caller-supplied hint artifact is accepted.
    a=account(selection,inventory,proof,requested_inspections=requested_inspections,scope_sha256=scope_sha256,
        limits=effective,deadline_ns=deadline_ns,tick=checked_tick,checkpoint=checkpoint,reference_corpus=reference_corpus,
        **({} if runtime_context is None else {'runtime_context':runtime_context}),
        **({} if purpose_corpus is None else {'purpose_corpus':purpose_corpus}),
        **({} if access_context is None else {'access_context':access_context}),
        **({} if auth_history is None else {'auth_history':auth_history}))
    if (type(a)is not CorpusAccounting or a.policy!=accounting_policy or a.inventory_sha256!=inventory.summary_sha256
        or a.requested_inspections!=requested_inspections or not sha(a.summary_sha256)
        or type(a.work)is not int or not 0<=a.work<=effective.max_work
        or type(a.summary_bytes)is not int or not 0<a.summary_bytes<=effective.max_summary_bytes
        or type(a.entries)is not tuple or len(a.entries)!=len(index)
        or type(a.relationships)is not tuple or len(a.relationships)>limits.max_edges):
        raise ClassificationHeld('complete original recomputed accounting required')
    check(a.work)
    origins={}
    def context_reference(ref,policy):
        check(1)
        if type(ref)not in REFERENCES or ref.key not in index:
            raise ClassificationHeld('validated original context reference required')
        entry=index[ref.key]
        if type(ref.revision)is not int or ref.revision!=entry.revision or ref.sha256!=entry.payload_sha256:
            raise ClassificationHeld('context reference changed')
        origins.setdefault(ref.key,set()).add(policy)
    for ref in (proof.gate,proof.registry,proof.runtime):context_reference(ref,'EXACT_DRAIN_CONTEXT')
    if runtime_context is not None:
        for record in runtime_context.records:context_reference(record.reference,record.policy)
    if access_context is not None:
        for record in access_context.records:context_reference(record,ACCESS_CONTEXT_POLICY)
    if purpose_corpus is not None:
        for record in purpose_corpus.records:context_reference(record,PURPOSE_CONTEXT_POLICY)
    for family in selection.datasets.permissions.labels.families:
        check(1);context_reference(family.labels.recipe,'VALIDATED_LABEL_CONTEXT')
        for ref in family.labels.purposes:context_reference(ref,'VALIDATED_LABEL_CONTEXT')
    counts={name:0 for name in DISPOSITIONS};entries=[];rows={};memberships=0
    requested=set(requested_inspections)
    for position,row in enumerate(a.entries):
        check(1)
        if type(row)is not AccountedRecord or row.reference!=inventory.entries[position] or row.reference.key in rows:
            raise ClassificationHeld('complete unique original decisions required')
        if (type(row.disposition)is not str or type(row.reason)is not str or row.disposition not in counts or row.disposition in ('SHARED','UNRESOLVED')
            or not ordered(row.inspection_ids,limits.max_records) or not ordered(row.policies,len(CONTENT)+len(retention_policies))
            or not row.policies or not set(row.policies)<=CONTENT|retention_policies.keys()):
            raise ClassificationHeld('all families and collateral obligations must be resolved')
        memberships+=len(row.inspection_ids)
        if memberships>limits.max_edges:raise ClassificationHeld('classification membership bound exhausted')
        for ident in row.inspection_ids:
            check(1)
            if re.fullmatch('[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',ident)is None or Key('state','inspection#'+ident)not in index:
                raise ClassificationHeld('validated original inspection roots required')
        content=set(row.policies)&CONTENT;retention=()
        if row.disposition=='CONTEXT':
            if row.inspection_ids or content or row.reason!='VALIDATED_INTERPRETATION_OR_FENCE' or not set(row.policies)<=origins.get(row.reference.key,set()):
                raise ClassificationHeld('explicit validated context retention rationale required')
            retention=tuple(sorted(retention_policies[p] for p in row.policies))
        else:
            inside=set(row.inspection_ids)&requested
            if (not row.inspection_ids or not content or (row.disposition=='AFFECTED' and
                    (set(row.inspection_ids)!=inside or row.reason!='VALIDATED_CONTENT_MEMBERSHIP'))
                or (row.disposition=='UNRELATED' and (inside or row.reason!='SUPPORTED_OTHER_INSPECTION_CONTENT'))):
                raise ClassificationHeld('exact content ownership and original scope required')
        rows[row.reference.key]=row;counts[row.disposition]+=1
        entries.append(ClassificationEntry(index[row.reference.key],row.disposition,row.reason,row.inspection_ids,row.policies,retention))
    if (type(a.counts)is not tuple or any(type(pair)is not tuple or len(pair)!=2 or type(pair[0])is not str
        or type(pair[1])is not int for pair in a.counts) or a.counts!=tuple(counts.items())):
        raise ClassificationHeld('complete strict original counts required')
    seen=set();edge_members={};edge_policies={};previous=None
    for link in a.relationships:
        check(1)
        if (type(link)is not AccountingLink or type(link.source)is not Key or type(link.inspection)is not Key
            or any(type(v)is not str for v in (link.source.table,link.source.resource,link.inspection.table,link.inspection.resource,link.policy))):
            raise ClassificationHeld('typed original classification edges required')
        row=rows.get(link.source);ident=link.inspection.resource.removeprefix('inspection#')
        identity=(link.source.table,link.source.resource,link.inspection.table,link.inspection.resource,link.policy)
        if (row is None or row.disposition=='CONTEXT' or link.policy not in CONTENT or link.policy not in row.policies
            or link.inspection!=Key('state','inspection#'+ident) or link.inspection not in index
            or ident not in row.inspection_ids or identity in seen or (previous is not None and identity<=previous)):
            raise ClassificationHeld('exact ordered content membership edges required')
        previous=identity;seen.add(identity);edge_members.setdefault(link.source,set()).add(ident);edge_policies.setdefault(link.source,set()).add(link.policy)
    for key,row in rows.items():
        check(1)
        if row.disposition!='CONTEXT' and (edge_members.get(key,set())!=set(row.inspection_ids) or edge_policies.get(key,set())!=set(row.policies)&CONTENT):
            raise ClassificationHeld('complete validated content relationships required')
    # Check the complete fresh accounting digest as well as every decision/reference.
    _check_accounting_digest(a,inventory,requested_inspections,max_summary_bytes=effective.max_summary_bytes,
        check=check,runtime_context=runtime_context,purpose_corpus=purpose_corpus,
        access_context=access_context,auth_history=auth_history)
    def framed(value):
        payload=_encoded(value);return str(len(payload)).encode()+b':'+payload
    summary=hashlib.sha256();size=0
    def bind(value):
        nonlocal size
        check(1);payload=framed(value);size+=len(payload)
        if size>limits.max_summary_bytes:raise ClassificationHeld('classification summary bound exhausted')
        summary.update(payload)
    bind((policy,inventory.summary_sha256,scope_sha256,a.summary_sha256,requested_inspections,a.counts))
    for entry in entries:bind(asdict(entry))
    for link in a.relationships:bind(asdict(link))
    check()
    return OwnershipClassification(policy,inventory.summary_sha256,scope_sha256,a.summary_sha256,summary.hexdigest(),
        requested_inspections,tuple(entries),a.relationships,a,a.counts,work,size)
