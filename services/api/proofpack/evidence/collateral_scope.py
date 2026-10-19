"""Private advisory whole-artifact scope closure; never a cleanup capability."""
from collections import deque
from dataclasses import dataclass,field,asdict
import hashlib,re
from proofpack.evidence.corpus_accounting import CorpusAccounting,AccountedRecord,POLICY,DISPOSITIONS
from proofpack.evidence.inventory import InventoryEntry,_encoded
from proofpack.evidence.repository import Key
from proofpack.runtime.control import uuid

MAXIMUM=2**63-1
CONTENT=frozenset(('CAPTURE_CONTENT','HUMAN_CONTENT','SUPPORT_CONTENT','LABEL_CONTENT','OPTIONAL_PERMISSION_CONTENT','DATASET_ARTIFACT_CONTENT','REPLAY_RESULT_CONTENT'))
class CollateralHeld(RuntimeError):pass
@dataclass(frozen=True)
class CollateralLimits:
    max_records:int
    max_memberships:int
    max_scope:int
    max_work:int
    def __post_init__(self):
        if any(type(v)is not int or not 1<=v<=MAXIMUM for v in (self.max_records,self.max_memberships,self.max_scope,self.max_work)):
            raise ValueError('independent finite collateral bounds required')
@dataclass(frozen=True)
class ScopeProposal:
    policy:str
    accounting_sha256:str
    original_scope:tuple[str,...]=field(repr=False)
    proposed_scope:tuple[str,...]=field(repr=False)
    implicated:tuple[InventoryEntry,...]=field(repr=False)
    unresolved:tuple[InventoryEntry,...]=field(repr=False)
    summary_sha256:str
    work:int
    historical:bool=True
    can_confirm_cleanup:bool=False

def propose(accounting,*,limits,deadline_ns,tick,checkpoint):
    if type(accounting)is not CorpusAccounting or type(limits)is not CollateralLimits or type(deadline_ns)is not int or not 1<=deadline_ns<=MAXIMUM or not callable(tick) or not callable(checkpoint):
        raise ValueError('typed accounting, finite limits and original clock/checkpoint required')
    work=0;last=-1
    def check(cost=0):
        nonlocal work,last
        work+=cost
        if work>limits.max_work:raise CollateralHeld('collateral work bound exhausted')
        checkpoint();now=tick()
        if type(now)is not int or not 0<=now<deadline_ns or now<last:raise CollateralHeld('original collateral deadline or clock invalid')
        last=now;checkpoint()
    def ids(values,cap):
        if type(values)is not tuple or len(values)>cap or any(type(v)is not str for v in values) or tuple(sorted(set(values)))!=values:raise CollateralHeld('ordered unique inspection membership required')
        for ident in values:check(1);uuid(ident)
        return values
    check();scope=ids(accounting.requested_inspections,limits.max_scope)
    if not scope or len(scope)>limits.max_scope or accounting.policy!=POLICY or type(accounting.summary_sha256)is not str or re.fullmatch('[a-f0-9]{64}',accounting.summary_sha256)is None:
        raise CollateralHeld('original bounded accounting scope/policy required')
    if type(accounting.entries)is not tuple or len(accounting.entries)>limits.max_records:raise CollateralHeld('collateral record bound exhausted')
    reverse={};records={};unknown=[];memberships=0;counts={k:0 for k in DISPOSITIONS};original=set(scope)
    for row in accounting.entries:
        check(1)
        if type(row)is not AccountedRecord or type(row.reference)is not InventoryEntry or type(row.reference.key)is not Key or row.disposition not in counts:raise CollateralHeld('typed accounting entry required')
        ref=row.reference;key=ref.key
        valid_sha=lambda v:type(v)is str and re.fullmatch('[a-f0-9]{64}',v)is not None
        if type(key.table)is not str or key.table not in ('state','events') or type(key.resource)is not str or not 1<=len(key.resource)<=256 or type(ref.revision)is not int or not 1<=ref.revision<=MAXIMUM:
            raise CollateralHeld('bounded exact record reference required')
        if ref.kind=='live':
            valid=valid_sha(ref.payload_sha256) and ref.reference_sha256 is None and ref.resource_sha256 is None
        elif ref.kind=='erased':
            valid=ref.revision>=2 and ref.payload_sha256 is None and valid_sha(ref.reference_sha256) and valid_sha(ref.resource_sha256)
        else:valid=False
        if not valid or (ref.kind=='erased' and row.disposition!='UNRESOLVED'):raise CollateralHeld('intact original record or unresolved retained marker required')
        if key in records:raise CollateralHeld('duplicate accounting identity')
        records[key]=row;counts[row.disposition]+=1
        members=ids(row.inspection_ids,limits.max_memberships-memberships);memberships+=len(members)
        if memberships>limits.max_memberships:raise CollateralHeld('collateral membership bound exhausted')
        if row.disposition=='UNRESOLVED':unknown.append(row.reference);continue
        if row.disposition=='CONTEXT':continue
        if not members or type(row.policies)is not tuple or not row.policies or any(type(v)is not str or v not in CONTENT for v in row.policies):raise CollateralHeld('supported content policy required')
        relevant=set(members)&original
        expected='SHARED' if relevant and set(members)-original else 'AFFECTED' if relevant else 'UNRELATED'
        if row.disposition!=expected:raise CollateralHeld('accounting scope disposition mismatch')
        for ident in members:check(1);reverse.setdefault(ident,[]).append(key)
    if (type(accounting.counts)is not tuple or any(type(pair)is not tuple or len(pair)!=2 or type(pair[0])is not str or type(pair[1])is not int for pair in accounting.counts) or accounting.counts!=tuple(counts.items())):raise CollateralHeld('complete accounting counts required')
    proposed=set(scope);queue=deque(scope);seen=set()
    while queue:
        check(1);ident=queue.popleft()
        for key in reverse.get(ident,()):
            check(1)
            if key in seen:continue
            seen.add(key)
            for other in records[key].inspection_ids:
                check(1)
                if other not in proposed:
                    if len(proposed)>=limits.max_scope:raise CollateralHeld('expanded collateral scope bound exhausted')
                    proposed.add(other);queue.append(other)
    sort=lambda ref:(ref.key.table,ref.key.resource)
    implicated=tuple(sorted((records[k].reference for k in seen),key=sort));unresolved=tuple(sorted(unknown,key=sort));expanded=tuple(sorted(proposed))
    check(len(implicated)+len(unresolved))
    payload=_encoded(('whole-artifact-collateral-proposal-v1',accounting.summary_sha256,scope,expanded,[asdict(r) for r in implicated],[asdict(r) for r in unresolved]))
    digest=hashlib.sha256(payload).hexdigest();check()
    return ScopeProposal('whole-artifact-collateral-proposal-v1',accounting.summary_sha256,scope,expanded,implicated,unresolved,digest,work)
