"""Selected operational purpose interpretation; never renewed rights or ownership."""
from dataclasses import asdict, dataclass, field, replace
import hashlib
import re
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.inventory import InventoryPass, _encoded
from proofpack.evidence.inspection_corpus import CorpusReference
from proofpack.evidence.label_corpus import _snapshot, _inspection_references
from proofpack.evidence.replay_corpus import ReplayCorpus
from proofpack.evidence.privacy_admission import DrainProof
from proofpack.evidence.resource_lineage import decode, MissingResourceBindings, InvalidResourceBindings
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.purpose_history import PurposeHistory,PurposeRecord,PurposeDependency,PurposeHistoryLimits,PurposeHistoryHeld,discover
from proofpack.runtime.control import uuid

MAXIMUM=2**63-1
POLICY='purpose-context-v1'
CONTEXT_POLICY='VALIDATED_OPERATIONAL_PURPOSE_CONTEXT'
RETENTION_REASON='retained_original_operational_purpose_and_history_for_interpretation'


class PurposeCorpusHeld(RuntimeError):pass


@dataclass(frozen=True)
class PurposeCorpusLimits:
    max_families:int
    family:PurposeHistoryLimits
    max_work:int
    max_summary_bytes:int

    def __post_init__(self):
        if type(self.family)is not PurposeHistoryLimits or any(type(v)is not int or not 1<=v<=MAXIMUM for v in
                (self.max_families,self.max_work,self.max_summary_bytes)):
            raise ValueError('explicit nested finite purpose corpus limits required')


@dataclass(frozen=True)
class PurposeUse:
    inspection:CorpusReference=field(repr=False)
    source:CorpusReference=field(repr=False)
    purpose:Key=field(repr=False)


@dataclass(frozen=True)
class PurposeCorpus:
    policy:str
    inventory_sha256:str
    proof_sha256:str
    scope_sha256:str
    requested_inspections:tuple[str,...]=field(repr=False)
    families:tuple[PurposeHistory,...]=field(repr=False)
    records:tuple[CorpusReference,...]=field(repr=False)
    uses:tuple[PurposeUse,...]=field(repr=False)
    source_records:int
    family_count:int
    work:int
    summary_bytes:int
    summary_sha256:str
    read_only:bool=True
    rights_independently_verified:bool=False
    can_confirm_cleanup:bool=False


def _projection(value):return {k:v for k,v in asdict(value).items() if k not in {'summary_sha256','summary_bytes'}}


def validate(value,inventory,proof,*,scope_sha256,requested_inspections,checkpoint):
    def hold():raise PurposeCorpusHeld('exact bounded original non-authorizing purpose corpus required')
    checkpoint()
    if (type(value)is not PurposeCorpus or value.policy!=POLICY or value.inventory_sha256!=inventory.summary_sha256
            or value.proof_sha256!=hashlib.sha256(_encoded(asdict(proof))).hexdigest()
            or value.scope_sha256!=scope_sha256 or value.requested_inspections!=requested_inspections
            or value.read_only is not True or value.rights_independently_verified is not False or value.can_confirm_cleanup is not False
            or type(value.source_records)is not int or value.source_records!=len(inventory.entries)
            or type(value.family_count)is not int or type(value.families)is not tuple or value.family_count!=len(value.families)
            or type(value.work)is not int or not 1<=value.work<=MAXIMUM
            or type(value.summary_bytes)is not int or not 1<=value.summary_bytes<=MAXIMUM
            or any(type(v)is not tuple or len(v)>len(inventory.entries) for v in (value.records,value.uses,value.families))):hold()
    index={e.key:e for e in inventory.entries}
    def reference(r):
        checkpoint()
        if type(r)is not CorpusReference or type(r.key)is not Key:hold()
        e=index.get(r.key)
        if (e is None or e.kind!='live' or r.kind!='live' or type(r.revision)is not int or r.revision!=e.revision
                or r.sha256!=e.payload_sha256 or r.marker_resource_sha256 is not None):hold()
        return r.key
    records={};previous=None
    for r in value.records:
        key=reference(r);identity=(key.table,key.resource)
        if previous is not None and identity<=previous:hold()
        previous=identity;records[key]=r
    family_records={};roots=set()
    for family in value.families:
        checkpoint()
        if (type(family)is not PurposeHistory or family.policy!='purpose-history-v1' or family.historical is not True
                or family.rights_independently_verified is not False or family.can_confirm_cleanup is not False
                or type(family.purpose)is not PurposeRecord or type(family.purpose.key)is not Key
                or type(family.state)is not str or family.state not in {'ACTIVE_HISTORY','WITHDRAWN_HISTORY'}
                or type(family.records)is not tuple or len(family.records)>len(value.records)
                or type(family.dependencies)is not tuple
                or any(type(v)is not int or not 1<=v<=MAXIMUM for v in (family.work,family.payload_bytes,family.summary_bytes))):hold()
        if family.purpose.key in roots:hold()
        roots.add(family.purpose.key)
        for r in family.records:
            if type(r)is not PurposeRecord or type(r.key)is not Key or type(r.revision)is not int:hold()
            expected=records.get(r.key)
            if expected is None or r.revision!=expected.revision or r.sha256!=expected.sha256 or r.key in family_records:hold()
            family_records[r.key]=r
        if family_records.get(family.purpose.key)!=family.purpose:hold()
        for r in family.dependencies:
            checkpoint()
            if (type(r)is not PurposeDependency or type(r.key)is not Key or type(r.revision)is not int
                    or not 1<=r.revision<=MAXIMUM or type(r.sha256)is not str or re.fullmatch('[a-f0-9]{64}',r.sha256)is None
                    or type(r.kind)is not str or r.kind not in {'write','check'}):hold()
        payload=_encoded({'policy':family.policy,'deployment':inventory.deployment,'state':family.state,
            'records':[asdict(r) for r in family.records],'dependencies':[asdict(r) for r in family.dependencies]})
        if len(payload)!=family.summary_bytes or hashlib.sha256(payload).hexdigest()!=family.summary_sha256:hold()
    if family_records.keys()!=records.keys():hold()
    identities=[]
    for use in value.uses:
        if type(use)is not PurposeUse:hold()
        inspection=reference(use.inspection);source=reference(use.source)
        if use.purpose not in roots:hold()
        identities.append((inspection.table,inspection.resource,source.table,source.resource,use.purpose.resource))
    if identities!=sorted(set(identities)) or {u.purpose for u in value.uses}!=roots:hold()
    payload=_encoded(_projection(value));checkpoint()
    if len(payload)!=value.summary_bytes or hashlib.sha256(payload).hexdigest()!=value.summary_sha256:hold()
    return value


def derive(rows,selection,inventory,proof,*,requested_inspections,scope_sha256,limits,deadline_ns,tick,checkpoint):
    if (type(rows)is not tuple or type(selection)is not ReplayCorpus or type(inventory)is not InventoryPass
            or type(proof)is not DrainProof or type(limits)is not PurposeCorpusLimits or type(deadline_ns)is not int
            or not 1<=deadline_ns<=MAXIMUM or not callable(tick) or not callable(checkpoint)):
        raise ValueError('exact bounded original held purpose inputs required')
    work=0;last=-1
    def check(cost=0):
        nonlocal work,last
        work+=cost
        if work>limits.max_work:raise PurposeCorpusHeld('purpose corpus cumulative work exhausted')
        checkpoint();now=tick()
        if type(now)is not int or not 0<=now<deadline_ns or now<last:raise PurposeCorpusHeld('original purpose corpus deadline or clock invalid')
        last=now;checkpoint()
    def hold():raise PurposeCorpusHeld('complete selected original purpose history/use required')
    try:
        check()
        if (type(requested_inspections)is not tuple or not requested_inspections or any(type(v)is not str for v in requested_inspections)
                or requested_inspections!=tuple(sorted(set(requested_inspections)))):hold()
        for ident in requested_inspections:uuid(ident)
        if type(scope_sha256)is not str or re.fullmatch('[a-f0-9]{64}',scope_sha256)is None or proof.scope_sha256!=scope_sha256:hold()
        encoded=_encoded({'deployment':inventory.deployment,'tables':dict(inventory.tables),'entries':[asdict(e) for e in inventory.entries]})
        if len(encoded)!=inventory.summary_bytes or hashlib.sha256(encoded).hexdigest()!=inventory.summary_sha256:hold()
        refs=_inspection_references(selection.datasets.permissions.labels.inspections)
        expected={e.key:CorpusReference(e.key,e.revision,e.kind,e.payload_sha256 if e.kind=='live' else e.reference_sha256,e.resource_sha256) for e in inventory.entries}
        if refs!=expected:hold()
        copied=_snapshot(rows,expected,check)
        for r in (proof.gate,proof.registry,proof.runtime):
            e=expected.get(r.key)
            if e is None or e.kind!='live' or e.revision!=r.revision or e.sha256!=r.sha256:hold()
        uses=set();historical={};selected=set()
        def use(inspection,source,purpose):
            check(1);uuid(purpose)
            target=Key('state','purpose#'+purpose)
            if type(copied.get(target))is not Row:hold()
            selected.add(target)
            if len(selected)>limits.max_families:raise PurposeCorpusHeld('purpose corpus family bound exhausted')
            uses.add(PurposeUse(expected[inspection],expected[source],target))
            return target
        for family in selection.datasets.permissions.labels.inspections.families:
            check(1)
            records={r.key:r for r in family.capture.records}
            for media in family.capture.media:
                check(1);source=copied[media.source]
                if media.source not in records or records[media.source].sha256!=_payload_sha256(source.data):hold()
                target=use(family.capture.inspection.key,media.source,source.data['purpose_id'])
                dependencies=[r for r in family.capture.dependencies if r.key==target]
                if not dependencies:hold()
                historical.setdefault(target,set()).update((r.revision,r.sha256) for r in dependencies)
        for family in selection.datasets.permissions.labels.families:
            inspection=Key('state','inspection#'+family.inspection_id)
            for r in family.labels.purposes:
                check(1)
                if expected.get(r.key)!=CorpusReference(r.key,r.revision,'live',r.sha256):hold()
                use(inspection,r.key,copied[r.key].data['id'])
        groups={key:[] for key in selected}
        for row in copied.values():
            check(1)
            if type(row)is not Row:continue
            raw=row.data.get('resource_bindings');operation=raw.get('operation') if type(raw)is dict else None
            if operation not in {'purpose-create','purpose-withdraw'} and row.data.get('kind') not in {'purpose-create','purpose-withdraw'}:continue
            binding=decode(row,deployment=inventory.deployment)
            targets={r.key for r in (*binding.writes,*binding.checks)}&selected
            details=row.data.get('details');result=row.data.get('result')
            for value in (details.get('purpose_id') if type(details)is dict else None,result.get('id') if type(result)is dict else None):
                if type(value)is str and Key('state','purpose#'+value) in selected:targets.add(Key('state','purpose#'+value))
            for target in targets:groups[target].append(row)
        families=[];records={}
        for key in sorted(selected,key=lambda k:(k.table,k.resource)):
            check(1);remaining=limits.max_work-work
            if remaining<1:raise PurposeCorpusHeld('purpose corpus exhausted before family allocation')
            family=discover(copied[key],tuple(sorted(groups[key],key=lambda r:(r.key.table,r.key.resource))),deployment=inventory.deployment,
                limits=replace(limits.family,max_work=min(limits.family.max_work,remaining)),deadline_ns=deadline_ns,tick=tick,checkpoint=lambda:check())
            check(family.work)
            current=copied[key];initial={k:v for k,v in current.data.items() if k!='withdrawn_at_ms'}|{'withdrawn':False}
            allowed={(1,_payload_sha256(initial)),(current.revision,_payload_sha256(current.data))}
            if not historical.get(key,set())<=allowed:hold()
            for ref in family.records:
                check(1);r=expected.get(ref.key)
                if r is None or r.kind!='live' or r.revision!=ref.revision or r.sha256!=ref.sha256 or ref.key in records:hold()
                records[ref.key]=r
            families.append(family)
        ordered=tuple(sorted(uses,key=lambda u:(u.inspection.key.table,u.inspection.key.resource,u.source.key.table,u.source.key.resource,u.purpose.resource)))
        value=PurposeCorpus(POLICY,inventory.summary_sha256,hashlib.sha256(_encoded(asdict(proof))).hexdigest(),scope_sha256,
            requested_inspections,tuple(families),tuple(records[k] for k in sorted(records,key=lambda k:(k.table,k.resource))),
            ordered,len(rows),len(families),work,1,'')
        payload=_encoded(_projection(value))
        if len(payload)>limits.max_summary_bytes:raise PurposeCorpusHeld('purpose corpus summary bound exhausted')
        value=replace(value,summary_bytes=len(payload),summary_sha256=hashlib.sha256(payload).hexdigest())
        check();return validate(value,inventory,proof,scope_sha256=scope_sha256,requested_inspections=requested_inspections,checkpoint=check)
    except (PurposeHistoryHeld,MissingResourceBindings,InvalidResourceBindings,ValueError,TypeError,KeyError,AttributeError,ArithmeticError,RecursionError):
        raise PurposeCorpusHeld('exact complete selected original purpose corpus unavailable') from None
