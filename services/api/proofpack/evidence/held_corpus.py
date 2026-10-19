"""Server-owned read/selection under an exact drain; no owner or cleanup grant."""
from dataclasses import dataclass, field, fields, is_dataclass, replace
import hashlib
import json
import re
from threading import Lock

from proofpack.calibrations.dependencies import digest
from proofpack.evidence.held_inventory import HeldInventoryReader, HeldInventoryLimits, HeldInventoryHeld
from proofpack.evidence.inventory import InventoryPass, InventoryHeld, reconcile
from proofpack.evidence.privacy_admission import PersistentAdmission, DrainProof, AdmissionHeld
from proofpack.evidence.repository import StoreConflict, StoreUnavailable
from proofpack.evidence.replay_corpus import ReplayCorpus, ReplayCorpusLimits, ReplayCorpusHeld, derive
from proofpack.runtime.control import uuid
from proofpack.runtime.ownership import ResourceOwner
from proofpack.evidence.corpus_accounting import account, AccountingLimits, AccountingHeld, CorpusAccounting,DISPOSITIONS,POLICY as ACCOUNTING_POLICY
from proofpack.evidence.reference_corpus import ReferenceCorpus,ReferenceCorpusLimits,ReferenceCorpusHeld,derive as reference_derive
from proofpack.evidence.collateral_scope import CollateralLimits,CollateralHeld,ScopeProposal,propose
from proofpack.evidence.ownership_classification import ClassificationLimits,ClassificationHeld,OwnershipClassification,classify,POLICY as CLASSIFICATION_POLICY
from proofpack.evidence.runtime_context import RuntimeContext,RuntimeContextLimits,RuntimeContextHeld,derive as runtime_derive,validate as validate_runtime_context
from proofpack.evidence.corpus_accounting import RUNTIME_POLICY as RUNTIME_ACCOUNTING_POLICY
from proofpack.evidence.ownership_classification import RUNTIME_POLICY as RUNTIME_CLASSIFICATION_POLICY
from proofpack.evidence.purpose_corpus import PurposeCorpus,PurposeCorpusLimits,PurposeCorpusHeld,derive as purpose_derive,validate as validate_purpose_corpus
from proofpack.evidence.corpus_accounting import PURPOSE_POLICY as PURPOSE_ACCOUNTING_POLICY
from proofpack.evidence.ownership_classification import PURPOSE_POLICY as PURPOSE_CLASSIFICATION_POLICY


from proofpack.evidence.access_context import AccessContext, AccessContextLimits, AccessContextHeld, derive as access_derive, validate as validate_access_context
from proofpack.evidence.corpus_accounting import ACCESS_POLICY as ACCESS_ACCOUNTING_POLICY
from proofpack.evidence.ownership_classification import ACCESS_POLICY as ACCESS_CLASSIFICATION_POLICY

from proofpack.evidence.auth_history import AuthHistory, AuthHistoryLimits, AuthHistoryHeld, derive as auth_derive, validate as validate_auth_history
from proofpack.evidence.corpus_accounting import AUTH_POLICY as AUTH_ACCOUNTING_POLICY
from proofpack.evidence.ownership_classification import AUTH_POLICY as AUTH_CLASSIFICATION_POLICY
from proofpack.evidence.metadata_history import MetadataHistory, MetadataHistoryLimits, MetadataHistoryHeld, derive as metadata_derive, validate as validate_metadata_history
from proofpack.evidence.corpus_accounting import METADATA_POLICY as METADATA_ACCOUNTING_POLICY

MAXIMUM = 2**63-1
PURE_CHECKPOINT_INTERVAL = 32


class HeldCorpusHeld(RuntimeError):
    pass


from proofpack.evidence.inspection_scope import InspectionScope, inspection_scope, scope_sha256, POLICY


@dataclass(frozen=True)
class HeldCorpusLimits:
    analysis: ReplayCorpusLimits
    max_total_snapshot_batches: int
    max_total_payload_bytes: int
    max_binding_bytes: int
    references: ReferenceCorpusLimits

    def __post_init__(self):
        if (type(self.analysis) is not ReplayCorpusLimits or type(self.references) is not ReferenceCorpusLimits
                or self.references.max_work>self.analysis.dataset.corpus.max_work or any(type(v) is not int
                or not 1 <= v <= MAXIMUM for v in (self.max_total_snapshot_batches,
                    self.max_total_payload_bytes, self.max_binding_bytes))):
            raise ValueError('explicit typed selection and cumulative read/binding limits required')


@dataclass(frozen=True)
class HeldCorpus:
    scope: InspectionScope
    proof: DrainProof
    inventory: InventoryPass
    selection: ReplayCorpus
    snapshot_batches: int
    payload_bytes: int
    binding_bytes: int
    binding_sha256: str
    references: ReferenceCorpus
    runtime_context: RuntimeContext | None = field(default=None,repr=False)
    purposes: PurposeCorpus | None = field(default=None,repr=False)
    access_context: AccessContext | None = field(default=None,repr=False)
    auth_history: AuthHistory | None = field(default=None,repr=False)
    metadata_history: MetadataHistory | None = field(default=None,repr=False)


@dataclass(frozen=True)
class HeldAccountedCorpus:
    corpus: HeldCorpus = field(repr=False)
    accounting: CorpusAccounting


@dataclass(frozen=True)
class HeldScopeProposal:
    corpus: HeldCorpus = field(repr=False)
    accounting: CorpusAccounting = field(repr=False)
    proposal: ScopeProposal


@dataclass(frozen=True)
class HeldClassifiedCorpus:
    corpus: HeldCorpus = field(repr=False)
    classification: OwnershipClassification


def _metadata_digest(value, *, max_bytes, tick):
    """Stream frozen typed metadata only; omitted private targets remain input-bound."""
    if type(max_bytes) is not int or not 1 <= max_bytes <= MAXIMUM or not callable(tick):
        raise ValueError('explicit metadata projection budget and trusted clock required')
    size = 0; next_tick = 0; hasher = hashlib.sha256(); active = set()

    def emit(text):
        nonlocal size, next_tick
        encoded = text.encode('utf-8'); size += len(encoded)
        if size > max_bytes: raise HeldCorpusHeld('metadata binding budget exhausted')
        hasher.update(encoded)
        if size >= next_tick:
            tick(); next_tick = size+1024

    def walk(item):
        if item is None or type(item) in {str, int, bool}:
            if type(item) is int and not 0 <= item <= MAXIMUM: raise HeldCorpusHeld('unsupported metadata integer')
            if type(item) is str and len(item) > max_bytes: raise HeldCorpusHeld('metadata binding budget exhausted')
            emit(json.dumps(item, ensure_ascii=True, allow_nan=False, separators=(',', ':')))
            return
        if type(item) is tuple or (is_dataclass(item) and not isinstance(item, type)):
            ident = id(item)
            if ident in active: raise HeldCorpusHeld('cyclic metadata projection')
            active.add(ident)
            try:
                if type(item) is tuple:
                    emit('[')
                    for index, element in enumerate(item):
                        if index: emit(',')
                        walk(element)
                    emit(']')
                else:
                    if not item.__dataclass_params__.frozen: raise HeldCorpusHeld('mutable metadata projection')
                    emit('["'+type(item).__module__+'.'+type(item).__name__+'",[')
                    first = True
                    for field in fields(item):
                        if not field.repr: continue
                        if not first: emit(',')
                        first = False; emit('['); walk(field.name); emit(',')
                        walk(getattr(item, field.name)); emit(']')
                    emit(']]')
            finally:
                active.remove(ident)
            return
        raise HeldCorpusHeld('raw payload or unsupported metadata projection')

    tick(); walk(value); tick()
    return size, hasher.hexdigest()


class HeldCorpusReader:
    def __init__(self, admission, resource_owner, *, inventory_limits, limits, tick):
        if (type(admission) is not PersistentAdmission or type(resource_owner) is not ResourceOwner
                or type(inventory_limits) is not HeldInventoryLimits or type(limits) is not HeldCorpusLimits
                or not callable(tick)):
            raise ValueError('exact shared admission/owner, finite limits and trusted clock required')
        if (limits.max_total_snapshot_batches < 2*inventory_limits.max_snapshot_batches
                or limits.max_total_payload_bytes < 2*inventory_limits.max_payload_bytes):
            raise ValueError('cumulative limits must cover both configured reconciliation phases')
        self.admission = admission; self.resource_owner = resource_owner
        self.inventory_limits = inventory_limits; self.limits = limits; self.tick = tick
        self._initial = (admission, resource_owner, inventory_limits, limits, tick, admission.repository)
        self._lock = Lock(); self.release_pending = False; self._pending_reader = None

    def read(self, *, request_id, inspection_ids, deadline_ns):
        return self._read(request_id=request_id, inspection_ids=inspection_ids,
            deadline_ns=deadline_ns, accounting_limits=None)

    def read_accounting(self, *, request_id, inspection_ids, deadline_ns, accounting_limits):
        if type(accounting_limits) is not AccountingLimits:
            raise ValueError('explicit finite accounting limits required')
        return self._read(request_id=request_id, inspection_ids=inspection_ids,
            deadline_ns=deadline_ns, accounting_limits=accounting_limits)

    def read_scope_proposal(self, *, request_id, inspection_ids, deadline_ns, accounting_limits, collateral_limits):
        if type(accounting_limits) is not AccountingLimits or type(collateral_limits) is not CollateralLimits:
            raise ValueError('explicit finite accounting and collateral limits required')
        return self._read(request_id=request_id, inspection_ids=inspection_ids, deadline_ns=deadline_ns,
            accounting_limits=accounting_limits, collateral_limits=collateral_limits)

    def read_classification(self, *, request_id, inspection_ids, deadline_ns, accounting_limits, classification_limits):
        if type(accounting_limits)is not AccountingLimits or type(classification_limits)is not ClassificationLimits:
            raise ValueError('explicit finite accounting and classification limits required')
        return self._read(request_id=request_id,inspection_ids=inspection_ids,deadline_ns=deadline_ns,
            accounting_limits=accounting_limits,classification_limits=classification_limits)

    def read_runtime_accounting(self, *, request_id, inspection_ids, deadline_ns, accounting_limits, runtime_context_limits):
        if type(accounting_limits)is not AccountingLimits or type(runtime_context_limits)is not RuntimeContextLimits:
            raise ValueError('explicit accounting and runtime context limits required')
        return self._read(request_id=request_id,inspection_ids=inspection_ids,deadline_ns=deadline_ns,
            accounting_limits=accounting_limits,runtime_context_limits=runtime_context_limits)

    def read_runtime_classification(self, *, request_id, inspection_ids, deadline_ns, accounting_limits, classification_limits, runtime_context_limits):
        if (type(accounting_limits)is not AccountingLimits or type(classification_limits)is not ClassificationLimits
                or type(runtime_context_limits)is not RuntimeContextLimits):
            raise ValueError('explicit accounting, classification and runtime context limits required')
        return self._read(request_id=request_id,inspection_ids=inspection_ids,deadline_ns=deadline_ns,
            accounting_limits=accounting_limits,classification_limits=classification_limits,runtime_context_limits=runtime_context_limits)

    def read_purpose_accounting(self, *, request_id, inspection_ids, deadline_ns, accounting_limits, runtime_context_limits, purpose_corpus_limits):
        if (type(accounting_limits)is not AccountingLimits or type(runtime_context_limits)is not RuntimeContextLimits
                or type(purpose_corpus_limits)is not PurposeCorpusLimits):
            raise ValueError('explicit finite runtime, purpose and accounting limits required')
        return self._read(request_id=request_id,inspection_ids=inspection_ids,deadline_ns=deadline_ns,
            accounting_limits=accounting_limits,runtime_context_limits=runtime_context_limits,purpose_corpus_limits=purpose_corpus_limits)

    def read_purpose_classification(self, *, request_id, inspection_ids, deadline_ns, accounting_limits, runtime_context_limits, purpose_corpus_limits, classification_limits):
        if (type(accounting_limits)is not AccountingLimits or type(runtime_context_limits)is not RuntimeContextLimits
                or type(purpose_corpus_limits)is not PurposeCorpusLimits or type(classification_limits)is not ClassificationLimits):
            raise ValueError('explicit finite runtime, purpose, accounting and classification limits required')
        return self._read(request_id=request_id,inspection_ids=inspection_ids,deadline_ns=deadline_ns,
            accounting_limits=accounting_limits,runtime_context_limits=runtime_context_limits,
            purpose_corpus_limits=purpose_corpus_limits,classification_limits=classification_limits)

    def read_access_accounting(self, *, request_id, inspection_ids, deadline_ns, accounting_limits, runtime_context_limits, access_context_limits, purpose_corpus_limits=None):
        if (type(accounting_limits)is not AccountingLimits or type(runtime_context_limits)is not RuntimeContextLimits
                or type(access_context_limits)is not AccessContextLimits):
            raise ValueError('explicit finite access, runtime and accounting limits required')
        return self._read(request_id=request_id,inspection_ids=inspection_ids,deadline_ns=deadline_ns,
            accounting_limits=accounting_limits,runtime_context_limits=runtime_context_limits,
            access_context_limits=access_context_limits,purpose_corpus_limits=purpose_corpus_limits)

    def read_access_classification(self, *, request_id, inspection_ids, deadline_ns, accounting_limits, runtime_context_limits, access_context_limits, classification_limits, purpose_corpus_limits=None):
        if (type(accounting_limits)is not AccountingLimits or type(runtime_context_limits)is not RuntimeContextLimits
                or type(access_context_limits)is not AccessContextLimits or type(classification_limits)is not ClassificationLimits):
            raise ValueError('explicit finite access, runtime, accounting and classification limits required')
        return self._read(request_id=request_id,inspection_ids=inspection_ids,deadline_ns=deadline_ns,
            accounting_limits=accounting_limits,runtime_context_limits=runtime_context_limits,
            access_context_limits=access_context_limits,purpose_corpus_limits=purpose_corpus_limits,classification_limits=classification_limits)

    def read_auth_accounting(self, *, request_id, inspection_ids, deadline_ns, accounting_limits, runtime_context_limits, access_context_limits, auth_history_limits, purpose_corpus_limits=None):
        if (type(accounting_limits) is not AccountingLimits or type(runtime_context_limits) is not RuntimeContextLimits
                or type(access_context_limits) is not AccessContextLimits or type(auth_history_limits) is not AuthHistoryLimits):
            raise ValueError('explicit independent auth/access/runtime/accounting limits required')
        return self._read(request_id=request_id,inspection_ids=inspection_ids,deadline_ns=deadline_ns,
            accounting_limits=accounting_limits,runtime_context_limits=runtime_context_limits,access_context_limits=access_context_limits,
            auth_history_limits=auth_history_limits,purpose_corpus_limits=purpose_corpus_limits)

    def read_auth_classification(self, *, request_id, inspection_ids, deadline_ns, accounting_limits, runtime_context_limits, access_context_limits, auth_history_limits, classification_limits, purpose_corpus_limits=None):
        if (type(accounting_limits) is not AccountingLimits or type(runtime_context_limits) is not RuntimeContextLimits
                or type(access_context_limits) is not AccessContextLimits or type(auth_history_limits) is not AuthHistoryLimits
                or type(classification_limits) is not ClassificationLimits):
            raise ValueError('explicit independent auth/access/runtime/accounting/classification limits required')
        return self._read(request_id=request_id,inspection_ids=inspection_ids,deadline_ns=deadline_ns,
            accounting_limits=accounting_limits,runtime_context_limits=runtime_context_limits,access_context_limits=access_context_limits,
            auth_history_limits=auth_history_limits,purpose_corpus_limits=purpose_corpus_limits,classification_limits=classification_limits)

    def read_metadata_accounting(self, *, request_id, inspection_ids, deadline_ns, accounting_limits,
            runtime_context_limits, access_context_limits, auth_history_limits, metadata_history_limits,
            metadata_configuration_sha256, purpose_corpus_limits=None):
        if type(metadata_history_limits) is not MetadataHistoryLimits:
            raise ValueError('explicit independent metadata history limits required')
        return self._read(request_id=request_id,inspection_ids=inspection_ids,deadline_ns=deadline_ns,
            accounting_limits=accounting_limits,runtime_context_limits=runtime_context_limits,
            access_context_limits=access_context_limits,auth_history_limits=auth_history_limits,
            metadata_history_limits=metadata_history_limits,metadata_configuration_sha256=metadata_configuration_sha256,
            purpose_corpus_limits=purpose_corpus_limits)

    def _read(self, *, request_id, inspection_ids, deadline_ns, accounting_limits, collateral_limits=None, classification_limits=None,runtime_context_limits=None,purpose_corpus_limits=None,access_context_limits=None,auth_history_limits=None,metadata_history_limits=None,metadata_configuration_sha256=None):
        if metadata_history_limits is not None or metadata_configuration_sha256 is not None:
            if (type(metadata_history_limits) is not MetadataHistoryLimits
                    or type(metadata_configuration_sha256) is not str or re.fullmatch('[a-f0-9]{64}',metadata_configuration_sha256) is None
                    or type(auth_history_limits) is not AuthHistoryLimits or type(access_context_limits) is not AccessContextLimits
                    or type(runtime_context_limits) is not RuntimeContextLimits or type(accounting_limits) is not AccountingLimits
                    or classification_limits is not None or collateral_limits is not None):
                raise ValueError('one explicit bounded metadata accounting operation and original configuration required')
        metadata_limits_signature=(None if metadata_history_limits is None else
            tuple(getattr(metadata_history_limits,f.name) for f in fields(metadata_history_limits)))
        if auth_history_limits is not None and (type(auth_history_limits) is not AuthHistoryLimits
                or type(access_context_limits) is not AccessContextLimits or type(runtime_context_limits) is not RuntimeContextLimits
                or type(accounting_limits) is not AccountingLimits or collateral_limits is not None):
            raise ValueError('one explicit bounded auth history/accounting operation required')
        if access_context_limits is not None and (type(access_context_limits)is not AccessContextLimits
                or type(runtime_context_limits)is not RuntimeContextLimits or type(accounting_limits)is not AccountingLimits or collateral_limits is not None):
            raise ValueError('one explicitly bounded access/runtime accounting or classification operation required')
        if purpose_corpus_limits is not None and (type(purpose_corpus_limits)is not PurposeCorpusLimits
                or type(runtime_context_limits)is not RuntimeContextLimits or collateral_limits is not None):
            raise ValueError('one explicitly bounded runtime/purpose operation required')
        if runtime_context_limits is not None and (type(runtime_context_limits)is not RuntimeContextLimits
                or type(accounting_limits)is not AccountingLimits or collateral_limits is not None):
            raise ValueError('one explicitly bounded runtime accounting/classification operation required')
        if classification_limits is not None and (type(classification_limits)is not ClassificationLimits
                or type(accounting_limits)is not AccountingLimits or collateral_limits is not None):
            raise ValueError('one explicitly bounded private classification operation required')
        if type(deadline_ns) is not int or not 1 <= deadline_ns <= MAXIMUM:
            raise ValueError('original positive absolute deadline required')
        uuid(request_id)
        admission, owner, inventory_limits, limits, tick, repository = self._initial
        scope = inspection_scope(repository.deployment, inspection_ids,
            max_inspections=limits.analysis.dataset.corpus.max_inspections)
        scope_hash = scope_sha256(scope)
        if self.release_pending is not False: raise HeldCorpusHeld('prior completion remains unconfirmed')
        if not self._lock.acquire(blocking=False): raise HeldCorpusHeld('reader incarnation already active')
        ticket = None; uncertain = False; inner = None; last_tick = -1

        def configuration():
            if (metadata_history_limits is not None and tuple(getattr(metadata_history_limits,f.name)
                    for f in fields(metadata_history_limits))!=metadata_limits_signature):
                raise HeldCorpusHeld('original metadata history limits changed')
            if (self.admission is not admission or self.resource_owner is not owner
                    or self.inventory_limits is not inventory_limits or self.limits is not limits
                    or self.tick is not tick or admission.repository is not repository):
                raise HeldCorpusHeld('read configuration changed')
            admission._check_target()

        def checked_tick():
            nonlocal last_tick
            configuration(); now = tick(); configuration()
            if type(now) is not int or not 0 <= now < deadline_ns or now < last_tick:
                raise HeldCorpusHeld('original corpus deadline or monotonic clock invalid')
            last_tick = now
            return now

        try:
            configuration()
            ticket = owner.acquire()  # Before the first coordinator/SDK read.
            checked_tick()
            proof = admission.drained(request_id=request_id, scope_sha256=scope_hash)

            def checkpoint():
                configuration(); admission.assert_drained(proof)
                checked_tick(); admission.assert_drained(proof)

            pure_checks = 0
            def pure_checkpoint():
                nonlocal pure_checks
                checked_tick(); pure_checks += 1
                if pure_checks % PURE_CHECKPOINT_INTERVAL == 0:
                    checkpoint()

            checkpoint()
            inner = HeldInventoryReader(admission, owner, limits=inventory_limits, tick=checked_tick)
            seed = inner.read(request_id=request_id, scope_sha256=scope_hash, deadline_ns=deadline_ns)
            checkpoint()
            if seed.proof != proof or seed.read_set.inventory != seed.inventory:
                raise HeldCorpusHeld('seed did not preserve the original proof/inventory')
            inventory = seed.inventory; seed_binding = seed.binding_sha256
            batches = seed.read_set.snapshot_batches; payload_bytes = seed.read_set.payload_bytes
            now_ms = admission._now(); checkpoint()
            raw = (*seed.read_set.rows, *seed.read_set.markers)
            selection = derive(raw, deployment=repository.deployment, requested_inspections=scope.inspection_ids,
                limits=limits.analysis, now_ms=now_ms, deadline_ns=deadline_ns,
                tick=checked_tick, checkpoint=pure_checkpoint)
            checkpoint()
            if type(selection) is not ReplayCorpus: raise HeldCorpusHeld('exact private selection required')
            references=reference_derive(raw,selection,deployment=repository.deployment,limits=limits.references,
                deadline_ns=deadline_ns,tick=checked_tick,checkpoint=pure_checkpoint)
            checkpoint()
            if type(references) is not ReferenceCorpus:raise HeldCorpusHeld('exact private references required')
            runtime_context=None
            accounting_policy=ACCOUNTING_POLICY;classification_policy=CLASSIFICATION_POLICY
            if runtime_context_limits is not None:
                effective_context_limits=runtime_context_limits if classification_limits is None else replace(
                    runtime_context_limits,max_work=min(runtime_context_limits.max_work,classification_limits.max_work))
                runtime_context=runtime_derive(raw,selection,inventory,proof,requested_inspections=scope.inspection_ids,
                    scope_sha256=scope_hash,now_ms=now_ms,limits=effective_context_limits,deadline_ns=deadline_ns,
                    tick=checked_tick,checkpoint=pure_checkpoint)
                checkpoint()
                validate_runtime_context(runtime_context,inventory,proof,scope_sha256=scope_hash,requested_inspections=scope.inspection_ids,checkpoint=pure_checkpoint)
                if (runtime_context.source_records>effective_context_limits.max_records
                        or runtime_context.payload_bytes>effective_context_limits.max_payload_bytes
                        or runtime_context.work>effective_context_limits.max_work
                        or runtime_context.summary_bytes>effective_context_limits.max_summary_bytes):
                    raise HeldCorpusHeld('original finite runtime context bounds required')
                accounting_policy=RUNTIME_ACCOUNTING_POLICY;classification_policy=RUNTIME_CLASSIFICATION_POLICY
            purposes=None
            if purpose_corpus_limits is not None:
                effective_purpose_limits=purpose_corpus_limits
                if classification_limits is not None:
                    remaining=classification_limits.max_work-runtime_context.work
                    if remaining<1:raise HeldCorpusHeld('classification work exhausted before purpose allocation')
                    effective_purpose_limits=replace(purpose_corpus_limits,max_work=min(purpose_corpus_limits.max_work,remaining))
                purposes=purpose_derive(raw,selection,inventory,proof,requested_inspections=scope.inspection_ids,
                    scope_sha256=scope_hash,limits=effective_purpose_limits,deadline_ns=deadline_ns,tick=checked_tick,checkpoint=pure_checkpoint)
                checkpoint()
                validate_purpose_corpus(purposes,inventory,proof,scope_sha256=scope_hash,requested_inspections=scope.inspection_ids,checkpoint=pure_checkpoint)
                if (purposes.family_count>effective_purpose_limits.max_families or purposes.work>effective_purpose_limits.max_work
                        or purposes.summary_bytes>effective_purpose_limits.max_summary_bytes):
                    raise HeldCorpusHeld('original finite purpose corpus bounds required')
                for family in purposes.families:
                    if (len(family.records)>purpose_corpus_limits.family.max_records
                            or family.payload_bytes>purpose_corpus_limits.family.max_payload_bytes
                            or len(family.dependencies)>purpose_corpus_limits.family.max_dependencies
                            or family.work>purpose_corpus_limits.family.max_work
                            or family.summary_bytes>purpose_corpus_limits.family.max_summary_bytes):
                        raise HeldCorpusHeld('original finite purpose family bounds required')
                accounting_policy=PURPOSE_ACCOUNTING_POLICY;classification_policy=PURPOSE_CLASSIFICATION_POLICY
            access_context=None
            if access_context_limits is not None:
                effective_access_limits=access_context_limits
                if classification_limits is not None:
                    remaining=classification_limits.max_work-runtime_context.work-(0 if purposes is None else purposes.work)
                    if remaining<1:raise HeldCorpusHeld('classification work exhausted before access allocation')
                    effective_access_limits=replace(access_context_limits,max_work=min(access_context_limits.max_work,remaining))
                access_context=access_derive(raw,selection,inventory,proof,requested_inspections=scope.inspection_ids,
                    scope_sha256=scope_hash,now_ms=now_ms,limits=effective_access_limits,deadline_ns=deadline_ns,tick=checked_tick,checkpoint=pure_checkpoint)
                checkpoint()
                validate_access_context(access_context,inventory,proof,scope_sha256=scope_hash,requested_inspections=scope.inspection_ids,checkpoint=pure_checkpoint)
                if (access_context.source_records>effective_access_limits.max_records or access_context.payload_bytes>effective_access_limits.max_payload_bytes
                        or access_context.work>effective_access_limits.max_work or access_context.summary_bytes>effective_access_limits.max_summary_bytes):
                    raise HeldCorpusHeld('original finite access context bounds required')
                accounting_policy=ACCESS_ACCOUNTING_POLICY;classification_policy=ACCESS_CLASSIFICATION_POLICY
            auth_history=None
            if auth_history_limits is not None:
                effective_auth_limits=auth_history_limits
                if classification_limits is not None:
                    remaining=classification_limits.max_work-runtime_context.work-access_context.work-(0 if purposes is None else purposes.work)
                    if remaining<1:raise HeldCorpusHeld('classification work exhausted before auth history allocation')
                    effective_auth_limits=replace(auth_history_limits,max_work=min(auth_history_limits.max_work,remaining))
                auth_history=auth_derive(raw,inventory,proof,access_context,requested_inspections=scope.inspection_ids,
                    scope_sha256=scope_hash,now_ms=now_ms,limits=effective_auth_limits,deadline_ns=deadline_ns,tick=checked_tick,checkpoint=pure_checkpoint)
                checkpoint()
                validate_auth_history(auth_history,inventory,proof,scope_sha256=scope_hash,
                    requested_inspections=scope.inspection_ids,checkpoint=pure_checkpoint)
                if (auth_history.source_records>effective_auth_limits.max_records
                        or auth_history.payload_bytes>effective_auth_limits.max_payload_bytes
                        or auth_history.dependencies>effective_auth_limits.max_dependencies
                        or auth_history.work>effective_auth_limits.max_work
                        or auth_history.summary_bytes>effective_auth_limits.max_summary_bytes):
                    raise HeldCorpusHeld('original finite auth history bounds required')
                accounting_policy=AUTH_ACCOUNTING_POLICY;classification_policy=AUTH_CLASSIFICATION_POLICY
            metadata_history=None
            if metadata_history_limits is not None:
                metadata_history=metadata_derive(raw,inventory,proof,auth_history,
                    configuration_sha256=metadata_configuration_sha256,requested_inspections=scope.inspection_ids,
                    scope_sha256=scope_hash,now_ms=now_ms,limits=metadata_history_limits,
                    deadline_ns=deadline_ns,tick=checked_tick,checkpoint=pure_checkpoint)
                checkpoint()
                validate_metadata_history(metadata_history,inventory,proof,auth_history,scope_sha256=scope_hash,
                    requested_inspections=scope.inspection_ids,checkpoint=pure_checkpoint)
                if (metadata_history.source_records>metadata_history_limits.max_records
                        or metadata_history.payload_bytes>metadata_history_limits.max_payload_bytes
                        or metadata_history.dependencies>metadata_history_limits.max_dependencies
                        or metadata_history.work>metadata_history_limits.max_work
                        or metadata_history.summary_bytes>metadata_history_limits.max_summary_bytes):
                    raise HeldCorpusHeld('original finite metadata history bounds required')
                accounting_policy=METADATA_ACCOUNTING_POLICY
            accounting = None;classification=None
            if classification_limits is not None:
                classification=classify(selection,inventory,proof,requested_inspections=scope.inspection_ids,
                    scope_sha256=scope_hash,accounting_limits=accounting_limits,limits=classification_limits,
                    deadline_ns=deadline_ns,tick=checked_tick,checkpoint=pure_checkpoint,reference_corpus=references,
                    **({} if runtime_context is None else {'runtime_context':runtime_context}),
                    **({} if purposes is None else {'purpose_corpus':purposes}),
                    **({} if access_context is None else {'access_context':access_context}),
                    **({} if auth_history is None else {'auth_history':auth_history}))
                checkpoint()
                if type(classification)is not OwnershipClassification:raise HeldCorpusHeld('exact complete private classification required')
                accounting=classification.accounting
                if (type(accounting)is not CorpusAccounting or classification.policy!=classification_policy
                    or classification.inventory_sha256!=inventory.summary_sha256 or classification.scope_sha256!=scope_hash
                    or classification.requested_inspections!=scope.inspection_ids
                    or accounting.policy!=accounting_policy or accounting.inventory_sha256!=inventory.summary_sha256
                    or accounting.requested_inspections!=scope.inspection_ids or classification.accounting_sha256!=accounting.summary_sha256
                    or type(classification.summary_sha256)is not str or re.fullmatch('[a-f0-9]{64}',classification.summary_sha256)is None
                    or classification.historical is not True or classification.read_only is not True
                    or any(v is not False for v in (classification.can_confirm_cleanup,classification.erasure_complete,classification.request_fulfilled))
                    or type(classification.work)is not int or not 1<=classification.work<=classification_limits.max_work
                    or type(classification.summary_bytes)is not int or not 1<=classification.summary_bytes<=classification_limits.max_summary_bytes
                    or type(classification.entries)is not tuple or len(classification.entries)!=len(inventory.entries)
                    or type(accounting.entries)is not tuple or len(accounting.entries)!=len(inventory.entries)
                    or type(classification.relationships)is not tuple or len(classification.relationships)>classification_limits.max_edges
                    or classification.relationships!=accounting.relationships):
                    raise HeldCorpusHeld('original bounded non-authorizing classification binding required')
                for counts in (classification.counts,accounting.counts):
                    if (type(counts)is not tuple or len(counts)!=len(DISPOSITIONS)
                        or any(type(pair)is not tuple or len(pair)!=2 or type(pair[0])is not str
                            or type(pair[1])is not int or not 0<=pair[1]<=MAXIMUM for pair in counts)
                        or tuple(name for name,count in counts)!=DISPOSITIONS
                        or sum(count for name,count in counts)!=len(inventory.entries)
                        or any(count for name,count in counts if name in ('SHARED','UNRESOLVED'))):
                        raise HeldCorpusHeld('complete strict accepted classification counts required')
                if classification.counts!=accounting.counts:raise HeldCorpusHeld('original classification accounting mismatch')
            elif accounting_limits is not None:
                accounting = account(selection, inventory, proof, requested_inspections=scope.inspection_ids,
                    scope_sha256=scope_hash, limits=accounting_limits, deadline_ns=deadline_ns,
                    tick=checked_tick, checkpoint=pure_checkpoint,reference_corpus=references,
                    **({} if runtime_context is None else {'runtime_context':runtime_context}),
                    **({} if purposes is None else {'purpose_corpus':purposes}),
                    **({} if access_context is None else {'access_context':access_context}),
                    **({} if auth_history is None else {'auth_history':auth_history}),
                    **({} if metadata_history is None else {'metadata_history':metadata_history}))
                checkpoint()
                if type(accounting) is not CorpusAccounting:
                    raise HeldCorpusHeld('exact private accounting required')
            proposal = None
            if collateral_limits is not None:
                proposal = propose(accounting, limits=collateral_limits, deadline_ns=deadline_ns,
                    tick=checked_tick, checkpoint=pure_checkpoint)
                checkpoint()
            del raw, seed
            final = reconcile(repository, inventory, limits=inventory_limits.inventory,
                max_snapshot_batches=inventory_limits.max_snapshot_batches,
                max_payload_bytes=inventory_limits.max_payload_bytes, deadline_ns=deadline_ns,
                checkpoint=checkpoint, tick=checked_tick)
            batches += final.snapshot_batches; payload_bytes += final.payload_bytes
            if (type(batches) is not int or type(payload_bytes) is not int
                    or batches > limits.max_total_snapshot_batches or payload_bytes > limits.max_total_payload_bytes):
                raise HeldCorpusHeld('cumulative private read budget exhausted')
            del final
            context = (1, POLICY, PURE_CHECKPOINT_INTERVAL, scope, proof, inventory, seed_binding, inventory_limits,
                limits, now_ms, selection, references, batches, payload_bytes)
            if accounting is not None: context += (accounting_limits, accounting)
            if proposal is not None: context += (collateral_limits, proposal)
            if classification is not None: context += (classification_limits,classification)
            if runtime_context is not None:context+=(runtime_context_limits,runtime_context)
            if purposes is not None:context+=(purpose_corpus_limits,purposes)
            if access_context is not None:context+=(access_context_limits,access_context)
            if auth_history is not None:context+=(auth_history_limits,auth_history)
            if metadata_history is not None:context+=(metadata_history_limits,metadata_configuration_sha256,metadata_history)
            binding_bytes, binding = _metadata_digest(context,
                max_bytes=limits.max_binding_bytes, tick=checked_tick)
            checkpoint()
            corpus = HeldCorpus(scope, proof, inventory, selection, batches, payload_bytes, binding_bytes, binding,references,runtime_context,purposes,access_context,auth_history,metadata_history)
            if proposal is not None: return HeldScopeProposal(corpus,accounting,proposal)
            if classification is not None:return HeldClassifiedCorpus(corpus,classification)
            return corpus if accounting is None else HeldAccountedCorpus(corpus,accounting)
        except (AdmissionHeld, HeldInventoryHeld, InventoryHeld, ReplayCorpusHeld, ReferenceCorpusHeld,AccountingHeld,CollateralHeld,ClassificationHeld,RuntimeContextHeld,PurposeCorpusHeld,AccessContextHeld,AuthHistoryHeld,MetadataHistoryHeld, StoreConflict, StoreUnavailable):
            raise HeldCorpusHeld('exact held corpus read/selection is unavailable') from None
        except BaseException as error:
            if not isinstance(error, Exception):
                uncertain = True; self.release_pending = True; self._pending_reader = inner
            raise
        finally:
            try:
                if inner is not None and inner.release_pending:
                    self.release_pending = True; self._pending_reader = inner
                if ticket is not None and not uncertain:
                    try: owner.release(ticket)
                    except BaseException:
                        self.release_pending = True
                        raise
            finally:
                self._lock.release()
