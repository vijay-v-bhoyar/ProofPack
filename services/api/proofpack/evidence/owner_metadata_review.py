"""Owner-authorized conservative accounting review; never cleanup authority."""
from dataclasses import dataclass,asdict
from proofpack.evidence.owner_metadata import OwnerMetadataRequests,request_key,_version
from proofpack.evidence.held_corpus import HeldCorpusReader,HeldAccountedCorpus,HeldScopeProposal,HeldCorpusHeld,HeldCorpusLimits,scope_sha256
from proofpack.evidence.held_inventory import HeldInventoryLimits
from proofpack.evidence.corpus_accounting import AccountingLimits,AccountedRecord,POLICY,AUTH_POLICY,METADATA_POLICY,DISPOSITIONS
from proofpack.evidence.collateral_scope import CollateralLimits,ScopeProposal
from proofpack.evidence.inventory import InventoryEntry
from proofpack.evidence.repository import Key,StoreConflict
from proofpack.evidence.inventory import reconcile,InventoryHeld,_encoded
from proofpack.runtime.control import integer,uuid


from proofpack.evidence.runtime_context import RuntimeContextLimits
from proofpack.evidence.access_context import AccessContextLimits
from proofpack.evidence.auth_history import AuthHistoryLimits,AuthHistoryHeld,FAMILIES as AUTH_FAMILIES,validate as validate_auth_history
from proofpack.evidence.purpose_corpus import PurposeCorpusLimits
from proofpack.evidence.metadata_history import MetadataHistoryLimits,MetadataHistoryHeld,FAMILIES as METADATA_FAMILIES,validate as validate_metadata_history

MAXIMUM=9007199254740991


@dataclass(frozen=True)
class AuthReviewLimits:
    runtime:RuntimeContextLimits
    access:AccessContextLimits
    auth:AuthHistoryLimits
    purposes:PurposeCorpusLimits|None=None

    def __post_init__(self):
        if (type(self.runtime) is not RuntimeContextLimits or type(self.access) is not AccessContextLimits
                or type(self.auth) is not AuthHistoryLimits
                or self.purposes is not None and type(self.purposes) is not PurposeCorpusLimits):
            raise ValueError('explicit typed runtime/access/auth and optional purpose limits required')


@dataclass(frozen=True)
class OwnerReviewConfiguration:
    inventory:HeldInventoryLimits
    corpus:HeldCorpusLimits
    accounting:AccountingLimits
    max_response_bytes:int
    collateral_limits:CollateralLimits|None=None
    auth_review:AuthReviewLimits|None=None
    metadata_review:MetadataHistoryLimits|None=None

    def __post_init__(self):
        if (type(self.inventory) is not HeldInventoryLimits or type(self.corpus) is not HeldCorpusLimits
                or type(self.accounting) is not AccountingLimits or type(self.max_response_bytes) is not int
                or not 1<=self.max_response_bytes<=65536
                or (self.collateral_limits is not None and type(self.collateral_limits) is not CollateralLimits)
                or (self.auth_review is not None and type(self.auth_review) is not AuthReviewLimits)
                or (self.metadata_review is not None and (type(self.metadata_review) is not MetadataHistoryLimits or self.auth_review is None))
                or self.corpus.max_total_snapshot_batches<2*self.inventory.max_snapshot_batches
                or self.corpus.max_total_payload_bytes<2*self.inventory.max_payload_bytes):
            raise ValueError('explicit exact review limits with original cumulative capacity required')


class OwnerMetadataReview:
    def __init__(self,requests,reader,*,accounting_limits,max_response_bytes,collateral_limits=None,auth_review=None,metadata_review=None):
        if (type(requests) is not OwnerMetadataRequests or type(reader) is not HeldCorpusReader
                or type(accounting_limits) is not AccountingLimits or type(max_response_bytes) is not int
                or not 1<=max_response_bytes<=65536 or reader.admission is not requests.admission
                or reader.resource_owner is not requests.resource_owner or reader.tick is not requests.tick_ns
                or reader._initial[-1] is not requests.repository
                or reader.limits.analysis.dataset.corpus.max_inspections<requests.limits.max_inspections):
            raise ValueError('exact shared owner/reader/repository/clock and finite review limits required')
        if collateral_limits is not None and (type(collateral_limits) is not CollateralLimits or collateral_limits.max_scope>requests.limits.max_inspections):
            raise ValueError('exact collateral limits within owner request capacity required')
        if auth_review is not None and type(auth_review) is not AuthReviewLimits:
            raise ValueError('exact optional auth review limits required')
        if metadata_review is not None and (type(metadata_review) is not MetadataHistoryLimits or auth_review is None
                or metadata_review.max_inspections!=requests.limits.max_inspections
                or metadata_review.writes_per_minute!=requests.limits.writes_per_minute):
            raise ValueError('metadata review requires auth review and exact original owner writer limits')
        self.metadata_review=metadata_review;self._metadata_initial=metadata_review
        self._metadata_signature=None if metadata_review is None else asdict(metadata_review)
        self.auth_review=auth_review;self._auth_initial=auth_review
        self.requests=requests;self.reader=reader;self.accounting_limits=accounting_limits
        self.collateral_limits=collateral_limits;self._collateral_initial=collateral_limits
        self.max_response_bytes=max_response_bytes
        self._initial=(requests,reader,accounting_limits,max_response_bytes,
            reader.inventory_limits,reader.limits,reader.tick,requests.repository)

    def _check(self):
        requests,reader,limits,response,inventory,corpus,tick,repository=self._initial
        if (self.requests is not requests or self.reader is not reader or self.accounting_limits is not limits
                or type(self.max_response_bytes) is not int or self.max_response_bytes!=response
                or reader.inventory_limits is not inventory or reader.limits is not corpus or reader.tick is not tick
                or requests.repository is not repository or reader.admission is not requests.admission
                or reader.resource_owner is not requests.resource_owner or requests.tick_ns is not tick
                or reader._initial!=(requests.admission,requests.resource_owner,inventory,corpus,tick,repository)):
            raise HeldCorpusHeld('original owner review configuration changed')
        if self.auth_review is not self._auth_initial:
            raise HeldCorpusHeld('original auth review configuration changed')
        if (self.metadata_review is not self._metadata_initial or self.metadata_review is not None and
                (asdict(self.metadata_review)!=self._metadata_signature
                 or self.metadata_review.max_inspections!=requests.limits.max_inspections
                 or self.metadata_review.writes_per_minute!=requests.limits.writes_per_minute)):
            raise HeldCorpusHeld('original metadata review configuration changed')
        if self.collateral_limits is not self._collateral_initial:
            raise HeldCorpusHeld('original collateral configuration changed')
        requests._check()
        if reader.release_pending:
            requests.release_pending=True
            raise HeldCorpusHeld('private reader completion remains unconfirmed')

    def read(self,actor,*,ident,expected_request_version,expected_gate_version,expected_control_version):
        return self._read(actor,ident=ident,expected_request_version=expected_request_version,
            expected_gate_version=expected_gate_version,expected_control_version=expected_control_version,collateral=False)

    def read_collateral(self,actor,*,ident,expected_request_version,expected_gate_version,expected_control_version):
        if self.collateral_limits is None:raise HeldCorpusHeld('owner collateral review is not configured')
        return self._read(actor,ident=ident,expected_request_version=expected_request_version,
            expected_gate_version=expected_gate_version,expected_control_version=expected_control_version,collateral=True)

    def read_policy_obligations(self,actor,*,ident,expected_request_version,expected_gate_version,expected_control_version):
        if self.auth_review is None:raise HeldCorpusHeld('auth history policy review is not configured')
        return self._read(actor,ident=ident,expected_request_version=expected_request_version,
            expected_gate_version=expected_gate_version,expected_control_version=expected_control_version,
            collateral=False,policy_obligations=True)

    def _read(self,actor,*,ident,expected_request_version,expected_gate_version,expected_control_version,collateral,policy_obligations=False):
        uuid(ident)
        for version in (expected_request_version,expected_gate_version,expected_control_version):_version(version)
        requests,reader,limits,*_=self._initial
        with requests._work():
            self._check();actor=requests._fresh(actor);requests._read_allowance()
            key=request_key(ident);row=requests.repository.snapshot((key,))[key]
            value,history=requests._request(row)
            gate,registry,runtime,current,active,data=requests._heads()
            if (row.revision!=expected_request_version or gate.revision!=expected_gate_version
                    or integer(runtime.data['control_version'])!=expected_control_version
                    or value['status']!='held' or current['phase']!='HELD' or current.get('request_id')!=ident
                    or current.get('scope_sha256')!=value['scope_sha256']
                    or current['epoch']!=integer(value['gate_epoch'])
                    or runtime.data['inspection_enabled'] is not False or active):
                raise StoreConflict('exact current held request review required')
            proof=requests.admission.drained(request_id=ident,scope_sha256=value['scope_sha256'])
            if requests.admission.assert_drained(proof)!=(gate,registry,runtime):
                raise StoreConflict('original owner review drain changed')
            self._check()
            try:
                arguments=dict(request_id=ident,inspection_ids=tuple(value['scope']['inspection_ids']),
                    deadline_ns=requests._deadline,accounting_limits=limits)
                if collateral:
                    result=reader.read_scope_proposal(**arguments,collateral_limits=self.collateral_limits)
                elif self.metadata_review is not None:
                    bounds=self.auth_review
                    result=reader.read_metadata_accounting(**arguments,runtime_context_limits=bounds.runtime,
                        access_context_limits=bounds.access,auth_history_limits=bounds.auth,purpose_corpus_limits=bounds.purposes,
                        metadata_history_limits=self.metadata_review,metadata_configuration_sha256=requests._configuration)
                elif self.auth_review is not None:
                    bounds=self.auth_review
                    result=reader.read_auth_accounting(**arguments,runtime_context_limits=bounds.runtime,
                        access_context_limits=bounds.access,auth_history_limits=bounds.auth,purpose_corpus_limits=bounds.purposes)
                else:
                    result=reader.read_accounting(**arguments)
            finally:
                if reader.release_pending:requests.release_pending=True
            self._check()
            expected_policy=AUTH_POLICY if self.auth_review is not None and not collateral else POLICY
            if self.metadata_review is not None and not collateral:expected_policy=METADATA_POLICY
            if (type(result) is not (HeldScopeProposal if collateral else HeldAccountedCorpus) or result.corpus.proof!=proof
                    or scope_sha256(result.corpus.scope)!=value['scope_sha256']
                    or result.corpus.scope.inspection_ids!=tuple(value['scope']['inspection_ids'])
                    or result.accounting.requested_inspections!=result.corpus.scope.inspection_ids
                    or result.accounting.policy!=expected_policy
                    or result.accounting.inventory_sha256!=result.corpus.inventory.summary_sha256):
                raise HeldCorpusHeld('original exact private review required')
            counts=result.accounting.counts
            if (type(counts) is not tuple or len(counts)!=len(DISPOSITIONS)
                    or tuple(name for name,count in counts)!=DISPOSITIONS
                    or any(type(count) is not int or not 0<=count<=MAXIMUM for name,count in counts)
                    or sum(count for name,count in counts)!=len(result.corpus.inventory.entries)
                    or len(result.accounting.entries)!=len(result.corpus.inventory.entries)):
                raise HeldCorpusHeld('complete safe accounting counts required')
            output={'id':ident,'scope_sha256':value['scope_sha256'],'request_version':row.revision,
                'gate_version':gate.revision,'control_version':expected_control_version,'accounting_policy':expected_policy,
                'counts':dict(counts),'total_records':len(result.corpus.inventory.entries),
                'historical':True,'read_only':True,'can_confirm_cleanup':False,
                'erasure_complete':False,'request_fulfilled':False}
            if self.auth_review is not None and not collateral:
                def auth_checkpoint():
                    self._check();requests.admission.assert_drained(proof)
                try:
                    auth=validate_auth_history(result.corpus.auth_history,result.corpus.inventory,proof,
                        scope_sha256=value['scope_sha256'],requested_inspections=result.corpus.scope.inspection_ids,
                        checkpoint=auth_checkpoint)
                except AuthHistoryHeld:
                    raise HeldCorpusHeld('complete original non-authorizing auth history required') from None
                bounds=self.auth_review.auth
                if (auth.source_records>bounds.max_records or auth.payload_bytes>bounds.max_payload_bytes
                        or auth.dependencies>bounds.max_dependencies or auth.work>bounds.max_work
                        or auth.summary_bytes>bounds.max_summary_bytes):
                    raise HeldCorpusHeld('original configured auth review limits exceeded')
                output.update(auth_history_policy_resolved=False,historical_auth_authority_proven=False)
                if policy_obligations:
                    if auth.work+len(auth.records)+len(AUTH_FAMILIES)>bounds.max_work:
                        raise HeldCorpusHeld('original auth work budget cannot fit policy explanation')
                    families={name:0 for name in sorted(AUTH_FAMILIES)}
                    for record in auth.records:
                        auth_checkpoint()
                        families[record.family]+=1
                    output={key:output[key] for key in ('id','scope_sha256','request_version','gate_version','control_version')}
                    output.update(policy='auth-policy-obligations-v1',accounting_policy=AUTH_POLICY,
                        family_counts=families,validated_auth_records=len(auth.records),source_records=auth.source_records,
                        historical_dependencies_unavailable=auth.historical_dependencies_unavailable,
                        next_step='OWNER_D11_POLICY_DECISION_REQUIRED',historical=True,read_only=True,
                        auth_history_policy_resolved=False,historical_auth_authority_proven=False,
                        can_confirm_cleanup=False,erasure_complete=False,request_fulfilled=False)
            if self.metadata_review is not None and not collateral:
                try:
                    metadata=validate_metadata_history(result.corpus.metadata_history,result.corpus.inventory,proof,result.corpus.auth_history,
                        scope_sha256=value['scope_sha256'],requested_inspections=result.corpus.scope.inspection_ids,checkpoint=auth_checkpoint)
                except MetadataHistoryHeld:
                    raise HeldCorpusHeld('complete original non-authorizing metadata history required') from None
                bounds=self.metadata_review
                if (metadata.configuration_sha256!=requests._configuration or metadata.source_records>bounds.max_records
                        or metadata.payload_bytes>bounds.max_payload_bytes or metadata.dependencies>bounds.max_dependencies
                        or metadata.work>bounds.max_work or metadata.summary_bytes>bounds.max_summary_bytes):
                    raise HeldCorpusHeld('original configured metadata review limits exceeded')
                output.update(metadata_history_policy_resolved=False,historical_metadata_authority_proven=False)
                if policy_obligations:
                    if metadata.work+len(metadata.records)+len(METADATA_FAMILIES)>bounds.max_work:
                        raise HeldCorpusHeld('original metadata work budget cannot fit policy explanation')
                    families={name:0 for name in sorted(METADATA_FAMILIES)}
                    for record in metadata.records:
                        auth_checkpoint();families[record.family]+=1
                    output.update(policy='privacy-policy-obligations-v2',accounting_policy=METADATA_POLICY,
                        metadata_family_counts=families,validated_metadata_records=len(metadata.records),
                        metadata_historical_dependencies_unavailable=metadata.historical_dependencies_unavailable)
            if collateral:
                proposal=result.proposal;original=result.corpus.scope.inspection_ids
                if (type(proposal) is not ScopeProposal or proposal.policy!='whole-artifact-collateral-proposal-v1'
                        or proposal.accounting_sha256!=result.accounting.summary_sha256 or proposal.original_scope!=original
                        or proposal.historical is not True or proposal.can_confirm_cleanup is not False
                        or type(proposal.proposed_scope) is not tuple or not proposal.proposed_scope
                        or len(proposal.proposed_scope)>self.collateral_limits.max_scope
                        or any(type(v) is not str for v in proposal.proposed_scope)
                        or tuple(sorted(set(proposal.proposed_scope)))!=proposal.proposed_scope
                        or not set(original)<=set(proposal.proposed_scope)):
                    raise HeldCorpusHeld('exact bounded original collateral proposal required')
                try:
                    for ident_value in proposal.proposed_scope:uuid(ident_value)
                except ValueError:
                    raise HeldCorpusHeld('canonical private proposal identifiers required') from None
                indexed={e.key:e for e in result.corpus.inventory.entries};keys=[]
                for references in (proposal.implicated,proposal.unresolved):
                    if type(references) is not tuple or len(references)>len(indexed):
                        raise HeldCorpusHeld('bounded private collateral references required')
                    current=set()
                    for reference in references:
                        if type(reference) is not InventoryEntry or indexed.get(reference.key)!=reference or reference.key in current:
                            raise HeldCorpusHeld('intact unique collateral references required')
                        current.add(reference.key)
                    keys.append(current)
                chosen=set(proposal.proposed_scope);known=set(original);implicated=set();unresolved=set();seen=set();actual_counts={k:0 for k in DISPOSITIONS}
                for entry in result.accounting.entries:
                    if (type(entry) is not AccountedRecord or entry.disposition not in actual_counts
                            or type(entry.reference) is not InventoryEntry or type(entry.reference.key) is not Key
                            or indexed.get(entry.reference.key)!=entry.reference or entry.reference.key in seen
                            or type(entry.inspection_ids) is not tuple or len(entry.inspection_ids)>limits.max_scope
                            or any(type(v) is not str for v in entry.inspection_ids)):
                        raise HeldCorpusHeld('complete typed private collateral accounting required')
                    seen.add(entry.reference.key);actual_counts[entry.disposition]+=1
                    if entry.disposition=='UNRESOLVED':unresolved.add(entry.reference.key)
                    elif entry.disposition!='CONTEXT':
                        members=set(entry.inspection_ids);known.update(members)
                        if members&chosen:
                            if not members<=chosen:raise HeldCorpusHeld('collateral scope is not content-closed')
                            implicated.add(entry.reference.key)
                if (seen!=set(indexed) or tuple(actual_counts.items())!=counts or not chosen<=known
                        or keys[0]!=implicated or keys[0]&keys[1] or keys[1]!=unresolved):
                    raise HeldCorpusHeld('complete disjoint collateral obligations required')
                output={k:output[k] for k in ('id','scope_sha256','request_version','gate_version','control_version')}
                output.update(proposal_policy=proposal.policy,original_inspection_ids=list(original),
                    proposed_inspection_ids=list(proposal.proposed_scope),additional_inspection_ids=sorted(set(proposal.proposed_scope)-set(original)),
                    implicated_records=len(keys[0]),unresolved_records=len(keys[1]),total_records=len(indexed),
                    historical=True,read_only=True,scope_changed=False,can_confirm_cleanup=False,erasure_complete=False,request_fulfilled=False)
            if len(_encoded(output))>self.max_response_bytes:
                raise HeldCorpusHeld('bounded minimized owner review response required')
            requests._checked_delivery(actor,(row,*history,gate,registry,runtime,data))

            def checkpoint():
                self._check();requests.admission.assert_drained(proof)

            consumed_batches=result.corpus.snapshot_batches;consumed_bytes=result.corpus.payload_bytes
            if (type(consumed_batches) is not int or type(consumed_bytes) is not int
                    or not 0<=consumed_batches<reader.limits.max_total_snapshot_batches
                    or not 0<=consumed_bytes<reader.limits.max_total_payload_bytes):
                raise HeldCorpusHeld('no remaining original owner review read capacity')
            remaining_batches=reader.limits.max_total_snapshot_batches-consumed_batches
            remaining_bytes=reader.limits.max_total_payload_bytes-consumed_bytes
            try:
                final=reconcile(requests.repository,result.corpus.inventory,
                    limits=reader.inventory_limits.inventory,
                    max_snapshot_batches=min(reader.inventory_limits.max_snapshot_batches,remaining_batches),
                    max_payload_bytes=min(reader.inventory_limits.max_payload_bytes,remaining_bytes),
                    deadline_ns=requests._deadline,checkpoint=checkpoint,tick=requests.tick_ns)
            except InventoryHeld:
                raise HeldCorpusHeld('complete original inventory changed before owner delivery') from None
            if (result.corpus.snapshot_batches+final.snapshot_batches>reader.limits.max_total_snapshot_batches
                    or result.corpus.payload_bytes+final.payload_bytes>reader.limits.max_total_payload_bytes):
                raise HeldCorpusHeld('original cumulative owner review read budget exhausted')
            checkpoint()
            requests._checked_delivery(actor,(row,*history,gate,registry,runtime,data))
            self._check()
            return output
