"""Owner-authorized conservative accounting review; never cleanup authority."""
from proofpack.evidence.owner_metadata import OwnerMetadataRequests,request_key,_version
from proofpack.evidence.held_corpus import HeldCorpusReader,HeldAccountedCorpus,HeldCorpusHeld,scope_sha256
from proofpack.evidence.corpus_accounting import AccountingLimits,POLICY,DISPOSITIONS
from proofpack.evidence.repository import StoreConflict
from proofpack.evidence.inventory import reconcile,InventoryHeld,_encoded
from proofpack.runtime.control import integer,uuid


MAXIMUM=9007199254740991


class OwnerMetadataReview:
    def __init__(self,requests,reader,*,accounting_limits,max_response_bytes):
        if (type(requests) is not OwnerMetadataRequests or type(reader) is not HeldCorpusReader
                or type(accounting_limits) is not AccountingLimits or type(max_response_bytes) is not int
                or not 1<=max_response_bytes<=65536 or reader.admission is not requests.admission
                or reader.resource_owner is not requests.resource_owner or reader.tick is not requests.tick_ns
                or reader._initial[-1] is not requests.repository
                or reader.limits.analysis.dataset.corpus.max_inspections<requests.limits.max_inspections):
            raise ValueError('exact shared owner/reader/repository/clock and finite review limits required')
        self.requests=requests;self.reader=reader;self.accounting_limits=accounting_limits
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
        requests._check()
        if reader.release_pending:
            requests.release_pending=True
            raise HeldCorpusHeld('private reader completion remains unconfirmed')

    def read(self,actor,*,ident,expected_request_version,expected_gate_version,expected_control_version):
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
                result=reader.read_accounting(request_id=ident,inspection_ids=tuple(value['scope']['inspection_ids']),
                    deadline_ns=requests._deadline,accounting_limits=limits)
            finally:
                if reader.release_pending:requests.release_pending=True
            self._check()
            if (type(result) is not HeldAccountedCorpus or result.corpus.proof!=proof
                    or scope_sha256(result.corpus.scope)!=value['scope_sha256']
                    or result.corpus.scope.inspection_ids!=tuple(value['scope']['inspection_ids'])
                    or result.accounting.requested_inspections!=result.corpus.scope.inspection_ids
                    or result.accounting.policy!=POLICY
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
                'gate_version':gate.revision,'control_version':expected_control_version,'accounting_policy':POLICY,
                'counts':dict(counts),'total_records':len(result.corpus.inventory.entries),
                'historical':True,'read_only':True,'can_confirm_cleanup':False,
                'erasure_complete':False,'request_fulfilled':False}
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
