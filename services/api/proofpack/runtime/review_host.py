"""Closed private-file review limits; no defaults, clients or initialization I/O."""
from typing import Annotated
from pydantic import Field
from proofpack.recipes.models import Contract
from proofpack.evidence.inventory import InventoryLimits
from proofpack.evidence.held_inventory import HeldInventoryLimits
from proofpack.evidence.inspection_corpus import InspectionCorpusLimits
from proofpack.evidence.dataset_corpus import DatasetCorpusLimits
from proofpack.evidence.replay_corpus import ReplayCorpusLimits
from proofpack.evidence.reference_lineage import ReferenceLimits
from proofpack.evidence.reference_corpus import ReferenceCorpusLimits
from proofpack.evidence.held_corpus import HeldCorpusLimits
from proofpack.evidence.corpus_accounting import AccountingLimits
from proofpack.evidence.owner_metadata_review import OwnerReviewConfiguration,AuthReviewLimits
from proofpack.evidence.collateral_scope import CollateralLimits

from proofpack.evidence.runtime_context import RuntimeContextLimits
from proofpack.evidence.access_context import AccessContextLimits
from proofpack.evidence.auth_history import AuthHistoryLimits
from proofpack.evidence.purpose_history import PurposeHistoryLimits
from proofpack.evidence.purpose_corpus import PurposeCorpusLimits
from proofpack.evidence.metadata_history import MetadataHistoryLimits

Positive=Annotated[int,Field(strict=True,ge=1,le=2**63-1)]


class InventoryDocument(Contract):
    page_size:Positive
    max_pages:Positive
    max_records:Positive
    max_summary_bytes:Positive


class HeldInventoryDocument(Contract):
    inventory:InventoryDocument
    max_snapshot_batches:Positive
    max_payload_bytes:Positive

    def build(self):
        return HeldInventoryLimits(InventoryLimits(**self.inventory.model_dump()),self.max_snapshot_batches,self.max_payload_bytes)


class InspectionDocument(Contract):
    max_records:Positive
    max_payload_bytes:Positive
    max_inspections:Positive
    max_work:Positive


class DatasetDocument(Contract):
    corpus:InspectionDocument
    family_max_records:Positive
    family_max_payload_bytes:Positive
    max_datasets:Positive
    max_groups:Positive

    def build(self):
        return DatasetCorpusLimits(InspectionCorpusLimits(**self.corpus.model_dump()),**self.model_dump(exclude={'corpus'}))


class ReplayDocument(Contract):
    dataset:DatasetDocument
    max_replays:Positive
    max_transaction_events:Positive

    def build(self):return ReplayCorpusLimits(self.dataset.build(),self.max_replays,self.max_transaction_events)


class ReferenceFamilyDocument(Contract):
    max_records:Positive
    max_payload_bytes:Positive
    max_dependencies:Positive
    max_work:Positive


class ReferenceDocument(Contract):
    max_references:Positive
    family:ReferenceFamilyDocument
    max_work:Positive
    max_summary_bytes:Positive

    def build(self):
        return ReferenceCorpusLimits(self.max_references,ReferenceLimits(**self.family.model_dump()),self.max_work,self.max_summary_bytes)


class CorpusDocument(Contract):
    analysis:ReplayDocument
    max_total_snapshot_batches:Positive
    max_total_payload_bytes:Positive
    max_binding_bytes:Positive
    references:ReferenceDocument

    def build(self):
        return HeldCorpusLimits(self.analysis.build(),self.max_total_snapshot_batches,self.max_total_payload_bytes,
            self.max_binding_bytes,self.references.build())


class AccountingDocument(Contract):
    max_records:Positive
    max_scope:Positive
    max_relationships:Positive
    max_work:Positive
    max_summary_bytes:Positive


class CollateralDocument(Contract):
    max_records:Positive
    max_memberships:Positive
    max_scope:Positive
    max_work:Positive

    def build(self):return CollateralLimits(**self.model_dump())


class ContextDocument(Contract):
    max_records:Positive
    max_payload_bytes:Positive
    max_work:Positive
    max_summary_bytes:Positive


class AuthHistoryDocument(ContextDocument):
    max_dependencies:Positive


class PurposeHistoryDocument(ContextDocument):
    max_dependencies:Positive


class PurposeCorpusDocument(Contract):
    max_families:Positive
    family:PurposeHistoryDocument
    max_work:Positive
    max_summary_bytes:Positive

    def build(self):
        return PurposeCorpusLimits(self.max_families,PurposeHistoryLimits(**self.family.model_dump()),
            self.max_work,self.max_summary_bytes)


class AuthReviewDocument(Contract):
    runtime:ContextDocument
    access:ContextDocument
    auth:AuthHistoryDocument
    purposes:PurposeCorpusDocument|None=None

    def build(self):
        return AuthReviewLimits(RuntimeContextLimits(**self.runtime.model_dump()),
            AccessContextLimits(**self.access.model_dump()),AuthHistoryLimits(**self.auth.model_dump()),
            self.purposes.build() if self.purposes is not None else None)


class MetadataHistoryDocument(AuthHistoryDocument):
    max_inspections:Annotated[int,Field(strict=True,ge=1,le=64)]
    writes_per_minute:Annotated[int,Field(strict=True,ge=1,le=100)]


class OwnerReviewDocument(Contract):
    inventory:HeldInventoryDocument
    corpus:CorpusDocument
    accounting:AccountingDocument
    max_response_bytes:Annotated[int,Field(strict=True,ge=1,le=65536)]
    collateral_limits:CollateralDocument|None=None
    auth_review:AuthReviewDocument|None=None
    metadata_review:MetadataHistoryDocument|None=None

    def build(self):
        return OwnerReviewConfiguration(self.inventory.build(),self.corpus.build(),
            AccountingLimits(**self.accounting.model_dump()),self.max_response_bytes,
            self.collateral_limits.build() if self.collateral_limits is not None else None,
            self.auth_review.build() if self.auth_review is not None else None,
            MetadataHistoryLimits(**self.metadata_review.model_dump()) if self.metadata_review is not None else None)
