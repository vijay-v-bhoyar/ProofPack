"""Strict owner maintenance transport; review grants no cleanup or fulfillment."""
from typing import Annotated,Literal
from fastapi import APIRouter,Depends,Request,HTTPException
from pydantic import BaseModel,ConfigDict,Field,StringConstraints,StrictBool,model_validator
from proofpack.auth.http import actor,write_guard,Idempotency
from proofpack.evidence.repository import StoreUnavailable
from proofpack.evidence.corpus_accounting import POLICY,AUTH_POLICY,METADATA_POLICY

router=APIRouter(prefix='/api/v1/privacy/metadata-requests')
Identifier=Annotated[str,StringConstraints(strict=True,pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')]
Version=Annotated[int,Field(strict=True,ge=1,le=9007199254740991)]


class Body(BaseModel):model_config=ConfigDict(extra='forbid',strict=True)


class CreateBody(Body):
    inspection_ids:list[Identifier]=Field(min_length=1,max_length=64)
    expected_gate_version:Version
    expected_control_version:Version
    interruption_acknowledged:StrictBool


class CancelBody(Body):
    confirmed_scope_sha256:Annotated[str,StringConstraints(strict=True,pattern=r'^[a-f0-9]{64}$')]
    expected_request_version:Version
    expected_gate_version:Version
    expected_control_version:Version
    no_erasure_acknowledged:StrictBool


class ReviewBody(Body):
    expected_request_version:Version
    expected_gate_version:Version
    expected_control_version:Version


class CurrentRequestView(Body):
    id:Identifier
    state_version:Version
    status:Literal['held']
    scope_sha256:Annotated[str,StringConstraints(strict=True,pattern=r'^[a-f0-9]{64}$')]
    inspection_ids:list[Identifier]=Field(min_length=1,max_length=64)
    selector_policy:Literal['read-only-family-selection-v3']
    created_at_ms:Annotated[int,Field(strict=True,ge=0,le=9007199254740991)]
    original_owner_session:StrictBool
    current_hold:StrictBool
    gate_version:Version
    gate_epoch:Version
    gate_phase:Literal['HELD']
    control_version:Version
    inspection_enabled:StrictBool
    active_count:Annotated[int,Field(strict=True,ge=0,le=64)]
    foreign_active:StrictBool
    drain_status:Literal['blocked_runtime','waiting','empty']
    can_cancel:StrictBool
    can_confirm_cleanup:StrictBool
    erasure_complete:StrictBool
    request_fulfilled:StrictBool

    @model_validator(mode='after')
    def exact_current_snapshot(self):
        if (self.state_version!=1 or self.current_hold is not True
                or self.inspection_ids!=sorted(set(self.inspection_ids))
                or (self.foreign_active and not self.active_count)
                or self.drain_status!=('blocked_runtime' if self.inspection_enabled else 'waiting' if self.active_count else 'empty')
                or self.can_cancel!=(not self.inspection_enabled and self.active_count==0)
                or any(v is not False for v in (self.can_confirm_cleanup,self.erasure_complete,self.request_fulfilled))):
            raise ValueError('exact non-authorizing current request required')
        return self


class CurrentRecoveryResult(Body):
    status:Literal['open','held']
    request:CurrentRequestView|None
    unknown_writes_reconciled:StrictBool
    inspection_resumption_authorized:StrictBool
    can_confirm_cleanup:StrictBool
    erasure_complete:StrictBool
    request_fulfilled:StrictBool

    @model_validator(mode='after')
    def no_fulfillment_claim(self):
        if ((self.status=='open')!=(self.request is None)
                or any(v is not False for v in (self.unknown_writes_reconciled,self.inspection_resumption_authorized,
                    self.can_confirm_cleanup,self.erasure_complete,self.request_fulfilled))):
            raise ValueError('current read cannot authorize or settle work')
        return self


Count=Annotated[int,Field(strict=True,ge=0,le=9007199254740991)]


class ReviewCounts(Body):
    AFFECTED:Count
    SHARED:Count
    CONTEXT:Count
    UNRELATED:Count
    UNRESOLVED:Count


class ReviewResult(Body):
    id:Identifier
    scope_sha256:Annotated[str,StringConstraints(strict=True,pattern=r'^[a-f0-9]{64}$')]
    request_version:Version
    gate_version:Version
    control_version:Version
    accounting_policy:Literal[POLICY]
    counts:ReviewCounts
    total_records:Count
    historical:StrictBool
    read_only:StrictBool
    can_confirm_cleanup:StrictBool
    erasure_complete:StrictBool
    request_fulfilled:StrictBool

    @model_validator(mode='after')
    def non_authorizing(self):
        if (self.historical is not True or self.read_only is not True
                or self.can_confirm_cleanup is not False or self.erasure_complete is not False
                or self.request_fulfilled is not False or sum(self.counts.model_dump().values())!=self.total_records):
            raise ValueError('closed non-authorizing complete review required')
        return self



class AuthReviewResult(ReviewResult):
    accounting_policy:Literal[AUTH_POLICY]
    auth_history_policy_resolved:StrictBool
    historical_auth_authority_proven:StrictBool

    @model_validator(mode='after')
    def held_auth_policy(self):
        if self.auth_history_policy_resolved is not False or self.historical_auth_authority_proven is not False:
            raise ValueError('auth history cannot resolve operational policy or historical authority')
        return self


class MetadataReviewResult(AuthReviewResult):
    accounting_policy:Literal[METADATA_POLICY]
    metadata_history_policy_resolved:StrictBool
    historical_metadata_authority_proven:StrictBool

    @model_validator(mode='after')
    def held_metadata_policy(self):
        if self.metadata_history_policy_resolved is not False or self.historical_metadata_authority_proven is not False:
            raise ValueError('metadata provenance cannot resolve retention or historical authority')
        return self


ReviewResponse=Annotated[ReviewResult|AuthReviewResult|MetadataReviewResult,Field(discriminator='accounting_policy')]


class PolicyObligationsResult(Body):
    id:Identifier
    scope_sha256:Annotated[str,StringConstraints(strict=True,pattern=r'^[a-f0-9]{64}$')]
    request_version:Version
    gate_version:Version
    control_version:Version
    policy:Literal['auth-policy-obligations-v1']
    accounting_policy:Literal[AUTH_POLICY]
    family_counts:dict[Literal['access-head','bootstrap','user','identity','session','cookie','invitation',
        'owner-transfer','access-replay','oauth-flow','oauth-quota'],Count]
    validated_auth_records:Count
    source_records:Count
    historical_dependencies_unavailable:Count
    next_step:Literal['OWNER_D11_POLICY_DECISION_REQUIRED']
    historical:StrictBool
    read_only:StrictBool
    auth_history_policy_resolved:StrictBool
    historical_auth_authority_proven:StrictBool
    can_confirm_cleanup:StrictBool
    erasure_complete:StrictBool
    request_fulfilled:StrictBool

    @model_validator(mode='after')
    def unresolved(self):
        from proofpack.evidence.auth_history import FAMILIES
        if (set(self.family_counts)!=FAMILIES or sum(self.family_counts.values())!=self.validated_auth_records
                or self.validated_auth_records>self.source_records or self.historical is not True or self.read_only is not True
                or any(getattr(self,key) is not False for key in ('auth_history_policy_resolved',
                    'historical_auth_authority_proven','can_confirm_cleanup','erasure_complete','request_fulfilled'))):
            raise ValueError('closed non-authorizing policy explanation required')
        return self


class MetadataPolicyObligationsResult(PolicyObligationsResult):
    policy:Literal['privacy-policy-obligations-v2']
    accounting_policy:Literal[METADATA_POLICY]
    metadata_family_counts:dict[Literal['metadata-request','metadata-operation','metadata-event','metadata-quota'],Count]
    validated_metadata_records:Count
    metadata_historical_dependencies_unavailable:Count
    metadata_history_policy_resolved:StrictBool
    historical_metadata_authority_proven:StrictBool

    @model_validator(mode='after')
    def unresolved_metadata(self):
        from proofpack.evidence.metadata_history import FAMILIES
        if (set(self.metadata_family_counts)!=FAMILIES or sum(self.metadata_family_counts.values())!=self.validated_metadata_records
                or self.validated_auth_records+self.validated_metadata_records>self.source_records
                or self.metadata_history_policy_resolved is not False or self.historical_metadata_authority_proven is not False):
            raise ValueError('closed non-authorizing metadata policy explanation required')
        return self


PolicyObligationsResponse=Annotated[PolicyObligationsResult|MetadataPolicyObligationsResult,Field(discriminator='policy')]


class CollateralResult(Body):
    id:Identifier
    scope_sha256:Annotated[str,StringConstraints(strict=True,pattern=r'^[a-f0-9]{64}$')]
    request_version:Version
    gate_version:Version
    control_version:Version
    proposal_policy:Literal['whole-artifact-collateral-proposal-v1']
    original_inspection_ids:list[Identifier]=Field(min_length=1,max_length=64)
    proposed_inspection_ids:list[Identifier]=Field(min_length=1,max_length=64)
    additional_inspection_ids:list[Identifier]=Field(max_length=64)
    implicated_records:Count
    unresolved_records:Count
    total_records:Count
    historical:StrictBool
    read_only:StrictBool
    scope_changed:StrictBool
    can_confirm_cleanup:StrictBool
    erasure_complete:StrictBool
    request_fulfilled:StrictBool

    @model_validator(mode='after')
    def non_authorizing(self):
        if (any(values!=sorted(set(values)) for values in (self.original_inspection_ids,self.proposed_inspection_ids,self.additional_inspection_ids))
                or not set(self.original_inspection_ids)<=set(self.proposed_inspection_ids)
                or self.additional_inspection_ids!=sorted(set(self.proposed_inspection_ids)-set(self.original_inspection_ids))
                or self.implicated_records+self.unresolved_records>self.total_records
                or self.historical is not True or self.read_only is not True or self.scope_changed is not False
                or self.can_confirm_cleanup is not False or self.erasure_complete is not False or self.request_fulfilled is not False):
            raise ValueError('complete closed non-authorizing collateral proposal required')
        return self


def service(request:Request):
    value=request.app.state.owner_metadata_service
    if value is None:raise StoreUnavailable('owner metadata requests are not configured')
    return value


@router.get('/context')
def context(request:Request,current=Depends(actor),value=Depends(service)):
    result=value.context(current)
    review=request.app.state.owner_metadata_review_service
    if review is not None and review.collateral_limits is not None:result={**result,'collateral_review_available':True}
    return result


@router.post('',status_code=201)
def create(body:CreateBody,request:Request,key:Idempotency,current=Depends(actor),value=Depends(service)):
    write_guard(request,current)
    return value.create(current,**{**body.model_dump(),'inspection_ids':tuple(body.inspection_ids)},idempotency_key=key)


@router.get('/current',response_model=CurrentRecoveryResult)
def recover_current(request:Request,current=Depends(actor),value=Depends(service)):
    if request.scope.get('query_string',b''):
        raise HTTPException(status_code=422,detail='Current-hold recovery accepts no selectors')
    return value.recover_current(current)


@router.get('/{ident}')
def read(ident:Identifier,current=Depends(actor),value=Depends(service)):return value.get(current,ident)


@router.post('/{ident}/cancel')
def cancel(ident:Identifier,body:CancelBody,request:Request,key:Idempotency,current=Depends(actor),value=Depends(service)):
    write_guard(request,current)
    return value.cancel(current,ident=ident,**body.model_dump(),idempotency_key=key)


def review_service(request:Request):
    value=request.app.state.owner_metadata_review_service
    if value is None:raise StoreUnavailable('owner metadata review is not configured')
    return value


@router.post('/{ident}/review',response_model=ReviewResponse)
def review(ident:Identifier,body:ReviewBody,request:Request,current=Depends(actor),value=Depends(review_service)):
    write_guard(request,current)
    return value.read(current,ident=ident,**body.model_dump())


@router.post('/{ident}/policy-obligations',response_model=PolicyObligationsResponse)
def policy_obligations(ident:Identifier,body:ReviewBody,request:Request,current=Depends(actor),value=Depends(review_service)):
    write_guard(request,current)
    if request.scope.get('query_string',b''):
        raise HTTPException(status_code=422,detail='Policy review accepts no query selectors')
    return value.read_policy_obligations(current,ident=ident,**body.model_dump())


@router.post('/{ident}/collateral-scope-proposal',response_model=CollateralResult)
def collateral_scope_proposal(ident:Identifier,body:ReviewBody,request:Request,current=Depends(actor),value=Depends(review_service)):
    write_guard(request,current)
    return value.read_collateral(current,ident=ident,**body.model_dump())
