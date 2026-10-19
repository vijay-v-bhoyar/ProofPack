"""Scoped optional-use review and withdrawal; no media or training endpoint."""
import json
from typing import Annotated
from uuid import UUID
from fastapi import APIRouter, Depends, Request, Query
from proofpack.auth.http import actor, write_guard, IfMatch, Idempotency, version
from proofpack.evidence.repository import StoreUnavailable
from proofpack.evidence.improvement import ImprovementPreview, ImprovementConfirmation

router = APIRouter(prefix='/api/v1/privacy')


def service(request: Request):
    value = request.app.state.improvement_service
    if value is None: raise StoreUnavailable('optional improvement permissions are not configured')
    return value


@router.get('/improvement-options')
def options(current=Depends(actor), value=Depends(service)): return value.options(current)


@router.post('/improvement-previews', status_code=201)
def preview(body: dict, request: Request, key: Idempotency, current=Depends(actor), value=Depends(service)):
    write_guard(request, current)
    return value.preview(current, request=ImprovementPreview.model_validate_json(json.dumps(body, allow_nan=False)), idempotency_key=key)


@router.get('/improvement-previews/{ident}')
def preview_read(ident: UUID, current=Depends(actor), value=Depends(service)): return value.preview_read(current, str(ident))


@router.post('/improvement-permissions', status_code=201)
def confirm(body: dict, request: Request, key: Idempotency, match: IfMatch, current=Depends(actor), value=Depends(service)):
    write_guard(request, current)
    return value.confirm(current, request=ImprovementConfirmation.model_validate_json(json.dumps(body, allow_nan=False)),
        expected_version=version(match), idempotency_key=key)


@router.get('/improvement-permissions')
def list_permissions(limit: Annotated[int, Query(ge=1, le=20)]=20, cursor: Annotated[str | None, Query(max_length=36)]=None,
        current=Depends(actor), value=Depends(service)): return value.list(current, limit=limit, cursor=cursor)


@router.get('/improvement-permissions/{ident}')
def read(ident: UUID, current=Depends(actor), value=Depends(service)): return value.get(current, str(ident))


@router.post('/improvement-permissions/{ident}/withdraw')
def withdraw(ident: UUID, request: Request, key: Idempotency, match: IfMatch, current=Depends(actor), value=Depends(service)):
    write_guard(request, current)
    return value.withdraw(current, str(ident), expected_version=version(match), idempotency_key=key)
