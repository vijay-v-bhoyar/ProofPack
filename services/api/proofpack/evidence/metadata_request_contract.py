"""Shared current-schema request validation; provenance is not cleanup authority.

The live owner path and the planned complete held-history consumer use one parser.
snapshot/now are supplied by their original operation lifetime, never by HTTP input.
"""
from dataclasses import asdict
import re
from proofpack.evidence.inspection_scope import inspection_scope, scope_sha256
from proofpack.evidence.privacy_admission import AdmissionHeld
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode, MissingResourceBindings, InvalidResourceBindings
from proofpack.runtime.control import integer, uuid, sha

MAXIMUM=9007199254740991
BASE=frozenset('schema_version id kind status scope scope_sha256 creator_scope owner_user_id owner_session_id owner_access_version initial_control_version initial_runtime_epoch initial_runtime_id initial_gate_revision gate_epoch created_at_ms configuration_sha256 creation_operation_resource original_request_sha256'.split())
CANCEL=frozenset('cancelled_at_ms cancelled_by_user_id cancelled_gate_epoch cancelled_control_version cancellation_operation_resource'.split())


def request_key(ident):return Key('state','metadata-request#'+uuid(ident))


def _version(value):
    if type(value) is not int or not 1<=value<=MAXIMUM:raise ValueError('exact positive safe version required')
    return value


def _operation(value):
    if type(value) is not str or re.fullmatch('idempotency#[a-f0-9]{64}',value) is None:raise ValueError()
    return Key('state',value)


def validate_request(row, *, deployment, configuration_sha256, max_inspections, now, snapshot):
    try:
        if type(row) is not Row or type(row.data) is not dict:raise ValueError()
        value=row.data;cancelled=value['status']=='cancelled'
        if (set(value)!=BASE|(CANCEL if cancelled else set()) or value['status'] not in {'held','cancelled'}
                or row.key!=request_key(value['id']) or row.revision!=(2 if cancelled else 1)
                or integer(value['schema_version'])!=1 or value['kind']!='inspection_metadata_request'
                or value['configuration_sha256']!=configuration_sha256):raise ValueError()
        scope=value['scope']
        if type(scope) is not dict or type(scope.get('inspection_ids')) is not list:raise ValueError()
        typed=inspection_scope(deployment,tuple(scope['inspection_ids']),max_inspections=max_inspections)
        if scope!={**asdict(typed),'inspection_ids':list(typed.inspection_ids)} or scope_sha256(typed)!=sha(value['scope_sha256']):raise ValueError()
        for name in ['owner_user_id','owner_session_id','initial_runtime_id']:uuid(value[name])
        sha(value['creator_scope'])
        for name in ['owner_access_version','initial_control_version','initial_runtime_epoch','initial_gate_revision','gate_epoch']:
            _version(integer(value[name]))
        created=integer(value['created_at_ms'])
        if created>now():raise ValueError()
        original={k:v for k,v in value.items() if k in BASE and k!='original_request_sha256'};original['status']='held'
        if _payload_sha256(original)!=sha(value['original_request_sha256']):raise ValueError()
        original['original_request_sha256']=value['original_request_sha256']
        key=_operation(value['creation_operation_resource']);operation=snapshot((key,))[key]
        if type(operation) is not Row or operation.revision!=1:raise ValueError()
        binding=decode(operation,deployment=deployment)
        expected={'id':value['id'],'scope_sha256':value['scope_sha256'],'request_sha256':value['original_request_sha256']}
        if binding.operation!='owner-metadata-create' or operation.data['result']!=expected:raise ValueError()
        ref=next(r for r in binding.writes if r.key==row.key)
        if ref.revision!=1 or ref.previous_revision is not None or ref.sha256!=_payload_sha256(original):raise ValueError()
        dependencies=[operation]
        if cancelled:
            uuid(value['cancelled_by_user_id'])
            if (integer(value['cancelled_at_ms'])<created or integer(value['cancelled_at_ms'])>now()
                    or integer(value['cancelled_gate_epoch'])!=integer(value['gate_epoch'])+1
                    or integer(value['cancelled_control_version'])<=integer(value['initial_control_version'])):raise ValueError()
            key=_operation(value['cancellation_operation_resource']);op=snapshot((key,))[key]
            if type(op) is not Row or op.revision!=1:raise ValueError()
            bound=decode(op,deployment=deployment)
            if bound.operation!='owner-metadata-cancel' or op.data['result']!=expected:raise ValueError()
            ref=next(r for r in bound.writes if r.key==row.key)
            if ref.revision!=2 or ref.previous_revision!=1 or ref.sha256!=_payload_sha256(value):raise ValueError()
            dependencies.append(op)
        return value,tuple(dependencies)
    except (KeyError,TypeError,ValueError,AttributeError,StopIteration,MissingResourceBindings,InvalidResourceBindings):
        raise AdmissionHeld('intact original owner request and provenance required') from None
