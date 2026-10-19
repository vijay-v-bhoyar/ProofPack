"""Private exact-scope session references for maintenance dispatch, never bearer tokens."""
import hmac
import re
import hashlib

from proofpack.auth.policy import Denied, Role
from proofpack.calibrations.dependencies import digest
from proofpack.evidence.repository import Key
from proofpack.runtime.control import integer, uuid


_FIELDS = frozenset({'schema_version', 'job_id', 'kind', 'scope_sha256', 'cookie_ref',
    'user_id', 'session_id', 'access_version', 'session_epoch', 'role', 'issued_at_ms', 'expires_at_ms'})
_EXPORT_SCOPE = ('id', 'kind', 'requested_by', 'inspection_id', 'inspection_revision',
    'inspection_sha256', 'configuration', 'artifact_sha256', 'controls_sha256', 'environment',
    'data_epoch', 'created_at_ms', 'expires_at_ms', 'selected')
_ERASURE_SCOPE = ('id', 'kind', 'scope', 'scope_sha256', 'created_at_ms', 'created_by')
_DATASET_SCOPE = ('id','kind','requested_by','configuration','data_epoch','artifact_sha256','controls_sha256',
    'environment','created_at_ms','expires_at_ms','request_sha256','example_count')


def scope_sha256(job):
    """Bind immutable intent; progress/lease changes cannot renew its permission."""
    kind = job['kind']
    if kind == 'inspection_export':
        fields = _EXPORT_SCOPE
    elif kind == 'asset_erasure':
        fields = _ERASURE_SCOPE
        if digest(job['scope']) != job['scope_sha256']:
            raise Denied('intact maintenance scope required')
    elif kind in {'dataset_manifest','policy_evaluation','policy_qualification_preparation','policy_qualification'}:
        fields = _DATASET_SCOPE
        if kind=='policy_qualification_preparation':
            fields=(*fields,'validation_runtime','control_version','registry_sha256','implementation_sha256','software_cases','source_examples')
        if kind=='policy_qualification':
            fields=(*fields,'validation_runtime','control_version','registry_sha256','software_cases','source_examples','preparation_count',
                'preparation_pages','required_case_count','golden_cases','golden_manifest_sha256')
        if hashlib.sha256(job['request_json'].encode()).hexdigest()!=job['request_sha256']:
            raise Denied('intact dataset request required')
    else:
        raise Denied('supported maintenance kind required')
    uuid(job['id'])
    return digest({key: job[key] for key in fields})


def _role(kind, value):
    role = Role(value)
    if ((kind == 'asset_erasure' and role == Role.OWNER)
            or (kind == 'inspection_export' and role in (Role.OPERATOR, Role.REVIEWER))
            or (kind in {'dataset_manifest','policy_evaluation','policy_qualification_preparation','policy_qualification'} and role == Role.REVIEWER)):
        return role
    raise Denied('scoped maintenance role required')


def issue(access, actor, job, role):
    """Only an existing executor may attach this to its conditional job write."""
    role = _role(job['kind'], role)
    actor = access._fresh(actor, role)
    if job['kind'] in {'inspection_export','dataset_manifest','policy_evaluation','policy_qualification_preparation','policy_qualification'} and job['requested_by'] != actor.member.data['id']:
        raise Denied('export requestor required')
    now = access.now()
    expires = integer(actor.session.data['expires_at_ms'])
    if role == Role.OWNER:
        # AccessService permits the exact final millisecond of this grant.
        expires = min(expires, integer(actor.session.data['auth_time_ms'])
            + access.config.mfa_grant_max_age_seconds * 1000 + 1)
    if job['kind'] in {'inspection_export','dataset_manifest','policy_evaluation','policy_qualification_preparation','policy_qualification'}:
        expires = min(expires, integer(job['expires_at_ms']))
    if now >= expires or now < integer(job['created_at_ms']):
        raise Denied('unexpired maintenance grant required')
    body = {'schema_version': 1, 'job_id': uuid(job['id']), 'kind': job['kind'],
        'scope_sha256': scope_sha256(job), 'cookie_ref': actor.cookie.key.resource,
        'user_id': actor.member.data['id'], 'session_id': actor.session.data['id'],
        'access_version': integer(actor.member.data['access_version']),
        'session_epoch': integer(actor.member.data['session_epoch']), 'role': role.value,
        'issued_at_ms': now, 'expires_at_ms': expires}
    return {'body': body, 'signature': access._token('maintenance-authority', digest(body))}


def resolve(access, job):
    """Fail closed for legacy/malformed references; never look up a user as a grant."""
    try:
        record = job['processing_authority']
        if not isinstance(record, dict) or set(record) != {'body', 'signature'}:
            raise ValueError()
        body = record['body']
        if not isinstance(body, dict) or set(body) != _FIELDS:
            raise ValueError()
        if integer(body['schema_version']) != 1:
            raise ValueError()
        if not isinstance(record['signature'], str) or not hmac.compare_digest(
                record['signature'], access._token('maintenance-authority', digest(body))):
            raise ValueError()
        if (body['job_id'] != uuid(job['id']) or body['kind'] != job['kind']
                or body['scope_sha256'] != scope_sha256(job)
                or not integer(body['issued_at_ms']) <= access.now() < integer(body['expires_at_ms'])
                or not isinstance(body['cookie_ref'], str)
                or re.fullmatch(r'cookie#[0-9a-f]{64}', body['cookie_ref']) is None):
            raise ValueError()
        role = _role(job['kind'], body['role'])
        actor = access._resolve_key(Key('state', body['cookie_ref']))
        actor = access._fresh(actor, role)
        if (actor.member.data['id'] != body['user_id'] or actor.session.data['id'] != body['session_id']
                or integer(actor.member.data['access_version']) != integer(body['access_version'])
                or integer(actor.member.data['session_epoch']) != integer(body['session_epoch'])
                or integer(body['issued_at_ms']) < max(integer(job['created_at_ms']), integer(actor.session.data['created_at_ms']))
                or integer(body['expires_at_ms']) > integer(actor.session.data['expires_at_ms'])
                or (job['kind'] in {'inspection_export','dataset_manifest','policy_evaluation','policy_qualification_preparation','policy_qualification'} and (job['requested_by'] != body['user_id']
                    or integer(body['expires_at_ms']) > integer(job['expires_at_ms'])))):
            raise ValueError()
        if role == Role.OWNER and integer(body['expires_at_ms']) > (
                integer(actor.session.data['auth_time_ms']) + access.config.mfa_grant_max_age_seconds * 1000 + 1):
            raise ValueError()
        return actor
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise Denied('current exact-scope maintenance authority required') from exc
