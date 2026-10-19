"""Explicit original-transmitted-frame permission and deterministic provenance IDs."""
import hashlib
from uuid import UUID,uuid5
from proofpack.evidence.repository import Key,Row,StoreUnavailable
from proofpack.runtime.control import uuid,integer
from proofpack.calibrations.dependencies import digest
from proofpack.vision.worker_result import WorkerResult

ORIGINAL_NOTICE_VERSION='original-capture-v1'
ORIGINAL_NOTICE_TEXT=('I hold documented operational permission to retain explicitly selected original transmitted work-frames, '
    'including their visible markers and full previewed rectangle, for later review. At most three attempts per inspection '
    'are reserved without refunds; retained images expire at the earlier purpose deadline or seven days. '
    'This does not permit continuous video, improvement use or publicity, or verify camera authenticity or physical truth.')
ORIGINAL_NOTICE_SHA256=hashlib.sha256(ORIGINAL_NOTICE_TEXT.encode()).hexdigest()
ORIGINAL_MAX_ATTEMPTS=3
ORIGINAL_RETENTION_MS=7*86400000


def original_asset_id(observation_id):return str(uuid5(UUID(uuid(observation_id)),'original-transmitted-frame-v1'))


def original_permission_binding(rows):
    return digest([{'table':r.key.table,'resource':r.key.resource,'revision':r.revision,'sha256':digest(r.data)}
                   for r in sorted(rows,key=lambda r:(r.key.table,r.key.resource))])


def original_profile(asset):
    from proofpack.vision.calibration import CalibrationProfile
    try:
        text=asset.data['replay_profile_json']
        if not isinstance(text,str) or not 1<=len(text.encode())<=65536:raise ValueError()
        profile=CalibrationProfile.model_validate_json(text)
        if (profile.model_dump_json()!=text or profile.content_hash!=asset.data['calibration_sha256']
                or profile.data_origin.value!=asset.data['data_origin']):raise ValueError()
        return profile
    except (KeyError,TypeError,ValueError,AttributeError) as exc:raise StoreUnavailable('exact retained original geometry required for vision replay') from exc


def _metadata_row(row,prefix):
    if (not isinstance(row,Row) or type(row.data) is not dict
            or type(row.revision) is not int or not 1<=row.revision<=2**63-1
            or row.key!=Key('state',prefix+uuid(row.data['id']))):raise ValueError()


def _metadata_media_record(row):
    """Private shared lifecycle parser, never media delivery or removal authority."""
    _metadata_row(row,'asset#')
    data=row.data;status=data['status'];denied=data['read_denied']
    if status not in {'committed','deleted'} or type(denied) is not bool:raise ValueError()
    if denied:
        uuid(data['deletion_job_id']);at=integer(data['denied_at_ms'])
        if at>2**63-1:raise ValueError()
        if status=='deleted':
            checked=integer(data['live_versions_checked_at_ms'])
            if not at<=checked<=2**63-1:raise ValueError()
        elif 'live_versions_checked_at_ms' in data:raise ValueError()
    elif (status!='committed' or any(k in data for k in ('deletion_job_id','denied_at_ms','live_versions_checked_at_ms'))):
        raise ValueError()


def _metadata_media_records(asset,observation,crop):
    """Parse lifecycle metadata only; no read or removal authority is granted."""
    _metadata_row(observation,'observation#')
    _metadata_media_record(asset)
    _metadata_media_record(crop)


def validate_original_source(asset,observation,crop,*,metadata_only=False):
    """Validate completed links; the private metadata mode never enables delivery."""
    if type(metadata_only) is not bool:raise ValueError('explicit internal metadata-only mode required')
    try:
        if metadata_only:_metadata_media_records(asset,observation,crop)
        a=asset.data;o=observation.data;c=crop.data
        result=WorkerResult.model_validate_json(o['result_json'])
        if 'replay_profile_json' in a:original_profile(asset)
        if (o['status']!='completed' or o.get('retain_original_frame') is not True
                or a['id']!=original_asset_id(o['id']) or a['id']!=o['original_asset_id']
                or a['derivation']!='original_transmitted_frame' or a['observation_id']!=o['id']
                or c['id']!=o['asset_id'] or c['id']!=o['id'] or c['id']==a['id']
                or c['derivation']!='rectified_roi_jpeg' or c['observation_id']!=o['id']
                or (not metadata_only and (c['status']!='committed' or c['read_denied'] is not False))
                or a['purpose_id']!=c['purpose_id'] or a['data_origin']!=c['data_origin']
                or a['sha256']!=o['original_evidence_sha256'] or a['sha256']!=o['source_sha256']
                or result.source_sha256!=o['source_sha256'] or a['input_sha256']!=o['source_sha256']
                or c['input_sha256']!=o['source_sha256'] or c['sha256']!=o['evidence_sha256']
                or a['context_sha256']!=o['context_sha256'] or c['context_sha256']!=o['context_sha256']
                or a['calibration_sha256']!=result.calibration_hash
                or not 0<integer(a['byte_length'])<=2097152 or integer(a['byte_length'])!=integer(o['byte_length'])
                or a['content_type']!=o['content_type'] or a['content_type'] not in {'image/jpeg','image/png'}
                or integer(a['expires_at_ms'])>integer(o['accepted_at_ms'])+ORIGINAL_RETENTION_MS):raise ValueError()
        return result
    except (KeyError,TypeError,ValueError,AttributeError) as exc:
        raise StoreUnavailable('intact completed original/crop provenance required') from exc


def original_capture_enabled(row,access):
    data=row.data;value=data.get('original_capture_retention_allowed',False)
    if value is False:return False
    try:
        if (value is not True or data['authority_basis']!='owner_attestation' or data['rights_independently_verified'] is not False
                or data['allowed_uses']!=['operation'] or data['withdrawn'] is not False
                or data['optional_improvement'] is not False or data['optional_publicity'] is not False
                or data['notice_version']!=access.config.notice_version
                or data['notice_sha256']!=hashlib.sha256(access.config.notice_text.encode()).hexdigest()
                or data['original_capture_notice_version']!=ORIGINAL_NOTICE_VERSION
                or data['original_capture_notice_sha256']!=ORIGINAL_NOTICE_SHA256
                or data['original_capture_notice_text']!=ORIGINAL_NOTICE_TEXT
                or not isinstance(data['source_permission_reference'],str) or not data['source_permission_reference']
                or access.now()>=integer(data['expires_at_ms'])):raise ValueError()
        uuid(data['owner_user_id']);integer(data['owner_access_version'])
    except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('intact current original-capture permission required') from exc
    return True
