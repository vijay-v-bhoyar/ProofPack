"""Shared active-calibration snapshot validation for station admission and summaries."""
import re
from proofpack.auth.service import user_key
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable
from proofpack.runtime.control import DATA,integer,sha,uuid
from proofpack.vision.calibration import CalibrationProfile
from proofpack.calibrations.models import PhysicalReview
import hashlib
import json
from decimal import Decimal


def canonical(value):
    def number(item):
        if isinstance(item,Decimal) and item.is_finite() and item==item.to_integral_value():return int(item)
        raise ValueError('unsupported diagnostic record value')
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False,default=number)


def digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()


def physical_assurance(repository,access,runtime,ident,profile,report_sha256,manifest,data_epoch,source_rows,originator_ids=()):
    try:
        key=Key('state','physical-calibration-assurance#'+uuid(ident));first=repository.snapshot((key,))[key]
        if first is None or first.revision!=1:raise ValueError('physical review missing')
        record=first.data;review=PhysicalReview.model_validate_json(record['review_json'])
        def number(value):
            if isinstance(value,Decimal) and value==value.to_integral_value():return int(value)
            raise ValueError('invalid manifest number')
        manifest_sha=hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':'),default=number).encode()).hexdigest()
        reviewer_key=user_key(review.reviewed_by);rows=repository.snapshot((key,reviewer_key));member=rows[reviewer_key]
        if (rows[key]!=first or member is None or member.data['enabled'] is not True or 'reviewer' not in member.data['roles']
                or integer(member.data['access_version'])!=review.reviewer_access_version
                or record['review_sha256']!=hashlib.sha256(record['review_json'].encode()).hexdigest()
                or record['status']!='approved' or record['profile_sha256']!=profile.content_hash
                or record['report_sha256']!=sha(report_sha256) or record['source_manifest_sha256']!=manifest_sha
                or record['environment']!=runtime.environment or record['artifact_sha256']!=runtime.artifact_sha256
                or integer(record['data_epoch'])!=data_epoch or access.now()>=integer(record['expires_at_ms'])
                or set(record['checks'])!={'measured_ruler','lens','physical_sources','scope_review'}
                or not all(value is True for value in record['checks'].values()) or review.camera_id!=profile.camera_id
                or review.ruler_nominal_mm!=100. or review.lens_residual_px>profile.max_reprojection_error_px):raise ValueError('physical review binding mismatch')
        error=abs(review.ruler_measured_mm-review.ruler_nominal_mm)/min(review.ruler_measured_mm,review.ruler_nominal_mm)*max(profile.physical_width_mm,profile.physical_height_mm)+review.ruler_uncertainty_mm
        ids={item['asset_id'] for item in manifest}
        if error>profile.measurement_error_mm or not set((*review.lens_evidence_asset_ids,*review.scope_evidence_asset_ids))<=ids:raise ValueError('physical envelope not supported')
        if review.independence_verified:
            contributors=set(originator_ids)
            for item in manifest:
                source=source_rows[Key('state','asset#'+item['asset_id'])]
                contributors.add(source.data['owner_user_id'])
            if review.reviewed_by in contributors:raise ValueError('independence unsupported')
        return rows,integer(record['expires_at_ms'])
    except StoreConflict:raise
    except (KeyError,TypeError,ValueError,AttributeError) as exc:raise StoreUnavailable('reviewed physical ruler/lens/source evidence required') from exc

def active_calibration(repository,access,runtime,profile_id):
    if not isinstance(profile_id,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',profile_id):raise ValueError('bounded calibration profile required')
    key=Key('state','calibration-active#'+profile_id);first=repository.snapshot((key,))[key]
    if first is None:raise StoreUnavailable('approved calibration required')
    try:
        receiptkey=Key('state','calibration-dependencies#'+uuid(first.data['dependency_receipt_id']))
        receipt=repository.snapshot((receiptkey,))[receiptkey]
        if receipt is None:raise ValueError('calibration dependencies missing')
        manifest=receipt.data['reference_manifest']
        if not isinstance(manifest,list) or not 1<=len(manifest)<=16:raise ValueError('bounded calibration references required')
        reportkey=Key('state','calibration-report#'+uuid(receipt.data['report_id']))
        keys=[key,receiptkey,DATA,reportkey]
        for item in manifest:keys.extend((Key('state','asset#'+uuid(item['asset_id'])),Key('state','purpose#'+uuid(item['purpose_id']))))
        rows=repository.snapshot(tuple(dict.fromkeys(keys)))
        if rows[key]!=first or rows[receiptkey]!=receipt:raise StoreConflict('calibration changed')
        data=rows[DATA]
        if (data is None or receipt.revision!=1 or first.data['status']!='approved'
                or first.data['environment']!=runtime.environment
                or (runtime.environment=='beta' and first.data['data_origin']!='physical')
                or receipt.data['environment']!=runtime.environment
                or receipt.data['profile_sha256']!=sha(first.data['profile_sha256'])
                or integer(receipt.data['profile_state_version'])!=first.revision
                or integer(receipt.data['data_epoch'])!=integer(data.data['epoch'])
                or len({item['asset_id'] for item in manifest})!=len(manifest)):
            raise ValueError('calibration qualification mismatch')
        report=rows[reportkey]
        if report is None or report.revision!=1:raise ValueError('immutable calibration report missing')
        proof=report.data
        if (proof['sha256']!=digest({k:v for k,v in proof.items() if k!='sha256'})
                or proof['sha256']!=sha(receipt.data['report_sha256'])
                or proof['id']!=receipt.data['report_id'] or proof['calibration_id']!=profile_id
                or proof['passed'] is not True or integer(proof['revision'])<1
                or proof['profile_sha256']!=first.data['profile_sha256']
                or proof['environment']!=runtime.environment or proof['artifact_sha256']!=runtime.artifact_sha256
                or integer(proof['data_epoch'])!=integer(data.data['epoch'])
                or proof['reference_manifest']!=manifest):raise ValueError('calibration report binding mismatch')
        if 'profile_json' in first.data:
            profile=CalibrationProfile.model_validate_json(first.data['profile_json'])
            if profile.content_hash!=first.data['profile_sha256'] or profile.revision!=integer(proof['revision']):
                raise ValueError('calibration report revision mismatch')
        deadlines=[integer(receipt.data['expires_at_ms']),integer(proof['expires_at_ms'])]
        for item in manifest:
            asset=rows[Key('state','asset#'+item['asset_id'])];purpose=rows[Key('state','purpose#'+item['purpose_id'])]
            if (asset is None or purpose is None or asset.revision!=integer(item['asset_state_version'])
                    or purpose.revision!=integer(item['purpose_state_version'])
                    or asset.data['sha256']!=sha(item['sha256']) or asset.data['purpose_id']!=item['purpose_id']
                    or asset.data['status']!='committed' or asset.data['read_denied'] is not False
                    or asset.data['data_origin']!=first.data['data_origin']
                    or purpose.data['withdrawn'] is not False or 'operation' not in purpose.data['allowed_uses']):
                raise ValueError('calibration reference unavailable')
            deadlines.extend((integer(asset.data['expires_at_ms']),integer(purpose.data['expires_at_ms'])))
        deadline=min(deadlines)
        if first.data['data_origin']=='physical':
            profile=CalibrationProfile.model_validate_json(first.data['profile_json'])
            witness,expires=physical_assurance(repository,access,runtime,receipt.data['physical_assurance_id'],profile,
                receipt.data['report_sha256'],manifest,integer(data.data['epoch']),rows,
                (first.data.get('enrolled_by'),first.data.get('qualified_by'),first.data.get('approved_by')))
            for ident,row in witness.items():
                if ident in rows and rows[ident]!=row:raise StoreConflict('physical reviewer changed')
                rows[ident]=row
            final=repository.snapshot(tuple(rows))
            if any(final[key]!=row for key,row in rows.items()):raise StoreConflict('physical assurance changed')
            deadline=min(deadline,expires)
        if access.now()>=deadline:raise ValueError('calibration dependencies expired')
        return rows,first,deadline
    except StoreConflict:raise
    except (KeyError,TypeError,ValueError,AttributeError) as exc:raise StoreUnavailable('qualified calibration dependencies unavailable') from exc

