"""Measured crop references: geometry and provenance, never pose/pass authority."""
import hashlib
from proofpack.calibrations.dependencies import digest
from proofpack.verifier.core import Finding
from proofpack.vision.worker_result import WorkerResult


def geometry(result):
    selected=[(index,c) for index,c in enumerate(result.candidates) if c.correction_reason is not None]
    if not selected:return None
    if result.rectified_size is None or not result.quality_ok:raise ValueError('measured crop geometry required')
    width,height=result.rectified_size
    return {'schema_version':1,'coordinate_space':'rectified_crop_v1','width':width,'height':height,
        'regions':[{'candidate_index':index,'box':list(c.box),'reason':c.correction_reason,
            'part_class':None if c.part_class is None else c.part_class.value,
            'aspect_ratio_interval':None if c.aspect_ratio_interval is None else list(c.aspect_ratio_interval)} for index,c in selected]}


def validate_measurement(result,recipe,profile):
    if any(c.box[0]+c.box[2]>profile.output_width or c.box[1]+c.box[3]>profile.output_height for c in result.candidates):
        raise ValueError('measured candidate outside actual output profile')
    for index,constraint in enumerate(recipe.constraints):
        reference=constraint.flat_reference_aspect_ratio
        if reference is not None and constraint.expected_count>0 and not constraint.permitted_variant_ids:
            for candidate in result.candidates:
                if candidate.part_class!=constraint.part_class_id:continue
                interval=candidate.aspect_ratio_interval
                matches=interval is not None and reference.minimum<=interval[0]<=interval[1]<=reference.maximum
                if not matches and (candidate.correction_reason!='not_flat' or result.findings[index]!=Finding.UNOBSERVABLE):
                    raise ValueError('unresolved flat projection cannot assert observable contents')
    value=geometry(result)
    if value is None:return None
    if result.rectified_size!=(profile.output_width,profile.output_height):raise ValueError('correction crop differs from actual profile')
    if result.unknown_regions<sum(c.part_class is None for c in result.candidates):raise ValueError('unknown correction region must block satisfaction')
    for c in result.candidates:
        if c.correction_reason=='overlap' and any(f!=Finding.UNOBSERVABLE for f in result.findings):
            raise ValueError('overlap cannot assert known contents')
        if c.correction_reason=='not_flat':
            selected=next(((i,k) for i,k in enumerate(recipe.constraints) if k.part_class_id==c.part_class),None)
            if selected is None:raise ValueError('flat-reference constraint required')
            index,constraint=selected;reference=constraint.flat_reference_aspect_ratio
            if (reference is None or constraint.expected_count==0 or constraint.permitted_variant_ids or result.findings[index]!=Finding.UNOBSERVABLE
                    or (c.aspect_ratio_interval is not None and reference.minimum<=c.aspect_ratio_interval[0]<=c.aspect_ratio_interval[1]<=reference.maximum)):
                raise ValueError('unresolved enrolled flat-reference projection required')
    return value


def basis(result_json,crop_sha256):
    if not isinstance(result_json,str) or len(result_json.encode())>65536:raise ValueError('bounded measured result required')
    result=WorkerResult.model_validate_json(result_json);value=geometry(result)
    if value is None:return None,None
    if not isinstance(crop_sha256,str) or len(crop_sha256)!=64 or any(c not in '0123456789abcdef' for c in crop_sha256):
        raise ValueError('exact correction crop digest required')
    signature=digest({'schema_version':1,'result_sha256':hashlib.sha256(result_json.encode()).hexdigest(),
        'crop_sha256':crop_sha256,'source_sha256':result.source_sha256,'calibration_sha256':result.calibration_hash,'geometry':value})
    return {**value,'source_sha256':result.source_sha256,'calibration_sha256':result.calibration_hash,'crop_sha256':crop_sha256,'basis_sha256':signature},signature


def verified_reference(asset,observation):
    left=asset.get('correction_basis_sha256');right=observation.get('correction_basis_sha256')
    if asset.get('derivation')!='rectified_roi_jpeg':
        if left is not None:raise ValueError('crop geometry cannot describe an original/reference image')
        return None
    if left is None and right is None:
        text=observation.get('result_json')
        if isinstance(text,str) and '"correction_reason"' in text and geometry(WorkerResult.model_validate_json(text)) is not None:
            raise ValueError('measured correction reference basis missing')
        return None
    value,signature=basis(observation['result_json'],asset['sha256'])
    if (signature is None or signature!=left or signature!=right or value['source_sha256']!=observation['source_sha256']
            or value['source_sha256']!=asset['input_sha256'] or asset['observation_id']!=observation['id']):
        raise ValueError('correction result/image/observation binding changed')
    return {**value,'observation_id':observation['id']}


def target_indices(value,kind):
    reason={'SEPARATE_REGION':'overlap','PLACE_FLAT':'not_flat'}.get(kind)
    return [] if value is None or reason is None else [r['candidate_index'] for r in value['regions'] if r['reason']==reason]
