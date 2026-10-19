import { positive, sha, uuid } from './workbench';

export type CorrectionRegion = { candidate_index: number; box: number[]; reason: 'overlap' | 'not_flat'; part_class: string | null; aspect_ratio_interval: number[] | null };
export type CorrectionReference = { schema_version: 1; coordinate_space: 'rectified_crop_v1'; width: number; height: number; regions: CorrectionRegion[];
  source_sha256: string; calibration_sha256: string; crop_sha256: string; basis_sha256: string; observation_id: string };
export type CorrectionRequest = { inspection_id: string; observation_id: string; action_id: string; kind: string };
export function correctionValue(raw: unknown, asset: { sha256: string; derivation?: string | null; observation_id?: string | null; can_download: boolean }): CorrectionReference {
  const x = raw as CorrectionReference;
  const allowed = ['schema_version', 'coordinate_space', 'width', 'height', 'regions', 'source_sha256', 'calibration_sha256', 'crop_sha256', 'basis_sha256', 'observation_id'];
  if (!x || typeof x !== 'object' || Object.keys(x).some(k => !allowed.includes(k)) || !asset.can_download || asset.derivation !== 'rectified_roi_jpeg'
    || x.schema_version !== 1 || x.coordinate_space !== 'rectified_crop_v1' || !positive(x.width) || !positive(x.height)
    || Math.min(x.width, x.height) < 16 || Math.max(x.width, x.height) > 2000 || x.width * x.height > 2000000
    || !uuid.test(x.observation_id) || x.observation_id !== asset.observation_id || x.crop_sha256 !== asset.sha256
    || [x.source_sha256, x.calibration_sha256, x.crop_sha256, x.basis_sha256].some(v => !sha.test(v ?? ''))
    || !Array.isArray(x.regions) || !x.regions.length || x.regions.length > 30 || new Set(x.regions.map(r => r?.candidate_index)).size !== x.regions.length
    || x.regions.some(r => !r || Object.keys(r).some(k => !['candidate_index', 'box', 'reason', 'part_class', 'aspect_ratio_interval'].includes(k))
      || !Number.isSafeInteger(r.candidate_index) || r.candidate_index < 0 || r.candidate_index >= 30 || !Array.isArray(r.box) || r.box.length !== 4
      || r.box.some(n => !Number.isSafeInteger(n) || n < 0) || !positive(r.box[2]) || !positive(r.box[3]) || r.box[0] + r.box[2] > x.width || r.box[1] + r.box[3] > x.height
      || !['overlap', 'not_flat'].includes(r.reason) || (r.reason === 'overlap' ? r.part_class !== null : !['washer', 'nut', 'bolt', 'flat_bracket'].includes(r.part_class ?? ''))
      || (r.aspect_ratio_interval !== null && (!Array.isArray(r.aspect_ratio_interval) || r.aspect_ratio_interval.length !== 2
        || r.aspect_ratio_interval.some(n => !Number.isFinite(n)) || r.aspect_ratio_interval[0] < 1 || r.aspect_ratio_interval[1] < r.aspect_ratio_interval[0]))))
    throw new Error('Measured correction reference is mismatched or unavailable. Use manual review.');
  return x;
}
export function selectedRegions(reference: CorrectionReference, request?: CorrectionRequest) {
  const reason = request?.kind === 'SEPARATE_REGION' ? 'overlap' : request?.kind === 'PLACE_FLAT' ? 'not_flat' : null;
  return request ? reference.regions.filter(region => region.reason === reason) : reference.regions;
}
export function regionText(region: CorrectionRegion) {
  return region.reason === 'overlap' ? 'Unclassified connected region: possible touching or overlapping parts. This historical reference does not authorize another correction.'
    : `${region.part_class?.replaceAll('_', ' ')} projection is outside its enrolled flat reference or cannot be bounded. 3D pose was not measured; this historical reference is not action authority.`;
}
