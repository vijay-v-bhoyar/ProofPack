"""Select complete optional-permission history; historical facts grant no rights."""
from dataclasses import dataclass

from proofpack.evidence.label_corpus import (
    LabelCorpus, LabelCorpusHeld, derive as label_derive, _inspection_references, _snapshot,
)
from proofpack.evidence.inspection_corpus import InspectionCorpusLimits, CorpusReference
from proofpack.evidence.capture_lineage import CaptureRecord
from proofpack.evidence.improvement_lineage import (
    ImprovementFamily, ImprovementHistoryHeld, discover as permission_discover,
)
from proofpack.evidence.repository import Key, Row
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.runtime.control import uuid, integer


class ImprovementCorpusHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class OptionalPermission:
    preview_id: str
    inspection_ids: tuple[str, ...]
    requested_inspection_ids: tuple[str, ...]
    unresolved_reference_sources: tuple[Key, ...]
    history: ImprovementFamily


@dataclass(frozen=True)
class ImprovementCorpus:
    labels: LabelCorpus
    families: tuple[OptionalPermission, ...]
    source_inputs: tuple[CaptureRecord, ...]
    residual: tuple[CorpusReference, ...]
    work: int


def derive(rows, *, deployment, requested_inspections, limits, now_ms,
           deadline_ns, tick, checkpoint):
    if (type(limits) is not InspectionCorpusLimits or not callable(tick)
            or not callable(checkpoint)):
        raise ValueError('explicit bounded permission corpus and trusted checkpoints required')
    last_tick = -1

    def checked_tick():
        nonlocal last_tick
        now = tick()
        if (type(now) is not int or type(deadline_ns) is not int
                or not 0 <= now < deadline_ns or now < last_tick):
            raise ImprovementCorpusHeld('original permission-corpus clock/deadline invalid')
        last_tick = now
        return now

    try:
        labels = label_derive(rows, deployment=deployment, requested_inspections=requested_inspections,
            limits=limits, now_ms=now_ms, deadline_ns=deadline_ns, tick=checked_tick, checkpoint=checkpoint)
        work = labels.work

        def check(cost=0):
            nonlocal work
            work += cost
            if work > limits.max_work:
                raise ImprovementCorpusHeld('shared permission-corpus work bound exhausted')
            checkpoint(); checked_tick(); checkpoint()

        copied = _snapshot(rows, _inspection_references(labels.inspections), check)
        frames = {}
        for family in labels.inspections.families:
            for record in family.capture.records:
                if record.key.table == 'state' and record.key.resource.startswith('asset#'):
                    if record.key in frames and frames[record.key] != family.inspection_id:
                        raise ValueError()
                    frames[record.key] = family.inspection_id
        previews = {}; grants = {}; heads = {}; events = []; permissions = {}
        for row in copied.values():
            check(1)
            if type(row) is not Row: continue
            prefix = row.key.resource.split('#', 1)[0]; data = row.data
            if prefix in {'improvement-preview', 'improvement-grant', 'improvement-permission'}:
                if row.key.table != 'state': raise ValueError()
                ident = uuid(data['id'])
                target = {'improvement-preview': previews, 'improvement-grant': grants,
                          'improvement-permission': heads}[prefix]
                if ident in target: raise ValueError()
                target[ident] = row
                if prefix == 'improvement-preview' and data.get('permission_id') is not None:
                    permission = uuid(data['permission_id'])
                    if permission in permissions: raise ValueError()
                    permissions[permission] = ident
            elif prefix == 'access' and row.key.table == 'events':
                kind = data.get('kind')
                if type(kind) is not str: raise ValueError()
                if kind in {'improvement-preview', 'improvement-confirm'} or kind.startswith('improvement-withdraw:'):
                    events.append(row)
        if grants.keys() != heads.keys() or grants.keys() != permissions.keys():
            raise ValueError()
        groups = {ident: [] for ident in previews}
        for permission, ident in permissions.items():
            groups[ident].extend((grants[permission], heads[permission]))
        for event in events:
            kind = event.data['kind']; details = event.data['details']
            ident = uuid(details['preview_id']) if kind == 'improvement-preview' else permissions[uuid(details['permission_id'])]
            if ident not in groups: raise ValueError()
            groups[ident].append(event)
        families = []; sources = {}; consumed = set()
        for ident, preview in sorted(previews.items()):
            selected = tuple(sorted(groups[ident], key=lambda r: (r.key.table, r.key.resource)))
            check(1 + len(selected))
            parsed = permission_discover(preview, selected, deployment=deployment,
                max_records=limits.max_records, max_payload_bytes=limits.max_payload_bytes)
            check()
            if {r.key for r in parsed.records} != {r.key for r in selected}:
                raise ValueError()
            related = set(); unresolved = set()
            # The parser has validated the exact finite scope and historical
            # source bindings. Current rows are inputs, not renewed permissions.
            for entry in preview.data['scope']['assets']:
                check(1)
                asset_key = Key('state', 'asset#' + uuid(entry['id']))
                purpose_key = Key('state', 'purpose#' + uuid(entry['purpose_id']))
                asset = copied[asset_key]; purpose = copied[purpose_key]
                if type(asset) is not Row or type(purpose) is not Row: raise ValueError()
                for row, version, digest in ((asset, entry['asset_revision'], entry['asset_record_sha256']),
                        (purpose, entry['purpose_revision'], entry['purpose_record_sha256'])):
                    historical = integer(version)
                    if row.revision < historical or (row.revision == historical and _payload_sha256(row.data) != digest):
                        raise ValueError()
                    record = CaptureRecord(row.key, row.revision, _payload_sha256(row.data))
                    if row.key in sources and sources[row.key] != record: raise ValueError()
                    sources[row.key] = record
                if entry['kind'] == 'frame':
                    if asset_key not in frames or asset.data.get('kind') == 'reference': raise ValueError()
                    related.add(frames[asset_key])
                elif entry['kind'] == 'reference':
                    if asset.data.get('kind') != 'reference' or asset_key in frames: raise ValueError()
                    unresolved.add(asset_key)
                else: raise ValueError()
            families.append(OptionalPermission(ident, tuple(sorted(related)),
                tuple(sorted(related.intersection(requested_inspections))), tuple(sorted(
                    unresolved, key=lambda k: (k.table, k.resource))), parsed))
            consumed.update((preview.key, *(r.key for r in parsed.records)))
        residual = tuple(r for r in labels.residual if r.key not in consumed)
        if consumed - {r.key for r in labels.residual}: raise ValueError()
        result = ImprovementCorpus(labels, tuple(families), tuple(sources[k] for k in sorted(
            sources, key=lambda k: (k.table, k.resource))), residual, work)
        check()
        return result
    except ImprovementCorpusHeld:
        raise
    except (LabelCorpusHeld, ImprovementHistoryHeld, KeyError, TypeError, ValueError,
            AttributeError, ArithmeticError, RecursionError):
        raise ImprovementCorpusHeld('intact complete optional-permission corpus required') from None
