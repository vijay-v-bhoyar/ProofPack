"""Server-derived historical label inputs; not complete classification or rights.

Shared recipe/purpose inputs remain residual obligations, even after validation.
Caller-authentication, actual held-reader provenance and final source revalidation
belong to the complete privacy workflow and cannot be supplied by this value.
"""
from copy import deepcopy
from dataclasses import dataclass

from proofpack.evidence.inspection_corpus import (
    InspectionCorpus, InspectionCorpusLimits, InspectionCorpusHeld, CorpusReference,
    derive as inspection_derive,
)
from proofpack.evidence.capture_lineage import CaptureRecord
from proofpack.evidence.label_lineage import LabelFamily, LabelHistoryHeld, discover as label_discover
from proofpack.evidence.repository import Key, Row, ErasureMarker
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.recipes.service import revision_key as recipe_key
from proofpack.runtime.control import uuid


class LabelCorpusHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class InspectionLabels:
    inspection_id: str
    requested: bool
    labels: LabelFamily


@dataclass(frozen=True)
class LabelCorpus:
    inspections: InspectionCorpus
    families: tuple[InspectionLabels, ...]
    shared_inputs: tuple[CaptureRecord, ...]
    residual: tuple[CorpusReference, ...]
    work: int


def _inspection_references(inspections):
    references = {r.key: r for r in inspections.residual}
    for family in inspections.families:
        root = family.capture.inspection
        references[root.key] = CorpusReference(root.key, root.revision, 'live', root.sha256)
        for parsed in (family.capture, family.human, family.support):
            for ref in parsed.records:
                old = references.get(ref.key)
                current = CorpusReference(ref.key, ref.revision, 'live', ref.sha256)
                if old is not None and old != current:
                    raise ValueError()
                references[ref.key] = current
    return references


def _snapshot(rows, references, check):
    copied = {}
    for original in rows:
        check(1)
        row = deepcopy(original)
        if (type(row) not in {Row, ErasureMarker} or type(row.key) is not Key
                or type(row.key.table) is not str or row.key.table not in {'state', 'events'}
                or type(row.key.resource) is not str or not 1 <= len(row.key.resource) <= 256
                or type(row.revision) is not int or not 1 <= row.revision <= 2**63-1):
            raise ValueError()
        expected = references[row.key]
        if type(row) is Row:
            if type(row.data) is not dict: raise ValueError()
            actual = CorpusReference(row.key, row.revision, 'live', _payload_sha256(row.data))
        elif type(row) is ErasureMarker:
            if (row.revision < 2 or type(row.reference_sha256) is not str
                    or type(row.resource_sha256) is not str): raise ValueError()
            actual = CorpusReference(row.key, row.revision, 'erased',
                row.reference_sha256, row.resource_sha256)
        else:
            raise ValueError()
        if actual != expected or row.key in copied:
            raise ValueError()
        copied[row.key] = row
    if copied.keys() != references.keys():
        raise ValueError()
    return copied


def derive(rows, *, deployment, requested_inspections, limits, now_ms,
           deadline_ns, tick, checkpoint):
    """Derive all label histories from immutable source contexts, not heads alone."""
    if (type(limits) is not InspectionCorpusLimits or not callable(tick)
            or not callable(checkpoint)):
        raise ValueError('typed corpus bounds and trusted clock/checkpoint required')
    last_tick = -1

    def checked_tick():
        nonlocal last_tick
        now = tick()
        if (type(now) is not int or type(deadline_ns) is not int
                or not 0 <= now < deadline_ns or now < last_tick):
            raise LabelCorpusHeld('original label-corpus deadline or monotonic clock invalid')
        last_tick = now
        return now

    try:
        inspections = inspection_derive(rows, deployment=deployment,
            requested_inspections=requested_inspections, limits=limits,
            now_ms=now_ms, deadline_ns=deadline_ns, tick=checked_tick, checkpoint=checkpoint)
        work = inspections.work

        def check(cost=0):
            nonlocal work
            work += cost
            if work > limits.max_work:
                raise LabelCorpusHeld('shared corpus work bound exhausted')
            checkpoint(); checked_tick(); checkpoint()

        # Compare the second detached snapshot against every reference from the
        # preceding selection. A callback cannot silently replace its inputs.
        copied = _snapshot(rows, _inspection_references(inspections), check)
        by_inspection = {f.inspection_id: f for f in inspections.families}
        revisions = {}; heads = {}; events = []; label_owner = {}
        for row in copied.values():
            check(1)
            if type(row) is not Row:
                continue
            prefix = row.key.resource.split('#', 1)[0]; data = row.data
            if prefix == 'label':
                if row.key.table != 'state': raise ValueError()
                ident = uuid(data['id'])
                if ident in heads: raise ValueError()
                heads[ident] = row
            elif prefix == 'label-revision':
                if row.key.table != 'state': raise ValueError()
                ident = uuid(data['id']); owner = uuid(data['source_context']['inspection_id'])
                if owner not in by_inspection or (ident in label_owner and label_owner[ident] != owner):
                    raise ValueError()
                label_owner[ident] = owner
                revisions.setdefault(ident, []).append(row)
            elif prefix == 'access' and row.key.table == 'events':
                kind = data.get('kind')
                if type(kind) is not str: raise ValueError()
                if kind == 'label-create' or kind.startswith('label-revise:'):
                    events.append(row)
        if heads.keys() != revisions.keys():
            raise ValueError()
        groups = {}
        for ident, chain in revisions.items():
            owner = label_owner[ident]
            groups.setdefault(owner, []).extend((heads[ident], *chain))
        for event in events:
            ident = uuid(event.data['details']['label_id'])
            if ident not in label_owner:
                raise ValueError()
            groups[label_owner[ident]].append(event)
        families = []; shared = {}; consumed = set()
        order = lambda row: (row.key.table, row.key.resource)
        for ident, selected in sorted(groups.items()):
            previous = by_inspection[ident]
            root = copied[previous.capture.inspection.key]
            cr = tuple(copied[r.key] for r in previous.capture.records)
            recipe = copied[recipe_key(root.data['recipe_id'], root.data['recipe_revision'])]
            if type(recipe) is not Row: raise ValueError()
            purpose_keys = set()
            for row in selected:
                if row.key.resource.startswith('label-revision#'):
                    sources = row.data['source_context']['sources']
                    if type(sources) is not list or len(sources) > limits.max_records:
                        raise ValueError()
                    for source in sources:
                        check(1)
                        purpose_keys.add(Key('state', 'purpose#' + uuid(source['purpose_id'])))
            purposes = tuple(copied[k] for k in sorted(purpose_keys, key=lambda k: (k.table, k.resource)))
            if any(type(row) is not Row for row in purposes): raise ValueError()
            lr = tuple(sorted(selected, key=order))
            check(2 + len(cr) + len(lr) + len(purposes))
            parsed = label_discover(root, lr, capture_rows=cr, recipe=recipe,
                purpose_rows=purposes, deployment=deployment, max_records=limits.max_records,
                max_payload_bytes=limits.max_payload_bytes)
            check()
            if (parsed.capture != previous.capture or {r.key for r in parsed.records} != {r.key for r in lr}):
                raise ValueError()
            for source in (parsed.recipe, *parsed.purposes):
                old = shared.get(source.key)
                if old is not None and old != source: raise ValueError()
                shared[source.key] = source
            consumed.update(r.key for r in parsed.records)
            families.append(InspectionLabels(ident, previous.requested, parsed))
        residual = tuple(r for r in inspections.residual if r.key not in consumed)
        if consumed - {r.key for r in inspections.residual}:
            raise ValueError()
        result = LabelCorpus(inspections, tuple(families), tuple(shared[k] for k in sorted(
            shared, key=lambda k: (k.table, k.resource))), residual, work)
        check()
        return result
    except LabelCorpusHeld:
        raise
    except (InspectionCorpusHeld, LabelHistoryHeld, KeyError, TypeError, ValueError,
            AttributeError, ArithmeticError, RecursionError):
        raise LabelCorpusHeld('intact complete historical label inputs required') from None
