"""Derive dataset copies/intents and shared group history; never cleanup authority."""
from dataclasses import dataclass
from itertools import chain

from proofpack.evidence.improvement_corpus import ImprovementCorpus, ImprovementCorpusHeld, derive as permission_derive
from proofpack.evidence.label_corpus import _inspection_references, _snapshot
from proofpack.evidence.inspection_corpus import InspectionCorpusLimits, CorpusReference
from proofpack.evidence.inventory import _private_payload_size
from proofpack.evidence.dataset_lineage import (
    LabelInputs, PermissionInputs, DatasetFamily, DatasetIntent, DatasetHistoryHeld, discover as dataset_discover,
)
from proofpack.evidence.dataset_group_lineage import (
    DatasetInputs, GroupFamily, GroupHistoryHeld, discover as group_discover, _raw as dataset_raw,
)
from proofpack.evidence.repository import Row
from proofpack.review.manifests import ManifestRequest, group_key
from proofpack.runtime.control import uuid


class DatasetCorpusHeld(RuntimeError):
    pass


@dataclass(frozen=True)
class DatasetCorpusLimits:
    corpus: InspectionCorpusLimits
    family_max_records: int
    family_max_payload_bytes: int
    max_datasets: int
    max_groups: int

    def __post_init__(self):
        if (type(self.corpus) is not InspectionCorpusLimits or any(type(v) is not int
                or not 1 <= v <= 2**63-1 for v in (self.family_max_records,
                    self.family_max_payload_bytes, self.max_datasets, self.max_groups))):
            raise ValueError('explicit separate corpus, expanded family and root bounds required')


@dataclass(frozen=True)
class DatasetDependency:
    dataset_id: str
    status: str
    inspection_ids: tuple[str, ...]
    copied_inspection_ids: tuple[str, ...]
    requested_inspection_ids: tuple[str, ...]
    unresolved_intents: tuple[DatasetIntent, ...]
    history: DatasetFamily


@dataclass(frozen=True)
class SharedGroup:
    group_id: str
    dataset_ids: tuple[str, ...]
    copied_inspection_ids: tuple[str, ...]
    history: GroupFamily


@dataclass(frozen=True)
class DatasetCorpus:
    permissions: ImprovementCorpus
    families: tuple[DatasetDependency, ...]
    groups: tuple[SharedGroup, ...]
    residual: tuple[CorpusReference, ...]
    work: int
    max_family_records_used: int
    max_family_payload_bytes_used: int


def derive(rows, *, deployment, requested_inspections, limits, now_ms,
           deadline_ns, tick, checkpoint):
    if type(limits) is not DatasetCorpusLimits or not callable(tick) or not callable(checkpoint):
        raise ValueError('explicit dataset corpus limits and trusted checkpoints required')
    last_tick = -1

    def checked_tick():
        nonlocal last_tick
        now = tick()
        if (type(now) is not int or type(deadline_ns) is not int
                or not 0 <= now < deadline_ns or now < last_tick):
            raise DatasetCorpusHeld('original dataset-corpus clock/deadline invalid')
        last_tick = now
        return now

    try:
        upstream = permission_derive(rows, deployment=deployment, requested_inspections=requested_inspections,
            limits=limits.corpus, now_ms=now_ms, deadline_ns=deadline_ns,
            tick=checked_tick, checkpoint=checkpoint)
        work = upstream.work; peak_records = 0; peak_bytes = 0

        def check(cost=0):
            nonlocal work
            work += cost
            if work > limits.corpus.max_work:
                raise DatasetCorpusHeld('shared dataset-corpus work bound exhausted')
            checkpoint(); checked_tick(); checkpoint()

        def charge(expanded):
            nonlocal peak_records, peak_bytes
            count = 0; size = 0
            for row in expanded:
                check(1); count += 1; size += _private_payload_size(row.data)
                if count > limits.family_max_records or size > limits.family_max_payload_bytes:
                    raise DatasetCorpusHeld('explicit expanded-family bound exhausted')
            peak_records = max(peak_records, count); peak_bytes = max(peak_bytes, size)

        copied = _snapshot(rows, _inspection_references(upstream.labels.inspections), check)
        jobs = {}; groups = {}; group_history = {}; job_rows = {}
        for row in copied.values():
            check(1)
            if type(row) is not Row: continue
            prefix = row.key.resource.split('#', 1)[0]
            if prefix == 'maintenance-job' and row.data.get('kind') == 'dataset_manifest':
                if row.key.table != 'state': raise ValueError()
                ident = uuid(row.data['id'])
                if ident in jobs: raise ValueError()
                jobs[ident] = row; job_rows[ident] = []
                if len(jobs) > limits.max_datasets:
                    raise DatasetCorpusHeld('dataset root bound exhausted')
            elif prefix == 'dataset-group':
                if row.key.table != 'state' or row.key != group_key(row.data['id']): raise ValueError()
                ident = row.data['id']
                if ident in groups: raise ValueError()
                groups[ident] = row; group_history[ident] = []
                if len(groups) > limits.max_groups:
                    raise DatasetCorpusHeld('shared-group root bound exhausted')
        for row in copied.values():
            check(1)
            if type(row) is not Row: continue
            prefix = row.key.resource.split('#', 1)[0]; data = row.data
            parent = None; shared = None
            if prefix in {'dataset-catalog', 'dataset-manifest', 'dataset-example'}:
                if row.key.table != 'state': raise ValueError()
                parent = uuid(data['dataset_id'] if prefix == 'dataset-example' else data['id'])
            elif prefix in {'dataset-transition', 'dataset-access'}:
                if row.key.table != 'events': raise ValueError()
                parent = uuid(data['dataset_id'])
            elif prefix == 'dataset-declassification':
                if row.key.table != 'events': raise ValueError()
                shared = data['group_id']
            elif prefix == 'access' and row.key.table == 'events':
                kind = data.get('kind')
                if type(kind) is not str: raise ValueError()
                if kind == 'dataset-create': parent = uuid(data['details']['dataset_id'])
                elif kind.startswith(('dataset-step:', 'dataset-cancel:', 'dataset-retire:')):
                    parent = uuid(kind.split(':', 1)[1])
                elif kind.startswith('dataset-declassify:'): shared = kind.split(':', 1)[1]
            if parent is not None:
                if parent not in jobs: raise ValueError()
                job_rows[parent].append(row)
            if shared is not None:
                if shared not in groups: raise ValueError()
                group_history[shared].append(row)
        by_inspection = {f.inspection_id: f for f in upstream.labels.inspections.families}
        label_families = {f.inspection_id: f.labels for f in upstream.labels.families}
        label_owners = {}; label_revisions = set()
        for owner, family in label_families.items():
            for ref in family.records:
                row = copied[ref.key]
                if row.key.resource.startswith('label#'):
                    ident = uuid(row.data['id'])
                    if ident in label_owners and label_owners[ident] != owner: raise ValueError()
                    label_owners[ident] = owner
                elif row.key.resource.startswith('label-revision#'): label_revisions.add(row.key)
        permissions = {copied[f.history.grant.key].data['id']: f for f in upstream.families if f.history.grant is not None}
        raw_datasets = {}; dependencies = []; consumed = set(); copied_owners = {}
        order = lambda row: (row.key.table, row.key.resource)
        for ident, job in sorted(jobs.items()):
            text = job.data['request_json']
            if type(text) is not str or not 1 <= len(text.encode()) <= 262144: raise ValueError()
            request = ManifestRequest.model_validate_json(text)
            owners = {label_owners[s.label_id] for s in request.selections if s.label_id in label_owners}
            li = []
            for owner in sorted(owners):
                family = label_families[owner]; inspection = by_inspection[owner]
                li.append(LabelInputs(copied[inspection.capture.inspection.key],
                    tuple(copied[r.key] for r in family.records), tuple(copied[r.key] for r in inspection.capture.records),
                    copied[family.recipe.key], tuple(copied[r.key] for r in family.purposes)))
            selected_permissions = {p.id for s in request.selections for p in s.permissions if p.id in permissions}
            pi = tuple(PermissionInputs(copied[permissions[p].history.preview.key],
                tuple(copied[r.key] for r in permissions[p].history.records)) for p in sorted(selected_permissions))
            selected = tuple(sorted(job_rows[ident], key=order)); needed_groups = set()
            for row in selected:
                if row.key.resource.startswith('dataset-example#'):
                    values = row.data['content']['groups']
                    if type(values) is not list or len(values) != 3: raise ValueError()
                    needed_groups.update(value['id'] for value in values)
            gr = tuple(groups[g] for g in sorted(needed_groups))
            raw = DatasetInputs(job, selected, tuple(li), pi, gr)
            charge(dataset_raw(raw))
            parsed = dataset_discover(job, selected, label_families=tuple(li), permission_families=pi,
                group_rows=gr, deployment=deployment, max_records=limits.family_max_records,
                max_payload_bytes=limits.family_max_payload_bytes)
            check()
            if {r.key for r in parsed.records} != {r.key for r in selected}: raise ValueError()
            actual_owners = {label_owners[r.data['content']['label_id']] for r in selected
                             if r.key.resource.startswith('dataset-example#')}
            unresolved = []
            for intent in parsed.intents:
                if intent.kind == 'requested_label' and intent.target not in label_revisions:
                    unresolved.append(intent)
                elif intent.kind == 'requested_permission':
                    current = copied.get(intent.target)
                    if (type(current) is not Row or current.revision < intent.revision
                            or current.data.get('id') not in permissions): unresolved.append(intent)
            related = owners | actual_owners
            dependencies.append(DatasetDependency(ident, job.data['status'], tuple(sorted(related)), tuple(sorted(actual_owners)),
                tuple(sorted(related.intersection(requested_inspections))), tuple(unresolved), parsed))
            raw_datasets[ident] = raw; copied_owners[ident] = actual_owners
            consumed.update((job.key, *(r.key for r in parsed.records)))
        shared_groups = []
        for ident, group in sorted(groups.items()):
            members = tuple(name for name, value in sorted(raw_datasets.items()) if group.key in {r.key for r in value.group_rows})
            raw = tuple(raw_datasets[name] for name in members)
            history = tuple(sorted(group_history[ident], key=order))
            charge(chain((group,), history, *(dataset_raw(d) for d in raw)))
            parsed = group_discover(group, history, datasets=raw, deployment=deployment,
                max_records=limits.family_max_records, max_payload_bytes=limits.family_max_payload_bytes)
            check()
            related = set().union(*(copied_owners[name] for name in members)) if members else set()
            shared_groups.append(SharedGroup(ident, members, tuple(sorted(related)), parsed))
        residual = tuple(r for r in upstream.residual if r.key not in consumed)
        if consumed - {r.key for r in upstream.residual}: raise ValueError()
        # Shared group rows/history remain residual; validated history is not a
        # supported target-only redaction/retention or collateral-scope decision.
        result = DatasetCorpus(upstream, tuple(dependencies), tuple(shared_groups), residual, work,
            peak_records, peak_bytes)
        check()
        return result
    except DatasetCorpusHeld:
        raise
    except (ImprovementCorpusHeld, DatasetHistoryHeld, GroupHistoryHeld, KeyError,
            TypeError, ValueError, AttributeError, ArithmeticError, RecursionError):
        raise DatasetCorpusHeld('intact complete dataset/copy/shared-group corpus required') from None
