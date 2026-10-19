"""Historical shared split-denial evidence, never ownership or action authority."""
from copy import deepcopy
from dataclasses import dataclass, replace
import re

from proofpack.calibrations.dependencies import canonical, digest
from proofpack.evidence.capture_lineage import CaptureRecord, CaptureLink, _record, _shape, _n
from proofpack.evidence.dataset_lineage import LabelInputs, PermissionInputs, DatasetHistoryHeld, discover as dataset_discover
from proofpack.evidence.repository import Key, Row, ErasureMarker
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.resource_lineage import decode
from proofpack.review.datasets import Split
from proofpack.review.manifests import group_key
from proofpack.runtime.control import DATA, RUNTIME, uuid, sha


class GroupHistoryHeld(RuntimeError):pass


@dataclass(frozen=True)
class DatasetInputs:
    job: Row
    rows: tuple
    label_families: tuple
    permission_families: tuple
    group_rows: tuple


@dataclass(frozen=True)
class GroupFamily:
    group: CaptureRecord
    versions: tuple
    history: tuple
    links: tuple
    dependencies: tuple
    intents: tuple
    payload_bytes: int


def _known(group):
    value = group.data
    _shape(value, frozenset('id category split generation original_split created_at_ms sha256'.split()), {'reason', 'changed_at_ms'})
    if group.key != group_key(sha(value['id'])) or group.revision != _n(value['generation'], positive=True):raise ValueError()
    if value['category'] not in {'kit', 'session', 'operator'} or any(value[name] not in {s.value for s in Split} for name in ('split', 'original_split')):raise ValueError()
    if digest({key: item for key, item in value.items() if key != 'sha256'}) != sha(value['sha256']):raise ValueError()
    _n(value['created_at_ms'])
    if group.revision == 1:
        if value['split'] != value['original_split'] or set(value) & {'reason', 'changed_at_ms'}:raise ValueError()
        return {1: _record(group)}
    if (group.revision != 2 or value['split'] != 'DEVELOPMENT' or value['original_split'] == 'DEVELOPMENT'
            or _n(value['changed_at_ms']) < value['created_at_ms']):raise ValueError()
    _reason(value['reason'])
    first = {key: value[key] for key in ('id', 'category', 'original_split', 'created_at_ms')}
    first.update(split=value['original_split'], generation=1);first['sha256'] = digest(first)
    return {1: CaptureRecord(group.key, 1, _payload_sha256(first)), 2: _record(group)}


def _reason(value):
    if type(value) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', value) is None:raise ValueError()


def _matches(reference, expected):
    if reference is None or (reference.key, reference.revision, reference.sha256) != (expected.key, expected.revision, expected.sha256):raise ValueError()


def _raw(dataset):
    if type(dataset) is not DatasetInputs or any(type(getattr(dataset, name)) is not tuple for name in ('rows', 'label_families', 'permission_families', 'group_rows')):raise ValueError()
    yield dataset.job
    yield from dataset.rows
    yield from dataset.group_rows
    for family in dataset.label_families:
        if type(family) is not LabelInputs or any(type(getattr(family, name)) is not tuple for name in ('rows', 'capture_rows', 'purpose_rows')):raise ValueError()
        yield family.inspection
        yield family.recipe
        yield from family.rows
        yield from family.capture_rows
        yield from family.purpose_rows
    for family in dataset.permission_families:
        if type(family) is not PermissionInputs or type(family.rows) is not tuple:raise ValueError()
        yield family.preview
        yield from family.rows


def discover(group, rows, *, datasets, deployment, max_records, max_payload_bytes):
    """The caller must separately admit complete inventory, drain and read sets."""
    if (type(rows) is not tuple or type(datasets) is not tuple
            or type(deployment) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', deployment) is None
            or any(type(value) is not int or not 1 <= value <= 2**63 - 1 for value in (max_records, max_payload_bytes))):
        raise ValueError('explicit bounded shared-group inputs required')
    try:
        if 1 + len(rows) > max_records:raise GroupHistoryHeld('group record bound exhausted')
        incoming = [group, *rows]
        for dataset in datasets:
            for row in _raw(dataset):
                if len(incoming) >= max_records:raise GroupHistoryHeld('group source record bound exhausted')
                incoming.append(row)
        copies = {};size = 0
        for row in incoming:
            if (isinstance(row, ErasureMarker) or not isinstance(row, Row) or not isinstance(row.key, Key)
                    or type(row.revision) is not int or not 1 <= row.revision <= 2**63 - 1 or type(row.data) is not dict):raise ValueError()
            _payload_sha256(row.data);size += len(canonical(row.data).encode())
            if size > max_payload_bytes:raise GroupHistoryHeld('group source byte bound exhausted')
            if row.key in copies:
                previous = copies[row.key]
                if previous.revision != row.revision or canonical(previous.data) != canonical(row.data):raise ValueError()
            else:copies[row.key] = deepcopy(row)
        if len({row.key for row in (group, *rows)}) != 1 + len(rows):raise ValueError()
        root = copies[group.key];known = _known(root);history = set();links = set();dependencies = set();creators = set();intents = set()
        for dataset in datasets:
            selected = tuple(copies[row.key] for row in dataset.group_rows)
            labels = tuple(replace(family, inspection=copies[family.inspection.key], recipe=copies[family.recipe.key],
                rows=tuple(copies[row.key] for row in family.rows), capture_rows=tuple(copies[row.key] for row in family.capture_rows),
                purpose_rows=tuple(copies[row.key] for row in family.purpose_rows)) for family in dataset.label_families)
            permissions = tuple(replace(family, preview=copies[family.preview.key], rows=tuple(copies[row.key] for row in family.rows)) for family in dataset.permission_families)
            result = dataset_discover(copies[dataset.job.key], tuple(copies[row.key] for row in dataset.rows),
                label_families=labels, permission_families=permissions, group_rows=selected, deployment=deployment,
                max_records=max_records, max_payload_bytes=max_payload_bytes)
            intents.update(result.intents);requested = False
            category = {'kit': 'kit_group', 'session': 'session_group', 'operator': 'operator_group'}[root.data['category']]
            for intent in result.intents:
                if intent.kind != 'requested_label':continue
                label = copies.get(intent.target)
                if label is not None and digest({'category': root.data['category'], 'group': label.data['source_context'][category]}) == root.data['id']:
                    requested = True;links.add(CaptureLink(root.key, label.key, 'group_requested_label'))
            if not requested and not any(row.key == root.key for row in selected):
                raise GroupHistoryHeld('supplied dataset association needs a copied group or resolved requested label')
            dependencies.update(ref for ref in (result.job, *result.records, *result.dependencies) if ref.key != root.key)
            links.add(CaptureLink(root.key, result.job.key, 'shared_dataset_group'))
            for original in dataset.rows:
                row = copies[original.key]
                if row.key.table != 'events':continue
                binding = decode(row, deployment=deployment)
                for reference in (*binding.checks, *binding.writes):
                    if reference.key == root.key:_matches(reference, known[reference.revision])
                written = next((ref for ref in binding.writes if ref.key == root.key), None)
                if written is not None:
                    if binding.operation != 'dataset-example-committed' or written.revision != 1 or written.previous_revision is not None:raise ValueError()
                    if row.data['at_ms'] < root.data['created_at_ms']:raise ValueError()
                    creators.add(row.key);history.add(_record(row));links.add(CaptureLink(root.key, row.key, 'group_created'))
        if len(creators) != 1:raise GroupHistoryHeld('exact supplied group creator required')
        first = [];details = []
        for original in rows:
            row = copies[original.key]
            if row.key.table != 'events' or row.revision != 1:raise ValueError()
            binding = decode(row, deployment=deployment)
            operation = 'dataset-declassify:' + root.data['id']
            if binding.operation != operation:raise ValueError()
            checked = {ref.key: ref for ref in binding.checks};written = {ref.key: ref for ref in binding.writes}
            if root.key not in checked or DATA not in checked or RUNTIME not in checked:raise ValueError()
            _matches(checked[root.key], known[checked[root.key].revision])
            if row.key.resource.startswith('access#'):
                uuid(row.key.resource[7:]);_shape(row.data, frozenset('kind actor_scope at_ms session_id details resource_bindings'.split()))
                value = row.data;sha(value['actor_scope']);uuid(value['session_id'])
                if value['kind'] != operation or Key('state', 'session#' + value['session_id']) not in checked:raise ValueError()
                users = [key for key in checked if key.table == 'state' and key.resource.startswith('user#')]
                if len(users) != 1 or users[0].resource != 'user#' + uuid(users[0].resource[5:]):raise ValueError()
                _shape(value['details'], frozenset(('group_id', 'to_split', 'reason')));_reason(value['details']['reason'])
                if value['details']['group_id'] != root.data['id'] or value['details']['to_split'] != 'DEVELOPMENT':raise ValueError()
                if _n(value['at_ms']) < root.data.get('changed_at_ms', root.data['created_at_ms']):raise ValueError()
                quota = Key('state', 'dataset-end-quota#' + value['actor_scope'])
                if root.key in written:
                    if set(written) != {root.key, DATA, quota} or root.revision != 2:raise ValueError()
                    _matches(checked[root.key], known[1]);_matches(written[root.key], known[2])
                    if written[root.key].previous_revision != 1 or written[DATA].previous_revision != checked[DATA].revision:raise ValueError()
                    if value['details']['reason'] != root.data['reason']:raise ValueError()
                    first.append((row, binding))
                elif set(written) != {quota} or root.data['split'] != 'DEVELOPMENT' or checked[root.key].revision != root.revision:raise ValueError()
                links.add(CaptureLink(root.key, row.key, 'group_declassification_access'))
            elif row.key.resource.startswith('dataset-declassification#'):
                uuid(row.key.resource[len('dataset-declassification#'):]);_shape(row.data, frozenset('group_id from_split to_split at_ms reason resource_bindings'.split()))
                value = row.data
                if (root.revision != 2 or value['group_id'] != root.data['id'] or value['from_split'] != root.data['original_split']
                        or value['to_split'] != 'DEVELOPMENT' or value['reason'] != root.data['reason']
                        or _n(value['at_ms']) < root.data['changed_at_ms']):raise ValueError()
                details.append((row, binding));links.add(CaptureLink(root.key, row.key, 'group_declassification_detail'))
            else:raise ValueError()
            history.add(_record(row))
            dependencies.update(CaptureRecord(ref.key, ref.revision, ref.sha256) for ref in (*binding.checks, *binding.writes) if ref.key != root.key)
        if root.revision == 2:
            if len(first) != 1 or len(details) != 1 or first[0][1] != details[0][1]:raise ValueError()
            if details[0][0].data['at_ms'] > first[0][0].data['at_ms']:raise ValueError()
        elif first or details:raise ValueError()
        order = lambda ref: (ref.key.table, ref.key.resource, ref.revision, ref.sha256)
        return GroupFamily(_record(root), tuple(known[number] for number in sorted(known)), tuple(sorted(history, key=order)),
            tuple(sorted(links, key=lambda link: (link.source.table, link.source.resource, link.target.table, link.target.resource, link.kind))),
            tuple(sorted(dependencies, key=order)),
            tuple(sorted(intents, key=lambda intent: (intent.source.table, intent.source.resource, intent.target.table, intent.target.resource, intent.revision, intent.kind))), size)
    except GroupHistoryHeld:raise
    except (KeyError, TypeError, ValueError, AttributeError, DatasetHistoryHeld) as exc:
        raise GroupHistoryHeld('complete supported shared-group and raw dataset history required') from exc
