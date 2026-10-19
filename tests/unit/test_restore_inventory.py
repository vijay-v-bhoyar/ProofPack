"""Synthetic source/backup/target models; no actual restore or release authority."""
from copy import deepcopy
from dataclasses import asdict, replace, FrozenInstanceError
import hashlib
import json

from botocore.exceptions import ReadTimeoutError
import pytest

from test_journal_anchors import world as anchor_world, init, prepare, seal, opts
from proofpack.evidence.inventory import InventoryLimits, InventoryPass, collect, InventoryHeld, _encoded
from proofpack.evidence.repository import DynamoRepository, Key
from proofpack.evidence.resource_bindings import _payload_sha256
from proofpack.evidence.erasure_journal import JournalHeld
from proofpack.evidence.restore_inventory import RestoreInventoryLimits, read_restore_inventory


class TargetClient:
    def __init__(self, source):
        self.meta = deepcopy(source.meta)
        self.calls = []
        self.items = {'restore-events': [], 'restore-state': []}
        self.after = None
        self.ttl = 'DISABLED'
        self.wrong_arn = False

    def describe_table(self, **kw):
        self.calls.append(('describe_table', deepcopy(kw)))
        name = kw['TableName']
        arn = 'arn:aws:dynamodb:us-east-1:000000000000:table/' + name
        return {'Table': {'TableName': name, 'TableArn': arn + ('-wrong' if self.wrong_arn else ''),
            'TableStatus': 'ACTIVE', 'KeySchema': [{'AttributeName': 'pk', 'KeyType': 'HASH'},
                {'AttributeName': 'sk', 'KeyType': 'RANGE'}],
            'AttributeDefinitions': [{'AttributeName': 'pk', 'AttributeType': 'S'},
                {'AttributeName': 'sk', 'AttributeType': 'S'}]}}

    def describe_time_to_live(self, **kw):
        self.calls.append(('describe_time_to_live', deepcopy(kw)))
        return {'TimeToLiveDescription': {'TimeToLiveStatus': self.ttl}}

    def query(self, **kw):
        self.calls.append(('query', deepcopy(kw)))
        start = kw.get('ExclusiveStartKey', {}).get('sk', {}).get('S', '')
        values = [deepcopy(r) for r in self.items[kw['TableName']] if r['sk']['S'] > start]
        page = values[:kw['Limit']]
        result = {'Items': page, 'Count': len(page), 'ScannedCount': len(page)}
        if len(values) > len(page):
            result['LastEvaluatedKey'] = {k: page[-1][k] for k in ('pk', 'sk')}
        if self.after:
            self.after(kw, result)
        return result


def source_pass(target_pass, original):
    body = {'deployment': original.deployment, 'tables': original.tables,
            'entries': [asdict(e) for e in target_pass.entries]}
    encoded = _encoded(body)
    return InventoryPass(original.deployment, tuple(sorted(original.tables.items())), target_pass.entries,
                         target_pass.pages, hashlib.sha256(encoded).hexdigest(), len(encoded))


def world(kind='live'):
    v = anchor_world()
    root = init(v)
    original = v[1].repository
    client = TargetClient(original.client)
    target = DynamoRepository(client, deployment=original.deployment,
                              state_table='restore-state', events_table='restore-events')
    key = Key('state', 'private-key#never-log')
    payload = {'private': 'NEVER_PRINT_PAYLOAD'}
    intent = replace(v[3][0], resource_sha256=original._erasure_identity(key),
                     source_revision=1, source_payload_sha256=_payload_sha256(payload))
    v = (v[0], v[1], v[2], (intent,))
    prepare(v)
    point = seal(v, root.checkpoint).checkpoint
    item = {**target.key(key), 'revision': {'N': '1'}, 'data': target.serialize.serialize(payload)}
    if kind == 'erased':
        item['revision'] = {'N': '2'}
        item['data'] = {'M': {}}
        item['payload_erasure'] = target.serialize.serialize({'schema_version': 1,
            'reference_sha256': intent.reference_sha256, 'resource_sha256': intent.resource_sha256})
    if kind != 'absent':
        client.items['restore-state'] = [item]
    limits = RestoreInventoryLimits(InventoryLimits(1, 10, 20, 20000), 1000, 100000)
    inventory = collect(target, limits=limits.inventory, **opts())
    backup = source_pass(inventory, original)
    arns = tuple((role, 'arn:aws:dynamodb:us-east-1:000000000000:table/' + name)
                 for role, name in sorted(target.tables.items()))
    kwargs = dict(expected_head=point, target_arns=arns, backup_sha256='a'*64,
        source_inventory=backup, artifact_sha256='b'*64, limits=limits, **opts())
    client.calls.clear()
    return v, target, client, kwargs


@pytest.mark.parametrize('kind,status', [('live', 'pending_effect'), ('erased', 'marker_observed'),
                                       ('absent', 'unresolved_absent')])
def test_exact_original_identity_and_complete_backup_match_never_authorizes_release(kind, status):
    v, target, client, kw = world(kind)
    before = deepcopy(client.items)
    result = read_restore_inventory(v[0], target, **kw)
    assert result.matches[0].resource_sha256 == v[3][0].resource_sha256
    assert result.matches[0].status == status
    assert result.source_tables == tuple(sorted(v[1].repository.tables.items()))
    assert result.target_tables == tuple(sorted(target.tables.items()))
    assert result.source_tables != result.target_tables
    assert result.source_inventory_sha256 == kw['source_inventory'].summary_sha256
    assert result.target_inventory_sha256 != result.source_inventory_sha256
    assert result.checkpoint == kw['expected_head']
    assert not any((result.can_erase, result.can_release, result.restore_authorized, result.request_fulfilled))
    assert 'NEVER_PRINT_PAYLOAD' not in repr(result) and 'private-key' not in repr(result)
    assert client.items == before
    assert all(name in {'query', 'describe_table', 'describe_time_to_live'} for name, _ in client.calls)
    with pytest.raises(FrozenInstanceError):
        result.backup_sha256 = 'f'*64


@pytest.mark.parametrize('fault', ['overlap', 'deployment', 'arn', 'ttl', 'wrong_region', 'backup_digest',
    'backup_missing', 'backup_added', 'backup_revision', 'sdk_budget', 'work_budget', 'deadline', 'clock_bool'])
def test_mismatched_targets_inventory_and_original_allowances_hold(fault):
    v, target, client, kw = world()
    if fault == 'overlap': target.tables['state'] = v[1].repository.tables['state']
    elif fault == 'deployment': target.deployment = 'different'
    elif fault == 'arn': client.wrong_arn = True
    elif fault == 'ttl': client.ttl = 'ENABLED'
    elif fault == 'wrong_region': kw['target_arns'] = tuple((r, a.replace('us-east-1', 'us-west-2')) for r, a in kw['target_arns'])
    elif fault == 'backup_digest': kw['source_inventory'] = replace(kw['source_inventory'], summary_sha256='f'*64)
    elif fault == 'backup_missing': client.items['restore-state'] = []
    elif fault == 'backup_added':
        extra = deepcopy(client.items['restore-state'][0]); extra['sk']['S'] += '-extra'; client.items['restore-state'].append(extra)
    elif fault == 'backup_revision': client.items['restore-state'][0]['revision']['N'] = '3'
    elif fault == 'sdk_budget': kw['limits'] = replace(kw['limits'], max_sdk_calls=1)
    elif fault == 'work_budget': kw['limits'] = replace(kw['limits'], max_work=1)
    elif fault == 'deadline': kw['tick'] = lambda: 1000
    else: kw['tick'] = lambda: True
    with pytest.raises((JournalHeld, InventoryHeld)):
        read_restore_inventory(v[0], target, **kw)


@pytest.mark.parametrize('kind,fault', [('live', 'payload'), ('live', 'revision'),
                                      ('erased', 'reference'), ('erased', 'revision')])
def test_even_self_consistent_backup_cannot_hide_intent_source_or_marker_mismatch(kind, fault):
    v, target, client, kw = world(kind)
    item = client.items['restore-state'][0]
    if fault == 'payload': item['data'] = target.serialize.serialize({'different': 'value'})
    elif fault == 'revision': item['revision']['N'] = '8'
    else: item['payload_erasure']['M']['reference_sha256']['S'] = 'f'*64
    inventory = collect(target, limits=kw['limits'].inventory, **opts())
    kw['source_inventory'] = source_pass(inventory, v[1].repository)
    with pytest.raises(JournalHeld): read_restore_inventory(v[0], target, **kw)


@pytest.mark.parametrize('fault', ['change', 'cancel', 'config', 'clock', 'transport', 'backup_mutation'])
def test_changes_during_real_page_boundary_withhold_all_results(fault):
    v, target, client, kw = world()
    state = [False]
    def after(parameters, result):
        if state[0]: return
        state[0] = True
        if fault == 'change': client.items['restore-state'][0]['revision']['N'] = '3'
        elif fault == 'cancel': pass
        elif fault == 'config': client.meta.config.read_timeout = 2
        elif fault == 'transport': raise ReadTimeoutError(endpoint_url='synthetic-local')
        elif fault == 'backup_mutation': object.__setattr__(kw['source_inventory'], 'summary_sha256', 'f'*64)
    client.after = after
    if fault == 'cancel':
        def checkpoint():
            if state[0]: raise JournalHeld('synthetic cancelled admission')
        kw['checkpoint'] = checkpoint
    if fault == 'clock': kw['tick'] = lambda: 1000 if state[0] else 1
    with pytest.raises((JournalHeld, InventoryHeld)): read_restore_inventory(v[0], target, **kw)


def test_exact_duplicate_sealed_intents_deduplicate_without_losing_history():
    v, target, client, kw = world()
    again = seal(v, kw['expected_head']).checkpoint
    kw['expected_head'] = again
    result = read_restore_inventory(v[0], target, **kw)
    assert again.sequence == 2 and len(result.matches) == 1


def test_conflicting_sealed_intents_for_one_resource_are_never_latest_wins():
    v, target, client, kw = world()
    other = (v[0], v[1], v[2], (replace(v[3][0], reference_sha256='8'*64),))
    prepare(other); kw['expected_head'] = seal(other, kw['expected_head']).checkpoint
    with pytest.raises(JournalHeld, match='conflicting'): read_restore_inventory(v[0], target, **kw)


@pytest.mark.parametrize('fault',['limits','backup'])
def test_final_clock_callback_cannot_change_original_inputs_after_last_check(fault):
    v,target,client,kw=world();count=[0]
    def baseline_tick():count[0]+=1;return 1
    read_restore_inventory(v[0],target,**(kw|{'tick':baseline_tick}))
    last=count[0];v,target,client,kw=world();count[0]=0
    def tick():
        count[0]+=1
        if count[0]==last:
            if fault=='limits':object.__setattr__(kw['limits'],'max_sdk_calls',1)
            else:object.__setattr__(kw['source_inventory'],'summary_sha256','f'*64)
        return 1
    with pytest.raises((JournalHeld,InventoryHeld)):
        read_restore_inventory(v[0],target,**(kw|{'tick':tick}))
