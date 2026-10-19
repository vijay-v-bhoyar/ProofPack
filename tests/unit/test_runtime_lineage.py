"""Original RuntimeControl writer on modeled storage; no retention authority."""
from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
from itertools import count
from types import SimpleNamespace

import pytest
from test_privacy_admission import ModelRepository, ident
from proofpack.auth.service import RUNTIME
from proofpack.runtime.control import RuntimeControl, ALLOCATION, DATA
from proofpack.evidence.repository import Row, Write
from proofpack.evidence.resource_bindings import prepare_linked


def family(*, existing=False):
    repo = ModelRepository()
    if existing:
        repo.rows[ALLOCATION] = Row(ALLOCATION, 4, {'slots': {}})
        repo.rows[DATA] = Row(DATA, 7, {'epoch': 3, 'changed_at_ms': 80})
    clock = count(100)
    access = SimpleNamespace(repository=repo, now=lambda: next(clock),
        _prepare_linked=lambda op, writes, checks: prepare_linked(repo.deployment, op, writes, checks))
    runtime = RuntimeControl(access, instance_id=ident(500), artifact_sha256='a'*64,
                             controls_sha256='b'*64, environment='test')
    runtime.start()
    event = next(row for key, row in repo.rows.items() if key.table == 'events')
    marker = next(row for key, row in repo.rows.items() if key.resource.startswith('runtime-start#'))
    return repo, event, marker, repo.rows[RUNTIME]


def run(event, marker, runtime, repo, **changes):
    from proofpack.evidence.runtime_lineage import discover, RuntimeLineageLimits
    args = dict(deployment=repo.deployment, now_ms=200,
        created_allocation=repo.rows[ALLOCATION] if repo.rows[ALLOCATION].revision == 1 else None,
        created_data=repo.rows[DATA] if repo.rows[DATA].revision == 1 else None,
        limits=RuntimeLineageLimits(5, 100000, 1000, 100000),
        deadline_ns=1000, tick=lambda: 1, checkpoint=lambda: None)
    return discover(event, marker, runtime, **(args | changes))


@pytest.mark.parametrize('existing', [False, True])
def test_real_writer_history_with_distinct_clock_reads_is_valid_and_private(existing):
    repo, event, marker, runtime = family(existing=existing)
    before = deepcopy(repo.rows)
    result = run(event, marker, runtime, repo)
    assert runtime.data['started_at_ms'] < event.data['at_ms']
    assert result.policy == 'runtime-startup-provenance-v1'
    assert len(result.records) == (3 if existing else 5)
    assert result.read_only is True and result.can_confirm_cleanup is False
    assert result == run(event, marker, runtime, repo) and repo.rows == before
    assert ident(500) not in repr(result) and 'runtime-start#' not in repr(result)
    with pytest.raises(FrozenInstanceError): result.work = 0


@pytest.mark.parametrize('fault', ['event_extra', 'marker_extra', 'runtime_extra', 'event_revision',
    'marker_revision', 'runtime_digest', 'marker_digest', 'foreign', 'operation', 'event_time',
    'runtime_time', 'boolean_epoch', 'missing_allocation', 'missing_data', 'occupied', 'data_time',
    'extra_peer', 'event_identity', 'marker_identity', 'runtime_identity'])
def test_corruption_never_yields_partial_provenance(fault):
    from proofpack.evidence.runtime_lineage import RuntimeLineageHeld
    repo, event, marker, runtime = family()
    kwargs = {}
    if fault.endswith('_extra'):
        row = {'event_extra': event, 'marker_extra': marker, 'runtime_extra': runtime}[fault]
        row.data['copied_inspection'] = 'PRIVATE'
    elif fault == 'event_revision': event = replace(event, revision=2)
    elif fault == 'marker_revision': marker = replace(marker, revision=2)
    elif fault == 'runtime_digest': runtime.data['controls_sha256'] = 'c'*64
    elif fault == 'marker_digest': marker.data['controls_sha256'] = 'c'*64
    elif fault == 'foreign': kwargs['deployment'] = 'foreign'
    elif fault == 'operation': event.data['resource_bindings']['operation'] = 'other'
    elif fault == 'event_time': event.data['at_ms'] = 201
    elif fault == 'runtime_time': runtime.data['started_at_ms'] = 199
    elif fault == 'boolean_epoch': event.data['runtime_epoch'] = True
    elif fault == 'missing_allocation': kwargs['created_allocation'] = None
    elif fault == 'missing_data': kwargs['created_data'] = None
    elif fault == 'occupied': repo.rows[ALLOCATION].data['slots'] = {ident(1): ident(2)}
    elif fault == 'data_time': repo.rows[DATA].data['changed_at_ms'] = 201
    elif fault == 'extra_peer':
        peer = deepcopy(event.data['resource_bindings']['writes'][0]); peer['resource'] = 'arbitrary'
        event.data['resource_bindings']['writes'].append(peer)
    elif fault.endswith('_identity'):
        row = {'event_identity': event, 'marker_identity': marker, 'runtime_identity': runtime}[fault]
        changed = replace(row, key=replace(row.key, resource='other'))
        if fault == 'event_identity': event = changed
        elif fault == 'marker_identity': marker = changed
        else: runtime = changed
    with pytest.raises(RuntimeLineageHeld): run(event, marker, runtime, repo, **kwargs)


@pytest.mark.parametrize('field', ['max_records', 'max_payload_bytes', 'max_work', 'max_summary_bytes'])
def test_independent_exact_bounds_and_one_below(field):
    from proofpack.evidence.runtime_lineage import RuntimeLineageHeld, RuntimeLineageLimits
    repo, event, marker, runtime = family()
    result = run(event, marker, runtime, repo)
    value = {'max_records': len(result.records), 'max_payload_bytes': result.payload_bytes,
             'max_work': result.work, 'max_summary_bytes': result.summary_bytes}[field]
    limits = RuntimeLineageLimits(5, 100000, 1000, 100000)
    assert run(event, marker, runtime, repo, limits=replace(limits, **{field: value})) == result
    with pytest.raises(RuntimeLineageHeld):
        run(event, marker, runtime, repo, limits=replace(limits, **{field: value-1}))


@pytest.mark.parametrize('field', ['max_records', 'max_payload_bytes', 'max_work', 'max_summary_bytes'])
@pytest.mark.parametrize('value', [True, 0, -1, 1.5, '3', 2**63])
def test_limits_are_explicit_exact_finite_integers(field, value):
    from proofpack.evidence.runtime_lineage import RuntimeLineageLimits
    with pytest.raises(ValueError): replace(RuntimeLineageLimits(5, 100000, 1000, 100000), **{field: value})


@pytest.mark.parametrize('fault', ['expired', 'backwards', 'checkpoint'])
def test_original_execution_fences_remain_effective(fault):
    from proofpack.evidence.runtime_lineage import RuntimeLineageHeld
    repo, event, marker, runtime = family()
    kwargs = {'tick': lambda: 1000} if fault == 'expired' else {}
    if fault == 'backwards':
        ticks = iter([2, 1]); kwargs['tick'] = lambda: next(ticks)
    if fault == 'checkpoint':
        def checkpoint(): raise RuntimeError('original authority checkpoint')
        kwargs['checkpoint'] = checkpoint
        with pytest.raises(RuntimeError, match='original authority checkpoint'):
            run(event, marker, runtime, repo, **kwargs)
        return
    with pytest.raises(RuntimeLineageHeld): run(event, marker, runtime, repo, **kwargs)


@pytest.mark.parametrize('fault', ['enabled', 'receipt', 'reason', 'epoch_mismatch', 'control_mismatch',
    'reversed_runtime', 'reversed_data', 'data_epoch', 'allocation_content', 'unsupported_environment'])
def test_linked_but_unsupported_payloads_are_not_accepted(fault):
    from proofpack.evidence.runtime_lineage import RuntimeLineageHeld
    repo, event, marker, runtime = family()
    if fault == 'enabled': runtime.data['inspection_enabled'] = True
    elif fault == 'receipt': runtime.data['enable_receipt_id'] = ident(3)
    elif fault == 'reason': runtime.data['reason'] = 'enabled'
    elif fault == 'epoch_mismatch': runtime.data['runtime_epoch'] += 1
    elif fault == 'control_mismatch': runtime.data['control_version'] += 1
    elif fault == 'reversed_runtime': runtime.data['started_at_ms'] = event.data['at_ms'] + 1
    elif fault == 'reversed_data': repo.rows[DATA].data['changed_at_ms'] = event.data['at_ms'] - 1
    elif fault == 'data_epoch': repo.rows[DATA].data['epoch'] = 2
    elif fault == 'allocation_content': repo.rows[ALLOCATION].data['slots'] = {ident(1): ident(2)}
    elif fault == 'unsupported_environment':
        runtime.data['environment'] = marker.data['environment'] = 'unsupported'
    # Keep all digests intact: these probes exercise semantic validation, not corruption alone.
    raw = {k: v for k, v in event.data.items() if k != 'resource_bindings'}
    writes = [Write(event.key, None, raw)] + [Write(row.key, None if row.revision == 1 else row.revision-1,
        row.data) for row in (runtime, marker, repo.rows[ALLOCATION], repo.rows[DATA])]
    linked, _ = prepare_linked(repo.deployment, 'runtime_started', writes, ())
    event = Row(event.key, 1, next(w.data for w in linked if w.key == event.key))
    with pytest.raises(RuntimeLineageHeld): run(event, marker, runtime, repo)


def test_checked_historical_heads_do_not_require_or_claim_current_payloads():
    from proofpack.evidence.runtime_lineage import RuntimeLineageHeld
    repo, event, marker, runtime = family(existing=True)
    result = run(event, marker, runtime, repo)
    assert all(ref.key not in (ALLOCATION, DATA) for ref in result.records)
    # Current heads can have changed; historical checks are not retained-current evidence.
    repo.rows[DATA].data['epoch'] = 999
    assert run(event, marker, runtime, repo) == result
    with pytest.raises(RuntimeLineageHeld):
        run(event, marker, runtime, repo, created_data=repo.rows[DATA])
