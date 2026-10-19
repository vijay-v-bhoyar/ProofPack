from copy import deepcopy
from pathlib import Path
import sys
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from run_python_suite import plan,coverage_errors
import run_python_suite as cohort_runner
import json
import hashlib


@pytest.mark.parametrize('fault',[None,'stale','running','state_retained','coerced_boolean','log_tampered'])
def test_database_receipt_retention_preserves_logs_and_never_reuses_stale_cleanup(tmp_path,monkeypatch,fault):
    output=tmp_path/'evidence';output.mkdir()
    monkeypatch.setattr(cohort_runner,'ROOT',tmp_path);monkeypatch.setattr(cohort_runner,'OUTPUT',output)
    row={'started_at':'2026-10-15T04:00:01+00:00','terminated':True,'state_removed':True,
        'server_log_sha256':hashlib.sha256(b'preserve daemon output').hexdigest()}
    if fault=='stale':row['started_at']='2026-10-15T03:59:59+00:00'
    elif fault=='running':row['terminated']=False
    elif fault=='state_retained':row['state_removed']=False
    elif fault=='coerced_boolean':row['terminated']=1
    (output/'dynamodb-local.json').write_text(json.dumps(row));(output/'dynamodb-server.log').write_text('preserve daemon output')
    if fault=='log_tampered':(output/'dynamodb-server.log').write_text('changed output')
    result=cohort_runner.retain_database_evidence('cohort-fixture','2026-10-15T04:00:00+00:00')
    assert result['database_terminated'] is (fault not in {'stale','running','coerced_boolean'})
    assert result['database_state_removed'] is (fault not in {'stale','state_retained'})
    if fault=='stale':assert 'database_receipt' not in result and 'database_log' not in result
    else:
        assert (output/'cohort-fixture-database.json').read_text()==json.dumps(row)
        if fault=='log_tampered':assert 'database_log' not in result and not (output/'cohort-fixture-database.log').exists()
        else:assert (output/'cohort-fixture-database.log').read_text()=='preserve daemon output'


def execution(nodes):
    return {'expected_nodeids':nodes,'exit_code':0,'execution':{'nodeids':nodes,'exit_code':0,'phase':'COMPLETE',
        'outcomes':[{'nodeid':node,'phase':phase,'outcome':'passed'} for node in nodes for phase in ('setup','call','teardown')]}}


def test_module_cohorts_preserve_every_case_and_parameter_without_splitting_shared_fixtures():
    nodes=['tests/unit/test_a.py::a[x]','tests/unit/test_a.py::a[y]','tests/integration/test_b.py::b']
    batches=plan(nodes,target=1)
    assert [b['files'] for b in batches]==[['tests/unit/test_a.py'],['tests/integration/test_b.py']]
    assert coverage_errors(nodes,[execution(b['expected_nodeids']) for b in batches])==[]


@pytest.mark.parametrize('fault',['omitted','duplicate','skipped','failure','missing_teardown','extra_phase','collection_changed','interrupted','exit','unexpected'])
def test_false_coverage_cannot_become_a_full_suite_pass(fault):
    nodes=['tests/unit/test_a.py::a','tests/unit/test_a.py::b'];batch=execution(nodes.copy());data=batch['execution']
    if fault=='omitted':data['nodeids']=nodes[:1];data['outcomes']=[x for x in data['outcomes'] if x['nodeid']==nodes[0]]
    elif fault=='duplicate':data['nodeids'].append(nodes[0])
    elif fault=='skipped':data['outcomes'][1]['outcome']='skipped'
    elif fault=='failure':data['outcomes'][0]['outcome']='failed'
    elif fault=='missing_teardown':data['outcomes'].pop()
    elif fault=='extra_phase':data['outcomes'].append(deepcopy(data['outcomes'][0]))
    elif fault=='collection_changed':data['nodeids']=nodes[::-1]
    elif fault=='interrupted':data['phase']='COLLECTED'
    elif fault=='exit':batch['exit_code']=124
    else:data['outcomes'].append({'nodeid':'unexpected','phase':'call','outcome':'passed'})
    assert coverage_errors(nodes,[batch])


@pytest.mark.parametrize('nodes',[[],['tests/a.py::a']*2,['../outside.py::a'],['tests/a.ts::a']])
def test_invalid_complete_inventory_is_rejected(nodes):
    with pytest.raises(ValueError):plan(nodes)


@pytest.mark.parametrize('target',[0,True,251,None])
def test_invalid_cohort_admission_cannot_start_collection_or_test_effects(monkeypatch,target):
    def unexpected(*args,**kwargs):
        pytest.fail('invalid cohort admission reached a command')
    monkeypatch.setattr(cohort_runner,'run_check',unexpected)
    with pytest.raises(ValueError):cohort_runner.run_suite(cohort_target=target)


def cost_fixture(counts):
    names=[f'tests/unit/test_cost_{i}.py' for i in range(len(counts))]
    return names,[f'{name}::test_value[{j}]' for name,count in zip(names,counts) for j in range(count)]


def test_balanced_plan_matches_independent_exhaustive_partition_oracle():
    from itertools import combinations
    from math import ceil
    examples=[([1]*6,4,[5,5,1,1,1,1]),
        ([2,1,1,1,2,1,1],4,[3,1,2,4,1,5,2]),
        ([1,5,1,1,2],3,[1,16,2,1,3]),
        ([1]*6,4,[1e-10]*6)]
    for counts,target,values in examples:
        names,nodes=cost_fixture(counts);costs=dict(zip(names,values))
        baseline=plan(nodes,target=target);budget=len(baseline);possible=[]
        for cuts in combinations(range(1,len(names)),budget-1):
            edges=(0,*cuts,len(names));parts=[list(range(a,b)) for a,b in zip(edges,edges[1:])]
            if all(sum(counts[i] for i in part)<=target or len(part)==1 for part in parts):
                possible.append(max(sum(ceil(values[i]*1000000) for i in part) for part in parts))
        result=cohort_runner.balanced_plan(nodes,target=target,module_costs=costs)
        assert len(result)==budget and [node for batch in result for node in batch['expected_nodeids']]==nodes
        assert [name for batch in result for name in batch['files']]==names
        assert all(len(batch['expected_nodeids'])<=target or len(batch['files'])==1 for batch in result)
        assert max(sum(ceil(costs[name]*1000000) for name in batch['files']) for batch in result)==min(possible)
    names,nodes=cost_fixture([1]*6);costs=dict(zip(names,[5,5,1,1,1,1]))
    result=cohort_runner.balanced_plan(nodes,target=4,module_costs=costs)
    assert max(sum(costs[name] for name in batch['files']) for batch in result)==10
    assert max(sum(costs[name] for name in batch['files']) for batch in plan(nodes,target=4))==12


def test_balanced_plan_is_deterministic_and_never_mutates_inputs():
    names,nodes=cost_fixture([1]*6);costs=dict.fromkeys(names,1);original_nodes=nodes.copy();original_costs=costs.copy()
    first=cohort_runner.balanced_plan(nodes,target=4,module_costs=costs)
    assert first==cohort_runner.balanced_plan(nodes,target=4,module_costs=costs)
    assert nodes==original_nodes and costs==original_costs
    assert [batch['files'] for batch in plan(nodes,target=4)]==[names[:4],names[4:]]


def test_invalid_cost_map_shapes_paths_and_numeric_values_are_rejected():
    names,nodes=cost_fixture([1,1]);good=dict.fromkeys(names,1)
    bad=[None,{},True,{'../outside.py':1},{'tests/../outside.py':1},{'tests\\bad.py':1},
        {f'tests/unit/test_many_{i}.py':1 for i in range(1001)}]
    for value in [0,-1,True,'1',None,float('nan'),float('inf'),2**63]:
        bad.append({**good,names[0]:value})
    for costs in bad:
        with pytest.raises(ValueError):cohort_runner.balanced_plan(nodes,target=1,module_costs=costs)


def test_cost_coverage_and_contiguous_original_module_order_are_required():
    names,nodes=cost_fixture([2,1]);good=dict.fromkeys(names,1)
    for costs in [{names[0]:1},{**good,'tests/unit/test_extra.py':1}]:
        with pytest.raises(ValueError):cohort_runner.balanced_plan(nodes,target=2,module_costs=costs)
    with pytest.raises(ValueError):
        cohort_runner.balanced_plan([nodes[0],nodes[2],nodes[1]],target=2,module_costs=good)


def test_exhausted_scheduler_work_fails_without_partial_schedule(monkeypatch):
    names,nodes=cost_fixture([1]*6);costs=dict.fromkeys(names,1)
    monkeypatch.setattr(cohort_runner,'_MAX_COST_TRANSITIONS',1)
    with pytest.raises(ValueError,match='work exhausted'):
        cohort_runner.balanced_plan(nodes,target=4,module_costs=costs)


def test_invalid_cost_or_cohort_ceiling_has_no_collection_or_file_effects(tmp_path,monkeypatch):
    output=tmp_path/'never-created';monkeypatch.setattr(cohort_runner,'OUTPUT',output)
    def unexpected(*args,**kwargs):pytest.fail('invalid planning admission reached collection')
    monkeypatch.setattr(cohort_runner,'run_check',unexpected)
    for kwargs in [{'module_costs':{}},{'module_costs':{'tests/unit/test_a.py':True}},
        {'cohort_limit':0},{'cohort_limit':True},{'cohort_limit':1001},
        {'cohort_process_budget':0},{'cohort_process_budget':True},
        {'cohort_process_budget':31500.0},{'cohort_process_budget':2**63}]:
        with pytest.raises(ValueError):cohort_runner.run_suite(**kwargs)
        assert not output.exists()


def test_mismatched_costs_or_invocation_ceiling_stop_before_any_test_cohort(tmp_path,monkeypatch):
    names,nodes=cost_fixture([1,1]);good=dict.fromkeys(names,1)
    for fault in ('missing','extra','ceiling','budget'):
        output=tmp_path/fault;calls=[];monkeypatch.setattr(cohort_runner,'ROOT',tmp_path)
        monkeypatch.setattr(cohort_runner,'OUTPUT',output)
        def collection_only(command,log_path,*,timeout,env):
            assert '--collect-only' in command and timeout==120
            calls.append(command)
            Path(env['PROOFPACK_PYTEST_EVIDENCE_PATH']).write_text(json.dumps(
                {'phase':'COMPLETE','nodeids':nodes,'outcomes':[],'exit_code':0}))
            return 0
        monkeypatch.setattr(cohort_runner,'run_check',collection_only)
        costs={names[0]:1} if fault=='missing' else {**good,'tests/unit/test_extra.py':1} if fault=='extra' else good
        assert cohort_runner.run_suite(cohort_target=1,module_costs=costs,cohort_limit=1 if fault=='ceiling' else 2,
            cohort_process_budget=1 if fault=='budget' else None)==1
        report=json.loads((output/'python-suite.json').read_text())
        assert report['status']=='FAIL' and report['errors'] and report['batches']==[] and len(calls)==1
        assert not (output/'dynamodb-local.json').exists()


def test_balanced_groups_still_use_unchanged_complete_phase_coverage_oracles():
    names,nodes=cost_fixture([1]*6);costs=dict.fromkeys(names,1)
    batches=cohort_runner.balanced_plan(nodes,target=4,module_costs=costs)
    complete=[execution(batch['expected_nodeids']) for batch in batches]
    assert not coverage_errors(nodes,complete)
    assert coverage_errors(nodes,complete[:-1])
    assert coverage_errors(nodes,complete+[deepcopy(complete[0])])
    complete[0]['execution']['outcomes'][0]['outcome']='skipped'
    assert coverage_errors(nodes,complete)


def test_aggregate_budget_reaches_every_cohort_invocation_and_never_expands900(tmp_path,monkeypatch):
    from contextlib import contextmanager
    import xml.etree.ElementTree as ET
    import dynamodb_local
    names,nodes=cost_fixture([1,1]);costs=dict.fromkeys(names,1)
    @contextmanager
    def modeled_database():
        yield 'http://127.0.0.1:1'
    monkeypatch.setattr(dynamodb_local,'local_database',modeled_database)
    monkeypatch.setattr(cohort_runner,'ROOT',tmp_path)
    monkeypatch.setattr(cohort_runner,'retain_database_evidence',lambda *args:{
        'database_terminated':True,'database_state_removed':True,'database_log':'modeled-unit-receipt'})
    for number,(budget,expected_timeout) in enumerate(((None,900),(1751,875),(100000,900))):
        output=tmp_path/f'budget-{number}';timeouts=[]
        monkeypatch.setattr(cohort_runner,'OUTPUT',output)
        def modeled_run(command,log_path,*,timeout,env):
            path=Path(env['PROOFPACK_PYTEST_EVIDENCE_PATH'])
            if '--collect-only' in command:
                assert timeout==120
                path.write_text(json.dumps({'phase':'COMPLETE','nodeids':nodes,'outcomes':[],'exit_code':0}))
            else:
                timeouts.append(timeout)
                selected=[node for node in nodes if node.split('::')[0] in command]
                assert len(selected)==1
                path.write_text(json.dumps(execution(selected)['execution']))
                suite=ET.Element('testsuite')
                for node in selected:
                    module,name=node.split('::');ET.SubElement(suite,'testcase',{
                        'classname':module.removesuffix('.py').replace('/','.'),'name':name})
                xml=next(value.split('=',1)[1] for value in command if value.startswith('--junitxml='))
                ET.ElementTree(suite).write(xml)
            return 0
        monkeypatch.setattr(cohort_runner,'run_check',modeled_run)
        assert cohort_runner.run_suite(cohort_target=1,module_costs=costs,cohort_limit=2,
            cohort_process_budget=budget)==0
        report=json.loads((output/'python-suite.json').read_text())
        assert timeouts==[expected_timeout,expected_timeout]
        assert report['cohort_timeout_seconds']==expected_timeout
        assert report['allocated_cohort_process_seconds']==sum(timeouts)
        assert all(batch['timeout_seconds']==expected_timeout for batch in report['batches'])
        assert max(timeouts)<=900 and len(report['batches'])==2
        if budget is not None:assert sum(timeouts)<=budget
