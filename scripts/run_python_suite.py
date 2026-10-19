"""Run every collected test in whole-module cohorts with exact outcome accounting."""
from collections import Counter
from datetime import datetime,timezone
import json
import hashlib
import math
import os
from pathlib import Path
import shutil
import sys
import traceback
import xml.etree.ElementTree as ET
from verify_local import ROOT,OUTPUT,run_check

_MAX_COST_MODULES=1000
_MAX_COST_TRANSITIONS=2000000


def _validate_module_costs(costs):
    if type(costs) is not dict or not 1<=len(costs)<=_MAX_COST_MODULES:
        raise ValueError('bounded nonempty module cost map required')
    for name,value in costs.items():
        if (type(name) is not str or not name.startswith('tests/') or not name.endswith('.py')
            or '\\' in name or '..' in Path(name).parts or name!=Path(name).as_posix()
            or type(value) not in (int,float) or not 0<value<=2**63-1 or not math.isfinite(value)):
            raise ValueError('normalized test paths and positive finite numeric cost hints required')


def plan(nodes,*,target=150):
    if not nodes or len(nodes)!=len(set(nodes)) or type(target) is not int or target<1:
        raise ValueError('nonempty distinct test inventory and positive cohort target required')
    modules={}
    for node in nodes:
        name=node.split('::',1)[0].replace('\\','/')
        if not name.startswith('tests/') or Path(name).suffix!='.py' or '..' in Path(name).parts:
            raise ValueError('test module path required')
        modules.setdefault(name,[]).append(node)
    batches=[];files=[];requested=[]
    for name,items in modules.items():
        if requested and len(requested)+len(items)>target:
            batches.append({'files':files,'expected_nodeids':requested});files=[];requested=[]
        files.append(name);requested.extend(items)
    if requested:batches.append({'files':files,'expected_nodeids':requested})
    return batches


def balanced_plan(nodes,*,target=150,module_costs):
    """Minimize estimated peak time at the exact legacy invocation budget."""
    _validate_module_costs(module_costs)
    baseline=plan(nodes,target=target)
    if [node for batch in baseline for node in batch['expected_nodeids']]!=list(nodes):
        raise ValueError('contiguous original module collection order required')
    groups={}
    for node in nodes:
        groups.setdefault(node.split('::',1)[0].replace('\\','/'),[]).append(node)
    names=list(groups)
    if set(module_costs)!=set(names):
        raise ValueError('exact complete module cost coverage required')
    count=[0];cost=[0]
    for name in names:
        count.append(count[-1]+len(groups[name]))
        cost.append(cost[-1]+math.ceil(module_costs[name]*1000000))
    total=len(names);budget=len(baseline)
    scores=[[None]*(total+1) for _ in range(budget+1)];scores[0][0]=0
    previous={};work=0
    for number in range(1,budget+1):
        for end in range(number,total-(budget-number)+1):
            for start in range(end-1,number-2,-1):
                work+=1
                if work>_MAX_COST_TRANSITIONS:
                    raise ValueError('finite module scheduling work exhausted')
                if count[end]-count[start]>target and end-start!=1:
                    break
                prior=scores[number-1][start]
                if prior is None:
                    continue
                value=max(prior,cost[end]-cost[start])
                if scores[number][end] is None or value<scores[number][end]:
                    scores[number][end]=value;previous[number,end]=start
    if scores[budget][total] is None:
        raise ValueError('original cohort budget cannot cover the inventory')
    result=[];end=total
    for number in range(budget,0,-1):
        start=previous[number,end];files=names[start:end]
        result.append({'files':files,'expected_nodeids':[node for name in files for node in groups[name]]})
        end=start
    result.reverse()
    if (len(result)!=len(baseline) or any(not batch['files'] for batch in result)
        or [node for batch in result for node in batch['expected_nodeids']]!=list(nodes)):
        raise ValueError('complete original order and fixed invocation budget required')
    return result


def coverage_errors(expected,batches):
    errors=[];actual=[]
    if not expected or len(expected)!=len(set(expected)):errors.append('full inventory is empty or duplicated')
    for i,batch in enumerate(batches):
        result=batch.get('execution',{});nodes=result.get('nodeids',[]);actual.extend(nodes)
        if (batch.get('exit_code')!=0 or result.get('exit_code')!=0 or result.get('phase')!='COMPLETE'):
            errors.append(f'cohort {i}: nonzero or incomplete execution')
        if nodes!=batch.get('expected_nodeids') or len(nodes)!=len(set(nodes)):
            errors.append(f'cohort {i}: collection differs from frozen requested inventory')
        outcomes={node:[] for node in nodes}
        for event in result.get('outcomes',[]):
            if event.get('nodeid') not in outcomes:errors.append(f'cohort {i}: unexpected outcome');continue
            outcomes[event['nodeid']].append((event.get('phase'),event.get('outcome')))
        required=Counter({('setup','passed'):1,('call','passed'):1,('teardown','passed'):1})
        for node,phases in outcomes.items():
            if Counter(phases)!=required:errors.append(f'cohort {i}: failed, skipped, missing or duplicate phase: {node}')
    if Counter(actual)!=Counter(expected):errors.append('combined collection omits or duplicates full-suite nodes')
    return errors


def retain_database_evidence(stem,started_at):
    """Retain this cohort's diagnostics; stale receipts cannot prove cleanup."""
    value={'database_terminated':False,'database_state_removed':False}
    source=OUTPUT/'dynamodb-local.json';log=OUTPUT/'dynamodb-server.log'
    if source.exists():
        receipt=json.loads(source.read_text(encoding='utf-8'))
        if datetime.fromisoformat(receipt['started_at'])>=datetime.fromisoformat(started_at):
            target=OUTPUT/(stem+'-database.json');shutil.copyfile(source,target)
            value.update(database_receipt=target.relative_to(ROOT).as_posix(),
                database_terminated=receipt.get('terminated') is True,database_state_removed=receipt.get('state_removed') is True)
            if log.exists() and receipt.get('server_log_sha256')==hashlib.sha256(log.read_bytes()).hexdigest():
                target=OUTPUT/(stem+'-database.log');shutil.copyfile(log,target)
                value['database_log']=target.relative_to(ROOT).as_posix()
    return value


def run_suite(*,cohort_target=150,module_costs=None,cohort_limit=None,cohort_process_budget=None):
    if type(cohort_target) is not int or not 1 <= cohort_target <= 250:
        raise ValueError('explicit cohort target between one and 250 required')
    if cohort_limit is not None and (type(cohort_limit) is not int or not 1<=cohort_limit<=_MAX_COST_MODULES):
        raise ValueError('positive finite cohort ceiling required')
    if cohort_process_budget is not None and (type(cohort_process_budget) is not int or not 1<=cohort_process_budget<=2**63-1):
        raise ValueError('positive finite integer aggregate process budget required')
    if module_costs is not None:
        _validate_module_costs(module_costs)
        module_costs=dict(module_costs)
    OUTPUT.mkdir(parents=True,exist_ok=True)
    summary={'scope':'all_collected_python_tests','status':'IN_PROGRESS','started_at':datetime.now(timezone.utc).isoformat(),
        'cohort_target_tests':cohort_target,'cohort_timeout_seconds':900,'batches':[],'errors':[]}
    summary.update(scheduler_policy='case-count-v1' if module_costs is None else 'same-budget-module-time-v1',
        cohort_limit=cohort_limit,cohort_process_budget=cohort_process_budget,module_cost_hints=module_costs,
        module_cost_hints_sha256=None if module_costs is None else hashlib.sha256(
            json.dumps(module_costs,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest())
    path=OUTPUT/'python-suite.json'
    def save():path.write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    save()
    env={**os.environ,'PYTHONPATH':str(ROOT/'scripts')+os.pathsep+os.environ.get('PYTHONPATH','')}
    collected=OUTPUT/'python-collection.json';collected.unlink(missing_ok=True)
    command=[sys.executable,'-m','pytest','--collect-only','-q','-p','pytest_evidence']
    code=run_check(command,OUTPUT/'python-collection.log',timeout=120,env={**env,'PROOFPACK_PYTEST_EVIDENCE_PATH':str(collected)})
    summary['collection_command']=command;summary['collection_exit_code']=code
    if code or not collected.exists():summary.update(status='FAIL',errors=['full collection failed']);save();return code or 1
    collection=json.loads(collected.read_text(encoding='utf-8'));expected=collection['nodeids']
    if collection['phase']!='COMPLETE' or collection['exit_code']!=0:summary.update(status='FAIL',errors=['incomplete full collection']);save();return 1
    try:
        batches=(plan(expected,target=cohort_target) if module_costs is None else
            balanced_plan(expected,target=cohort_target,module_costs=module_costs))
        if cohort_limit is not None and len(batches)>cohort_limit:
            raise ValueError('original invocation ceiling cannot cover the full inventory')
        timeout_seconds=900 if cohort_process_budget is None else min(900,cohort_process_budget//len(batches))
        if timeout_seconds<1:
            raise ValueError('aggregate process budget cannot admit every cohort')
    except ValueError as exc:summary.update(status='FAIL',errors=[str(exc)]);save();return 1
    summary.update(expected_nodeids=expected,batches=batches,cohort_timeout_seconds=timeout_seconds,
        allocated_cohort_process_seconds=timeout_seconds*len(batches));save()
    from dynamodb_local import local_database
    for i,batch in enumerate(batches,1):
        stem=f'python-cohort-{i:03d}';json_path=OUTPUT/(stem+'.json');xml_path=OUTPUT/(stem+'.xml');log_path=OUTPUT/(stem+'.log')
        for stale in (json_path,xml_path):stale.unlink(missing_ok=True)
        batch.update(status='RUNNING',started_at=datetime.now(timezone.utc).isoformat(),log=log_path.relative_to(ROOT).as_posix())
        command=[sys.executable,'-m','pytest','-q','-p','pytest_evidence',*batch['files'],'--junitxml='+str(xml_path)]
        batch.update(command=command,timeout_seconds=timeout_seconds);save()
        try:
            with local_database() as endpoint:
                code=run_check(command,log_path,timeout=timeout_seconds,env={**env,'PROOFPACK_TEST_DYNAMO_URL':endpoint,'PROOFPACK_PYTEST_EVIDENCE_PATH':str(json_path)})
        except Exception:
            with log_path.open('a',encoding='utf-8') as log:traceback.print_exc(file=log)
            code=1;batch['database_terminated']=False
        try:batch.update(retain_database_evidence(stem,batch['started_at']))
        except (OSError,ValueError,KeyError,TypeError):
            with log_path.open('a',encoding='utf-8') as log:traceback.print_exc(file=log)
            batch.update(database_terminated=False,database_state_removed=False)
        batch.update(exit_code=code,status='PASS' if code==0 else 'FAIL',ended_at=datetime.now(timezone.utc).isoformat())
        batch['execution']=json.loads(json_path.read_text(encoding='utf-8')) if json_path.exists() else {}
        if not batch.get('database_terminated'):summary['errors'].append(f'cohort {i}: database cleanup unproved')
        if not batch.get('database_state_removed'):summary['errors'].append(f'cohort {i}: disposable database state cleanup unproved')
        if not batch.get('database_log'):summary['errors'].append(f'cohort {i}: database diagnostics missing')
        save();print(f"Python cohort {i}/{len(batches)}: {batch['status']} ({len(batch['expected_nodeids'])} collected tests)",flush=True)
    summary['errors'].extend(coverage_errors(expected,batches))
    combined=ET.Element('testsuites')
    for i,batch in enumerate(batches,1):
        xml=OUTPUT/f'python-cohort-{i:03d}.xml'
        try:
            tree=ET.parse(xml).getroot();suites=[tree] if tree.tag=='testsuite' else list(tree)
            count=sum(len(list(suite.iter('testcase'))) for suite in suites)
            if count!=len(batch['expected_nodeids']):summary['errors'].append(f'cohort {i}: JUnit count mismatch')
            for suite in suites:combined.append(suite)
        except (OSError,ET.ParseError):summary['errors'].append(f'cohort {i}: missing or invalid JUnit')
    ET.ElementTree(combined).write(OUTPUT/'unit-tests.xml',encoding='utf-8',xml_declaration=True)
    summary.update(status='FAIL' if summary['errors'] else 'PASS',ended_at=datetime.now(timezone.utc).isoformat())
    save();print(f"Full Python inventory: {len(expected)}; coverage {summary['status']}",flush=True)
    return 0 if summary['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(run_suite())
