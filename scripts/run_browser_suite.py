"""Execute the complete frozen Playwright inventory in bounded whole-file cohorts."""
from collections import Counter
from datetime import datetime,timezone
import copy
import json
import os
from pathlib import Path,PurePosixPath
import shutil
import sys
import traceback
from uuid import uuid4
import xml.etree.ElementTree as ET

from verify_local import ROOT,OUTPUT,run_check,source_manifest
from browser_local import local_web


def profile(report):
    config=report['config']
    return {'rootDir':config['rootDir'],'workers':config['workers'],'fullyParallel':config['fullyParallel'],
        'globalTimeout':config['globalTimeout'],'shard':config.get('shard'),
        'projects':[{k:p[k] for k in ('id','name','testDir','testMatch','testIgnore','retries','repeatEach','timeout')}
                    for p in config['projects']]}


def cases(report,*,collection=False):
    if report.get('errors'):raise ValueError('browser runner reported errors')
    result=[]
    def walk(suite,parents):
        names=(*parents,suite['title'])
        for spec in suite.get('specs',[]):
            file=spec['file'].replace('\\','/');path=PurePosixPath(file)
            if path.is_absolute() or '..' in path.parts or ':' in file or path.suffix!='.ts':raise ValueError('scoped browser file required')
            for test in spec['tests']:
                if (not isinstance(spec['id'],str) or not spec['id'] or not isinstance(test['projectId'],str)
                        or test['expectedStatus']!='passed' or type(test['timeout']) is not int or test['timeout']<1):
                    raise ValueError('distinct normally passing browser case required')
                item={'id':spec['id']+'::'+test['projectId'],'file':file,'title':' › '.join((*names[1:],spec['title'])),
                    'project':test['projectName'],'timeout':test['timeout']}
                if collection:
                    if test['results']:raise ValueError('collection cannot contain executed results')
                elif (spec.get('ok') is not True or test['status']!='expected' or len(test['results'])!=1
                        or test['results'][0]['status']!='passed' or type(test['results'][0]['retry']) is not int or test['results'][0]['retry']!=0
                        or test['results'][0].get('error') or test['results'][0].get('errors')):
                    raise ValueError('failed, skipped, retried or incomplete browser case')
                result.append(item)
        for child in suite.get('suites',[]):walk(child,names)
    for suite in report['suites']:walk(suite,())
    if not result or len({c['id'] for c in result})!=len(result):raise ValueError('nonempty distinct browser inventory required')
    if not collection:
        stats=report['stats']
        if (type(stats['expected']) is not int or stats['expected']!=len(result) or any(type(stats[k]) is not int or stats[k]!=0 for k in ('skipped','unexpected','flaky'))):
            raise ValueError('browser totals contradict outcomes')
    return result


def plan(expected):
    if not expected or len({c['id'] for c in expected})!=len(expected):raise ValueError('complete distinct inventory required')
    files={}
    for item in expected:files.setdefault(item['file'],[]).append(item)
    return [{'file':file,'expected':items} for file,items in files.items()]


def xml_errors(path,expected):
    root=ET.parse(path).getroot();actual=[];errors=[]
    for suite in root.iter('testsuite'):
        for case in suite.findall('testcase'):
            actual.append((suite.attrib.get('hostname',''),case.attrib['classname'],case.attrib['name']))
            if any(case.find(tag) is not None for tag in ('failure','error','skipped')):errors.append('XML includes failed/skipped case')
    desired=[(c['project'],c['file'],c['title']) for c in expected]
    if Counter(actual)!=Counter(desired):errors.append('XML omits, duplicates or changes browser cases')
    return errors,root


def coverage_errors(expected,batches):
    errors=[];actual=[]
    if not expected or len({c['id'] for c in expected})!=len(expected):errors.append('full inventory missing or duplicated')
    for index,batch in enumerate(batches):
        if batch.get('exit_code')!=0 or batch.get('status')!='PASS' or batch.get('server_terminated') is not True:
            errors.append(f'cohort {index}: failure, incomplete execution or cleanup')
        if batch.get('actual')!=batch.get('expected') or batch.get('xml_errors'):
            errors.append(f'cohort {index}: outcome inventory or XML mismatch')
        actual.extend(batch.get('actual',[]))
    if Counter(c['id'] for c in actual)!=Counter(c['id'] for c in expected):errors.append('combined inventory omitted or duplicated cases')
    by_id={c['id']:c for c in expected}
    if any(by_id.get(c['id'])!=c for c in actual):errors.append('combined case identity or timeout changed')
    return errors


def read_report(path):
    if path.stat().st_size>16*1024*1024:raise ValueError('browser report exceeds explicit 16 MiB bound')
    return json.loads(path.read_text(encoding='utf-8-sig'))


def run_suite():
    OUTPUT.mkdir(parents=True,exist_ok=True)
    run=OUTPUT/'browser-runs'/(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid4().hex[:12]);run.mkdir(parents=True)
    before=source_manifest();summary={'scope':'all_collected_browser_tests','status':'IN_PROGRESS','started_at':datetime.now(timezone.utc).isoformat(),
        'cohort_timeout_seconds':120,'strategy':'whole-file, original default Chrome and original assertion settings',
        'run_directory':run.relative_to(ROOT).as_posix(),'source_manifest':before,'batches':[],'errors':[]}
    receipt=OUTPUT/'browser-suite.json'
    def save():receipt.write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
    save();node=shutil.which('node');base=[node,'node_modules/@playwright/test/cli.js','test','--config=apps/web/playwright.config.ts']
    collected=run/'collection.json';env={**os.environ,'PLAYWRIGHT_JSON_OUTPUT_FILE':str(collected)}
    command=[*base,'--list','--reporter=json'];code=run_check(command,run/'collection.log',env=env)
    summary.update(collection_command=command,collection_exit_code=code)
    try:
        if code:raise ValueError('complete browser collection failed')
        collection=read_report(collected);expected=cases(collection,collection=True);frozen=profile(collection)
        if (Path(frozen['rootDir']).resolve()!=(ROOT/'tests/e2e').resolve() or frozen['workers']!=1
                or frozen['fullyParallel'] is not False or frozen['globalTimeout']!=0 or frozen['shard'] is not None
                or any(p['retries']!=0 or p['repeatEach']!=1 for p in frozen['projects'])):
            raise ValueError('original unsharded single-worker/no-retry browser configuration required')
        summary.update(expected=expected,profile=frozen,batches=plan(expected));save()
    except (OSError,ValueError,KeyError,TypeError) as exc:
        summary.update(status='FAIL',errors=[str(exc)],ended_at=datetime.now(timezone.utc).isoformat());save();return 1
    aggregate=ET.Element('testsuites')
    for index,batch in enumerate(summary['batches'],1):
        prefix=run/f'cohort-{index:03d}';report=prefix.with_suffix('.json');xml=prefix.with_suffix('.xml');log=prefix.with_suffix('.log')
        batch.update(status='RUNNING',started_at=datetime.now(timezone.utc).isoformat(),log=log.relative_to(ROOT).as_posix(),
            report=report.relative_to(ROOT).as_posix(),xml=xml.relative_to(ROOT).as_posix(),server_terminated=False)
        command=[*base,'tests/e2e/'+batch['file'],'--reporter=list,json,junit','--output='+str(prefix)+'-artifacts'];batch['command']=command;save()
        (OUTPUT/'browser-server.json').unlink(missing_ok=True)
        try:
            with local_web() as endpoint:
                batch['exit_code']=run_check(command,log,timeout=120,env={**os.environ,'PROOFPACK_BROWSER_URL':endpoint,
                    'PLAYWRIGHT_JSON_OUTPUT_FILE':str(report),'PLAYWRIGHT_JUNIT_OUTPUT_FILE':str(xml),
                    'PLAYWRIGHT_JUNIT_INCLUDE_PROJECT_IN_TEST_NAME':'0','PLAYWRIGHT_JUNIT_INCLUDE_RETRIES':'0','PLAYWRIGHT_JUNIT_OMIT_TAGS':'0'})
            value=read_report(report)
            if profile(value)!=frozen:raise ValueError('browser configuration changed between collection and execution')
            batch['actual']=cases(value);batch['xml_errors'],root=xml_errors(xml,batch['expected'])
            for suite in root.findall('testsuite'):aggregate.append(copy.deepcopy(suite))
            batch['status']='PASS' if batch['exit_code']==0 and batch['actual']==batch['expected'] and not batch['xml_errors'] else 'FAIL'
        except (OSError,ValueError,KeyError,TypeError,RuntimeError,ET.ParseError) as exc:
            batch.update(status='FAIL',error=str(exc));(prefix.with_suffix('.error.log')).write_text(traceback.format_exc(),encoding='utf-8')
        finally:
            server=OUTPUT/'browser-server.json'
            if server.exists():
                data=read_report(server);batch['server_terminated']=data.get('terminated') is True
                target=prefix.with_suffix('.server.json');shutil.copyfile(server,target);batch['server_receipt']=target.relative_to(ROOT).as_posix()
                if (OUTPUT/'browser-server.log').exists():shutil.copyfile(OUTPUT/'browser-server.log',prefix.with_suffix('.server.log'))
            batch['ended_at']=datetime.now(timezone.utc).isoformat();save()
    ET.ElementTree(aggregate).write(OUTPUT/'browser-tests.xml',encoding='utf-8',xml_declaration=True)
    errors=coverage_errors(expected,summary['batches'])
    if source_manifest()!=before:errors.append('source changed during complete browser run')
    summary.update(status='FAIL' if errors else 'PASS',errors=errors,ended_at=datetime.now(timezone.utc).isoformat(),sources_unchanged_during_run=source_manifest()==before)
    save();print(json.dumps({'status':summary['status'],'expected':len(expected),'cohorts':len(summary['batches']),'errors':errors}))
    return 1 if errors else 0


if __name__=='__main__':raise SystemExit(run_suite())
