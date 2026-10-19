from copy import deepcopy
from pathlib import Path
import sys
import xml.etree.ElementTree as ET
import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'scripts'))
from run_browser_suite import cases,plan,coverage_errors,xml_errors


def report(*,collection=False):
    return {'errors':[],'suites':[{'title':'sample.spec.ts','specs':[{'id':'case-id','file':'sample.spec.ts','title':'a real test','ok':True,
        'tests':[{'projectId':'','projectName':'','timeout':30000,'expectedStatus':'passed','status':'skipped' if collection else 'expected',
            'results':[] if collection else [{'status':'passed','retry':0,'errors':[]}]}]}]}],
        'stats':{'expected':1,'skipped':0,'unexpected':0,'flaky':0}}


def execution(expected):
    return {'expected':expected,'actual':deepcopy(expected),'status':'PASS','exit_code':0,'server_terminated':True,'xml_errors':[]}


def test_collection_and_execution_share_exact_identity_without_counting_list_as_run():
    expected=cases(report(collection=True),collection=True)
    assert cases(report())==expected
    assert plan(expected)==[{'file':'sample.spec.ts','expected':expected}]
    assert coverage_errors(expected,[execution(expected)])==[]
    with pytest.raises(ValueError):cases(report(collection=True))
    with pytest.raises(ValueError):cases(report(),collection=True)


@pytest.mark.parametrize('fault',['missing','duplicate','skipped','failed','retried','flaky','interrupted','expected_failure','error','totals','extra_result','wrong_path','coerced_total','coerced_retry'])
def test_invalid_native_browser_outcomes_cannot_supply_pass(fault):
    value=report();spec=value['suites'][0]['specs'][0];test=spec['tests'][0]
    if fault=='missing':value['suites']=[]
    elif fault=='duplicate':value['suites'][0]['specs'].append(deepcopy(spec))
    elif fault in {'skipped','failed','interrupted'}:test['results'][0]['status']=fault
    elif fault=='retried':test['results'][0]['retry']=1
    elif fault=='flaky':test['status']='flaky'
    elif fault=='expected_failure':test['expectedStatus']='failed'
    elif fault=='error':value['errors']=[{'message':'runner failed'}]
    elif fault=='totals':value['stats']['expected']=2
    elif fault=='extra_result':test['results'].append(deepcopy(test['results'][0]))
    elif fault=='wrong_path':spec['file']='../outside.spec.ts'
    elif fault=='coerced_total':value['stats']['expected']=True
    else:test['results'][0]['retry']=False
    with pytest.raises(ValueError):cases(value)


@pytest.mark.parametrize('fault',['omitted','duplicate','unexecuted','exit','cleanup','xml','changed_timeout','changed_case'])
def test_combined_browser_inventory_requires_every_case_once_with_cleanup(fault):
    expected=cases(report());batch=execution(expected);batches=[batch]
    if fault=='omitted':batch['actual']=[]
    elif fault=='duplicate':batches.append(deepcopy(batch))
    elif fault=='unexecuted':batch['status']='RUNNING'
    elif fault=='exit':batch['exit_code']=124
    elif fault=='cleanup':batch['server_terminated']=False
    elif fault=='xml':batch['xml_errors']=['not complete']
    elif fault=='changed_timeout':batch['actual'][0]['timeout']=60000
    else:batch['actual'][0]['title']='another test'
    assert coverage_errors(expected,batches)


@pytest.mark.parametrize('fault',['none','skipped','failure','error','missing','duplicate','changed_name'])
def test_independent_xml_accounting_matches_project_file_and_full_title(tmp_path,fault):
    expected=cases(report());root=ET.Element('testsuites');suite=ET.SubElement(root,'testsuite',hostname='')
    case=ET.SubElement(suite,'testcase',classname='sample.spec.ts',name='a real test')
    if fault in {'skipped','failure','error'}:ET.SubElement(case,fault)
    elif fault=='missing':suite.remove(case)
    elif fault=='duplicate':suite.append(deepcopy(case))
    elif fault=='changed_name':case.set('name','different test')
    path=tmp_path/'report.xml';ET.ElementTree(root).write(path)
    errors,_=xml_errors(path,expected)
    assert bool(errors)==(fault!='none')
