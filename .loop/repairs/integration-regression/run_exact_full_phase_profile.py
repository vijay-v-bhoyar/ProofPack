"""Isolated actual-store/public boot/HTTPS browser; no provider or release authority."""
from pathlib import Path
from datetime import datetime,timezone
import importlib.util,hashlib,json,os,shutil,sys
D=Path(__file__).resolve().parent;CANONICAL=D.parents[2];ROOT=CANONICAL/'.loop/repairs/accumulated-current/candidate';STEM=sys.argv[1]
sys.path.insert(0,str(ROOT/'scripts'))
import verify_local,run_python_suite,dynamodb_local
spec=importlib.util.spec_from_file_location('canonical_native_guard',CANONICAL/'scripts/verify_local.py');canonical=importlib.util.module_from_spec(spec);spec.loader.exec_module(canonical)
before=verify_local.source_manifest();original=canonical.source_manifest();assert len(before)==707 and len(original)==669
parent=json.loads((ROOT.parent/'full-v3-process.json').read_text());assert parent['ended_at'] and parent['source_unchanged']
full=json.loads((ROOT/'evidence/local/accumulated-full-v3/evidence/local/python-suite.json').read_text());assert full['status'] in ('PASS','FAIL')
assert before==parent['source_manifest'];batch=full['batches'][2];assert len(batch['expected_nodeids'])==134
DBBASE=ROOT/'evidence/local'/STEM;OUT=DBBASE/'evidence/local';assert not DBBASE.exists();OUT.mkdir(parents=True);(DBBASE/'tools').mkdir()
shutil.copyfile(ROOT/'tools/dynamodb-local.lock.json',DBBASE/'tools/dynamodb-local.lock.json')
dynamodb_local.ROOT=DBBASE;dynamodb_local.CACHE=CANONICAL/'.runtime/dynamodb';run_python_suite.OUTPUT=OUT
sdk=CANONICAL/'.loop/repairs/metadata-payload-erasure/metadata_native_sdk_guard.py';assert hashlib.sha256(sdk.read_bytes()).hexdigest()=='7bf0ddca5658db5ecff2ee4acd43e99b54539efccb26b4271ac14b463e513582'
env={k:v for k,v in os.environ.items() if not k.startswith('AWS_')}
env.update(AWS_ACCESS_KEY_ID='localtest',AWS_SECRET_ACCESS_KEY='localtest',AWS_DEFAULT_REGION='us-east-1',AWS_EC2_METADATA_DISABLED='true',AWS_CONFIG_FILE=os.devnull,AWS_SHARED_CREDENTIALS_FILE=os.devnull,
 HTTP_PROXY='',HTTPS_PROXY='',ALL_PROXY='',http_proxy='',https_proxy='',all_proxy='',NO_PROXY='*',no_proxy='*',
 PYTHONPATH=os.pathsep.join(str(p) for p in [ROOT/'scripts',ROOT/'tests/unit',ROOT/'tests/integration',ROOT/'evidence/local',CANONICAL/'.loop/repairs/metadata-resource-lineage',CANONICAL/'.loop/repairs/metadata-payload-erasure',CANONICAL/'.loop/repairs/metadata-semantic-closure/working/evidence/local']),
 PYTEST_PLUGINS='metadata_native_sdk_guard,direct_output_probe,corpus_origin_probe',PROOFPACK_EXPECTED_SOURCE=str(ROOT/'services/api'),PROOFPACK_ORIGIN_RECEIPT=str(OUT/(STEM+'-origins.json')))
# Preserve inherited plugin-autoload setting exactly as the full runner does.
env['PYTHONPATH']=str(ROOT/'scripts')+os.pathsep+env['PYTHONPATH']
env['PYTHONPATH']+=os.pathsep+str(D)
env['PYTEST_PLUGINS']+=',phase_progress_probe'
env['PROOFPACK_PHASE_TRACE']=str(D/(STEM+'-phases.jsonl'))
assert not Path(env['PROOFPACK_PHASE_TRACE']).exists(), 'preserve original phase journals'
env['NODE_PATH']=str(CANONICAL/'apps/web/node_modules')

assert len(sys.argv)==2, 'only a fresh receipt stem is accepted; cohort inventory is frozen'
targets=batch['files']
assert all(t.startswith('tests/integration/') for t in targets)
external_oracles={}
command=[sys.executable,'-m','pytest','-q','-p','pytest_evidence',*targets,'--junitxml='+str(OUT/(STEM+'.xml'))]
assert command[:-1]==batch['command'][:-1], 'full command must match except receipt destination'
started=datetime.now(timezone.utc).isoformat();code=1
report={'profile':'full-v3 exact interpreter/pytest flags and module order; same900s; extra passive phase plugin/directory and fresh output/database paths disclosed','scope':'diagnosis of repeated full-v3 cohort3 timeout; no functional repair or complete-suite/provider/human acceptance','external_oracles':external_oracles,'expected_nodeids':batch['expected_nodeids'],'parent_full_receipt_sha256':hashlib.sha256((ROOT.parent/'full-v3-process.json').read_bytes()).hexdigest(),'instrumentation_difference':'phase_progress_probe plus its directory; passive journal adds overhead; separate fresh owned database and output paths; full-suite preceding workload is not reproduced','started_at':started,'source_manifest':before,'command':command,'timeout_seconds':900,'external_sdk_sends':'PROHIBITED','parent_complete':False,'beta_decision':'NO_GO'}
try:
 with dynamodb_local.local_database() as endpoint:
  code=verify_local.run_check(command,OUT/(STEM+'.log'),timeout=900,env={**env,'PROOFPACK_TEST_DYNAMO_URL':endpoint,'PROOFPACK_PYTEST_EVIDENCE_PATH':str(OUT/(STEM+'-execution.json'))})
except Exception as error:report.update(error_type=type(error).__name__,error=str(error))
finally:
 report.update(run_python_suite.retain_database_evidence(STEM,started))
 same=before==verify_local.source_manifest();untouched=original==canonical.source_manifest()
 if not same or not untouched or not report.get('database_terminated') or not report.get('database_state_removed'):code=1
 report.update(exit_code=code,source_unchanged=same,canonical_source_unchanged=untouched,ended_at=datetime.now(timezone.utc).isoformat())
 (D/(STEM+'-process.json')).write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report.get(k) for k in ['exit_code','source_unchanged','canonical_source_unchanged','database_terminated','database_state_removed','error_type']}));raise SystemExit(code)
