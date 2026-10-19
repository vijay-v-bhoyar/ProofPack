"""Frozen staged-candidate full Python regression; no exclusions or provider access."""
from pathlib import Path
from datetime import datetime,timezone
import hashlib,json,os,shutil,sys,subprocess
EPISODE=Path(__file__).resolve().parent;CANONICAL=EPISODE.parents[2];ROOT=EPISODE/'candidate'
sys.path.insert(0,str(ROOT/'scripts'))
import verify_local,run_python_suite,dynamodb_local
assert verify_local.ROOT==run_python_suite.ROOT==ROOT
dist_before=[{'path':p.relative_to(ROOT).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted((ROOT/'apps/web/dist').rglob('*')) if p.is_file()]
before=verify_local.source_manifest();selected=json.loads((EPISODE/'verification-current.json').read_text())
assert len(before)==707 and before==selected['source_manifest'] and selected['status']=='PASS'
installed=json.loads((EPISODE/'package-v1-verification.json').read_text());assert installed['exit_code']==0 and installed['source_manifest']==before and installed['temporary_installation_removed']
BASE=ROOT/'evidence/local/accumulated-full-v3';OUT=BASE/'evidence/local'
assert not BASE.exists(),'preserve all original attempts; never restart an unobserved run'
OUT.mkdir(parents=True);(BASE/'tools').mkdir()
shutil.copyfile(ROOT/'tools/dynamodb-local.lock.json',BASE/'tools/dynamodb-local.lock.json')
snapshot=EPISODE/'full-v3-source';snapshot.mkdir()
for entry in before:
    dest=snapshot/entry['path'];dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/entry['path'],dest)
run_python_suite.OUTPUT=OUT;dynamodb_local.ROOT=BASE;dynamodb_local.CACHE=CANONICAL/'.runtime/dynamodb'
sdk=CANONICAL/'.loop/repairs/metadata-payload-erasure/metadata_native_sdk_guard.py'
assert hashlib.sha256(sdk.read_bytes()).hexdigest()=='7bf0ddca5658db5ecff2ee4acd43e99b54539efccb26b4271ac14b463e513582'
for key in list(os.environ):
    if key.startswith('AWS_'):del os.environ[key]
os.environ.update(AWS_ACCESS_KEY_ID='localtest',AWS_SECRET_ACCESS_KEY='localtest',AWS_DEFAULT_REGION='us-east-1',
    AWS_EC2_METADATA_DISABLED='true',AWS_CONFIG_FILE=os.devnull,AWS_SHARED_CREDENTIALS_FILE=os.devnull,
    HTTP_PROXY='',HTTPS_PROXY='',ALL_PROXY='',http_proxy='',https_proxy='',all_proxy='',NO_PROXY='*',no_proxy='*')
os.environ.pop('PROOFPACK_TEST_DYNAMO_URL',None)
os.environ['PYTHONPATH']=os.pathsep.join(str(p) for p in [ROOT/'scripts',ROOT/'tests/unit',ROOT/'tests/integration',ROOT/'evidence/local',
    CANONICAL/'.loop/repairs/metadata-resource-lineage',CANONICAL/'.loop/repairs/metadata-payload-erasure',CANONICAL/'.loop/repairs/metadata-semantic-closure/working/evidence/local'])
os.environ['PYTEST_PLUGINS']='metadata_native_sdk_guard,direct_output_probe,corpus_origin_probe'
os.environ['NODE_PATH']=str(CANONICAL/'apps/web/node_modules')
node_path=shutil.which('node');assert node_path
node_runtime={'path':node_path,'sha256':hashlib.sha256(Path(node_path).read_bytes()).hexdigest(),'version':subprocess.run([node_path,'--version'],capture_output=True,text=True,timeout=10,check=True).stdout.strip()}
original=run_python_suite.run_check
def checked_run(command,log_path,*,timeout=120,env=None):
    child=dict(env or os.environ);evidence=Path(child['PROOFPACK_PYTEST_EVIDENCE_PATH'])
    child.update(PROOFPACK_EXPECTED_SOURCE=str(ROOT/'services/api'),PROOFPACK_ORIGIN_RECEIPT=str(evidence.with_suffix('.origins.json')))
    return original(command,log_path,timeout=timeout,env=child)
run_python_suite.run_check=checked_run
plan={'scope':'all collected current 707-input candidate Python cases; includes configured synthetic HTTPS/browser fixture; no actual provider/physical/human acceptance',
    'started_at':datetime.now(timezone.utc).isoformat(),'source_manifest':before,'frontend_artifacts':dist_before,'cohort_target_tests':150,
    'cohort_timeout_seconds':900,'collection_timeout_seconds':120,'case_exclusions':[],
    'external_sdk_sends':'PROHIBITED by exact owned-endpoint guard','inherited_aws_credentials':'REPLACED',
    'sdk_guard_sha256':hashlib.sha256(sdk.read_bytes()).hexdigest(),'source_snapshot':snapshot.relative_to(CANONICAL).as_posix(),
    'receipts':OUT.relative_to(ROOT).as_posix(),'beta_decision':'NO_GO','parent_complete':False}
plan.update(assembly_sha256=hashlib.sha256((EPISODE/'assembly.json').read_bytes()).hexdigest(),selected_preflight_sha256=hashlib.sha256((EPISODE/'verification-current.json').read_bytes()).hexdigest(),package_preflight_sha256=hashlib.sha256((EPISODE/'package-v1-verification.json').read_bytes()).hexdigest(),node_runtime=node_runtime)
(EPISODE/'full-v3-plan.json').write_text(json.dumps(plan,indent=2)+'\n')
import importlib.util
spec=importlib.util.spec_from_file_location('full_canonical_guard',CANONICAL/'scripts/verify_local.py');canonical=importlib.util.module_from_spec(spec);spec.loader.exec_module(canonical)
canonical_before=canonical.source_manifest();assert len(canonical_before)==669
code=1
try:code=run_python_suite.run_suite(cohort_target=150)
finally:
    unchanged=before==verify_local.source_manifest() and canonical_before==canonical.source_manifest() and all(hashlib.sha256((ROOT/r['path']).read_bytes()).hexdigest()==r['sha256'] for r in dist_before)
    runtime_unchanged=hashlib.sha256(Path(node_runtime['path']).read_bytes()).hexdigest()==node_runtime['sha256']
    if not unchanged or not runtime_unchanged:code=1
    report={**plan,'exit_code':code,'source_unchanged':unchanged,'external_node_runtime_unchanged':runtime_unchanged,'ended_at':datetime.now(timezone.utc).isoformat()}
    (EPISODE/'full-v3-process.json').write_text(json.dumps(report,indent=2)+'\n')
raise SystemExit(code)
