"""Offline, fixed controlled experiment. No SDK clients, app writes or activation."""
import argparse,hashlib,json,os,platform,sys,time
from datetime import datetime,timezone
from pathlib import Path
from uuid import uuid4

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'services/api'))
# Windows spawn executes this module before calling the worker entrypoint.
# Keep imports here standard-library-only so the child can install limits and
# thread settings before loading OpenCV, numpy or the application dependency graph.


def make_registry(limits,*,max_processes):
    from proofpack.vision.registry import WorkerRegistry
    return WorkerRegistry(limits,max_processes=max_processes)


def hashed(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def atomic_json(path,value,limit,*,before_commit=None):
    from proofpack.calibrations.dependencies import canonical
    from proofpack.review.controlled import ControlledHeld
    payload=(canonical(value)+'\n').encode()
    if len(payload)>limit:raise ControlledHeld('RUN_REPORT_TOO_LARGE')
    temp=path.parent/('.'+path.name+'-'+uuid4().hex+'.tmp')
    try:
        with temp.open('xb') as stream:stream.write(payload);stream.flush();os.fsync(stream.fileno())
        if before_commit is not None:before_commit()
        os.replace(temp,path)
    finally:
        if temp.exists():temp.unlink()


class Journal:
    def __init__(self,output,config):
        self.output=Path(output).resolve();self.output.mkdir(parents=True,exist_ok=True);self.config=config
        parent=self.output/'controlled-runs';parent.mkdir(exist_ok=True)
        self.ident=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')+'-'+uuid4().hex[:12]
        self.directory=parent/self.ident
        if self.directory.resolve().parent!=parent.resolve() or self.directory.exists():raise ValueError('new owned journal directory required')
        self.directory.mkdir();self.paths={};self.hashes={}

    def bounded_case(self,value):
        from proofpack.calibrations.dependencies import canonical,digest
        if len((canonical(value)+'\n').encode())>self.config.max_case_report_bytes:
            value={'index':value['index'],'case_id':value['case_id'],'status':'HELD','error':'CASE_REPORT_TOO_LARGE',
                'reserved_measurements':value['reserved_measurements'],'records_withheld_for_bound':True,'content_sha256':digest(value)}
        return value

    def case(self,value):
        from proofpack.calibrations.dependencies import canonical
        if type(value['index']) is not int or not 0<=value['index']<self.config.max_episodes:raise ValueError('bounded journal case required')
        path=self.directory/f"case-{value['index']:03d}.json";value=self.bounded_case(value)
        atomic_json(path,value,self.config.max_case_report_bytes);self.paths[value['index']]=path
        self.hashes[value['index']]=hashlib.sha256((canonical(value)+'\n').encode()).hexdigest()

    def write(self,value,*,final=False,before_commit=None):
        from proofpack.review.controlled_models import bounded_read
        from proofpack.review.controlled import ControlledHeld
        def actual(path):
            try:return hashlib.sha256(bounded_read(path,self.config.max_case_report_bytes)).hexdigest()
            except (OSError,ValueError):return None
        def gate():
            if before_commit is not None:before_commit()
            if value.get('complete') is True and any(actual(path)!=self.hashes[i] for i,path in self.paths.items()):
                raise ControlledHeld('CASE_JOURNAL_CHANGED')
            if before_commit is not None:before_commit()
        value={**value,'run_id':self.ident,'run_directory':self.directory.relative_to(self.output).as_posix(),
            'case_files':[{'index':i,'path':p.relative_to(self.output).as_posix(),'sha256':self.hashes[i],
                'current_sha256':actual(p),'current':actual(p)==self.hashes[i]} for i,p in sorted(self.paths.items())]}
        if final:atomic_json(self.directory/'report.json',value,self.config.max_run_report_bytes,before_commit=gate)
        atomic_json(self.output/'controlled-baselines.json',value,self.config.max_run_report_bytes,before_commit=gate)


def execution_subject():
    from proofpack.calibrations.dependencies import digest
    paths=sorted((ROOT/'services/api/proofpack').rglob('*.py'))
    paths.extend([ROOT/'scripts/evaluate_controlled.py',ROOT/'scripts/generate_controlled_fixtures.py'])
    return digest([{'path':p.relative_to(ROOT).as_posix(),'sha256':hashed(p)} for p in paths])


def run(candidate_path,*,output=None,bundle_path=None):
    import cv2,yaml
    from proofpack.review.controlled_models import FLAGS,ControlledConfig,bounded_read,candidate
    from proofpack.review.controlled import ControlledExperiment,ControlledHeld,summarize
    from proofpack.vision.controlled_fixtures import ControlledBundle
    from proofpack.vision.worker_limits import WorkerLimits
    started=time.monotonic_ns();journal=None;engine=None;bundle=None;rows=[];registry=None
    report={'schema_version':1,'status':'IN_PROGRESS','complete':False,'scope':'designer-authored synthetic response experiment only',
        'recorded_at':datetime.now(timezone.utc).isoformat(),'expected_episodes':144,'prepared_episodes':0,
        'provider_calls':0,'candidate_advantage_proved':False,**FLAGS}
    try:
        controls_path=ROOT/'docs/controls.yaml';controls_payload=bounded_read(controls_path,65536);controls_sha=hashlib.sha256(controls_payload).hexdigest()
        controls=yaml.safe_load(controls_payload);config=ControlledConfig(**controls['controlled_baselines']);limits=WorkerLimits.from_controls(controls)
        if cv2.__version__.split('.')[0]!='5':raise ValueError('actual OpenCV 5 required')
        journal=Journal(output or ROOT/'evidence/local',config);journal.write(report)
        definition,candidate_sha=candidate(Path(candidate_path),config)
        # Freeze the exact candidate before loading or observing the controlled cases.
        report.update(candidate=definition.model_dump(mode='json'),candidate_file_sha256=candidate_sha,controls_sha256=controls_sha,
            configuration_sha256=config.sha256,execution_artifact_sha256=execution_subject(),opencv_version=cv2.__version__,
            python_version=platform.python_version(),architecture=platform.machine(),worker_limits=vars(limits),worker_processes=1)
        bundle=ControlledBundle(bundle_path or ROOT/'fixtures/synthetic/controlled-v1',config)
        report.update(manifest_sha256=bundle.manifest_sha256,response_model_sha256=bundle.metadata['response_model_sha256'],
            generator_sha256=bundle.metadata['generator_sha256'],source_origin='synthetic',split='DEVELOPMENT',
            provenance='disjoint rendered seeds and authored responses; not independent physical/operator evidence')
        def checkpoint():
            if hashlib.sha256(bounded_read(controls_path,65536)).hexdigest()!=controls_sha:raise ControlledHeld('CONTROLS_CHANGED')
            if hashlib.sha256(bounded_read(Path(candidate_path),config.max_candidate_bytes)).hexdigest()!=candidate_sha:raise ControlledHeld('CANDIDATE_CHANGED')
        checkpoint();registry=make_registry(limits,max_processes=1)
        engine=ControlledExperiment(bundle,definition,candidate_sha,registry,config,checkpoint=checkpoint,
            progress=journal.case,started_ns=started)
        for index in range(len(bundle.episodes)):
            value=engine.case(index);rows.append(value)
            report.update(prepared_episodes=len(rows),reserved_measurements=engine.reserved);journal.write(report)
        checkpoint();bundle.assert_current(all_images=True)
        if execution_subject()!=report['execution_artifact_sha256']:raise ControlledHeld('EXECUTION_SOURCE_CHANGED')
        summary=summarize(bundle.episodes,rows,bundle.metadata['images'])
        if (len(rows)!=len(bundle.episodes) or any(row['status']!='COMPLETE' for row in rows)
                or sum(row['reserved_measurements'] for row in rows)!=engine.reserved):raise ControlledHeld('INCOMPLETE_RUN')
        registry.close();registry=None
        def final_gate():
            checkpoint();bundle.assert_current(all_images=True)
            if execution_subject()!=report['execution_artifact_sha256']:raise ControlledHeld('EXECUTION_SOURCE_CHANGED')
            if (time.monotonic_ns()-started)//1000000>=config.max_run_ms:raise ControlledHeld('DEADLINE_EXCEEDED')
        final_gate()
        report.update(status='COMPLETE',complete=True,summary=summary,cases=rows,reserved_measurements=engine.reserved,
            elapsed_before_final_publication_ms=(time.monotonic_ns()-started)/1000000,worker_registry_closed=True,
            unmeasured=['operator time/throughput/burden','physical dimension accuracy','service/network latency','actual AWS durability','cost per completed kit','human adoption'])
        journal.write(report,final=True,before_commit=final_gate)
        print(json.dumps({'status':'COMPLETE','episodes':len(rows),'arms':4,'reserved_measurements':engine.reserved,
            'manifest_sha256':bundle.manifest_sha256,'run_id':journal.ident,'candidate_advantage_proved':False,'promotion_eligible':False}))
        return 0
    except (Exception,KeyboardInterrupt) as exc:
        if registry is not None:
            try:registry.close();report['worker_registry_closed']=True
            except Exception:report['worker_registry_closed']=False
        reason=exc.reason if isinstance(exc,ControlledHeld) else 'CANCELLED' if isinstance(exc,KeyboardInterrupt) else type(exc).__name__
        if engine is not None and engine.last_case is not None and all(r['index']!=engine.last_case['index'] for r in rows):
            engine.last_case.update(status='HELD',error=reason);rows.append(engine.last_case)
        report.update(status='HELD',complete=False,error=reason,reserved_measurements=0 if engine is None else engine.reserved,
            prepared_episodes=sum(r['status']=='COMPLETE' for r in rows),cases=rows)
        if bundle is not None:report['summary']=summarize(bundle.episodes,rows,bundle.metadata['images'])
        if journal is not None:
            try:
                if engine is not None and engine.last_case is not None:journal.case(engine.last_case)
                report['cases']=[journal.bounded_case(row) for row in rows]
                journal.write(report,final=True)
            except (OSError,ValueError,ControlledHeld):pass  # A denied output cannot become COMPLETE; process exits nonzero.
        print(json.dumps({'status':'HELD','complete':False,'reason':reason,'reserved_measurements':report['reserved_measurements']}),file=sys.stderr)
        return 1


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--candidate',required=True,type=Path);args=parser.parse_args()
    return run(args.candidate)


if __name__=='__main__':raise SystemExit(main())
