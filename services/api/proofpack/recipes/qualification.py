"""Bounded stored-case measurements; physical qualification has no public shortcut."""
import hashlib
import json
import time
from uuid import uuid4

from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,ResourceUnavailable
from proofpack.calibrations.dependencies import active_calibration,canonical,digest
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.recipes.models import Recipe,Qualification,Origin
from proofpack.recipes.qualification_models import RecipeQualificationRequest
from proofpack.recipes.service import catalog_key,revision_key,qualification_key
from proofpack.runtime.control import DATA,integer,uuid
from proofpack.verifier.core import Finding
from proofpack.vision.calibration import CalibrationProfile
from proofpack.vision.worker import WorkerBusy,WorkerUnavailable


class RecipeQualificationLimited(RuntimeError):pass
def job_key(ident):return Key('state','recipe-qualification-job#'+uuid(ident))
def report_key(ident):return Key('state','recipe-qualification-report#'+uuid(ident))


class RecipeQualifications:
    def __init__(self,recipes,references,*,runs_per_minute,max_ms):
        if (recipes.access is not references.access or recipes.environment!=references.runtime.environment
                or recipes.artifact_sha256!=references.runtime.artifact_sha256 or type(runs_per_minute) is not int
                or not 1<=runs_per_minute<=100 or type(max_ms) is not int or not 1000<=max_ms<=60000):
            raise ValueError('shared services and explicit bounded qualification configuration required')
        self.recipes=recipes;self.references=references;self.access=recipes.access;self.repository=recipes.repository
        self.purposes=references.purposes;self.runtime=references.runtime;self.registry=references.registry;self.objects=references.objects
        self.runs_per_minute=runs_per_minute;self.max_ms=max_ms

    @staticmethod
    def _merge(*groups):
        rows={}
        for group in groups:
            for row in group:
                if row is None:continue
                if row.key in rows and rows[row.key]!=row:raise StoreConflict('qualification authority changed')
                rows[row.key]=row
        return rows

    def _check(self,actor,rows,deadline,started=None,*,owner=True):
        actor=self.access._fresh(actor,Role.OWNER) if owner else self.recipes._candidate(actor)
        expected=self._merge(rows.values(),actor.rows);final=self.repository.snapshot(tuple(expected))
        if any(final[k]!=v for k,v in expected.items()):raise StoreConflict('qualification context changed')
        actor=self.access._fresh(actor,Role.OWNER) if owner else self.recipes._candidate(actor)
        if self.access.now()>=deadline or (started is not None and not 0<=time.monotonic_ns()-started<self.max_ms*1000000):
            raise StoreUnavailable('qualification window expired')
        return actor

    def job(self,actor,ident):
        actor=self.recipes._candidate(actor);key=job_key(ident);row=self.repository.snapshot((key,))[key]
        if row is None:raise ResourceUnavailable('qualification job unavailable')
        expected=self._merge((row,),actor.rows);self.recipes._candidate(actor)
        final=self.repository.snapshot(tuple(expected))
        if any(final[k]!=v for k,v in expected.items()):raise StoreConflict('qualification job changed')
        self.recipes._candidate(actor);data=row.data;status=data['status']
        if status=='processing' and self.access.now()>=integer(data['deadline_ms']):status='expired'
        return {'id':ident,'recipe_id':data['recipe_id'],'status':status,'report_id':data.get('report_id'),
            'remaining_ms':max(0,integer(data['deadline_ms'])-self.access.now()),'reason':data.get('reason')}

    def _fail(self,jid):
        try:
            key=job_key(jid);row=self.repository.snapshot((key,))[key]
            if row is not None and row.data['status']=='processing':
                self.repository.transact((Write(key,row.revision,{**row.data,'status':'failed','reason':'DIAGNOSTIC_UNAVAILABLE'}),))
        except Exception:pass  # A lost failure update still expires; never publish a qualification.

    def run(self,actor,*,ident,expected_version,request,idempotency_key):
        actor=self.access._fresh(actor,Role.OWNER);ident=uuid(ident)
        if type(expected_version) is not int or expected_version<1 or not isinstance(request,RecipeQualificationRequest):raise ValueError('typed cases and draft version required')
        body={'expected_version':expected_version,'request':request.model_dump(mode='json')}
        idem,body_hash,previous=self.access._idempotency(actor,'recipe-qualify:'+ident,idempotency_key,body)
        if previous is not None:return self.job(actor,previous.data['result']['job_id'])
        key=catalog_key(ident);head=self.recipes._catalog(self.repository.snapshot((key,))[key])
        if head.revision!=expected_version or head.data['retired'] or head.data['draft_revision'] is None:raise StoreConflict('current nonretired draft required')
        prior_id=head.data.get('last_qualification_job_id')
        if prior_id is not None:
            prior=self.repository.snapshot((job_key(prior_id),))[job_key(prior_id)]
            if prior is None:raise StoreUnavailable('prior qualification job unavailable')
            if prior.data['status']=='processing' and self.access.now()<integer(prior.data['deadline_ms']):raise StoreConflict('qualification already processing')
        data=self.purposes.head();rkey=RUNTIME;runtime=self.repository.snapshot((rkey,))[rkey]
        if not self.runtime.matches(runtime):raise Denied('current qualification runtime required')
        qkey=Key('state','recipe-qualification-quota#'+actor.scope);quota=self.repository.snapshot((qkey,))[qkey];minute=self.access.now()//60000
        if quota is not None and integer(quota.data['minute'])>minute:raise StoreUnavailable('qualification allowance clock moved backwards')
        count=0 if quota is None or integer(quota.data['minute'])!=minute else integer(quota.data['count'])
        if count>=self.runs_per_minute:raise RecipeQualificationLimited('qualification allowance exhausted')
        jid=str(uuid4());deadline=self.access.now()+self.max_ms
        result=self.access._record(actor,'recipe-qualify:'+ident,idem,body_hash,{'job_id':jid},
            (Write(job_key(jid),None,{'id':jid,'recipe_id':ident,'status':'processing','deadline_ms':deadline,'report_id':None}),
             Write(key,head.revision,{**head.data,'last_qualification_job_id':jid,'last_qualification_id':None}),
             Write(qkey,None if quota is None else quota.revision,{'minute':minute,'count':count+1})),
            tuple(self._merge(actor.rows,(head,data,runtime)).values()),event_details={'recipe_id':ident,'job_id':jid})
        if result['job_id']!=jid:return self.job(actor,result['job_id'])
        started=time.monotonic_ns()
        try:
            pending=self.repository.snapshot((key,))[key]
            if pending is None or pending.revision!=head.revision+1 or pending.data.get('last_qualification_job_id')!=jid:raise StoreConflict('qualification superseded')
            revkey=revision_key(ident,integer(head.data['draft_revision']));rev=self.repository.snapshot((revkey,))[revkey]
            if rev is None or rev.revision!=1:raise StoreUnavailable('immutable recipe revision required')
            recipe=Recipe.model_validate_json(rev.data['recipe_json'])
            if hashlib.sha256(rev.data['recipe_json'].encode()).hexdigest()!=rev.data['sha256']:raise StoreUnavailable('recipe integrity unavailable')
            calrows,cal,expires=active_calibration(self.repository,self.access,self.runtime,recipe.calibration_profile_id)
            profile=CalibrationProfile.model_validate_json(cal.data['profile_json'])
            if profile.data_origin!=recipe.data_origin:raise Denied('recipe/calibration origin mismatch')
            ids=list(dict.fromkeys([*recipe.reference_asset_ids,*[case.asset_id for case in request.cases]]))
            if len(ids)>16:raise ValueError('at most sixteen combined source assets required')
            rows=self._merge(actor.rows,calrows.values(),(pending,rev,data,runtime));manifests={};receipts={}
            for asset_id in ids:
                source,asset,receipt,limit=self.references.snapshot(actor,asset_id)
                if asset.data['data_origin']!=recipe.data_origin.value:raise Denied('matching source origins required')
                rows=self._merge(rows.values(),source.values());purpose=source[Key('state','purpose#'+asset.data['purpose_id'])]
                manifests[asset_id]={'asset_id':asset_id,'purpose_id':asset.data['purpose_id'],'asset_state_version':asset.revision,
                    'purpose_state_version':purpose.revision,'sha256':asset.data['sha256']};receipts[asset_id]=receipt;expires=min(expires,limit)
            if len({receipts[c.asset_id].source_sha256 for c in request.cases})!=len(request.cases):raise ValueError('distinct case source hashes required')
            for case in request.cases:
                if len(case.expected_findings)!=len(recipe.constraints) or (case.kind=='complete' and tuple(case.expected_counts)!=tuple(c.expected_count for c in recipe.constraints)):
                    raise ValueError('case truth must match exact constraint order and complete target counts')
            deadline=min(deadline,expires);results=[]
            with self.registry.diagnostic(runtime_id=self.runtime.instance_id) as worker:
                for index,case in enumerate(request.cases,1):
                    actor=self._check(actor,rows,deadline,started);payload=self.objects.get(receipts[case.asset_id]);actor=self._check(actor,rows,deadline,started)
                    measured=worker.analyze(payload,recipe,profile,sequence=index,inspection_id=jid)
                    counts=tuple(sum(c.part_class==constraint.part_class_id for c in measured.candidates) for constraint in recipe.constraints)
                    matched=(measured.quality_ok or all(f==Finding.UNOBSERVABLE for f in case.expected_findings)) and tuple(measured.findings)==case.expected_findings and all(f==Finding.UNOBSERVABLE or counts[i]==case.expected_counts[i] for i,f in enumerate(case.expected_findings))
                    results.append({**case.model_dump(mode='json'),'matched':matched,'findings':[f.value for f in measured.findings],
                        'measured_counts':counts,'quality_ok':measured.quality_ok,'unknown_regions':measured.unknown_regions,
                        'reason_codes':measured.reason_codes,'source_sha256':measured.source_sha256,'calibration_sha256':measured.calibration_hash})
            actor=self._check(actor,rows,deadline,started);job=self.repository.snapshot((job_key(jid),))[job_key(jid)]
            if job is None or job.data['status']!='processing' or job.data['recipe_id']!=ident:raise StoreConflict('qualification job changed')
            diagnostic_passed=all(r['matched'] for r in results);passed=diagnostic_passed and recipe.data_origin!=Origin.PHYSICAL and self.runtime.environment!='beta'
            qualification=Qualification(run_id=jid,recipe_id=ident,recipe_revision=recipe.revision,calibration_profile_id=recipe.calibration_profile_id,
                data_origin=recipe.data_origin,passed=passed,artifact_sha256=self.runtime.artifact_sha256,reviewer_id=actor.member.data['id'])
            dependencies=[{'table':r.key.table,'resource':r.key.resource,'revision':r.revision,'sha256':digest(r.data)} for r in sorted(calrows.values(),key=lambda r:r.key.resource)]
            qdata={'qualification_json':qualification.model_dump_json(),'recipe_sha256':rev.data['sha256'],'environment':self.runtime.environment,
                'data_epoch':integer(data.data['epoch']),'notice_version':self.access.config.notice_version,'notice_sha256':hashlib.sha256(self.access.config.notice_text.encode()).hexdigest(),'calibration_state_version':cal.revision,'calibration_sha256':profile.content_hash,
                'reference_manifest':[manifests[i] for i in recipe.reference_asset_ids],'case_manifest':[manifests[c.asset_id] for c in request.cases],
                'calibration_dependencies':dependencies,'expires_at_ms':expires,'report_id':jid}
            report={**qdata,'id':jid,'recipe_id':ident,'recipe_revision':recipe.revision,'passed':passed,'diagnostic_passed':diagnostic_passed,
                'results':results,'physical_truth_verified':False,'independence_verified':False,'created_at_ms':self.access.now()}
            report['sha256']=digest(report);qdata['report_sha256']=report['sha256']
            self.access._commit_linked('recipe_qualification_completed',(Write(report_key(jid),None,report),Write(qualification_key(jid),None,qdata),
                Write(key,pending.revision,{**pending.data,'last_qualification_id':jid}),Write(job.key,job.revision,{**job.data,'status':'completed','report_id':jid}),
                Write(Key('events','recipe-qualification#'+str(uuid4())),None,{'recipe_id':ident,'report_id':jid,'passed':passed,'sha256':report['sha256'],'actor_scope':actor.scope,'at_ms':self.access.now()})),
                tuple(self._merge(rows.values(),actor.rows,(job,)).values()),before_commit=lambda:self._check(actor,rows,deadline,started))
            return self.job(actor,jid)
        except BaseException as exc:
            self._fail(jid)
            if isinstance(exc,WorkerBusy):raise RecipeQualificationLimited('shared diagnostic capacity exhausted') from exc
            if isinstance(exc,WorkerUnavailable):raise StoreUnavailable('qualification worker unavailable') from exc
            raise

    def report(self,actor,ident,rid):
        actor=self.recipes._candidate(actor);head=self.recipes._catalog(self.repository.snapshot((catalog_key(ident),))[catalog_key(ident)])
        rows,recipe,deadline=self.recipes._dependencies(ident,head.data['latest_revision'],rid,binding=head,allow_failed_read=True)
        self._check(actor,rows,deadline,owner=False)
        remaining=deadline-self.access.now()
        if remaining<=0:raise StoreUnavailable('qualification report expired before response')
        return {**json.loads(canonical(rows[report_key(rid)].data)),'remaining_validity_ms':remaining,
            'eligible_for_approval':bool(rows[report_key(rid)].data['passed'] and not head.data['retired']
                and head.data['draft_revision']==recipe.revision and head.data.get('last_qualification_id',rid)==rid)}
