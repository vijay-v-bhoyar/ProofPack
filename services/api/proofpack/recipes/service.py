"""Immutable recipe catalog and activation fences; qualification writers are private."""
import base64
import hashlib
import hmac
import json
import re
from uuid import uuid4

from proofpack.calibrations.dependencies import digest as record_digest
from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import ResourceUnavailable
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.recipes.models import Recipe,Qualification,check_activation,check_qualification_binding
from proofpack.runtime.control import DATA,integer,sha,uuid


def catalog_key(ident):return Key('state','recipe#'+uuid(ident))
def active_key(ident):return Key('state','recipe-active#'+uuid(ident))
def revision_key(ident,revision):return Key('state',f'recipe-revision#{uuid(ident)}#{integer(revision):012d}')
def qualification_key(ident):return Key('state','recipe-qualification#'+uuid(ident))


class RecipeService:
    def __init__(self,access,*,environment,artifact_sha256):
        if environment not in {'test','synthetic_demo','beta'}:raise ValueError('explicit recipe environment required')
        self.access=access;self.repository=access.repository;self.environment=environment
        self.artifact_sha256=sha(artifact_sha256)

    def _candidate(self,actor):
        actor=self.access._fresh(actor)
        return self.access._fresh(actor,Role.REVIEWER if Role.REVIEWER in actor.principal.roles else Role.OWNER)

    def _revision(self,ident,number,content):
        if not isinstance(content,dict) or set(content)&{'recipe_id','revision'}:
            raise ValueError('recipe content cannot assign identity/revision')
        encoded=json.dumps(content,sort_keys=True,separators=(',',':'),allow_nan=False)
        if len(encoded.encode())>8192:raise ValueError('recipe content exceeds bounds')
        recipe=Recipe.model_validate_json(json.dumps({'recipe_id':ident,'revision':number,**content},allow_nan=False))
        canonical=json.dumps(recipe.model_dump(mode='json'),sort_keys=True,separators=(',',':'),allow_nan=False)
        return recipe,{'recipe_json':canonical,'sha256':hashlib.sha256(canonical.encode()).hexdigest()}

    def _catalog(self,row):
        if row is None:raise ResourceUnavailable('recipe unavailable')
        return row

    def _current(self,ident):
        try:
            rows,recipe,deadline=self.active_snapshot(ident)
            return {'effective_approved':True,'active_revision':recipe.revision,
                'active_state_version':rows[active_key(ident)].revision,'expires_at_ms':deadline,'active_name':recipe.name}
        except (Denied,ResourceUnavailable,StoreUnavailable,StoreConflict):
            return {'effective_approved':False,'active_revision':None,'active_state_version':None,'expires_at_ms':None,'active_name':None}

    def _result(self,actor,result):
        self.access._fresh(actor,Role.OWNER)
        return {**result,'current':self._current(result['id'])}

    def create(self,actor,*,content,idempotency_key):
        actor=self.access._fresh(actor,Role.OWNER)
        # Validate before idempotency hashing so unsupported NaN/types cannot persist.
        ident=str(uuid4());recipe,revision=self._revision(ident,1,content)
        idem,body_hash,replay=self.access._idempotency(actor,'recipe-create',idempotency_key,content)
        if replay is not None:return self._result(actor,replay.data['result'])
        head={'id':ident,'name':recipe.name,'latest_revision':1,'draft_revision':1,
            'retired':False,'created_at_ms':self.access.now()}
        result={'id':ident,'revision':1,'state_version':1}
        committed=self.access._record(actor,'recipe-create',idem,body_hash,result,
            (Write(catalog_key(ident),None,head),Write(revision_key(ident,1),None,revision)),
            event_details={'recipe_id':ident,'revision':1,'recipe_sha256':revision['sha256'],'environment':self.environment})
        return self._result(actor,committed)

    def save(self,actor,*,recipe_id,expected_version,content,idempotency_key):
        actor=self.access._fresh(actor,Role.OWNER);key=catalog_key(recipe_id)
        if type(expected_version) is not int or expected_version<1:raise ValueError('positive recipe state version required')
        idem,body_hash,replay=self.access._idempotency(actor,'recipe-save:'+recipe_id,idempotency_key,
            {'expected_version':expected_version,'content':content})
        if replay is not None:return self._result(actor,replay.data['result'])
        head=self._catalog(self.repository.snapshot((key,))[key])
        if head.revision!=expected_version:raise StoreConflict('recipe changed')
        number=integer(head.data['latest_revision'])+1;recipe,revision=self._revision(recipe_id,number,content)
        result={'id':recipe_id,'revision':number,'state_version':head.revision+1}
        committed=self.access._record(actor,'recipe-save:'+recipe_id,idem,body_hash,result,
            (Write(key,head.revision,{**head.data,'name':recipe.name,'latest_revision':number,'draft_revision':number,'retired':False}),
             Write(revision_key(recipe_id,number),None,revision)),event_details={'recipe_id':recipe_id,
                'revision':number,'recipe_sha256':revision['sha256'],'environment':self.environment})
        return self._result(actor,committed)

    def draft(self,actor,recipe_id):
        actor=self._candidate(actor);key=catalog_key(recipe_id)
        first=self._catalog(self.repository.snapshot((key,))[key])
        revision=revision_key(recipe_id,first.data['latest_revision'])
        rows=self.repository.snapshot((key,revision))
        if rows[key]!=first:raise StoreConflict('recipe changed during read')
        if rows[revision] is None:raise StoreUnavailable('recipe revision unavailable')
        recipe=Recipe.model_validate_json(rows[revision].data['recipe_json'])
        if (rows[revision].revision!=1 or hashlib.sha256(rows[revision].data['recipe_json'].encode()).hexdigest()!=rows[revision].data['sha256']
                or recipe.recipe_id!=recipe_id or recipe.revision!=integer(first.data['latest_revision'])):raise StoreUnavailable('intact exact recipe revision required')
        self._candidate(actor)
        return {'id':recipe_id,'revision':recipe.revision,'state_version':first.revision,'recipe_sha256':rows[revision].data['sha256'],
            'content':{k:v for k,v in recipe.model_dump(mode='json').items() if k not in {'recipe_id','revision'}},
            'retired':first.data['retired'],'last_qualification_job_id':first.data.get('last_qualification_job_id'),'current':self._current(recipe_id)}

    def _dependencies(self,ident,number,qualification_id,*,binding,allow_failed_read=False):
        revkey=revision_key(ident,number);qkey=qualification_key(qualification_id)
        first=self.repository.snapshot((revkey,qkey))
        if first[revkey] is None or first[qkey] is None:raise StoreUnavailable('matching qualification required')
        try:
            recipe=Recipe.model_validate_json(first[revkey].data['recipe_json'])
            qdata=first[qkey].data;qualification=Qualification.model_validate_json(qdata['qualification_json'])
            manifest=qdata['reference_manifest']
            if not isinstance(manifest,list) or not 1<=len(manifest)<=16:raise ValueError('bounded reference manifest required')
            if [item['asset_id'] for item in manifest]!=list(recipe.reference_asset_ids):raise ValueError('exact references required')
            case_manifest=qdata['case_manifest'];dependencies=qdata['calibration_dependencies']
            if not isinstance(case_manifest,list) or len(case_manifest)>8 or not isinstance(dependencies,list) or not 1<=len(dependencies)<=64:
                raise ValueError('bounded case/calibration dependencies required')
            combined=manifest+case_manifest
            if len({item['asset_id'] for item in combined})>16:raise ValueError('bounded combined source manifest required')
            calkey=Key('state','calibration-active#'+recipe.calibration_profile_id)
            reportkey=Key('state','recipe-qualification-report#'+uuid(qdata['report_id']))
            if qdata['report_id']!=qualification_id:raise ValueError('exact qualification report required')
            keys=[binding.key,revkey,qkey,DATA,calkey,reportkey]
            depkeys=[]
            for item in dependencies:
                if item['table']!='state':raise ValueError('state-only calibration provenance required')
                depkeys.append(Key('state',item['resource']))
            if calkey not in depkeys or len(set(depkeys))!=len(depkeys):raise ValueError('unique active calibration dependencies required')
            keys.extend(depkeys)
            for item in combined:
                keys.extend((Key('state','asset#'+uuid(item['asset_id'])),Key('state','purpose#'+uuid(item['purpose_id']))))
            rows=self.repository.snapshot(tuple(dict.fromkeys(keys)))
            if rows[binding.key]!=binding or rows[revkey]!=first[revkey] or rows[qkey]!=first[qkey]:
                raise StoreConflict('recipe dependencies changed during snapshot')
            report=rows[reportkey]
            if report is None or report.revision!=1 or record_digest({k:v for k,v in report.data.items() if k!='sha256'})!=sha(qdata['report_sha256']) or report.data['sha256']!=qdata['report_sha256']:
                raise ValueError('intact immutable qualification report required')
            for name in ('qualification_json','recipe_sha256','environment','data_epoch','calibration_state_version','calibration_sha256',
                    'reference_manifest','case_manifest','calibration_dependencies','expires_at_ms','report_id','notice_version','notice_sha256'):
                if report.data[name]!=qdata[name]:raise ValueError('qualification report binding mismatch')
            if report.data['id']!=qualification_id or report.data['recipe_id']!=ident or integer(report.data['recipe_revision'])!=number or report.data['passed']!=qualification.passed:
                raise ValueError('exact recipe report required')
            for item,depkey in zip(dependencies,depkeys,strict=True):
                dep=rows[depkey]
                if dep is None or dep.revision!=integer(item['revision']) or record_digest(dep.data)!=sha(item['sha256']):raise ValueError('calibration provenance changed')
            if qdata['notice_version']!=self.access.config.notice_version or qdata['notice_sha256']!=hashlib.sha256(self.access.config.notice_text.encode()).hexdigest():raise ValueError('current operational notice required')
            cal=rows[calkey];data=rows[DATA]
            if (cal is None or data is None or first[revkey].revision!=1 or first[qkey].revision!=1
                    or hashlib.sha256(first[revkey].data['recipe_json'].encode()).hexdigest()!=first[revkey].data['sha256']
                    or qdata['recipe_sha256']!=first[revkey].data['sha256']
                    or qualification.run_id!=qualification_id or qualification.artifact_sha256!=self.artifact_sha256
                    or qdata['environment']!=self.environment or integer(qdata['data_epoch'])!=integer(data.data['epoch'])
                    or cal.data['status']!='approved' or cal.revision!=integer(qdata['calibration_state_version'])
                    or cal.data['profile_sha256']!=qdata['calibration_sha256']
                    or cal.data['environment']!=self.environment or cal.data['data_origin']!=recipe.data_origin.value):
                raise ValueError('qualification/calibration mismatch')
            deadlines=[integer(qdata['expires_at_ms'])]
            for item in combined:
                asset=rows[Key('state','asset#'+item['asset_id'])];purpose=rows[Key('state','purpose#'+item['purpose_id'])]
                if (asset is None or purpose is None or asset.revision!=integer(item['asset_state_version'])
                        or purpose.revision!=integer(item['purpose_state_version'])
                        or asset.data['sha256']!=sha(item['sha256']) or asset.data['purpose_id']!=item['purpose_id']
                        or asset.data['status']!='committed' or asset.data['read_denied'] is not False
                        or asset.data['data_origin']!=recipe.data_origin.value or purpose.data['withdrawn'] is not False
                        or 'operation' not in purpose.data['allowed_uses']):raise ValueError('reference permission unavailable')
                deadlines.extend((integer(asset.data['expires_at_ms']),integer(purpose.data['expires_at_ms'])))
            deadline=min(deadlines)
            if self.access.now()>=deadline:raise ValueError('qualification/reference expired')
            if (not allow_failed_read and 'draft_revision' in binding.data and binding.data.get('last_qualification_job_id') is not None
                    and binding.data.get('last_qualification_id')!=qualification_id):raise ValueError('current completed qualification required')
            check=(check_qualification_binding if allow_failed_read else check_activation)
            check(recipe,qualification,environment=self.environment,references_permitted=True)
            return rows,recipe,deadline
        except StoreConflict:
            raise
        except (KeyError,TypeError,ValueError,AttributeError) as exc:
            raise StoreUnavailable('qualified permitted recipe dependencies unavailable') from exc

    def qualification(self,actor,*,recipe_id,qualification_id):
        actor=self._candidate(actor);head=self._catalog(self.repository.snapshot((catalog_key(recipe_id),))[catalog_key(recipe_id)])
        rows,recipe,deadline=self._dependencies(recipe_id,head.data['latest_revision'],qualification_id,binding=head,allow_failed_read=True)
        qualification=Qualification.model_validate_json(rows[qualification_key(qualification_id)].data['qualification_json'])
        expected={**rows}
        for row in actor.rows:
            if row.key in expected and expected[row.key]!=row:raise StoreConflict('qualification authority changed')
            expected[row.key]=row
        final=self.repository.snapshot(tuple(expected))
        if any(final[key]!=row for key,row in expected.items()):raise StoreConflict('qualification changed during read')
        self._candidate(actor);remaining=deadline-self.access.now()
        if remaining<=0:raise StoreUnavailable('qualification expired')
        current= head.data.get('last_qualification_id',qualification_id)==qualification_id
        eligible=qualification.passed and not head.data['retired'] and head.data['draft_revision']==recipe.revision and current
        return {'id':qualification_id,'recipe_id':recipe_id,'recipe_revision':recipe.revision,'state_version':head.revision,
            'calibration_profile_id':recipe.calibration_profile_id,'data_origin':recipe.data_origin.value,'passed':qualification.passed,
            'artifact_sha256':qualification.artifact_sha256,'recipe_sha256':rows[revision_key(recipe_id,recipe.revision)].data['sha256'],
            'reviewer_id':qualification.reviewer_id,'environment':self.environment,'remaining_qualification_ms':remaining,
            'eligible_for_approval':eligible,'reason_codes':[] if eligible else ['SUPERSEDED_QUALIFICATION' if not current else 'FAILED_QUALIFICATION' if not qualification.passed else 'NO_CURRENT_DRAFT']}

    def active_snapshot(self,recipe_id):
        key=active_key(recipe_id);row=self.repository.snapshot((key,))[key]
        if row is None or row.data.get('retired') is not False:raise ResourceUnavailable('recipe not active')
        rows,recipe,deadline=self._dependencies(recipe_id,row.data['revision'],row.data['qualification_id'],binding=row)
        if row.data['recipe_sha256']!=rows[revision_key(recipe_id,recipe.revision)].data['sha256']:
            raise StoreUnavailable('active recipe digest mismatch')
        return rows,recipe,deadline

    def approve(self,actor,*,recipe_id,expected_version,qualification_id,idempotency_key):
        actor=self.access._fresh(actor,Role.OWNER);key=catalog_key(recipe_id);qkey=qualification_key(qualification_id)
        if type(expected_version) is not int or expected_version<1:raise ValueError('positive recipe state version required')
        idem,body_hash,replay=self.access._idempotency(actor,'recipe-approve:'+recipe_id,idempotency_key,
            {'expected_version':expected_version,'qualification_id':qualification_id})
        if replay is not None:return self._result(actor,replay.data['result'])
        head=self._catalog(self.repository.snapshot((key,))[key])
        if head.revision!=expected_version or head.data['draft_revision'] is None:raise StoreConflict('current draft revision required')
        rows,recipe,deadline=self._dependencies(recipe_id,head.data['draft_revision'],qualification_id,binding=head)
        active=active_key(recipe_id);previous=self.repository.snapshot((active,))[active]
        data={'revision':recipe.revision,'recipe_sha256':rows[revision_key(recipe_id,recipe.revision)].data['sha256'],
            'qualification_id':qualification_id,'retired':False,'approved_at_ms':self.access.now()}
        result={'id':recipe_id,'revision':recipe.revision,'state_version':head.revision+1,'operation':'approved'}
        committed=self.access._record(actor,'recipe-approve:'+recipe_id,idem,body_hash,result,
            (Write(key,head.revision,{**head.data,'draft_revision':None,'retired':False}),
             Write(active,None if previous is None else previous.revision,data)),tuple(rows.values()),
            event_details={'recipe_id':recipe_id,'revision':recipe.revision,'recipe_sha256':data['recipe_sha256'],
                'qualification_id':qualification_id,'data_epoch':integer(rows[DATA].data['epoch']),
                'calibration_state_version':integer(rows[qkey].data['calibration_state_version']),
                'valid_until_ms':deadline,'environment':self.environment,'artifact_sha256':self.artifact_sha256})
        return self._result(actor,committed)

    def retire(self,actor,*,recipe_id,expected_version,reason,idempotency_key):
        actor=self.access._fresh(actor,Role.OWNER);key=catalog_key(recipe_id)
        if (type(expected_version) is not int or expected_version<1 or not isinstance(reason,str)
                or not 1<=len(reason)<=120 or any(ord(c)<32 for c in reason)):raise ValueError('bounded retirement reason/version required')
        idem,body_hash,replay=self.access._idempotency(actor,'recipe-retire:'+recipe_id,idempotency_key,
            {'expected_version':expected_version,'reason':reason})
        if replay is not None:return self._result(actor,replay.data['result'])
        active=active_key(recipe_id);rows=self.repository.snapshot((key,active));head=self._catalog(rows[key])
        if head.revision!=expected_version:raise StoreConflict('recipe changed')
        old=rows[active]
        result={'id':recipe_id,'revision':integer(head.data['latest_revision']),'state_version':head.revision+1,'operation':'retired'}
        committed=self.access._record(actor,'recipe-retire:'+recipe_id,idem,body_hash,result,
            (Write(key,head.revision,{**head.data,'retired':True}),
             Write(active,None if old is None else old.revision,{'retired':True,'reason':reason})),
            event_details={'recipe_id':recipe_id,'latest_revision':integer(head.data['latest_revision']),
                'previous_active_revision':None if old is None else old.data.get('revision'),
                'reason':reason,'environment':self.environment})
        return self._result(actor,committed)

    def list(self,actor,*,view='approved',limit=20,cursor=None):
        actor=self._candidate(actor) if view=='candidates' else self.access._fresh(actor)
        if view not in {'approved','candidates'} or type(limit) is not int or not 1<=limit<=20:raise ValueError('bounded recipe view required')
        start=None
        if cursor is not None:
            if (not isinstance(cursor,str) or len(cursor)>2048
                    or not re.fullmatch(r'[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}',cursor)):
                raise ValueError('bounded recipe cursor required')
            encoded,signature=cursor.split('.')
            if not hmac.compare_digest(signature,self.access._token('recipe-cursor',encoded)):raise Denied('invalid recipe cursor')
            try:
                payload=json.loads(base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)))
                if payload['scope']!=actor.scope or payload['view']!=view or self.access.now()>=payload['expiry']:raise Denied('expired/wrong-scope recipe cursor')
                start='recipe#'+uuid(payload['id'])
            except (KeyError,TypeError,ValueError,UnicodeError) as exc:raise ValueError('invalid recipe cursor') from exc
        rows,last=self.repository.query(prefix='recipe#',limit=limit,start_resource=start)
        result=[]
        for row in rows:
            current=self._current(row.data['id'])
            if view=='candidates':
                result.append({'id':row.data['id'],'name':row.data['name'],'state_version':row.revision,
                    'latest_revision':integer(row.data['latest_revision']),'retired':row.data['retired'],'current':current})
            elif current['effective_approved']:
                result.append({'id':row.data['id'],'name':current['active_name'],
                    'state_version':current['active_state_version'],'current':current})
        next_cursor=None
        if last:
            encoded=base64.urlsafe_b64encode(json.dumps({'scope':actor.scope,'view':view,'id':last[len('recipe#'):],
                'expiry':self.access.now()+300000},separators=(',',':')).encode()).decode().rstrip('=')
            next_cursor=encoded+'.'+self.access._token('recipe-cursor',encoded)
        self._candidate(actor) if view=='candidates' else self.access._fresh(actor)
        return {'recipes':result,'next_cursor':next_cursor}
