"""Freshly authorized retained-image reads; no transferable object URL or live pass."""
import time
from threading import BoundedSemaphore
from uuid import uuid4

from proofpack.auth.policy import Denied,Role
from proofpack.auth.service import RUNTIME,ResourceUnavailable
from proofpack.calibrations.dependencies import digest
from proofpack.capture.service import observation_key
from proofpack.evidence.objects import EvidenceObjects,ReferenceObjects,ObjectReceipt
from proofpack.evidence.originals import ORIGINAL_MAX_ATTEMPTS,original_capture_enabled,original_permission_binding,validate_original_source
from proofpack.evidence.repository import Key,StoreConflict,StoreUnavailable,Write
from proofpack.runtime.control import DATA,integer,sha,uuid
from proofpack.stations.service import inspection_key
from proofpack.capture.provenance import inspection_context
from proofpack.vision.correction import verified_reference


class AssetReadLimited(RuntimeError):pass


class AssetReads:
    def __init__(self,purposes,frames,references,*,reads_per_minute,max_concurrent,read_window_ms,tick_ns=None):
        if (not isinstance(frames,EvidenceObjects) or isinstance(frames,ReferenceObjects) or not isinstance(references,ReferenceObjects)
                or frames.config!=references.config or frames.config.deployment!=purposes.repository.deployment
                or type(reads_per_minute) is not int or not 1<=reads_per_minute<=120
                or type(max_concurrent) is not int or not 1<=max_concurrent<=2
                or type(read_window_ms) is not int or not 1<=read_window_ms<=5000):raise ValueError('shared scoped stores and explicit bounded read configuration required')
        self.purposes=purposes;self.access=purposes.access;self.repository=purposes.repository;self.runtime=purposes.runtime
        self.frames=frames;self.references=references;self.reads_per_minute=reads_per_minute;self.read_window_ms=read_window_ms
        self._slots=BoundedSemaphore(max_concurrent);self.tick=tick_ns or time.monotonic_ns

    def _permission(self,actor,asset,work,*,binary):
        actor=self.access._fresh(actor);roles=actor.principal.roles;own=actor.member.data['id']
        if Role.REVIEWER in roles:return self.access._fresh(actor,Role.REVIEWER)
        reference=asset.data.get('kind')=='reference'
        if not reference and Role.OPERATOR in roles and work.data['originating_user_id']==own:return self.access._fresh(actor,Role.OPERATOR)
        if Role.OWNER in roles and (not binary or (reference and asset.data['owner_user_id']==own)):
            return self.access._fresh(actor,Role.OWNER)
        raise Denied('explicit scoped evidence access required')

    def _snapshot(self,actor,ident,*,binary):
        actor=self.access._fresh(actor);key=Key('state','asset#'+uuid(ident));asset=self.repository.snapshot((key,))[key]
        if asset is None:raise ResourceUnavailable('evidence unavailable')
        try:
            data=self.purposes.head();runtime=self.repository.snapshot((RUNTIME,))[RUNTIME]
            if not self.runtime.matches(runtime):raise Denied('current evidence service required')
            rows={row.key:row for row in (asset,data,runtime)};work=None
            if asset.data.get('kind')=='reference':
                store=self.references
                receipt=ObjectReceipt(**{**asset.data['object_receipt'],'byte_length':integer(asset.data['object_receipt']['byte_length'])})
            elif asset.data.get('derivation') in {'rectified_roi_jpeg','original_transmitted_frame'}:
                store=self.frames;obkey=observation_key(asset.data['observation_id']);observation=self.repository.snapshot((obkey,))[obkey]
                if observation is None or observation.data['status']!='completed':raise ValueError('completed observation required')
                workkey=inspection_key(observation.data['inspection_id']);work=self.repository.snapshot((workkey,))[workkey]
                original=asset.data.get('derivation')=='original_transmitted_frame'
                cropkey=Key('state','asset#'+uuid(observation.data['asset_id']))
                crop=self.repository.snapshot((cropkey,))[cropkey] if original else asset
                if crop is None:raise ValueError('linked crop required')
                if original:
                    validate_original_source(asset,observation,crop);rows[cropkey]=crop
                if (work is None or (not original and (observation.data['asset_id']!=ident or observation.data['evidence_sha256']!=sha(asset.data['sha256'])))
                        or observation.data['source_sha256']!=sha(asset.data['input_sha256'])
                        or observation.data['context_sha256']!=sha(asset.data['context_sha256'])):raise ValueError('observation binding mismatch')
                binding=inspection_context(work.data,observation.data['sequence'],observation.data)
                if digest(binding)!=observation.data['context_sha256']:raise ValueError('original capture binding missing')
                rows[workkey]=work;rows[obkey]=observation
                verified_reference(asset.data,observation.data)
                receipt=ObjectReceipt(ident,asset.data['object_key'],asset.data['object_version'],asset.data['sha256'],asset.data['context_sha256'],
                    integer(asset.data['byte_length']),asset.data['content_type'])
            else:raise ValueError('supported retained evidence required')
            actor=self._permission(actor,asset,work,binary=binary)
            permission_reference=None
            if asset.data.get('kind')=='reference':
                permission_reference=asset.data['source_permission_reference']
                if not isinstance(permission_reference,str) or not permission_reference:raise ValueError('source permission binding required')
            purpose=self.purposes.permitted(asset.data['purpose_id'],source_permission_reference=permission_reference,expires_at_ms=integer(asset.data['expires_at_ms']));rows[purpose.key]=purpose
            if asset.data.get('derivation')=='original_transmitted_frame':
                if (not original_capture_enabled(purpose,self.access)
                        or original_permission_binding((purpose,))!=observation.data.get('original_capture_purpose_binding')):
                    raise StoreUnavailable('current original-retention permission required')
            if asset.data['status']!='committed' or asset.data['read_denied'] is not False:raise StoreUnavailable('evidence unavailable')
            sha(receipt.context_sha256)
            if asset.data['data_origin'] not in {'synthetic','printable','physical'}:raise ValueError('recorded data origin required')
            if (receipt.asset_id!=ident or receipt.key!=store.key(ident) or receipt.source_sha256!=sha(asset.data['sha256'])
                    or receipt.byte_length!=integer(asset.data['byte_length']) or not 0<receipt.byte_length<=2097152
                    or receipt.content_type!=asset.data['content_type'] or receipt.content_type not in {'image/jpeg','image/png'}):raise ValueError('exact scoped receipt required')
            for row in actor.rows:
                if row.key in rows and rows[row.key]!=row:raise StoreConflict('read authority changed')
                rows[row.key]=row
            deadline=min(integer(asset.data['expires_at_ms']),integer(purpose.data['expires_at_ms']))
            if asset.data.get('derivation')=='original_transmitted_frame':deadline=min(deadline,integer(crop.data['expires_at_ms']))
            binding=digest({'asset_id':ident,'asset_version':asset.revision,'purpose_id':asset.data['purpose_id'],'purpose_version':purpose.revision,
                'data_epoch':integer(data.data['epoch']),'user_id':actor.member.data['id'],'access_version':integer(actor.member.data['access_version']),
                'session_id':actor.session.data['id']})
            return actor,rows,asset,work,store,receipt,deadline,binding
        except StoreConflict:raise
        except (KeyError,ValueError,TypeError,AttributeError) as exc:raise StoreUnavailable('retained evidence provenance unavailable') from exc

    def _final(self,actor,rows,asset,work,deadline,started,*,binary):
        actor=self._permission(actor,asset,work,binary=binary)
        final=self.repository.snapshot(tuple(rows))
        if any(final[key]!=row for key,row in rows.items()):raise StoreConflict('evidence authority changed')
        actor=self._permission(actor,asset,work,binary=binary)
        if self.access.now()>=deadline or not 0<=self.tick()-started<self.read_window_ms*1000000:raise StoreUnavailable('evidence read expired')
        return actor

    def _audit(self,actor,rows,ident,kind,*,charge):
        writes=[]
        if charge:
            key=Key('state','asset-read-quota#'+actor.scope);quota=self.repository.snapshot((key,))[key];minute=self.access.now()//60000
            if quota is not None and integer(quota.data['minute'])>minute:raise StoreUnavailable('read allowance clock moved backwards')
            count=0 if quota is None or integer(quota.data['minute'])!=minute else integer(quota.data['count'])
            if count>=self.reads_per_minute:raise AssetReadLimited('evidence read allowance exhausted')
            writes.append(Write(key,None if quota is None else quota.revision,{'minute':minute,'count':count+1}))
        resource='inspection_id' if kind.startswith('inspection_') else 'asset_id'
        writes.append(Write(Key('events','asset-read#'+str(uuid4())),None,{'kind':kind,resource:ident,'actor_scope':actor.scope,'at_ms':self.access.now()}))
        self.access._commit_linked(kind,tuple(writes),tuple(rows.values()),before_commit=lambda:self.access._fresh(actor))

    def _remaining(self,deadline,started):
        remaining=min(60000,deadline-self.access.now())
        if remaining<=0 or not 0<=self.tick()-started<self.read_window_ms*1000000:raise StoreUnavailable('evidence expired before response')
        return remaining

    def _latest_source(self,actor,inspection_id):
        actor=self.access._fresh(actor);key=inspection_key(inspection_id);work=self.repository.snapshot((key,))[key]
        if work is None:raise ResourceUnavailable('inspection evidence unavailable')
        if Role.REVIEWER in actor.principal.roles:actor=self.access._fresh(actor,Role.REVIEWER)
        elif Role.OPERATOR in actor.principal.roles and work.data['originating_user_id']==actor.member.data['id']:actor=self.access._fresh(actor,Role.OPERATOR)
        else:actor=self.access._fresh(actor,Role.OWNER)
        ident=work.data.get('latest_observation_id')
        if ident is None:raise ResourceUnavailable('no retained observation')
        obkey=observation_key(ident);observation=self.repository.snapshot((obkey,))[obkey]
        if observation is None or observation.data.get('status')!='completed' or observation.data['inspection_id']!=inspection_id:raise StoreUnavailable('retained observation unavailable')
        return actor,observation.data['asset_id'],(work,observation)

    def latest(self,actor,inspection_id):return self.read(actor,inspection_id,_inspection=True)

    def _metadata(self,actor,rows,asset,work,receipt,deadline,binding,started):
        can_download=True
        try:self._permission(actor,asset,work,binary=True)
        except Denied:can_download=False
        self._final(actor,rows,asset,work,deadline,started,binary=False)
        value={'id':asset.data['id'],'state_version':asset.revision,'kind':'reference' if asset.data.get('kind')=='reference' else 'inspection_evidence',
            'sha256':receipt.source_sha256,'byte_length':receipt.byte_length,'content_type':receipt.content_type,'data_origin':asset.data['data_origin'],
            'binding_sha256':binding,'expires_at_ms':deadline,'remaining_validity_ms':self._remaining(deadline,started),'can_download':can_download,
            'historical':True,'machine_pass':False,'storage_verified':False,'optional_improvement':False,
            'derivation':asset.data.get('derivation'),
            'observation_id':asset.data.get('observation_id'),'inspection_id':None if work is None else work.data['id']}
        if can_download and asset.data.get('kind')!='reference' and asset.data.get('derivation')=='rectified_roi_jpeg':
            observation=rows[observation_key(asset.data['observation_id'])]
            correction=verified_reference(asset.data,observation.data)
            if correction is not None:value['correction_reference']=correction
        return value

    def originals(self,actor,inspection_id):
        """One bounded inspection index; no table scan and no media access inheritance."""
        started=self.tick();inspection_id=uuid(inspection_id)
        if type(started) is not int or started<0:raise StoreUnavailable('trusted read time required')
        if not self._slots.acquire(blocking=False):raise AssetReadLimited('evidence reads busy')
        try:
            actor=self.access._fresh(actor)
            self._audit(actor,{row.key:row for row in actor.rows},inspection_id,'inspection_originals_attempt',charge=True)
            key=inspection_key(inspection_id);work=self.repository.snapshot((key,))[key]
            if work is None:raise ResourceUnavailable('inspection evidence unavailable')
            if Role.REVIEWER in actor.principal.roles:required_role=Role.REVIEWER
            elif Role.OPERATOR in actor.principal.roles and work.data['originating_user_id']==actor.member.data['id']:required_role=Role.OPERATOR
            else:required_role=Role.OWNER
            actor=self.access._fresh(actor,required_role)
            ids=work.data.get('original_asset_ids',[])
            if (not isinstance(ids,list) or len(ids)>ORIGINAL_MAX_ATTEMPTS or len(set(ids))!=len(ids)
                    or not len(ids)<=integer(work.data.get('original_attempts_reserved',0))<=ORIGINAL_MAX_ATTEMPTS):
                raise StoreUnavailable('bounded original history required')
            rows={r.key:r for r in actor.rows};rows[work.key]=work
            data=self.purposes.head();runtime=self.repository.snapshot((RUNTIME,))[RUNTIME]
            if not self.runtime.matches(runtime):raise Denied('current evidence service required')
            rows.update({data.key:data,runtime.key:runtime});snapshots=[]
            deadline=integer(actor.session.data['expires_at_ms'])
            for ident in ids:
                actor,current,asset,source,_,receipt,expires,binding=self._snapshot(actor,uuid(ident),binary=False)
                if source!=work or asset.data.get('derivation')!='original_transmitted_frame':raise StoreConflict('inspection original linkage changed')
                for k,row in current.items():
                    if k in rows and rows[k]!=row:raise StoreConflict('original catalog authority changed')
                    rows[k]=row
                deadline=min(deadline,expires);snapshots.append((asset,receipt,binding))
            views=[self._metadata(actor,rows,asset,work,receipt,deadline,binding,started) for asset,receipt,binding in snapshots]
            self._audit(actor,rows,inspection_id,'inspection_originals_metadata_read',charge=False)
            final=self.repository.snapshot(tuple(rows))
            if any(final[k]!=row for k,row in rows.items()):raise StoreConflict('original catalog authority changed')
            self.access._fresh(actor,required_role)
            remaining=self._remaining(deadline,started)
            # One common final horizon includes time spent building every result.
            for view in views:view['remaining_validity_ms']=remaining
            return {'inspection_id':inspection_id,'originals':views,'remaining_validity_ms':remaining,'historical':True,'machine_pass':False}
        except (KeyError,TypeError,ValueError,AttributeError) as exc:raise StoreUnavailable('original catalog provenance unavailable') from exc
        finally:self._slots.release()

    def read(self,actor,ident,*,binary=False,_inspection=False):
        started=self.tick();ident=uuid(ident)
        if type(started) is not int or started<0:raise StoreUnavailable('trusted read time required')
        if not self._slots.acquire(blocking=False):raise AssetReadLimited('evidence reads busy')
        try:
            actor=self.access._fresh(actor)
            self._audit(actor,{row.key:row for row in actor.rows},ident,'inspection_evidence_attempt' if _inspection else 'asset_read_attempt',charge=True)
            expected=()
            if _inspection:actor,ident,expected=self._latest_source(actor,ident)
            actor,rows,asset,work,store,receipt,deadline,binding=self._snapshot(actor,ident,binary=binary)
            for row in expected:
                if row.key not in rows or rows[row.key]!=row:raise StoreConflict('latest inspection evidence changed')
            actor=self._final(actor,rows,asset,work,deadline,started,binary=binary)
            self._audit(actor,rows,ident,'asset_download_admitted' if binary else 'asset_metadata_read',charge=False)
            if binary:
                payload=store.get(receipt)
                actor=self._final(actor,rows,asset,work,deadline,started,binary=True)
                self._audit(actor,rows,ident,'asset_download_ready',charge=False)
                self._final(actor,rows,asset,work,deadline,started,binary=True)
                return payload,receipt,asset.revision,binding,self._remaining(deadline,started)
            actor=self._final(actor,rows,asset,work,deadline,started,binary=False)
            return self._metadata(actor,rows,asset,work,receipt,deadline,binding,started)
        finally:self._slots.release()
