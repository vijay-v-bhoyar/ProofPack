"""Synthetic historical source graphs, not rights, physical truth, or adoption."""
from copy import deepcopy
from dataclasses import replace, FrozenInstanceError
from uuid import UUID
import hashlib
import pytest
from test_capture_lineage import family, uid, key, DEPLOYMENT
from proofpack.calibrations.dependencies import digest
from proofpack.capture.provenance import inspection_context
from proofpack.evidence.label_lineage import discover, LabelHistoryHeld
from proofpack.evidence.repository import Row, Key, Write, ErasureMarker
from proofpack.evidence.resource_bindings import prepare_linked, _payload_sha256
from proofpack.recipes.models import Recipe, Constraint, PartClass, Origin
from proofpack.recipes.service import revision_key as recipe_key
from proofpack.review.labels import head_key, label_revision_key
from proofpack.runtime.control import DATA
from proofpack.vision.worker_result import WorkerResult


def labels(count=2, *, ident=None, epoch_start=1):
    ident=ident or uid(70);root,capture=family(recipe_id=uid(3));capture=deepcopy(capture)
    definition=Recipe(recipe_id=uid(3),revision=1,name='Unit review recipe',kit_sku='unit-kit',
        constraints=(Constraint(constraint_id='washer',part_class_id=PartClass.WASHER,expected_count=1,required_visibility='top planar view'),),
        reference_asset_ids=('unit-reference',),calibration_profile_id='synthetic-mat',data_origin=Origin.SYNTHETIC)
    text=definition.model_dump_json();recipe=Row(recipe_key(uid(3),1),1,{'recipe_json':text,'sha256':hashlib.sha256(text.encode()).hexdigest()})
    purpose=Row(key('purpose',12),1,{'allowed_uses':['operation'],'withdrawn':False,'expires_at_ms':1000})
    for row in capture:
        if row.key.table=='events':
            if row.data['kind']=='observation_admitted':
                row.data['resource_bindings']['checks'].append({'table':'state','resource':recipe.key.resource,'revision':1,'sha256':_payload_sha256(recipe.data)})
                row.data['resource_bindings']['checks'].sort(key=lambda r:(r['table'],r['resource']))
            for reference in row.data['resource_bindings']['checks']:
                if reference['resource']==purpose.key.resource:reference['sha256']=_payload_sha256(purpose.data)
    observation=next(r for r in capture if r.key.resource.startswith('observation#'))
    asset=next(r for r in capture if r.key.resource.startswith('asset#'));o=observation.data
    result=WorkerResult.model_validate_json(o['result_json']);tuple_={'before_observation_id':o['id'],'action_id':None,'after_observation_id':None}
    context={'tuple':tuple_,'inspection_id':root.data['id'],'recipe_id':definition.recipe_id,'recipe_revision':1,
        'recipe_sha256':recipe.data['sha256'],'data_origin':'synthetic','artifact_sha256':root.data['artifact_sha256'],
        'runtime_instance_id':root.data['runtime_instance_id'],
        'inspection_bindings':{k:v for k,v in inspection_context(root.data,1,o).items() if k!='sequence'},
        'kit_group':root.data['kit_id'],'session_group':root.data['originating_session_id'],'operator_group':root.data['originating_user_id'],
        'sources':[{'observation_id':o['id'],'observation_version':3,'asset_id':o['asset_id'],'asset_version':1,
            'sha256':asset.data['sha256'],'purpose_id':uid(12),'purpose_version':1,'expires_at_ms':1000}],
        'observations':[{'observation_id':o['id'],'sequence':1,'findings':[v.value for v in result.findings],
            'reason_codes':list(result.reason_codes),'quality_ok':result.quality_ok,'unknown_regions':result.unknown_regions,'calibration_sha256':result.calibration_hash}],
        'expected_classes':['washer']}
    rows=[];previous=None;previous_head=None
    for number in range(1,count+1):
        reviewer=uid(59+number);scope=digest('unit-reviewer:'+reviewer);epoch=epoch_start+number-1;at=110+number
        data={'id':ident,'revision':number,'tuple':deepcopy(tuple_),'source_context':deepcopy(context),
            'source_context_sha256':digest(context),'outcome':'incorrect_finding','ground_truth_counts':[{'part_class':'washer','count':1}],
            'method':'synthetic_fixture','duration_ms':1000,'note':'Synthetic label note','reviewer_id':reviewer,
            'independence_declared':True,'independence_verified':False,'physical_truth_verified':False,
            'conflict_codes':[] if previous is None else ['different_revision_author'],'optional_improvement':False,'created_at_ms':at,
            'previous_sha256':None if previous is None else previous.data['sha256'],'data_epoch_before':epoch}
        data['sha256']=digest(data);revision=Row(label_revision_key(ident,number),1,data)
        label=Row(head_key(ident),number,{'id':ident,'latest_revision':number,'sha256':data['sha256']})
        event_key=key('access',10000+UUID(ident).int*100+number,'events')
        event_data={'kind':'label-create' if number==1 else 'label-revise:'+ident,'actor_scope':scope,'at_ms':at,'session_id':uid(90+number),
            'details':{'label_id':ident,'revision':number,'source_context_sha256':data['source_context_sha256']}}
        current_data=Row(DATA,epoch,{'epoch':epoch,'changed_at_ms':100})
        checks=(root,recipe,purpose,observation,asset,Row(Key('state','user#'+reviewer),1,{'id':reviewer}),current_data)
        if previous is not None:checks=(*checks,previous,previous_head)
        writes,_=prepare_linked(DEPLOYMENT,event_data['kind'],
            (Write(label.key,None if previous_head is None else previous_head.revision,label.data),Write(revision.key,None,data),
             Write(DATA,epoch,{'epoch':epoch+1,'changed_at_ms':at}),Write(Key('state','label-quota#'+scope),None,{'minute':0,'count':1}),
             Write(event_key,None,event_data)),checks)
        rows.extend((revision,Row(event_key,1,next(w.data for w in writes if w.key==event_key))))
        previous=revision;previous_head=label
    if previous_head is not None:rows.append(previous_head)
    return root,capture,recipe,(purpose,) if count else (),tuple(rows)


def run(root,capture,recipe,purposes,rows,**changes):
    return discover(root,rows,capture_rows=capture,recipe=recipe,purpose_rows=purposes,
        **({'deployment':DEPLOYMENT,'max_records':1000,'max_payload_bytes':2000000}|changes))


def mutate(rows,changes=None,context_change=None):
    rows=deepcopy(rows);target=max((r for r in rows if r.key.resource.startswith('label-revision#')),key=lambda r:r.data['revision'])
    data={**target.data,**(changes or {})}
    if context_change:context_change(data['source_context']);data['source_context_sha256']=digest(data['source_context'])
    data['sha256']=digest({k:v for k,v in data.items() if k!='sha256'});result=[]
    for row in rows:
        if row.key==target.key:row=replace(row,data=data)
        elif row.key.resource.startswith('label#'):row=replace(row,data={**row.data,'sha256':data['sha256']})
        elif row.key.table=='events' and row.data['details']['revision']==data['revision']:
            event=deepcopy(row.data);event['details']['source_context_sha256']=data['source_context_sha256']
            for reference in event['resource_bindings']['writes']:
                if reference['resource']==target.key.resource:reference['sha256']=_payload_sha256(data)
                elif reference['resource']==head_key(data['id']).resource:reference['sha256']=_payload_sha256({'id':data['id'],'latest_revision':data['revision'],'sha256':data['sha256']})
            row=replace(row,data=event)
        result.append(row)
    return tuple(result)


def test_complete_label_chain_is_detached_payload_free_and_distinguishes_catalog_and_model_ids():
    args=labels();before=deepcopy(args);result=run(*args)
    assert len(result.records)==5 and result.recipe.key.resource.startswith('recipe-revision#'+uid(3))
    assert not any(hasattr(r,'data') for r in result.records) and 'Synthetic label note' not in repr(result)
    assert result==run(args[0],tuple(reversed(args[1])),args[2],args[3],tuple(reversed(args[4])))
    assert args==before
    with pytest.raises(FrozenInstanceError):result.payload_bytes=0


def test_empty_label_family_requires_no_invented_history_or_purpose_grant():
    result=run(*labels(0));assert result.records==() and result.purposes==()


def test_multiple_heads_have_independent_chains_and_unique_data_effects():
    root,capture,recipe,purposes,rows=labels()
    other=labels(1,ident=uid(71),epoch_start=3)
    assert len(run(root,capture,recipe,purposes,(*rows,*other[-1])).records)==8


def test_record_and_payload_budgets_include_shared_recipe_and_purpose_sources():
    args=labels();result=run(*args);count=2+len(args[1])+len(args[3])+len(args[4])
    assert run(*args,max_records=count,max_payload_bytes=result.payload_bytes)==result
    for bounds in ({'max_records':count-1},{'max_payload_bytes':result.payload_bytes-1}):
        with pytest.raises(LabelHistoryHeld):run(*args,**bounds)


@pytest.mark.parametrize('name',['max_records','max_payload_bytes'])
@pytest.mark.parametrize('value',[0,-1,True,1.0,'10',None,2**63])
def test_explicit_bounds_are_exact_positive_storage_integers(name,value):
    with pytest.raises(ValueError):run(*labels(),**{name:value})


@pytest.mark.parametrize('value',[None,'','../foreign','foreign target'])
def test_deployment_configuration_is_explicit(value):
    with pytest.raises(ValueError):run(*labels(),deployment=value)


@pytest.mark.parametrize('changes',[
    {'independence_verified':True},{'physical_truth_verified':True},{'optional_improvement':True},
    {'independence_declared':1},{'method':'physical_manual_check'},{'outcome':'resolved'},
    {'ground_truth_counts':[{'part_class':'nut','count':1}]},{'duration_ms':0},{'note':' '},
    {'reviewer_id':uid(99)},{'conflict_codes':[]},{'created_at_ms':1000},{'data_epoch_before':1},
    {'previous_sha256':'f'*64},{'schema_version':2},
])
def test_resigned_unsupported_labels_do_not_become_verified_history(changes):
    root,capture,recipe,purposes,rows=labels()
    with pytest.raises(LabelHistoryHeld):run(root,capture,recipe,purposes,mutate(rows,changes=changes))


@pytest.mark.parametrize('field,value',[
    ('inspection_id',uid(99)),('recipe_id','foreign-recipe'),('recipe_revision',True),('recipe_sha256','f'*64),
    ('data_origin','physical'),('artifact_sha256','f'*64),('runtime_instance_id',uid(99)),
    ('kit_group','foreign'),('session_group',uid(99)),('operator_group',uid(99)),('expected_classes',['nut']),
])
def test_context_is_reconstructed_from_sources_not_just_its_own_hash(field,value):
    root,capture,recipe,purposes,rows=labels()
    with pytest.raises(LabelHistoryHeld):run(root,capture,recipe,purposes,mutate(rows,context_change=lambda c:c.update({field:value})))


@pytest.mark.parametrize('field,value',[
    ('asset_id',uid(99)),('asset_version',2),('purpose_id',uid(99)),('purpose_version',2),
    ('observation_version',1),('sha256','f'*64),('expires_at_ms',2000),('extra',True),
])
def test_original_source_manifest_cannot_be_resigned_to_different_media_or_windows(field,value):
    root,capture,recipe,purposes,rows=labels()
    with pytest.raises(LabelHistoryHeld):run(root,capture,recipe,purposes,mutate(rows,context_change=lambda c:c['sources'][0].update({field:value})))


def test_boolean_quality_is_not_equal_to_integer_quality_even_with_resigned_context():
    root,capture,recipe,purposes,rows=labels()
    with pytest.raises(LabelHistoryHeld):run(root,capture,recipe,purposes,mutate(rows,context_change=lambda c:c['observations'][0].update(quality_ok=1)))


@pytest.mark.parametrize('fault',['missing_head','missing_revision','missing_event','orphan_event','duplicate','marker','bad_head_count','bad_head_hash','revision_two','missing_purpose','wrong_recipe_key','recipe_hash','unknown_row'])
def test_missing_unknown_or_corrupt_family_members_hold(fault):
    root,capture,recipe,purposes,rows=labels()
    if fault=='missing_head':rows=tuple(r for r in rows if not r.key.resource.startswith('label#'))
    elif fault=='missing_revision':rows=tuple(r for r in rows if r.key!=label_revision_key(uid(70),1))
    elif fault=='missing_event':rows=tuple(r for r in rows if not(r.key.table=='events' and r.data['details']['revision']==1))
    elif fault=='orphan_event':rows=tuple(r for r in rows if r.key.table=='events')
    elif fault=='duplicate':rows=(*rows,rows[0])
    elif fault=='marker':rows=(ErasureMarker(rows[0].key,2,'a'*64,'b'*64),*rows[1:])
    elif fault in {'bad_head_count','bad_head_hash'}:rows=tuple(replace(r,data={**r.data,**({'latest_revision':100} if fault=='bad_head_count' else {'sha256':'f'*64})}) if r.key.resource.startswith('label#') else r for r in rows)
    elif fault=='revision_two':rows=(replace(rows[0],revision=2),*rows[1:])
    elif fault=='missing_purpose':purposes=()
    elif fault=='wrong_recipe_key':recipe=replace(recipe,key=recipe_key(uid(99),1))
    elif fault=='recipe_hash':recipe=replace(recipe,data={**recipe.data,'sha256':'f'*64})
    elif fault=='unknown_row':rows=(*rows,Row(key('unknown',99),1,{}))
    with pytest.raises(LabelHistoryHeld):run(root,capture,recipe,purposes,rows)


@pytest.mark.parametrize('fault',['missing_binding','wrong_operation','wrong_detail','missing_member','stray_write','wrong_previous_head','wrong_data_transition'])
def test_audit_and_shared_transition_bindings_are_required(fault):
    root,capture,recipe,purposes,rows=labels();rows=list(deepcopy(rows));index=next(i for i,r in enumerate(rows) if r.key.table=='events' and r.data['details']['revision']==2)
    data=rows[index].data
    if fault=='missing_binding':data.pop('resource_bindings')
    elif fault=='wrong_operation':data['kind']='label-create'
    elif fault=='wrong_detail':data['details']['source_context_sha256']='f'*64
    elif fault=='missing_member':data['resource_bindings']['checks']=[v for v in data['resource_bindings']['checks'] if not v['resource'].startswith('user#')]
    elif fault=='stray_write':data['resource_bindings']['writes'].append({'table':'state','resource':'foreign#'+uid(99),'previous_revision':None,'revision':1,'sha256':'f'*64});data['resource_bindings']['writes'].sort(key=lambda v:(v['table'],v['resource']))
    elif fault=='wrong_previous_head':next(v for v in data['resource_bindings']['checks'] if v['resource'].startswith('label#'))['sha256']='f'*64
    elif fault=='wrong_data_transition':next(v for v in data['resource_bindings']['writes'] if v['resource']==DATA.resource)['previous_revision']=None
    rows[index]=replace(rows[index],data=data)
    with pytest.raises(LabelHistoryHeld):run(root,capture,recipe,purposes,tuple(rows))


@pytest.mark.parametrize('status',['committed','deleted'])
def test_denied_media_and_withdrawn_purpose_preserve_metadata_without_restoring_read_rights(status):
    root,capture,recipe,purposes,rows=labels();changed=[]
    for r in capture:
        if r.key.resource.startswith('asset#'):
            data={**r.data,'status':status,'read_denied':True,'deletion_job_id':uid(99),'denied_at_ms':500}
            if status=='deleted':data['live_versions_checked_at_ms']=600
            r=replace(r,revision=2 if status=='committed' else 3,data=data)
        changed.append(r)
    purposes=(replace(purposes[0],revision=2,data={**purposes[0].data,'withdrawn':True}),)
    result=run(root,tuple(changed),recipe,purposes,rows)
    assert len(result.records)==5 and not hasattr(result,'can_download')
