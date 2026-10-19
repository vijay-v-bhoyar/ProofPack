"""Minimized historical support lineage; no live assignment or inbox capability."""
import json
from proofpack.auth.policy import Denied,Role
from proofpack.calibrations.dependencies import canonical
from proofpack.evidence.repository import StoreUnavailable
from proofpack.runtime.control import integer,uuid
from proofpack.stations.handoffs import InspectionHandoffs,INSPECTION_METADATA_MAX_MS

def source(access,actor,row,inspection_id,originating_user_id):
    try:ident=uuid(row.data.get('id'))
    except (TypeError,ValueError,AttributeError) as exc:raise StoreUnavailable('intact support export identity required') from exc
    row=InspectionHandoffs.retained(row,inspection_id,ident,now=access.now)
    request=row.data['request'];user=actor.member.data['id']
    if user==request['sender_user_id']:role=Role(request['sender_role'])
    elif user==request['recipient_user_id']:role=Role.REVIEWER
    elif user==originating_user_id:role=Role.OPERATOR
    else:raise Denied('each exported support record requires its existing detail scope')
    access._fresh(actor,role)
    return row

def summary(row):
    request=row.data['request'];decision=row.data['decision']
    result={'id':row.data['id'],'state_version':row.revision,'request_sha256':row.data['request_sha256'],
        'decision_sha256':row.data['decision_sha256'],'recorded_status':row.data['status'],
        'historical':True,'machine_approval':False,'capture_transferred':False,
        'request':{k:request[k] for k in ('sender_user_id','recipient_user_id','sender_role','reason_code','station_id','station_epoch','station_name','kit_reference',
            'source_inspection_revision','post_request_inspection_revision','source_observation_id','previous_accepted_handoff_id',
            'created_at_ms','expires_at_ms','metadata_expires_at_ms','parent_metadata_expires_at_ms','stop_acknowledged')},
        'decision':None if decision is None else {k:decision[k] for k in ('kind','actor_user_id','actor_role','at_ms','successor_id','acknowledge_no_capture_transfer') if k in decision}}
    return json.loads(canonical(result))

def state(work):
    return {'request_count':integer(work.data.get('handoff_count',0)),'latest_handoff_id':work.data.get('latest_handoff_id'),
        'accepted_handoff_id':work.data.get('accepted_handoff_id'),'recorded_recipient_user_id':work.data.get('accepted_recipient_user_id'),
        'historical':True,'machine_approval':False,'capture_transferred':False}

def copies(data,verified):
    """Bind sanitized copies to actual source rows, not mutually matching copies."""
    mutable=[row for row in verified if row.key.resource.startswith('inspection-handoff#')]
    try:
        expected={row.data['id']:canonical(summary(row)) for row in mutable}
        saved=data['handoffs']
        if (not isinstance(saved,list) or len(mutable)>16 or len(expected)!=len(mutable) or len(saved)!=len(expected)
            or {r['id']:canonical(r) for r in saved}!=expected):raise ValueError()
    except (KeyError,TypeError,ValueError) as exc:raise StoreUnavailable('sanitized support copies must match actual referenced records') from exc
    return mutable

def lineage(work,records,events):
    """Require all requests, exact predecessor transitions and their write events."""
    expected=state(work);count=expected['request_count']
    if not 0<=count<=16 or len(records)!=count:raise StoreUnavailable('complete bounded support history required')
    ordered=sorted(records,key=lambda r:(r['request']['source_inspection_revision'],r['id']))
    ids=[r['id'] for r in ordered];revisions=[r['request']['source_inspection_revision'] for r in ordered]
    if len(set(ids))!=len(ids) or len(set(revisions))!=len(revisions):raise StoreUnavailable('distinct support lineage required')
    if expected['latest_handoff_id']!=(ids[-1] if ids else None):raise StoreUnavailable('exact latest support pointer required')
    accepted=None;recipient=None
    def audit(kind,ident,decision=None):
        matches=[e for e in events if e['kind']==kind and e.get('handoff_id')==ident]
        if len(matches)!=1 or matches[0].get('machine_approval') is not False or (decision is not None and matches[0].get('decision')!=decision):
            raise StoreUnavailable('bound support write audit required')
    for index,record in enumerate(ordered):
        r=record['request'];decision=record['decision'];status=record['recorded_status']
        if (r['previous_accepted_handoff_id']!=accepted or r['station_id']!=work.data['station_id'] or r['station_epoch']!=work.data['station_epoch']
            or r['kit_reference']!=work.data['kit_id'] or r['post_request_inspection_revision']>work.revision
            or r['created_at_ms']<work.data['created_at_ms'] or r['parent_metadata_expires_at_ms']!=integer(work.data['created_at_ms'])+INSPECTION_METADATA_MAX_MS):
            raise StoreUnavailable('bound inspection support lineage required')
        audit('handoff-request:'+work.data['id'],record['id'])
        if status in {'accepted','declined'}:audit('handoff-response:'+record['id'],record['id'],status)
        elif status=='cancelled':audit('handoff-cancel:'+record['id'],record['id'])
        elif status=='superseded':
            if (index+1>=len(ordered) or decision['successor_id']!=ordered[index+1]['id']
                or decision['actor_user_id']!=ordered[index+1]['request']['sender_user_id'] or decision['actor_role']!=ordered[index+1]['request']['sender_role']):
                raise StoreUnavailable('explicit next support supersession required')
        elif index+1<len(ordered):raise StoreUnavailable('unresolved earlier support request required explicit supersession')
        if status=='accepted':accepted=record['id'];recipient=r['recipient_user_id']
    if expected['accepted_handoff_id']!=accepted or expected['recorded_recipient_user_id']!=recipient:raise StoreUnavailable('exact accepted support pointer required')
    return ordered,expected
