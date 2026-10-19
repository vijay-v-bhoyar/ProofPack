"""Canonical capture context shared by publication and historical evidence readers."""
from proofpack.runtime.control import integer,sha,uuid

POLICY_FIELDS=('policy_id','policy_revision','policy_revision_sha256','behavior_sha256',
    'activation_id','activation_sha256','qualification_id','qualification_report_sha256')
CONTEXT_FIELDS=('id','station_id','station_epoch','recipe_id','recipe_active_version','calibration_state_version',
    'policy_state_version','runtime_epoch','runtime_instance_id','control_version','data_epoch',
    'originating_session_id','originating_access_version')


def policy_provenance(data):
    value={name:data[name] for name in POLICY_FIELDS}
    for name in ('policy_id','activation_id','qualification_id'):uuid(value[name])
    for name in ('policy_revision_sha256','behavior_sha256','activation_sha256','qualification_report_sha256'):sha(value[name])
    value['policy_revision']=integer(value['policy_revision'])
    if value['policy_revision']<1:raise ValueError('positive qualified policy revision required')
    return value


def inspection_context(data,sequence,observation=None):
    result={name:integer(data[name]) if name.endswith(('_version','_epoch')) else data[name] for name in CONTEXT_FIELDS}
    result['sequence']=integer(sequence)
    # Old records retain their original hash for historical review only. Station
    # authority separately rejects legacy work without exact live provenance.
    if 'policy_provenance' in data:
        raw=data['policy_provenance']
        if not isinstance(raw,dict) or set(raw)!=set(POLICY_FIELDS):raise ValueError('complete policy provenance required')
        result['policy_provenance']=policy_provenance(raw)
        if observation is not None and observation.get('policy_provenance')!=result['policy_provenance']:
            raise ValueError('observation policy provenance differs from inspection')
    elif observation is not None and 'policy_provenance' in observation:
        raise ValueError('historical inspection policy provenance missing')
    return result
