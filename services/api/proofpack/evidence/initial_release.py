"""Closed fresh-install declarations; structure alone is not approval or IAM proof."""
from dataclasses import dataclass
import re
from uuid import UUID

ROLE=re.compile(r'arn:aws:iam::([0-9]{12}):role/([A-Za-z0-9_+=,.@-]{1,64})')
HASHES=frozenset({'controls_sha256','configuration_sha256','empty_inventory_sha256',
    'enrollment_sha256','admission_configuration_sha256','runtime_generation_sha256','initial_state_sha256'})
FIELDS=HASHES|{'operation_id','instance_id','enrollment_role_arn','created_at_ms','expires_at_ms'}


def identifier(value):
    if type(value) is not str or str(UUID(value))!=value:raise ValueError('canonical original enrollment identifier required')
    return value


@dataclass(frozen=True)
class EnrollmentIntent:
    operation_id:str
    instance_id:str
    role_arn:str
    created_at_ms:int
    expires_at_ms:int

    def __post_init__(self):
        identifier(self.operation_id);identifier(self.instance_id)
        if (self.operation_id==self.instance_id or type(self.role_arn) is not str or ROLE.fullmatch(self.role_arn) is None
                or type(self.created_at_ms) is not int or type(self.expires_at_ms) is not int
                or not 1<=self.created_at_ms<self.expires_at_ms<2**63-1
                or self.expires_at_ms-self.created_at_ms>300000):
            raise ValueError('explicit bounded first-install review and enrollment role required')


def validate_fields(body):
    if any(type(body[name]) is not str or re.fullmatch('[a-f0-9]{64}',body[name]) is None for name in HASHES):
        raise ValueError('intact first-install declarations required')
    return EnrollmentIntent(body['operation_id'],body['instance_id'],body['enrollment_role_arn'],body['created_at_ms'],body['expires_at_ms'])
