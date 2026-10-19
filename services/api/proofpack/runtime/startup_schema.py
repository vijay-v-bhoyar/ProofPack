"""Closed startup history versions; parsing never grants current authority."""
from decimal import Decimal
import re

MAXIMUM = 2**63-2
LEGACY_FIELDS = frozenset({'runtime_epoch','artifact_sha256','controls_sha256','environment'})
RESTORE_FIELDS = frozenset({'startup_schema_version','restore_generation_sha256','previous_data_epoch','data_epoch'})


def bounded_integer(value, minimum=0):
    if (type(value) not in (int,Decimal)
            or type(value) is Decimal and (not value.is_finite() or value != value.to_integral_value())
            or not minimum <= value <= MAXIMUM):
        raise ValueError('finite exact bounded startup integer required')
    return int(value)


def restore_startup(data):
    if type(data) is not dict:
        raise ValueError('closed startup marker required')
    if set(data)==LEGACY_FIELDS:
        return None
    if (set(data)!=LEGACY_FIELDS|RESTORE_FIELDS
            or bounded_integer(data.get('startup_schema_version'))!=2
            or type(data['restore_generation_sha256']) is not str
            or re.fullmatch('[a-f0-9]{64}',data['restore_generation_sha256']) is None):
        raise ValueError('closed restore-bound startup version required')
    previous=bounded_integer(data['previous_data_epoch'])
    current=bounded_integer(data['data_epoch'],1)
    if current!=previous+1:
        raise ValueError('exact startup DATA advancement required')
    return data['restore_generation_sha256'],previous,current


def valid_data_write(startup, previous_revision, revision):
    if startup is None or startup[1]==0:
        return previous_revision is None and type(revision) is int and revision==1
    return (type(previous_revision) is int and 1<=previous_revision<=MAXIMUM
            and type(revision) is int and revision==previous_revision+1)
