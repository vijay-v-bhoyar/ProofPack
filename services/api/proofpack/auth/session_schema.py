"""Closed stored session versions; parsing is never present authentication."""
import re
from decimal import Decimal

LEGACY_FIELDS = frozenset('id issuer subject email_hash display_name created_at_ms active expires_at_ms mfa_verified auth_time_ms csrf_hash user_id access_version session_epoch restricted_invitation_id'.split())
RESTORE_FIELDS = frozenset({'session_schema_version', 'restore_generation_sha256'})


def session_generation(data):
    if type(data) is not dict:
        raise ValueError('closed session object required')
    if set(data) == LEGACY_FIELDS:
        return None
    version = data.get('session_schema_version')
    exact_two = (type(version) is int and version == 2
                 or type(version) is Decimal and version.is_finite() and version == 2)
    if (set(data) != LEGACY_FIELDS | RESTORE_FIELDS or not exact_two
            or type(data['restore_generation_sha256']) is not str
            or re.fullmatch('[a-f0-9]{64}', data['restore_generation_sha256']) is None):
        raise ValueError('exact restore-bound session version and generation required')
    return data['restore_generation_sha256']
