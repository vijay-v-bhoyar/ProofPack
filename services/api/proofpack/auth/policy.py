from dataclasses import dataclass
from enum import StrEnum
import hashlib
import hmac
from math import isfinite
import secrets


class Role(StrEnum):
    OWNER = "owner"
    OPERATOR = "operator"
    REVIEWER = "reviewer"


@dataclass(frozen=True)
class Principal:
    subject: str
    deployment: str
    roles: frozenset[Role]
    enabled: bool
    invited: bool
    access_revision: int
    session_id: str
    session_expires_at: float
    mfa_verified: bool = False


class Denied(PermissionError):
    pass


def require(principal: Principal | None, role: Role | None, *, deployment: str, now: float) -> Principal:
    if (principal is None or not isfinite(now) or not isfinite(principal.session_expires_at)
            or not principal.enabled or not principal.invited
            or principal.deployment != deployment or now >= principal.session_expires_at):
        raise Denied("enabled invited session required")
    if role is not None and role not in principal.roles:
        raise Denied("explicit role required")
    if role == Role.OWNER and not principal.mfa_verified:
        raise Denied("owner MFA required")
    return principal


def cookie_secret() -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def validate_csrf(*, expected_origin: str, origin: str | None, csrf_header: str | None,
                  csrf_hash: str) -> None:
    if not expected_origin or origin != expected_origin or not csrf_header:
        raise Denied("origin and CSRF proof required")
    if not hmac.compare_digest(hashlib.sha256(csrf_header.encode()).hexdigest(), csrf_hash):
        raise Denied("invalid CSRF proof")
