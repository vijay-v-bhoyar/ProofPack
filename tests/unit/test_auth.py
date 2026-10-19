from dataclasses import replace
from itertools import chain, combinations

import pytest

from proofpack.auth.policy import Denied, Principal, Role, cookie_secret, require, validate_csrf


def principal(roles):
    return Principal("user","demo",frozenset(roles),True,True,1,"session",1000.,True)


SUBSETS = list(chain.from_iterable(combinations(list(Role),n) for n in range(4)))


@pytest.mark.parametrize("roles",SUBSETS)
@pytest.mark.parametrize("required",list(Role))
def test_all_eight_role_subsets_no_inheritance(roles,required):
    if required in roles:
        assert require(principal(roles),required,deployment="demo",now=10.)
    else:
        with pytest.raises(Denied):
            require(principal(roles),required,deployment="demo",now=10.)


@pytest.mark.parametrize("changes",[{"enabled":False},{"invited":False},{"deployment":"other"},
                                  {"session_expires_at":10.},{"mfa_verified":False}])
def test_disabled_uninvited_cross_deployment_expired_non_mfa_denied(changes):
    with pytest.raises(Denied):
        require(replace(principal([Role.OWNER]),**changes),Role.OWNER,deployment="demo",now=10.)


def test_csrf_origin_and_server_hash():
    raw,hashed=cookie_secret()
    assert raw != hashed
    validate_csrf(expected_origin="https://example.test",origin="https://example.test",csrf_header=raw,csrf_hash=hashed)
    for origin,header in ((None,raw),("https://evil.test",raw),("https://example.test",None),("https://example.test","wrong")):
        with pytest.raises(Denied):
            validate_csrf(expected_origin="https://example.test",origin=origin,csrf_header=header,csrf_hash=hashed)


@pytest.mark.parametrize("tick",[float('nan'),float('inf'),float('-inf')])
def test_invalid_clock_never_authorizes(tick):
    with pytest.raises(Denied):
        require(principal([Role.OPERATOR]),Role.OPERATOR,deployment="demo",now=tick)
    with pytest.raises(Denied):
        require(replace(principal([Role.OPERATOR]),session_expires_at=tick),Role.OPERATOR,deployment="demo",now=10.)
