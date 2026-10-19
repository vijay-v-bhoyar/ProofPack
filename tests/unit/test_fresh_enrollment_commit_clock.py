"""The exact clock read at the effect boundary must not outlive original review."""
import sys

import pytest

from test_host import host_files
from test_fresh_enrollment import world,run,approve_candidate
from proofpack.runtime.host import HostConfigurationError


def test_expiry_at_the_last_prewrite_clock_read_denies_all_seed_records(host_files):
    w=world(host_files);approve_candidate(w,run(w));reached=[]
    def clock():
        parent=sys._getframe(1)
        while parent is not None:
            if parent.f_code.co_name=='call' and parent.f_locals.get('name')=='transact_write_items':
                reached.append(True);return w.intent.expires_at_ms
            parent=parent.f_back
        return w.clock[0]
    with pytest.raises(HostConfigurationError):
        w.mod.run_enrollment(w.loaded,w.intent,commit=True,session_factory=w.Session,clock_ms=clock)
    assert reached and w.client.items=={}
    assert not any(n=='transact_write_items' for n,k in w.client.calls)
