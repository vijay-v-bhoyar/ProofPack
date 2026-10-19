"""Actual verifier block/helper on genuine writer artifacts, never cleanup authority."""
import ast,copy,inspect,textwrap
from dataclasses import replace
from types import SimpleNamespace
import pytest
from test_held_corpus import world,REQUEST
from test_corpus_accounting import run as base_read,no_sdk
from test_runtime_context import complete as runtime_world,read as runtime_read,limits as runtime_limits
from test_purpose_context import complete as purpose_world,read as purpose_read
from test_access_context import complete as access_world,read as access_read,limits as access_limits
from test_auth_history_consumption import history as auth_world,read as auth_read,limits as auth_limits
from test_ownership_classification import complete as supported_world,run as classify_read,bounds
from test_corpus_accounting import LIMITS
from test_capture_lineage import uid
import proofpack.evidence.ownership_classification as module
from proofpack.evidence.held_corpus import HeldCorpusHeld

def artifact(monkeypatch,version):
    if version==1:reader=world(monkeypatch)[0];return base_read(reader),reader
    if version==2:reader=runtime_world(monkeypatch)[0];return runtime_read(reader),reader
    if version==3:reader=purpose_world(monkeypatch)[0];return purpose_read(reader),reader
    if version==4:reader=access_world(monkeypatch)[0];return access_read(reader),reader
    reader=auth_world(monkeypatch,'bootstrap')[0];return auth_read(reader),reader

def verifier(accounting,corpus,*,maximum,check):
    args=dict(runtime_context=corpus.runtime_context,purpose_corpus=corpus.purposes,
        access_context=corpus.access_context,auth_history=corpus.auth_history)
    actual=getattr(module,'_check_accounting_digest',None)
    if actual is not None:
        return actual(accounting,corpus.inventory,corpus.scope.inspection_ids,
            max_summary_bytes=maximum,check=check,**args)
    # Reproduce the actual original verifier block, which current unresolved
    # v4/v5 classifications cannot reach. No policy/disposition is patched out.
    tree=ast.parse(textwrap.dedent(inspect.getsource(module.classify))).body[0]
    def assigns(node,name):
        return isinstance(node,ast.Assign) and any(isinstance(n,ast.Name) and n.id==name for n in node.targets)
    first=next(i for i,n in enumerate(tree.body) if assigns(n,'accounting_hash'))
    last=next(i for i,n in enumerate(tree.body[first:],first) if assigns(n,'summary'))
    fn=ast.parse('def original(a,inventory,requested_inspections,effective,check,runtime_context,purpose_corpus,access_context,auth_history):\n pass').body[0]
    fn.body=copy.deepcopy(tree.body[first:last]);code=ast.fix_missing_locations(ast.Module(body=[fn],type_ignores=[]))
    scope=dict(vars(module));exec(compile(code,'actual-original-verifier-block','exec'),scope)
    return scope['original'](accounting,corpus.inventory,corpus.scope.inspection_ids,
        SimpleNamespace(max_summary_bytes=maximum),check,**args)

@pytest.mark.parametrize('version',[1,2,3,4,5])
def test_genuine_versioned_accounting_roundtrips_independent_verifier(monkeypatch,version):
    result,_=artifact(monkeypatch,version);before=copy.deepcopy(result)
    assert verifier(result.accounting,result.corpus,maximum=result.accounting.summary_bytes,check=lambda cost=0:None) is None
    assert result==before and result.accounting.policy.endswith('v'+str(version))

@pytest.mark.parametrize('version',[1,2,3,4,5])
@pytest.mark.parametrize('one_below',[False,True])
def test_original_summary_byte_bound_exact_and_one_below(monkeypatch,version,one_below):
    result,_=artifact(monkeypatch,version)
    if one_below:
        with pytest.raises(module.ClassificationHeld):verifier(result.accounting,result.corpus,maximum=result.accounting.summary_bytes-1,check=lambda cost=0:None)
    else:assert verifier(result.accounting,result.corpus,maximum=result.accounting.summary_bytes,check=lambda cost=0:None) is None

@pytest.mark.parametrize('version',[1,2,3,4,5])
@pytest.mark.parametrize('one_below',[False,True])
def test_original_per_frame_work_bound_exact_and_one_below(monkeypatch,version,one_below):
    result,_=artifact(monkeypatch,version);a=result.accounting
    required=1+len(a.entries)+len(a.relationships);spent=[]
    def check(cost=0):
        spent.append(cost)
        if sum(spent)>required-int(one_below):raise module.ClassificationHeld('original work exhausted')
    if one_below:
        with pytest.raises(module.ClassificationHeld):verifier(a,result.corpus,maximum=a.summary_bytes,check=check)
    else:
        assert verifier(a,result.corpus,maximum=a.summary_bytes,check=check) is None
        assert sum(spent)==required

@pytest.mark.parametrize('fault',['digest','length','entries','relationships','inventory','context'])
def test_changed_independent_digest_inputs_cannot_pass(monkeypatch,fault):
    result,_=artifact(monkeypatch,5);a=result.accounting;c=result.corpus
    if fault=='digest':a=replace(a,summary_sha256='b'*64)
    elif fault=='length':a=replace(a,summary_bytes=a.summary_bytes+1)
    elif fault=='entries':a=replace(a,entries=tuple(reversed(a.entries)))
    elif fault=='relationships':a=replace(a,relationships=a.relationships[1:])
    elif fault=='inventory':c=replace(c,inventory=replace(c.inventory,summary_sha256='b'*64))
    elif fault=='context':c=replace(c,auth_history=replace(c.auth_history,summary_sha256='b'*64))
    with pytest.raises(module.ClassificationHeld):verifier(a,c,maximum=a.summary_bytes+100,check=lambda cost=0:None)

@pytest.mark.parametrize('version',[4,5])
def test_real_unresolved_classification_stays_held(monkeypatch,version):
    result,reader=artifact(monkeypatch,version)
    arguments=dict(request_id=REQUEST,inspection_ids=(uid(1),),deadline_ns=1000,accounting_limits=LIMITS,
        classification_limits=bounds(),runtime_context_limits=runtime_limits(),access_context_limits=access_limits())
    if version==5:
        with pytest.raises(HeldCorpusHeld):reader.read_auth_classification(**arguments,auth_history_limits=auth_limits())
    else:
        with pytest.raises(HeldCorpusHeld):reader.read_access_classification(**arguments)
    assert dict(result.accounting.counts)['UNRESOLVED']>0

def test_complete_real_v1_classification_consumes_actual_verifier_and_never_grants_cleanup(monkeypatch):
    original=getattr(module,'_check_accounting_digest',None);assert original is not None
    calls=[]
    def verify(*args,**kwargs):calls.append(True);return original(*args,**kwargs)
    monkeypatch.setattr(module,'_check_accounting_digest',verify)
    reader,_,owner,repo,data=supported_world(monkeypatch);before=copy.deepcopy(data)
    result=classify_read(reader)
    assert calls==[True] and data==before and owner.wait_for_drain(0)
    assert result.classification.can_confirm_cleanup is result.classification.erasure_complete is result.classification.request_fulfilled is False
