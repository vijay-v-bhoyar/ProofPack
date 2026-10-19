"""Server-derived private upload histories; missing origin never becomes ownership."""
from dataclasses import dataclass,field,asdict,replace
import hashlib

from proofpack.evidence.reference_lineage import ReferenceFamily,ReferenceLimits,ReferenceHistoryHeld,discover
from proofpack.evidence.replay_corpus import ReplayCorpus
from proofpack.evidence.label_corpus import _inspection_references,_snapshot
from proofpack.evidence.repository import Key,Row
from proofpack.evidence.resource_lineage import decode,MissingResourceBindings,InvalidResourceBindings
from proofpack.evidence.inventory import _encoded
from proofpack.runtime.control import uuid

POLICY='server-reference-upload-corpus-v1'


class ReferenceCorpusHeld(RuntimeError):pass


@dataclass(frozen=True)
class ReferenceCorpusLimits:
    max_references:int
    family:ReferenceLimits
    max_work:int
    max_summary_bytes:int

    def __post_init__(self):
        if (type(self.family) is not ReferenceLimits or any(type(v) is not int or not 1<=v<=2**63-1
                for v in (self.max_references,self.max_work,self.max_summary_bytes))):
            raise ValueError('explicit finite reference root/family/work/summary limits required')


@dataclass(frozen=True)
class ReferenceCorpus:
    policy:str
    families:tuple[ReferenceFamily,...]=field(repr=False)
    family_count:int
    work:int
    summary_bytes:int
    summary_sha256:str


def derive(rows,selection,*,deployment,limits,deadline_ns,tick,checkpoint):
    if (type(rows) is not tuple or type(selection) is not ReplayCorpus or type(limits) is not ReferenceCorpusLimits
            or type(deadline_ns) is not int or not 1<=deadline_ns<=2**63-1
            or not callable(tick) or not callable(checkpoint)):
        raise ValueError('exact upstream selection, bounded private rows and original deadline required')
    work=selection.work;last=-1
    def check(cost=0):
        nonlocal work,last
        if type(cost) is not int or cost<0:raise ValueError()
        work+=cost
        if work>limits.max_work:raise ReferenceCorpusHeld('cumulative reference work bound exhausted')
        checkpoint();now=tick()
        if type(now) is not int or not 0<=now<deadline_ns or now<last:
            raise ReferenceCorpusHeld('original reference corpus deadline/clock invalid')
        last=now;checkpoint()
    try:
        check()
        copied=_snapshot(rows,_inspection_references(selection.datasets.permissions.labels.inspections),check)
        roots={};groups={};operations={};accesses=[];committed=[]
        for row in copied.values():
            check(1)
            if type(row) is not Row:continue
            prefix=row.key.resource.split('#',1)[0]
            if prefix=='reference-intent':
                ident=uuid(row.data['id'])
                if row.key!=Key('state','reference-intent#'+ident) or ident in roots:raise ValueError()
                if len(roots)>=limits.max_references:raise ReferenceCorpusHeld('reference root bound exhausted')
                roots[ident]=row;groups[ident]=[]
            elif row.key.table=='state' and prefix=='idempotency':
                result=row.data.get('result')
                if type(result) is dict and type(result.get('id')) is str:
                    operations.setdefault(result['id'],[]).append(row)
            elif row.key.table=='events' and row.data.get('kind')=='reference-upload':accesses.append(row)
            elif row.key.table=='events' and row.data.get('kind')=='reference_committed':committed.append(row)
        for row in accesses:
            check(1);binding=decode(row,deployment=deployment)
            targets=[r.key for r in binding.writes if r.key.table=='state' and r.key.resource.startswith('reference-intent#')]
            if len(targets)!=1:raise ValueError()
            ident=uuid(targets[0].resource.split('#',1)[1])
            if ident not in roots:raise ValueError()
            groups[ident].append(row)
        for row in committed:
            check(1);ident=uuid(row.data['asset_id'])
            if ident not in roots:raise ValueError()
            groups[ident].append(row)
        families=[];hasher=hashlib.sha256();size=0
        for ident,root in sorted(roots.items()):
            check(1)
            selected=groups[ident]+operations.get(ident,[])
            asset=copied.get(Key('state','asset#'+ident))
            if asset is not None:selected.append(asset)
            selected=tuple(sorted(selected,key=lambda r:(r.key.table,r.key.resource)))
            remaining=limits.max_work-work
            if remaining<=0:raise ReferenceCorpusHeld('cumulative reference work bound exhausted')
            family=discover(root,selected,deployment=deployment,
                limits=replace(limits.family,max_work=min(limits.family.max_work,remaining)),
                deadline_ns=deadline_ns,tick=tick,checkpoint=lambda:check())
            check(family.work)
            encoded=_encoded(asdict(family));framed=str(len(encoded)).encode()+b':'+encoded
            size+=len(framed)
            if size>limits.max_summary_bytes:raise ReferenceCorpusHeld('reference summary bound exhausted')
            hasher.update(framed);families.append(family);check()
        result=ReferenceCorpus(POLICY,tuple(families),len(families),work,size,hasher.hexdigest())
        check();return result
    except ReferenceCorpusHeld:raise
    except (ReferenceHistoryHeld,MissingResourceBindings,InvalidResourceBindings,KeyError,TypeError,
            ValueError,AttributeError,ArithmeticError,RecursionError):
        raise ReferenceCorpusHeld('complete original supported reference corpus required') from None
