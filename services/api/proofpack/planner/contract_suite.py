"""Bounded installed software contracts; never a qualification/approval writer."""
from collections import Counter
from dataclasses import asdict,dataclass
import hashlib,json,time
from pathlib import Path

from proofpack.calibrations.dependencies import canonical,digest
from proofpack.planner import candidates,contract_registry,policy
from proofpack.planner.candidates import PolicyDraft
from proofpack.verifier import core


class ContractSuiteHeld(RuntimeError):
    def __init__(self,reason):self.reason=reason;super().__init__(reason)


@dataclass(frozen=True)
class ContractSuiteConfig:
    max_cases:int
    max_duration_ms:int
    max_case_report_bytes:int
    max_report_bytes:int

    def __post_init__(self):
        if any(type(value) is not int or not 1<=value<=high for value,high in (
                (self.max_cases,256),(self.max_duration_ms,15000),(self.max_case_report_bytes,8192),(self.max_report_bytes,1048576))):
            raise ValueError('explicit installed contract-suite bounds required')

    @classmethod
    def from_controls(cls,controls):
        section=controls.get('policy_contract_suite',{})
        if (set(section)!=set(cls.__dataclass_fields__)|{'runner','qualification_eligible','promotion_eligible','physical_truth_verified'}
                or section['runner']!='policy_contract_suite_v1'
                or any(section[k] is not False for k in ('qualification_eligible','promotion_eligible','physical_truth_verified'))):
            raise ValueError('complete non-authorizing contract-suite configuration required')
        return cls(**{name:section[name] for name in cls.__dataclass_fields__})


def implementation_sha256():
    modules=(candidates,contract_registry,policy,core)
    paths=[Path(module.__file__).resolve() for module in modules]+[Path(__file__).resolve()]
    return digest([{'module':path.name,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for path in paths])


class PolicyContractSuite:
    def __init__(self,definition,config,*,checkpoint=None,progress=None,tick_ns=None):
        if not isinstance(definition,PolicyDraft) or not isinstance(config,ContractSuiteConfig):raise ValueError('typed candidate and explicit bounds required')
        self.definition=definition;self.config=config;self.checkpoint=checkpoint or (lambda:None)
        self.progress=progress or (lambda report:None);self.tick=tick_ns or time.monotonic_ns
        self.used=False;self._report=None;self._last_tick=None

    @property
    def last_report(self):return None if self._report is None else json.loads(canonical(self._report))

    def _gate(self,start):
        if self.checkpoint() is False:raise ContractSuiteHeld('CHECKPOINT_REJECTED')
        if (digest(self.definition.model_dump(mode='json'))!=self._report['definition_sha256']
                or digest(asdict(self.config))!=self._report['configuration_sha256']):raise ContractSuiteHeld('SUBJECT_CHANGED')
        self._time_gate(start)

    def _time_gate(self,start):
        now=self.tick()
        if type(now) is not int or not now>=start>=0 or (self._last_tick is not None and now<self._last_tick):raise ContractSuiteHeld('TRUSTED_TIME_UNAVAILABLE')
        self._last_tick=now
        if now-start>=self.config.max_duration_ms*1000000:raise ContractSuiteHeld('DEADLINE_EXCEEDED')

    def _emit(self):
        if any(len((canonical(row)+'\n').encode())>self.config.max_case_report_bytes for row in self._report['cases']):raise ContractSuiteHeld('CASE_BYTE_LIMIT')
        if len((canonical(self._report)+'\n').encode())>self.config.max_report_bytes:raise ContractSuiteHeld('REPORT_BYTE_LIMIT')
        self.progress(self.last_report)

    def run(self):
        if self.used:raise ValueError('one contract-suite execution per instance; no refunded retry')
        self.used=True;cases=contract_registry.installed_cases()
        self._report={'runner':'policy_contract_suite_v1','status':'IN_PROGRESS','complete':False,'software_contract_suite_only':True,
            'qualification_eligible':False,'promotion_eligible':False,'physical_truth_verified':False,'independent_benchmark_qualified':False,
            'definition':self.definition.model_dump(mode='json'),'definition_sha256':digest(self.definition.model_dump(mode='json')),
            'configuration_sha256':digest(asdict(self.config)),'registry_sha256':digest(contract_registry.registry_record()),
            'planned_cases':len(cases),'reserved_attempts':0,'cases':[{'id':case.id,'status':'NOT_RUN'} for case in cases]}
        try:
            start=self.tick()
            self._gate(start)
            if len(cases)>self.config.max_cases:raise ContractSuiteHeld('CASE_BUDGET_INSUFFICIENT')
            implementation=implementation_sha256();self._report['implementation_sha256']=implementation;self._emit();self._gate(start)
            for index,case in enumerate(cases):
                self._gate(start);self._report['reserved_attempts']+=1
                row={'id':case.id,'status':'RUNNING','kind':case.kind,'input':asdict(case)}
                self._report['cases'][index]=row;self._emit();self._gate(start)
                expected=contract_registry.expected_result(case,self.definition)
                try:actual=contract_registry.execute_case(case,self.definition);reason=None
                except Exception:actual=None;reason='CASE_EXECUTION_ERROR'
                row.update(status='PASS' if actual==expected and reason is None else 'FAIL',expected=expected,actual=actual,reason=reason)
                if len((canonical(row)+'\n').encode())>self.config.max_case_report_bytes:raise ContractSuiteHeld('CASE_BYTE_LIMIT')
                self._gate(start);self._emit();self._gate(start)
            if implementation_sha256()!=implementation or digest(contract_registry.registry_record())!=self._report['registry_sha256']:raise ContractSuiteHeld('SOURCE_CHANGED')
            counts=Counter(row['status'] for row in self._report['cases'])
            if counts['PASS']+counts['FAIL']!=len(cases):raise ContractSuiteHeld('INCOMPLETE_CASES')
            final_report={**self.last_report,'status':'PASS' if not counts['FAIL'] else 'FAIL','complete':True,'counts':dict(counts)}
            if len((canonical(final_report)+'\n').encode())>self.config.max_report_bytes:raise ContractSuiteHeld('REPORT_BYTE_LIMIT')
            result=json.loads(canonical(final_report));self._gate(start)
            if implementation_sha256()!=implementation or digest(contract_registry.registry_record())!=self._report['registry_sha256']:raise ContractSuiteHeld('SOURCE_CHANGED')
            self._time_gate(start)
            self._report=final_report
            return result
        except (Exception,KeyboardInterrupt) as exc:
            reason=exc.reason if isinstance(exc,ContractSuiteHeld) else 'CANCELLED' if isinstance(exc,KeyboardInterrupt) else 'EXECUTION_OR_OUTPUT_UNAVAILABLE'
            self._report.update(status='HELD',complete=False,reason=reason)
            if isinstance(exc,ContractSuiteHeld):raise
            raise ContractSuiteHeld(reason) from exc
