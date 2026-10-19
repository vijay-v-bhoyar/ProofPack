from typing import Annotated,Literal

from pydantic import Field,model_validator
from proofpack.recipes.models import Contract,Identifier
from proofpack.verifier.core import Finding


class RecipeCase(Contract):
    asset_id:Identifier
    kind:Literal['complete','incorrect','challenge']
    expected_findings:tuple[Finding,...]=Field(min_length=1,max_length=4)
    expected_counts:tuple[Annotated[int,Field(ge=0,le=30)],...]=Field(min_length=1,max_length=4)

    @model_validator(mode='after')
    def coherent(self):
        if len(self.expected_counts)!=len(self.expected_findings):raise ValueError('one count/finding per constraint required')
        if self.kind=='complete' and any(f!=Finding.SATISFIED for f in self.expected_findings):raise ValueError('complete case must expect satisfied constraints')
        if self.kind=='incorrect' and Finding.VIOLATED not in self.expected_findings:raise ValueError('incorrect case must expect a violation')
        if self.kind=='challenge' and Finding.UNOBSERVABLE not in self.expected_findings:raise ValueError('challenge must expect uncertainty')
        return self


class RecipeQualificationRequest(Contract):
    cases:tuple[RecipeCase,...]=Field(min_length=3,max_length=8)

    @model_validator(mode='after')
    def coverage(self):
        if {c.kind for c in self.cases}!={'complete','incorrect','challenge'}:raise ValueError('complete, incorrect and challenge coverage required')
        if len({c.asset_id for c in self.cases})!=len(self.cases):raise ValueError('distinct case assets required')
        return self
