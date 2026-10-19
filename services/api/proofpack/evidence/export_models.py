from pydantic import Field,model_validator
from proofpack.recipes.models import Contract,Identifier


class ExportRequest(Contract):
    selected_asset_ids:tuple[Identifier,...]=Field(max_length=3)
    historical_export_acknowledged:bool

    @model_validator(mode='after')
    def reviewed(self):
        if len(set(self.selected_asset_ids))!=len(self.selected_asset_ids) or self.historical_export_acknowledged is not True:
            raise ValueError('distinct selected assets and historical acknowledgment required')
        return self


class ExportTicketRequest(Contract):
    historical_export_acknowledged:bool

    @model_validator(mode='after')
    def reviewed(self):
        if self.historical_export_acknowledged is not True:raise ValueError('historical acknowledgment required')
        return self
