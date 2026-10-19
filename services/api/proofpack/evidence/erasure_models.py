from pydantic import Field,model_validator
from proofpack.recipes.models import Contract,Identifier


class ErasurePreview(Contract):
    asset_ids:tuple[Identifier,...]=Field(min_length=1,max_length=16)

    @model_validator(mode='after')
    def unique(self):
        if len(set(self.asset_ids))!=len(self.asset_ids):raise ValueError('distinct selected assets required')
        return self


class ErasureConfirmation(Contract):
    preview_id:Identifier
    confirmed_digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    erase_asset_versions_acknowledged:bool
    understands_remaining_metadata_and_backups:bool

    @model_validator(mode='after')
    def explicit(self):
        if self.erase_asset_versions_acknowledged is not True or self.understands_remaining_metadata_and_backups is not True:
            raise ValueError('explicit irreversible denial and remaining-duty acknowledgments required')
        return self
