import json
import pytest
from pydantic import ValidationError
from proofpack.evidence.export_models import ExportRequest,ExportTicketRequest
from proofpack.evidence.exports import InspectionExports


@pytest.mark.parametrize('ack',[1,False,'true',None])
def test_export_requires_actual_true_acknowledgment(ack):
    for model,body in [(ExportRequest,{'selected_asset_ids':[]}), (ExportTicketRequest,{})]:
        with pytest.raises(ValidationError):model.model_validate_json(json.dumps({**body,'historical_export_acknowledged':ack}))


def test_export_rejects_duplicate_excess_and_unknown_fields():
    for ids in [('a','a'),('a','b','c','d')]:
        with pytest.raises(ValidationError):ExportRequest(selected_asset_ids=ids,historical_export_acknowledged=True)
    with pytest.raises(ValidationError):ExportTicketRequest.model_validate_json('{"historical_export_acknowledged":true,"url":"https://example.invalid"}')


@pytest.mark.parametrize('name',['jobs_per_minute','job_lifetime_ms','lease_ms','page_size','max_scan_rows','max_records','max_assets','ticket_ms','download_ms','max_concurrent'])
def test_export_configuration_rejects_missing_capacity_bound_before_any_io(name):
    values=dict(jobs_per_minute=8,job_lifetime_ms=60000,lease_ms=15000,page_size=25,max_scan_rows=500,max_records=128,max_assets=3,ticket_ms=30000,download_ms=20000,max_concurrent=2)
    values[name]=0
    with pytest.raises(ValueError):InspectionExports(None,**values)
