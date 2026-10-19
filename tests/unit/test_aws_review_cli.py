"""CLI size/failure closure and regional/provider-name format boundaries."""
import json
import pytest
from test_aws_review_pack import config,mod


def test_exact_input_size_limit_accepts_complete_json_and_rejects_one_extra_byte(tmp_path,monkeypatch,capsys):
    module=mod();monkeypatch.setattr(module,'ROOT',tmp_path)
    body=json.dumps(config()).encode();assert len(body)<65536
    source=tmp_path/'input.json';source.write_bytes(body+b' '*(65536-len(body)))
    assert module.main(['--config',str(source),'--output',str(tmp_path/'exact')])==0
    source.write_bytes(source.read_bytes()+b' ')
    assert module.main(['--config',str(source),'--output',str(tmp_path/'too-large')])==2
    assert not (tmp_path/'too-large').exists()
    assert 'No AWS action' in capsys.readouterr().err


def test_explicit_higher_declared_cost_region_is_not_silently_replaced():
    cfg=config();cfg.update(region='us-east-2',az_a='us-east-2a',az_b='us-east-2b')
    cfg['certificate_arn']=cfg['certificate_arn'].replace(':us-east-1:',':us-east-2:')
    pack=mod().prepare(cfg);cost=pack['cost-comparison.json']
    assert cost['selected_region']=='us-east-2' and cost['lower_declared_cost_region']=='us-east-1'
    assert pack['deployment-review.json']['existing_audit_trail']==cfg['cloudtrail_arn']
    assert pack['deployment-review.json']['deploy_authorized'] is False


def test_cli_write_failure_keeps_partial_payloads_but_no_manifest_or_private_error(tmp_path,monkeypatch,capsys):
    module=mod();monkeypatch.setattr(module,'ROOT',tmp_path);original=module._write_new
    def fail(path,payload):
        if path.name=='host.service':raise OSError('do-not-echo-private-error')
        return original(path,payload)
    monkeypatch.setattr(module,'_write_new',fail)
    source=tmp_path/'input.json';source.write_text(json.dumps(config()));out=tmp_path/'partial'
    assert module.main(['--config',str(source),'--output',str(out)])==2
    result=capsys.readouterr();assert result.out=='' and 'do-not-echo-private-error' not in result.err
    assert (out/'stack.template.json').is_file() and not (out/'manifest.json').exists()


def test_corrupt_completion_marker_is_removed_before_returning_success(tmp_path,monkeypatch):
    module=mod();monkeypatch.setattr(module,'ROOT',tmp_path);original=module._write_new;out=tmp_path/'pack'
    def corrupt(path,payload):
        result=original(path,payload)
        if path.name=='manifest.json':path.write_text('{"status":"corrupt"}')
        return result
    monkeypatch.setattr(module,'_write_new',corrupt)
    with pytest.raises(OSError):module.write_pack(config(),out)
    assert not (out/'manifest.json').exists()


def test_stack_slug_cannot_end_in_hyphen_and_produce_invalid_domain_names():
    cfg=config();cfg['stack_slug']='bad-'
    with pytest.raises(ValueError):mod().prepare(cfg)


def test_bucket_names_cannot_inherit_reserved_s3_alias_suffixes_from_slug():
    cfg=config();cfg['stack_slug']='my-s3alias'
    name=mod().prepare(cfg)['stack.template.json']['Resources']['EvidenceBucket']['Properties']['BucketName']
    assert name.endswith('-evidence') and not name.endswith('-s3alias') and len(name)<=63
