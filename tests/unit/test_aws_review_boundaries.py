"""Adversarial review-file consistency and explicit new-stack/AMI limits."""
from copy import deepcopy
import hashlib
import json
import pytest

from test_aws_review_pack import config,mod


def test_prepared_cost_inputs_are_snapshotted_not_aliased_to_mutable_caller():
    cfg=config();pack=mod().prepare(cfg);before=deepcopy(pack)
    cfg['costs']['regions']['us-east-1']['compute']='500.00'
    cfg['costs']['evidence_urls']['us-east-2']='changed-after-validation'
    assert pack==before


def test_plan_digest_binds_original_validated_input_even_if_caller_changes_during_write(tmp_path,monkeypatch):
    module=mod();monkeypatch.setattr(module,'ROOT',tmp_path);cfg=config()
    expected=hashlib.sha256(module._json(deepcopy(cfg))).hexdigest();original=module._write_new
    def mutate(path,payload):
        result=original(path,payload)
        if path.name=='stack.template.json':cfg['account_id']='111111111111'
        return result
    monkeypatch.setattr(module,'_write_new',mutate)
    manifest=module.write_pack(cfg,tmp_path/'pack')
    assert manifest['plan_sha256']==expected


@pytest.mark.parametrize('when',['before-manifest','during-manifest'])
def test_mid_write_file_mutation_cannot_leave_a_completed_manifest(tmp_path,monkeypatch,when):
    module=mod();monkeypatch.setattr(module,'ROOT',tmp_path);original=module._write_new;out=tmp_path/'pack'
    def mutate(path,payload):
        result=original(path,payload)
        if path.name==('operator-handoff.md' if when=='before-manifest' else 'manifest.json'):
            (path.parent/'stack.template.json').write_text('{"changed_after_its_first_readback":true}')
        return result
    monkeypatch.setattr(module,'_write_new',mutate)
    with pytest.raises(OSError):module.write_pack(config(),out)
    assert not (out/'manifest.json').exists()


def test_conditional_template_is_explicitly_create_only_not_an_update_safety_gate():
    pack=mod().prepare(config());review=pack['deployment-review.json']
    assert review['change_set_kind']=='CREATE_ONLY_DRAFT' and review['updates_supported'] is False
    assert 'changing conditions on an existing stack can delete resources' in pack['operator-handoff.md']


def test_pinned_ami_root_device_layout_remains_declared_and_unverified():
    pack=mod().prepare(config());review=pack['deployment-review.json']
    layout=pack['stack.template.json']['Resources']['HostLaunchTemplate']['Properties']['LaunchTemplateData']['BlockDeviceMappings']
    assert review['supported_ami_root_device']==layout[0]['DeviceName']=='/dev/xvda'
    assert review['ami_root_device_verified'] is False
    assert 'Hold if the actual AMI root device differs' in pack['operator-handoff.md']
