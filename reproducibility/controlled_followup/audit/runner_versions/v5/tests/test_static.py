import importlib.util
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('campaign_runner',ROOT/'campaign_runner.py')
mod=importlib.util.module_from_spec(spec); sys.modules[spec.name]=mod; spec.loader.exec_module(mod)

NETWORK={"vpc_id":"vpc-0123456789abcdef0","subnet_id":"subnet-0123456789abcdef0","security_group_id":"sg-0123456789abcdef0"}

def test_schedule():
    rows=mod.load_schedule(ROOT/'schedule.csv')
    assert len(rows)==80
    assert len({(r['repetition'],r['task'],r['model'],r['condition']) for r in rows})==80
    assert {r['model'] for r in rows}=={'haiku-4.5','sonnet-4.6'}

def test_no_feedback_context():
    previous={'python':'x','json':'{}','execution':'log','qpost':'Q_post = 0'}
    assert mod.feedback_context(previous,'chaos_adt_no_feedback')==''
    assert 'Previous execution evidence' in mod.feedback_context(previous,'chaos_adt_feedback')

def test_cloudformation_safe_sanitize():
    assert mod.sanitize('cn1_p')=='cn1-p'
    assert '_' not in mod.sanitize('cn2_d')

def test_prompt_has_frozen_controls():
    task=mod.read_yaml(ROOT/'tasks'/'cn1_p.yaml')
    template=(ROOT.parent/'automate'/'inputs'/'template.json').read_text()
    p=mod.generation_prompt(task,'chaos_adt_feedback',template,'cvr2-test',None,NETWORK)
    assert 'us-east-1' in p
    assert 'cvr2-test-' in p
    assert NETWORK['subnet_id'] in p
    assert NETWORK['security_group_id'] in p
    assert 'Do not create VPCs' in p

def test_cn2_prompt_requires_event_history_not_trail():
    task=mod.read_yaml(ROOT/'tasks'/'cn2_d.yaml')
    template=(ROOT.parent/'automate'/'inputs'/'template.json').read_text()
    p=mod.generation_prompt(task,'chaos_adt_feedback',template,'cvr2-test',None,NETWORK)
    assert 'lookup_events()' in p
    assert 'Do NOT create a CloudTrail trail' in p

def test_validator_accepts_minimal_safe_shape():
    runner=object.__new__(mod.CampaignRunner)
    py=f'''\nREGION="us-east-1"\nPREFIX="cvr2-test"\nSUBNET="{NETWORK['subnet_id']}"\nSG="{NETWORK['security_group_id']}"\ndef steady_state():\n    cfn.create_stack(StackName=PREFIX+"-1")\ndef attack():\n    return True\ndef hypothesis_verification():\n    return True\ndef rollback():\n    cfn.delete_stack(StackName=PREFIX+"-1")\n'''
    js='''{"steady-state-hypothesis":{"probes":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"hypothesis_verification"}}]},"method":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"steady_state"}},{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"attack"}}],"rollbacks":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"rollback"}}]}'''
    task=mod.read_yaml(ROOT/'tasks'/'cn1_p.yaml')
    report=mod.CampaignRunner.technical_validate(runner,py,js,'cvr2-test','cvr2_test',task,NETWORK)
    assert report['passed'], report

def test_comment_words_do_not_auto_reject():
    runner=object.__new__(mod.CampaignRunner)
    py=f'''\nREGION="us-east-1"\nPREFIX="cvr2-test"\nSUBNET="{NETWORK['subnet_id']}"\nSG="{NETWORK['security_group_id']}"\n# simulated attacker role - descriptive comment only\ndef steady_state():\n    cfn.create_stack(StackName=PREFIX+"-1")\ndef attack():\n    return True\ndef hypothesis_verification():\n    return True\ndef rollback():\n    cfn.delete_stack(StackName=PREFIX+"-1")\n'''
    js='''{"steady-state-hypothesis":{"probes":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"hypothesis_verification"}}]},"method":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"steady_state"}},{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"attack"}}],"rollbacks":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"rollback"}}]}'''
    task=mod.read_yaml(ROOT/'tasks'/'cn1_p.yaml')
    report=mod.CampaignRunner.technical_validate(runner,py,js,'cvr2-test','cvr2_test',task,NETWORK)
    assert report['passed'], report
    assert any('simulated' in w for w in report['warnings'])

def test_forbidden_resource_name_in_comment_or_docstring_does_not_reject():
    runner=object.__new__(mod.CampaignRunner)
    py=f'''\nREGION="us-east-1"\nPREFIX="cvr2-test"\nSUBNET="{NETWORK['subnet_id']}"\nSG="{NETWORK['security_group_id']}"\n# AWS::EC2::VPC is forbidden for per-attempt creation, descriptive comment only\ndef steady_state():\n    """Do not create AWS::S3::Bucket; descriptive docstring only."""\n    cfn.create_stack(StackName=PREFIX+"-1")\ndef attack():\n    return True\ndef hypothesis_verification():\n    return True\ndef rollback():\n    cfn.delete_stack(StackName=PREFIX+"-1")\n'''
    js='''{"steady-state-hypothesis":{"probes":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"hypothesis_verification"}}]},"method":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"steady_state"}},{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"attack"}}],"rollbacks":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"rollback"}}]}'''
    task=mod.read_yaml(ROOT/'tasks'/'cn1_p.yaml')
    report=mod.CampaignRunner.technical_validate(runner,py,js,'cvr2-test','cvr2_test',task,NETWORK)
    assert report['passed'], report


def test_forbidden_resource_name_in_executable_template_is_rejected():
    runner=object.__new__(mod.CampaignRunner)
    py=f'''\nREGION="us-east-1"\nPREFIX="cvr2-test"\nSUBNET="{NETWORK['subnet_id']}"\nSG="{NETWORK['security_group_id']}"\nTEMPLATE={{"Resources":{{"BadVpc":{{"Type":"AWS::EC2::VPC"}}}}}}\ndef steady_state():\n    cfn.create_stack(StackName=PREFIX+"-1", TemplateBody=str(TEMPLATE))\ndef attack():\n    return True\ndef hypothesis_verification():\n    return True\ndef rollback():\n    cfn.delete_stack(StackName=PREFIX+"-1")\n'''
    js='''{"steady-state-hypothesis":{"probes":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"hypothesis_verification"}}]},"method":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"steady_state"}},{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"attack"}}],"rollbacks":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"rollback"}}]}'''
    task=mod.read_yaml(ROOT/'tasks'/'cn1_p.yaml')
    report=mod.CampaignRunner.technical_validate(runner,py,js,'cvr2-test','cvr2_test',task,NETWORK)
    assert not report['passed']
    assert any('aws::ec2::vpc' in e.lower() for e in report['errors'])


def test_v3_source_has_no_preserve_and_resample_resume_path():
    source=(ROOT/'campaign_runner.py').read_text(encoding='utf-8')
    assert 'PRESERVE interrupted attempt' not in source
    assert '_preserved_' not in source
    assert 'REUSE archived Bedrock candidate' in source
    assert 'Stored Q_pre response is not parseable; preserved without re-querying' in source
    assert 'Stored Q_post response is not parseable; preserved without re-querying' in source


# ---------------------------------------------------------------------------
# v4 tests
# ---------------------------------------------------------------------------
import json as _json
import tempfile as _tempfile

_MANIFEST='''{"steady-state-hypothesis":{"probes":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"hypothesis_verification"}}]},"method":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"steady_state"}},{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"attack"}}],"rollbacks":[{"provider":{"type":"python","module":"chaosaws.ec2.cvr2_test","func":"rollback"}}]}'''

def _validate_template(resources_and_parameters):
    runner=object.__new__(mod.CampaignRunner)
    py=f'''\nREGION="us-east-1"\nPREFIX="cvr2-test"\nSUBNET="{NETWORK['subnet_id']}"\nSG="{NETWORK['security_group_id']}"\nTEMPLATE={resources_and_parameters}\ndef steady_state():\n    cfn.create_stack(StackName=PREFIX+"-1", TemplateBody=str(TEMPLATE))\ndef attack():\n    return True\ndef hypothesis_verification():\n    return True\ndef rollback():\n    cfn.delete_stack(StackName=PREFIX+"-1")\n'''
    task=mod.read_yaml(ROOT/'tasks'/'cn1_p.yaml')
    return mod.CampaignRunner.technical_validate(runner,py,_MANIFEST,'cvr2-test','cvr2_test',task,NETWORK)

def test_v4_typed_network_parameters_are_accepted():
    # Referencing the fixed network through CloudFormation parameter types creates nothing.
    report=_validate_template({"Parameters":{"Vpc":{"Type":"AWS::EC2::VPC::Id"},
                                             "Subnet":{"Type":"AWS::EC2::Subnet::Id"},
                                             "Sg":{"Type":"AWS::EC2::SecurityGroup::Id"}},
                               "Resources":{"Inst":{"Type":"AWS::EC2::Instance"}}})
    assert report['passed'], report

def test_v4_forbidden_resources_still_rejected():
    for rtype in ["AWS::EC2::VPC","AWS::EC2::Subnet","AWS::EC2::SecurityGroup","AWS::EC2::SecurityGroupIngress",
                  "AWS::S3::Bucket","AWS::CloudTrail::Trail","AWS::Config::ConfigRule","AWS::IAM::User"]:
        report=_validate_template({"Resources":{"X":{"Type":rtype}}})
        assert not report['passed'], rtype

def test_v4_attempt_event_log_is_append_only():
    with _tempfile.TemporaryDirectory() as d:
        d=Path(d)
        mod.append_attempt_event(d,"infrastructure_error",error="first")
        mod.append_attempt_event(d,"infrastructure_error",error="second")
        events=mod.read_attempt_events(d)
        assert [e['error'] for e in events]==['first','second']
        assert all('timestamp' in e for e in events)

def test_v4_failed_call_marker_does_not_mask_interrupted_retry():
    # call 1 fails -> retry allowed; the retry is interrupted (no response, no failure record)
    # -> the next resume must report an ambiguous state instead of calling the model again.
    with _tempfile.TemporaryDirectory() as d:
        d=Path(d)
        assert mod.begin_model_call(d,"generation","model-x") is True
        mod.record_model_call_failure(d,"generation",RuntimeError("throttled"))
        assert mod.begin_model_call(d,"generation","model-x") is True    # retry after a recorded failure
        assert not (d/"generation_call_failed.json").exists()
        assert mod.begin_model_call(d,"generation","model-x") is False   # retry was interrupted -> ambiguous
        names=[e['event'] for e in mod.read_attempt_events(d)]
        assert names==['generation_call_started','generation_call_failed','generation_call_retry','generation_call_started']

def test_v4_attempt_result_has_audit_counters():
    fields=set(mod.AttemptResult.__dataclass_fields__)
    assert {'resume_count','model_call_retries','infrastructure_errors'}<=fields
    assert mod.RUNNER_REVISION.startswith('v5')


# ---------------------------------------------------------------------------
# v5 tests
# ---------------------------------------------------------------------------
from botocore.exceptions import WaiterError as _WaiterError

def _validate_cn2(lookup_line):
    runner=object.__new__(mod.CampaignRunner)
    py=f'''\nREGION="us-east-1"\nPREFIX="cvr2-test"\nSUBNET="{NETWORK['subnet_id']}"\nSG="{NETWORK['security_group_id']}"\ndef steady_state():\n    cfn.create_stack(StackName=PREFIX+"-1")\ndef attack():\n    return True\ndef hypothesis_verification():\n    {lookup_line}\n    return False\ndef rollback():\n    cfn.delete_stack(StackName=PREFIX+"-1")\n'''
    task=mod.read_yaml(ROOT/'tasks'/'cn2_d.yaml')
    return mod.CampaignRunner.technical_validate(runner,py,_MANIFEST,'cvr2-test','cvr2_test',task,NETWORK)

def test_v5_cn2_lookup_events_direct_call_accepted():
    report=_validate_cn2('ct.lookup_events(LookupAttributes=[])')
    assert report['passed'], report

def test_v5_cn2_lookup_events_paginator_accepted():
    # get_paginator("lookup_events") issues the same CloudTrail LookupEvents API call page by page.
    report=_validate_cn2('pages=ct.get_paginator("lookup_events").paginate(LookupAttributes=[])')
    assert report['passed'], report
    assert report['observed_paginated_operations']==['lookup_events']

def test_v5_cn2_without_lookup_events_still_rejected():
    for line in ['pages=ct.get_paginator("describe_trails").paginate()', 'x="lookup_events"', 'pass']:
        report=_validate_cn2(line)
        assert any('lookup_events' in e for e in report['errors']), line

_IAM_LENGTH_ERROR=("Resource handler returned message: \"1 validation error detected: Value at 'roleName' failed to satisfy "
                   "constraint: Member must have length less than or equal to 64 (Service: Iam, Status Code: 400)\"")

class _FakeDeleteFailedCfn:
    """A per-attempt stack stuck in DELETE_FAILED because of one resource with the given event history."""
    def __init__(self, events):
        self.stack="cvr2-test-a01-20261115000000"; self.events=events; self.deleted=False; self.delete_calls=[]
    def list_stacks(self, **kw):
        return {"StackSummaries": [] if self.deleted else [{"StackName":self.stack,"StackStatus":"DELETE_FAILED"}]}
    def delete_stack(self, StackName, RetainResources=None):
        self.delete_calls.append(RetainResources)
        if RetainResources: self.deleted=True
    def get_waiter(self, name):
        cfn=self
        class _W:
            def wait(self, StackName, WaiterConfig):
                if not cfn.deleted: raise _WaiterError("StackDeleteComplete","terminal failure state: DELETE_FAILED",{})
        return _W()
    def describe_stacks(self, StackName):
        return {"Stacks":[{"StackName":StackName,"StackStatus":"DELETE_FAILED"}]}
    def describe_stack_resources(self, StackName):
        return {"StackResources":[{"LogicalResourceId":"Role","ResourceType":"AWS::IAM::Role",
                                   "PhysicalResourceId":"r"*73,"ResourceStatus":"DELETE_FAILED"}]}
    def get_paginator(self, name):
        cfn=self
        class _P:
            def paginate(self, StackName):
                return [{"StackEvents":[dict(LogicalResourceId="Role",**e) for e in cfn.events]}]
        return _P()

def _cleanup_with(events):
    runner=object.__new__(mod.CampaignRunner)
    runner.cfg={"execution":{"cleanup_wait_seconds":1,"cleanup_poll_seconds":1}}
    runner.cfn=_FakeDeleteFailedCfn(events)
    with _tempfile.TemporaryDirectory() as d:
        d=Path(d)
        report=runner.cleanup_stacks("cvr2-test-a01", d/"cleanup_report.json", d)
        events_logged=[e['event'] for e in mod.read_attempt_events(d)]
    return report, runner.cfn.delete_calls, events_logged

def test_v5_cleanup_retains_resource_that_was_never_created():
    report, calls, logged=_cleanup_with([
        {"ResourceStatus":"CREATE_IN_PROGRESS","ResourceStatusReason":None},
        {"ResourceStatus":"CREATE_FAILED","ResourceStatusReason":_IAM_LENGTH_ERROR},
        {"ResourceStatus":"DELETE_FAILED","ResourceStatusReason":_IAM_LENGTH_ERROR},
    ])
    assert report['clean'], report
    assert calls==[None,["Role"]]
    assert report['retained_never_created'][0]['logical_id']=="Role"
    assert logged==['cleanup_retained_never_created_resources']

def test_v5_cleanup_still_halts_when_resource_may_exist():
    cases={
        "resource was created": [
            {"ResourceStatus":"CREATE_COMPLETE","ResourceStatusReason":None},
            {"ResourceStatus":"DELETE_FAILED","ResourceStatusReason":"Cannot delete entity, must detach all policies first. (Service: Iam, Status Code: 409)"}],
        "creation failed for another reason": [
            {"ResourceStatus":"CREATE_FAILED","ResourceStatusReason":"Rate exceeded"},
            {"ResourceStatus":"DELETE_FAILED","ResourceStatusReason":_IAM_LENGTH_ERROR}],
        "deletion failed for another reason": [
            {"ResourceStatus":"CREATE_FAILED","ResourceStatusReason":_IAM_LENGTH_ERROR},
            {"ResourceStatus":"DELETE_FAILED","ResourceStatusReason":"Access denied"}],
    }
    for name, events in cases.items():
        report, calls, logged=_cleanup_with(events)
        assert not report['clean'], name
        assert calls==[None], name           # never retried with RetainResources
        assert logged==[], name
