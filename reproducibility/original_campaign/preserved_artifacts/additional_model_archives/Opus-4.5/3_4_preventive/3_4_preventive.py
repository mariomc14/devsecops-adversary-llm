#!/usr/bin/env python3
"""
Security Chaos Engineering Experiment 3.4 - Preventive Probe
EC2 IMDS Protection Weakening Prevention Validation

Attack Chain:
- Node 1.3: Cloud Infrastructure Discovery (T1580)
- Node 2.3: Weaken IMDS Protections (T1562.001)
- Node 3.3: Credential Exfiltration via IMDS (T1552.005)

Preventive Controls Validated:
- IAM Deny policy blocks ec2:ModifyInstanceMetadataOptions
- IMDSv2 enforcement (HttpTokens=required)
- Hop limit restriction (HttpPutResponseHopLimit=1)

Installation:
    mkdir -p chaosaws/ec2
    touch chaosaws/__init__.py chaosaws/ec2/__init__.py
    cp sce_3_4_preventive.py chaosaws/ec2/
    pip install -e .
"""

import json
import logging
import os
import subprocess
import sys
import time
import traceback

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(funcName)s: %(message)s"
)
logger = logging.getLogger(__name__)

EXPERIMENT_TAG = "sce-3-4-preventive"
STACK_PREFIX = "sce-imds-prev"
SLA_TIMEOUT = 1800
POLL_INTERVAL = 30
MAX_RETRIES = 5

_state = {
    "stack_name": None,
    "instance_id": None,
    "attacker_role_arn": None,
    "region": None,
    "timestamp": None,
    "exp_tag": None,
    "results": {"step_1_3": None, "step_2_3": None, "step_3_3": None},
    "ready": False,
    "verified": False
}


def _get_boto3():
    """Get boto3, installing if needed."""
    try:
        import boto3
        return boto3
    except ImportError:
        logger.info("Installing boto3...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
        import boto3
        return boto3


def _cfn_template(tag):
    """Generate CloudFormation template."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 3.4 Preventive - IMDS Protection Test",
        "Parameters": {
            "Tag": {"Type": "String", "Default": tag}
        },
        "Resources": {
            "VPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport": True,
                    "Tags": [{"Key": "Name", "Value": {"Fn::Sub": "${Tag}-vpc"}},
                             {"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "CidrBlock": "10.0.1.0/24",
                    "Tags": [{"Key": "Name", "Value": {"Fn::Sub": "${Tag}-subnet"}},
                             {"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            "SG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE Isolated SG",
                    "VpcId": {"Ref": "VPC"},
                    "SecurityGroupEgress": [{"IpProtocol": "-1", "CidrIp": "127.0.0.1/32"}],
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            "InstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Fn::Sub": "${Tag}-inst"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}]
                    },
                    "Policies": [{"PolicyName": "Min", "PolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": ["ec2:DescribeTags"], "Resource": "*"}]}}],
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            "InstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": {"Fn::Sub": "${Tag}-prof"},
                    "Roles": [{"Ref": "InstanceRole"}]
                }
            },
            "AttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Fn::Sub": "${Tag}-atk"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}}, "Action": "sts:AssumeRole", "Condition": {"StringEquals": {"sts:ExternalId": {"Ref": "Tag"}}}}]
                    },
                    "Policies": [{
                        "PolicyName": "Atk",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {"Sid": "Allow", "Effect": "Allow", "Action": ["ec2:DescribeInstances", "ec2:DescribeInstanceAttribute"], "Resource": "*"},
                                {"Sid": "Deny", "Effect": "Deny", "Action": ["ec2:ModifyInstanceMetadataOptions"], "Resource": "*"}
                            ]
                        }
                    }],
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": ["InstanceProfile"],
                "Properties": {
                    "ImageId": {"Fn::Sub": "{{resolve:ssm:/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2}}"},
                    "InstanceType": "t3.micro",
                    "SubnetId": {"Ref": "Subnet"},
                    "SecurityGroupIds": [{"Ref": "SG"}],
                    "IamInstanceProfile": {"Ref": "InstanceProfile"},
                    "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1, "HttpEndpoint": "enabled"},
                    "Tags": [{"Key": "Name", "Value": {"Fn::Sub": "${Tag}-target"}}, {"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            }
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "Instance"}},
            "AttackerRoleArn": {"Value": {"Fn::GetAtt": ["AttackerRole", "Arn"]}}
        }
    })


def _wait(check_fn, desc, timeout=SLA_TIMEOUT, interval=POLL_INTERVAL):
    """Poll until condition or timeout."""
    start = time.monotonic()
    attempt = 0
    while (time.monotonic() - start) < timeout:
        try:
            if check_fn():
                logger.info(f"✓ {desc} ({time.monotonic()-start:.1f}s)")
                return True
        except Exception as e:
            logger.debug(f"Check {desc}: {e}")
        attempt += 1
        sleep = min(interval * (1.2 ** min(attempt, 5)), 120)
        logger.info(f"Waiting: {desc} [{time.monotonic()-start:.0f}s/{timeout}s]")
        time.sleep(sleep)
    logger.error(f"Timeout: {desc}")
    return False


def steady_state():
    """Deploy experiment infrastructure."""
    global _state
    logger.info("=" * 50)
    logger.info("STEADY STATE: SCE 3.4 Preventive")
    logger.info("=" * 50)
    
    try:
        boto3 = _get_boto3()
        ts = int(time.time())
        stack = f"{STACK_PREFIX}-{ts}"
        tag = f"{EXPERIMENT_TAG}-{ts}"
        
        _state.update({"timestamp": ts, "stack_name": stack, "exp_tag": tag})
        
        session = boto3.session.Session()
        region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        _state["region"] = region
        
        logger.info(f"Stack: {stack} | Region: {region}")
        
        cfn = boto3.client("cloudformation", region_name=region)
        
        exists = False
        try:
            r = cfn.describe_stacks(StackName=stack)
            logger.warning(f"Stack exists: {r['Stacks'][0]['StackStatus']}")
            exists = True
        except cfn.exceptions.ClientError as e:
            if "does not exist" not in str(e):
                raise
        
        if not exists:
            for i in range(MAX_RETRIES):
                try:
                    cfn.create_stack(
                        StackName=stack,
                        TemplateBody=_cfn_template(tag),
                        Parameters=[{"ParameterKey": "Tag", "ParameterValue": tag}],
                        Capabilities=["CAPABILITY_NAMED_IAM"],
                        Tags=[{"Key": "Experiment", "Value": EXPERIMENT_TAG}, {"Key": "Timestamp", "Value": str(ts)}],
                        OnFailure="DELETE",
                        TimeoutInMinutes=15
                    )
                    logger.info("Stack creation started")
                    break
                except cfn.exceptions.AlreadyExistsException:
                    break
                except Exception as e:
                    logger.error(f"Attempt {i+1}: {e}")
                    if i < MAX_RETRIES - 1:
                        time.sleep(10 * (i + 1))
                    else:
                        raise
        
        def stack_ok():
            try:
                r = cfn.describe_stacks(StackName=stack)
                s = r["Stacks"][0]["StackStatus"]
                if s == "CREATE_COMPLETE":
                    return True
                if "FAILED" in s or "ROLLBACK" in s:
                    raise Exception(f"Stack failed: {s}")
                return False
            except cfn.exceptions.ClientError as e:
                if "does not exist" in str(e):
                    return False
                raise
        
        if not _wait(stack_ok, "stack creation", 900, 15):
            raise Exception("Stack timeout")
        
        r = cfn.describe_stacks(StackName=stack)
        outputs = {o["OutputKey"]: o["OutputValue"] for o in r["Stacks"][0].get("Outputs", [])}
        _state["instance_id"] = outputs.get("InstanceId")
        _state["attacker_role_arn"] = outputs.get("AttackerRoleArn")
        
        logger.info(f"Instance: {_state['instance_id']}")
        logger.info(f"Attacker Role: {_state['attacker_role_arn']}")
        
        ec2 = boto3.client("ec2", region_name=region)
        
        def inst_running():
            r = ec2.describe_instances(InstanceIds=[_state["instance_id"]])
            return r["Reservations"][0]["Instances"][0]["State"]["Name"] == "running" if r["Reservations"] else False
        
        if not _wait(inst_running, "instance running", 300, 10):
            raise Exception("Instance timeout")
        
        logger.info("IAM propagation wait (30s)...")
        time.sleep(30)
        
        _state["ready"] = True
        logger.info("STEADY STATE COMPLETE")
        return True
        
    except Exception as e:
        logger.error(f"Steady state failed: {e}")
        logger.error(traceback.format_exc())
        return False


def attack():
    """Execute attack steps."""
    global _state
    logger.info("=" * 50)
    logger.info("ATTACK: SCE 3.4 Preventive")
    logger.info("=" * 50)
    
    if not _state.get("ready"):
        logger.error("Not ready")
        return False
    
    try:
        boto3 = _get_boto3()
        region = _state["region"]
        inst_id = _state["instance_id"]
        role_arn = _state["attacker_role_arn"]
        tag = _state["exp_tag"]
        
        sts = boto3.client("sts", region_name=region)
        creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="SCE-Atk", ExternalId=tag, DurationSeconds=900)["Credentials"]
        
        atk_ec2 = boto3.client("ec2", region_name=region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"])
        
        # Step 1.3: Discovery
        logger.info("-" * 30)
        logger.info("Step 1.3: Discovery (T1580)")
        try:
            r = atk_ec2.describe_instances(InstanceIds=[inst_id])
            md = r["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
            _state["results"]["step_1_3"] = {"success": True, "http_tokens": md.get("HttpTokens"), "hop_limit": md.get("HttpPutResponseHopLimit")}
            logger.info(f"Discovery OK: HttpTokens={md.get('HttpTokens')}, HopLimit={md.get('HttpPutResponseHopLimit')}")
        except Exception as e:
            _state["results"]["step_1_3"] = {"success": False, "error": str(e)}
            logger.error(f"Discovery failed: {e}")
        
        # Step 2.3: Modify IMDS (expected: blocked)
        logger.info("-" * 30)
        logger.info("Step 2.3: Modify IMDS (T1562.001) - EXPECT BLOCKED")
        try:
            atk_ec2.modify_instance_metadata_options(InstanceId=inst_id, HttpTokens="optional", HttpPutResponseHopLimit=2, HttpEndpoint="enabled")
            _state["results"]["step_2_3"] = {"success": True, "blocked": False, "modified": True}
            logger.warning("IMDS MODIFIED - CONTROL FAILED!")
        except atk_ec2.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            _state["results"]["step_2_3"] = {"success": False, "blocked": code in ["UnauthorizedOperation", "AccessDenied"], "modified": False, "code": code}
            if _state["results"]["step_2_3"]["blocked"]:
                logger.info(f"IMDS modification BLOCKED: {code}")
            else:
                logger.warning(f"Unexpected error: {code}")
        except Exception as e:
            _state["results"]["step_2_3"] = {"success": False, "blocked": False, "modified": False, "error": str(e)}
            logger.error(f"Error: {e}")
        
        # Step 3.3: Verify IMDS state
        logger.info("-" * 30)
        logger.info("Step 3.3: Verify IMDS (T1552.005)")
        ec2 = boto3.client("ec2", region_name=region)
        r = ec2.describe_instances(InstanceIds=[inst_id])
        md = r["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
        _state["results"]["step_3_3"] = {
            "http_tokens": md.get("HttpTokens"),
            "hop_limit": md.get("HttpPutResponseHopLimit"),
            "imdsv2": md.get("HttpTokens") == "required",
            "hop_ok": md.get("HttpPutResponseHopLimit") == 1
        }
        logger.info(f"IMDS: HttpTokens={md.get('HttpTokens')}, HopLimit={md.get('HttpPutResponseHopLimit')}")
        
        logger.info("ATTACK COMPLETE")
        return True
        
    except Exception as e:
        logger.error(f"Attack failed: {e}")
        logger.error(traceback.format_exc())
        return False


def hypothesis_verification():
    """Verify preventive controls."""
    global _state
    logger.info("=" * 50)
    logger.info("VERIFICATION: SCE 3.4 Preventive")
    logger.info("=" * 50)
    
    r = _state.get("results", {})
    
    checks = {
        "imds_blocked": r.get("step_2_3", {}).get("blocked", False) and not r.get("step_2_3", {}).get("modified", True),
        "imdsv2_ok": r.get("step_3_3", {}).get("imdsv2", False),
        "hop_ok": r.get("step_3_3", {}).get("hop_ok", False)
    }
    
    for k, v in checks.items():
        logger.info(f"{'✓' if v else '✗'} {k}: {v}")
    
    ok = all(checks.values())
    _state["verified"] = ok
    
    logger.info("=" * 50)
    logger.info(f"RESULT: {'PASS' if ok else 'FAIL'}")
    logger.info("=" * 50)
    
    return ok


def rollback():
    """Delete CloudFormation stack."""
    global _state
    logger.info("=" * 50)
    logger.info("ROLLBACK: SCE 3.4 Preventive")
    logger.info("=" * 50)
    
    stack = _state.get("stack_name")
    if not stack:
        logger.info("No stack to delete")
        return True
    
    try:
        boto3 = _get_boto3()
        region = _state.get("region", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
        cfn = boto3.client("cloudformation", region_name=region)
        
        try:
            cfn.delete_stack(StackName=stack)
            logger.info(f"Deleting: {stack}")
        except cfn.exceptions.ClientError as e:
            if "does not exist" in str(e):
                logger.info("Stack already deleted")
                return True
            raise
        
        def deleted():
            try:
                r = cfn.describe_stacks(StackName=stack)
                s = r["Stacks"][0]["StackStatus"]
                return s == "DELETE_COMPLETE"
            except cfn.exceptions.ClientError as e:
                if "does not exist" in str(e):
                    return True
                raise
        
        if _wait(deleted, "stack deletion", 600, 15):
            logger.info("ROLLBACK COMPLETE")
            return True
        return False
        
    except Exception as e:
        logger.error(f"Rollback error: {e}")
        return False


def run():
    """Standalone runner."""
    result = False
    try:
        if steady_state() and attack():
            result = hypothesis_verification()
    finally:
        rollback()
    logger.info(f"FINAL: {'PASS' if result else 'FAIL'}")
    return result


if __name__ == "__main__":
    sys.exit(0 if run() else 1)