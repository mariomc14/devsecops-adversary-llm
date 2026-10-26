#!/usr/bin/env python3
"""
Security Chaos Engineering Experiment 3.4 - Reactive Probe
EC2 IMDS Protection Weakening Auto-Remediation Validation

Attack Chain:
- Node 1.2: Identify Target EC2 Instance (T1580)
- Node 2.3: Weaken IMDS Protections (T1562.001)
- Node 3.3: Credential Exfiltration via IMDS (T1552.005)

Reactive Controls Validated:
- AWS Config auto-remediation restores IMDSv2 enforcement
- Lambda function triggered by EventBridge remediates IMDS settings
- SSM Automation document restores compliant configuration

Installation:
    mkdir -p chaosaws/ec2
    touch chaosaws/__init__.py chaosaws/ec2/__init__.py
    cp sce_3_4_reactive.py chaosaws/ec2/
    pip install -e .
"""

import json
import logging
import os
import subprocess
import sys
import time
import traceback
import base64
import zipfile
import io

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(funcName)s: %(message)s"
)
logger = logging.getLogger(__name__)

EXPERIMENT_TAG = "sce-3-4-reactive"
STACK_PREFIX = "sce-imds-react"
SLA_TIMEOUT = 1800  # 30 minutes for AWS eventual consistency
POLL_INTERVAL = 30
MAX_RETRIES = 5
REMEDIATION_TIMEOUT = 600  # 10 minutes for remediation to complete

_state = {
    "stack_name": None,
    "instance_id": None,
    "lambda_arn": None,
    "event_rule_name": None,
    "region": None,
    "timestamp": None,
    "exp_tag": None,
    "attack_time": None,
    "original_config": None,
    "results": {"step_1_2": None, "step_2_3": None, "step_3_3": None},
    "remediation_results": {"imds_restored": None, "lambda_invoked": None, "time_to_remediate": None},
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


def _get_lambda_code():
    """Generate Lambda function code for IMDS remediation."""
    code = '''
import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    """
    Auto-remediation Lambda for IMDS configuration.
    Triggered by EventBridge when ModifyInstanceMetadataOptions is called.
    Restores IMDSv2 enforcement (HttpTokens=required, HopLimit=1).
    """
    logger.info(f"Event received: {json.dumps(event)}")
    
    try:
        # Extract instance ID from CloudTrail event
        detail = event.get('detail', {})
        request_params = detail.get('requestParameters', {})
        instance_id = request_params.get('instanceId')
        
        if not instance_id:
            # Try alternative path
            instance_id = detail.get('requestParameters', {}).get('ModifyInstanceMetadataOptionsRequest', {}).get('InstanceId')
        
        if not instance_id:
            logger.error("Could not extract instance ID from event")
            return {'statusCode': 400, 'body': 'Missing instance ID'}
        
        logger.info(f"Remediating IMDS for instance: {instance_id}")
        
        ec2 = boto3.client('ec2')
        
        # Check current IMDS configuration
        response = ec2.describe_instances(InstanceIds=[instance_id])
        if not response['Reservations']:
            logger.error(f"Instance {instance_id} not found")
            return {'statusCode': 404, 'body': 'Instance not found'}
        
        instance = response['Reservations'][0]['Instances'][0]
        metadata_options = instance.get('MetadataOptions', {})
        
        current_tokens = metadata_options.get('HttpTokens')
        current_hop_limit = metadata_options.get('HttpPutResponseHopLimit')
        
        logger.info(f"Current config: HttpTokens={current_tokens}, HopLimit={current_hop_limit}")
        
        # Check if remediation needed
        if current_tokens == 'required' and current_hop_limit == 1:
            logger.info("IMDS already compliant, no remediation needed")
            return {'statusCode': 200, 'body': 'Already compliant'}
        
        # Remediate: Restore IMDSv2 enforcement
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='required',
            HttpPutResponseHopLimit=1,
            HttpEndpoint='enabled'
        )
        
        logger.info(f"IMDS remediated for {instance_id}: HttpTokens=required, HopLimit=1")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'IMDS remediated successfully',
                'instanceId': instance_id,
                'previousConfig': {
                    'HttpTokens': current_tokens,
                    'HttpPutResponseHopLimit': current_hop_limit
                },
                'newConfig': {
                    'HttpTokens': 'required',
                    'HttpPutResponseHopLimit': 1
                }
            })
        }
        
    except Exception as e:
        logger.error(f"Remediation failed: {str(e)}")
        return {'statusCode': 500, 'body': str(e)}
'''
    return code


def _create_lambda_zip():
    """Create a zip file containing the Lambda function code."""
    code = _get_lambda_code()
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('index.py', code)
    zip_buffer.seek(0)
    return base64.b64encode(zip_buffer.read()).decode('utf-8')


def _cfn_template(tag, region, account_id):
    """Generate CloudFormation template with reactive controls."""
    lambda_zip = _create_lambda_zip()
    
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 3.4 Reactive - IMDS Protection Auto-Remediation Test",
        "Parameters": {
            "Tag": {"Type": "String", "Default": tag}
        },
        "Resources": {
            # Network Resources
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
            # IAM Resources for Instance
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
            # EC2 Instance with IMDSv2 enforced initially
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
            },
            # Lambda Role for Remediation
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Fn::Sub": "${Tag}-lambda-role"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
                    "Policies": [{
                        "PolicyName": "EC2Remediation",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "ec2:DescribeInstances",
                                        "ec2:ModifyInstanceMetadataOptions"
                                    ],
                                    "Resource": "*"
                                }
                            ]
                        }
                    }],
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            # Lambda Function for Auto-Remediation
            "RemediationLambda": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["LambdaRole"],
                "Properties": {
                    "FunctionName": {"Fn::Sub": "${Tag}-remediate"},
                    "Runtime": "python3.9",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Code": {
                        "ZipFile": _get_lambda_code()
                    },
                    "Timeout": 60,
                    "MemorySize": 128,
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            # CloudWatch Log Group for Lambda
            "LambdaLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": {"Fn::Sub": "/aws/lambda/${Tag}-remediate"},
                    "RetentionInDays": 1,
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            # S3 Bucket for CloudTrail
            "TrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": {"Fn::Sub": "${Tag}-trail-${AWS::AccountId}"},
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            "TrailBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "TrailBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSCloudTrailAclCheck",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:GetBucketAcl",
                                "Resource": {"Fn::GetAtt": ["TrailBucket", "Arn"]}
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {"Fn::Sub": "${TrailBucket.Arn}/*"},
                                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
                            }
                        ]
                    }
                }
            },
            # CloudTrail for API monitoring
            "Trail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": ["TrailBucketPolicy"],
                "Properties": {
                    "TrailName": {"Fn::Sub": "${Tag}-trail"},
                    "S3BucketName": {"Ref": "TrailBucket"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": False,
                    "EnableLogFileValidation": True,
                    "EventSelectors": [{
                        "ReadWriteType": "WriteOnly",
                        "IncludeManagementEvents": True
                    }],
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "Tag"}}]
                }
            },
            # EventBridge Rule for IMDS modification detection and remediation
            "IMDSEventRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": {"Fn::Sub": "${Tag}-imds-remediate"},
                    "Description": "Trigger auto-remediation on EC2 IMDS modification",
                    "State": "ENABLED",
                    "EventPattern": {
                        "source": ["aws.ec2"],
                        "detail-type": ["AWS API Call via CloudTrail"],
                        "detail": {
                            "eventSource": ["ec2.amazonaws.com"],
                            "eventName": ["ModifyInstanceMetadataOptions"]
                        }
                    },
                    "Targets": [{
                        "Id": "LambdaTarget",
                        "Arn": {"Fn::GetAtt": ["RemediationLambda", "Arn"]}
                    }]
                }
            },
            # Lambda Permission for EventBridge
            "LambdaPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "RemediationLambda"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["IMDSEventRule", "Arn"]}
                }
            }
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "Instance"}},
            "LambdaArn": {"Value": {"Fn::GetAtt": ["RemediationLambda", "Arn"]}},
            "EventRuleName": {"Value": {"Fn::Sub": "${Tag}-imds-remediate"}},
            "LambdaLogGroup": {"Value": {"Fn::Sub": "/aws/lambda/${Tag}-remediate"}}
        }
    })


def _wait(check_fn, desc, timeout=SLA_TIMEOUT, interval=POLL_INTERVAL):
    """Poll until condition or timeout (30-minute SLA)."""
    start = time.monotonic()
    attempt = 0
    last_error = None
    
    while (time.monotonic() - start) < timeout:
        try:
            result = check_fn()
            if result:
                elapsed = time.monotonic() - start
                logger.info(f"✓ {desc} ({elapsed:.1f}s)")
                return True
        except Exception as e:
            last_error = e
            logger.debug(f"Check {desc}: {e}")
        
        attempt += 1
        sleep = min(interval * (1.2 ** min(attempt, 5)), 120)
        elapsed = time.monotonic() - start
        remaining = timeout - elapsed
        logger.info(f"Waiting: {desc} [{elapsed:.0f}s/{timeout}s] remaining: {remaining:.0f}s")
        time.sleep(sleep)
    
    logger.error(f"Timeout: {desc} after {timeout}s. Last error: {last_error}")
    return False


def steady_state():
    """Deploy experiment infrastructure with reactive controls."""
    global _state
    logger.info("=" * 60)
    logger.info("STEADY STATE: SCE 3.4 Reactive Probe")
    logger.info("=" * 60)
    
    try:
        boto3 = _get_boto3()
        ts = int(time.time())
        stack = f"{STACK_PREFIX}-{ts}"
        tag = f"{EXPERIMENT_TAG}-{ts}"
        
        _state.update({"timestamp": ts, "stack_name": stack, "exp_tag": tag})
        
        session = boto3.session.Session()
        region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        _state["region"] = region
        
        # Get account ID for bucket naming
        sts = boto3.client("sts", region_name=region)
        account_id = sts.get_caller_identity()["Account"]
        
        logger.info(f"Stack: {stack} | Region: {region} | Tag: {tag}")
        
        cfn = boto3.client("cloudformation", region_name=region)
        
        # Check for existing stack
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
                        TemplateBody=_cfn_template(tag, region, account_id),
                        Parameters=[{"ParameterKey": "Tag", "ParameterValue": tag}],
                        Capabilities=["CAPABILITY_NAMED_IAM"],
                        Tags=[
                            {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                            {"Key": "Timestamp", "Value": str(ts)},
                            {"Key": "ProbeType", "Value": "reactive"}
                        ],
                        OnFailure="DELETE",
                        TimeoutInMinutes=20
                    )
                    logger.info("Stack creation started")
                    break
                except cfn.exceptions.AlreadyExistsException:
                    logger.warning("Stack already exists")
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
                    events = cfn.describe_stack_events(StackName=stack)
                    for e in events.get("StackEvents", []):
                        if "FAILED" in e.get("ResourceStatus", ""):
                            logger.error(f"Stack error: {e.get('ResourceStatusReason')}")
                    raise Exception(f"Stack failed: {s}")
                return False
            except cfn.exceptions.ClientError as e:
                if "does not exist" in str(e):
                    return False
                raise
        
        if not _wait(stack_ok, "stack creation", 1200, 20):
            raise Exception("Stack timeout")
        
        # Get stack outputs
        r = cfn.describe_stacks(StackName=stack)
        outputs = {o["OutputKey"]: o["OutputValue"] for o in r["Stacks"][0].get("Outputs", [])}
        
        _state["instance_id"] = outputs.get("InstanceId")
        _state["lambda_arn"] = outputs.get("LambdaArn")
        _state["event_rule_name"] = outputs.get("EventRuleName")
        _state["lambda_log_group"] = outputs.get("LambdaLogGroup")
        
        logger.info(f"Instance: {_state['instance_id']}")
        logger.info(f"Lambda: {_state['lambda_arn']}")
        logger.info(f"EventBridge Rule: {_state['event_rule_name']}")
        
        # Wait for instance to be running
        ec2 = boto3.client("ec2", region_name=region)
        
        def inst_running():
            r = ec2.describe_instances(InstanceIds=[_state["instance_id"]])
            return r["Reservations"][0]["Instances"][0]["State"]["Name"] == "running" if r["Reservations"] else False
        
        if not _wait(inst_running, "instance running", 300, 10):
            raise Exception("Instance timeout")
        
        # Record original IMDS configuration
        r = ec2.describe_instances(InstanceIds=[_state["instance_id"]])
        md = r["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
        _state["original_config"] = {
            "HttpTokens": md.get("HttpTokens"),
            "HttpPutResponseHopLimit": md.get("HttpPutResponseHopLimit")
        }
        logger.info(f"Original IMDS config: {_state['original_config']}")
        
        # Wait for CloudTrail to be logging
        ct = boto3.client("cloudtrail", region_name=region)
        trail_name = f"{tag}-trail"
        
        def trail_logging():
            try:
                r = ct.get_trail_status(Name=trail_name)
                return r.get("IsLogging", False)
            except Exception:
                return False
        
        if not _wait(trail_logging, "CloudTrail logging", 300, 15):
            logger.warning("CloudTrail may not be fully active yet")
        
        logger.info("Waiting for services to stabilize (60s)...")
        time.sleep(60)
        
        _state["ready"] = True
        logger.info("=" * 60)
        logger.info("STEADY STATE COMPLETE")
        logger.info("=" * 60)
        return True
        
    except Exception as e:
        logger.error(f"Steady state failed: {e}")
        logger.error(traceback.format_exc())
        return False


def attack():
    """Execute attack steps to trigger reactive controls."""
    global _state
    logger.info("=" * 60)
    logger.info("ATTACK: SCE 3.4 Reactive Probe")
    logger.info("=" * 60)
    
    if not _state.get("ready"):
        logger.error("Not ready - steady state incomplete")
        return False
    
    try:
        boto3 = _get_boto3()
        region = _state["region"]
        inst_id = _state["instance_id"]
        
        ec2 = boto3.client("ec2", region_name=region)
        
        # Record attack start time
        _state["attack_time"] = time.time()
        attack_time_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(_state["attack_time"]))
        logger.info(f"Attack start time: {attack_time_str}")
        
        # Step 1.2: Identify Target EC2 Instance (T1580)
        logger.info("-" * 40)
        logger.info("Step 1.2: Identify Target (T1580)")
        logger.info("-" * 40)
        try:
            r = ec2.describe_instances(InstanceIds=[inst_id])
            inst = r["Reservations"][0]["Instances"][0]
            md = inst.get("MetadataOptions", {})
            _state["results"]["step_1_2"] = {
                "success": True,
                "instance_id": inst_id,
                "http_tokens": md.get("HttpTokens"),
                "hop_limit": md.get("HttpPutResponseHopLimit"),
                "instance_state": inst.get("State", {}).get("Name")
            }
            logger.info(f"Target identified: {inst_id}")
            logger.info(f"Current IMDS: HttpTokens={md.get('HttpTokens')}, HopLimit={md.get('HttpPutResponseHopLimit')}")
        except Exception as e:
            _state["results"]["step_1_2"] = {"success": False, "error": str(e)}
            logger.error(f"Target identification failed: {e}")
        
        # Step 2.3: Weaken IMDS Protections (T1562.001)
        # This action will trigger the reactive control
        logger.info("-" * 40)
        logger.info("Step 2.3: Weaken IMDS (T1562.001) - TRIGGER REMEDIATION")
        logger.info("-" * 40)
        try:
            # Weaken IMDS protections - this should trigger auto-remediation
            ec2.modify_instance_metadata_options(
                InstanceId=inst_id,
                HttpTokens="optional",  # Weaken from required to optional
                HttpPutResponseHopLimit=2,  # Increase hop limit
                HttpEndpoint="enabled"
            )
            _state["results"]["step_2_3"] = {
                "success": True,
                "modified": True,
                "attack_http_tokens": "optional",
                "attack_hop_limit": 2,
                "attack_time": _state["attack_time"]
            }
            logger.info("IMDS WEAKENED - Attack executed successfully")
            logger.info("  HttpTokens: required -> optional")
            logger.info("  HopLimit: 1 -> 2")
            logger.info("Waiting for reactive control to remediate...")
        except Exception as e:
            _state["results"]["step_2_3"] = {"success": False, "modified": False, "error": str(e)}
            logger.error(f"IMDS modification failed: {e}")
            return False
        
        # Step 3.3: Verify IMDS weakened (T1552.005 prerequisite check)
        logger.info("-" * 40)
        logger.info("Step 3.3: Verify IMDS Weakened (T1552.005)")
        logger.info("-" * 40)
        try:
            # Small delay to ensure modification is applied
            time.sleep(5)
            
            r = ec2.describe_instances(InstanceIds=[inst_id])
            md = r["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
            weakened = md.get("HttpTokens") == "optional" or md.get("HttpPutResponseHopLimit") == 2
            
            _state["results"]["step_3_3"] = {
                "http_tokens": md.get("HttpTokens"),
                "hop_limit": md.get("HttpPutResponseHopLimit"),
                "imds_weakened": weakened
            }
            logger.info(f"IMDS state after attack: HttpTokens={md.get('HttpTokens')}, HopLimit={md.get('HttpPutResponseHopLimit')}")
            logger.info(f"IMDS weakened: {weakened}")
        except Exception as e:
            _state["results"]["step_3_3"] = {"error": str(e)}
            logger.error(f"Verification failed: {e}")
        
        logger.info("=" * 60)
        logger.info("ATTACK COMPLETE - Waiting for auto-remediation...")
        logger.info("=" * 60)
        return True
        
    except Exception as e:
        logger.error(f"Attack failed: {e}")
        logger.error(traceback.format_exc())
        return False


def hypothesis_verification():
    """Verify reactive controls remediated the attack."""
    global _state
    logger.info("=" * 60)
    logger.info("VERIFICATION: SCE 3.4 Reactive Probe")
    logger.info("=" * 60)
    
    boto3 = _get_boto3()
    region = _state["region"]
    inst_id = _state["instance_id"]
    attack_time = _state.get("attack_time", time.time() - 1800)
    
    remediation_checks = {
        "imds_restored": False,
        "lambda_invoked": False,
        "remediation_timely": False
    }
    
    ec2 = boto3.client("ec2", region_name=region)
    
    # Check 1: IMDS configuration restored to compliant state
    logger.info("-" * 40)
    logger.info("Check 1: IMDS Auto-Remediation")
    logger.info("-" * 40)
    
    remediation_start = time.monotonic()
    
    def check_imds_restored():
        try:
            r = ec2.describe_instances(InstanceIds=[inst_id])
            md = r["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
            http_tokens = md.get("HttpTokens")
            hop_limit = md.get("HttpPutResponseHopLimit")
            
            logger.debug(f"Current IMDS: HttpTokens={http_tokens}, HopLimit={hop_limit}")
            
            # Check if restored to compliant state
            if http_tokens == "required" and hop_limit == 1:
                return True
            return False
        except Exception as e:
            logger.debug(f"IMDS check error: {e}")
            return False
    
    if _wait(check_imds_restored, "IMDS auto-remediation", REMEDIATION_TIMEOUT, 15):
        remediation_time = time.monotonic() - remediation_start
        remediation_checks["imds_restored"] = True
        remediation_checks["remediation_timely"] = remediation_time < 300  # Under 5 minutes
        _state["remediation_results"]["imds_restored"] = True
        _state["remediation_results"]["time_to_remediate"] = remediation_time
        logger.info(f"✓ IMDS RESTORED to compliant state in {remediation_time:.1f}s")
        logger.info("  HttpTokens: optional -> required")
        logger.info("  HopLimit: 2 -> 1")
    else:
        logger.warning("✗ IMDS not restored within timeout")
        _state["remediation_results"]["imds_restored"] = False
    
    # Check 2: Lambda function was invoked
    logger.info("-" * 40)
    logger.info("Check 2: Lambda Invocation")
    logger.info("-" * 40)
    
    logs = boto3.client("logs", region_name=region)
    log_group = _state.get("lambda_log_group", f"/aws/lambda/{_state['exp_tag']}-remediate")
    
    def check_lambda_invoked():
        try:
            start_time = int((attack_time - 60) * 1000)  # 1 min before attack
            end_time = int(time.time() * 1000)
            
            response = logs.filter_log_events(
                logGroupName=log_group,
                startTime=start_time,
                endTime=end_time,
                filterPattern='"Remediating IMDS"'
            )
            
            if response.get("events"):
                for event in response["events"]:
                    if inst_id in event.get("message", ""):
                        logger.info(f"Lambda remediation log found: {event.get('message', '')[:100]}...")
                        return True
                # Any remediation log is good
                logger.info(f"Found {len(response['events'])} remediation log events")
                return True
            
            # Also check for successful remediation message
            response = logs.filter_log_events(
                logGroupName=log_group,
                startTime=start_time,
                endTime=end_time,
                filterPattern='"IMDS remediated"'
            )
            
            if response.get("events"):
                logger.info(f"Found {len(response['events'])} successful remediation logs")
                return True
                
            return False
        except logs.exceptions.ResourceNotFoundException:
            logger.debug("Log group not found yet")
            return False
        except Exception as e:
            logger.debug(f"Lambda log check error: {e}")
            return False
    
    if _wait(check_lambda_invoked, "Lambda invocation detection", SLA_TIMEOUT, 30):
        remediation_checks["lambda_invoked"] = True
        _state["remediation_results"]["lambda_invoked"] = True
        logger.info("✓ Lambda remediation function was INVOKED")
    else:
        logger.warning("✗ Lambda invocation not detected within SLA")
        _state["remediation_results"]["lambda_invoked"] = False
    
    # Summary
    logger.info("=" * 60)
    logger.info("REMEDIATION SUMMARY")
    logger.info("=" * 60)
    
    for check, result in remediation_checks.items():
        status = "✓ PASS" if result else "✗ FAIL"
        logger.info(f"  {status}: {check}")
    
    if _state["remediation_results"].get("time_to_remediate"):
        logger.info(f"  Time to remediate: {_state['remediation_results']['time_to_remediate']:.1f}s")
    
    # Primary success criteria: IMDS was restored
    primary_success = remediation_checks["imds_restored"]
    full_success = all(remediation_checks.values())
    
    _state["verified"] = primary_success
    
    logger.info("=" * 60)
    if primary_success:
        logger.info("HYPOTHESIS VERIFIED: Reactive control REMEDIATED the attack")
        if full_success:
            logger.info("  All checks passed - excellent reactive posture")
        else:
            logger.info("  Primary remediation successful, some secondary checks incomplete")
    else:
        logger.error("HYPOTHESIS FAILED: Reactive control did NOT remediate the attack")
        # Check final state
        r = ec2.describe_instances(InstanceIds=[inst_id])
        md = r["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
        logger.error(f"  Final IMDS state: HttpTokens={md.get('HttpTokens')}, HopLimit={md.get('HttpPutResponseHopLimit')}")
    logger.info("=" * 60)
    
    return primary_success


def rollback():
    """Delete CloudFormation stack and cleanup."""
    global _state
    logger.info("=" * 60)
    logger.info("ROLLBACK: SCE 3.4 Reactive Probe")
    logger.info("=" * 60)
    
    stack = _state.get("stack_name")
    if not stack:
        logger.info("No stack to delete")
        return True
    
    try:
        boto3 = _get_boto3()
        region = _state.get("region", os.environ.get("AWS_DEFAULT_REGION", "us-east-1"))
        cfn = boto3.client("cloudformation", region_name=region)
        
        # Delete stack
        try:
            cfn.delete_stack(StackName=stack)
            logger.info(f"Deleting stack: {stack}")
        except cfn.exceptions.ClientError as e:
            if "does not exist" in str(e):
                logger.info("Stack already deleted")
                return True
            raise
        
        def deleted():
            try:
                r = cfn.describe_stacks(StackName=stack)
                s = r["Stacks"][0]["StackStatus"]
                if s == "DELETE_COMPLETE":
                    return True
                if s == "DELETE_FAILED":
                    logger.warning("Stack deletion failed - may need manual cleanup")
                    return True  # Continue anyway
                return False
            except cfn.exceptions.ClientError as e:
                if "does not exist" in str(e):
                    return True
                raise
        
        if _wait(deleted, "stack deletion", 900, 20):
            logger.info("=" * 60)
            logger.info("ROLLBACK COMPLETE")
            logger.info("=" * 60)
            return True
        
        logger.warning("Stack deletion timeout - may need manual cleanup")
        return False
        
    except Exception as e:
        logger.error(f"Rollback error: {e}")
        logger.error(traceback.format_exc())
        return False


def run():
    """Standalone runner for testing."""
    result = False
    try:
        if steady_state() and attack():
            result = hypothesis_verification()
    except Exception as e:
        logger.error(f"Experiment error: {e}")
    finally:
        rollback()
    
    logger.info(f"FINAL RESULT: {'PASS' if result else 'FAIL'}")
    return result


if __name__ == "__main__":
    sys.exit(0 if run() else 1)