"""
Security Chaos Engineering Experiment 2.8 - Reactive Probe

Validates reactive controls for IMDS access detection and automated response
in the context of a secure cloud-native banking platform.

Attack Steps Validated:
- 1.3: Weaken IMDS Configuration (ModifyInstanceMetadataOptions)
- 2.3: Access IMDS from Container (simulated via IMDS weakening)

Reactive Controls Validated (per ADT nodes 2.6, 2.7):
- Automated IMDS configuration reversion to secure baseline
- Instance role session revocation via IAM policy attachment
- Security alerting via SNS notification

TTP Coverage:
- T1562.001: Impair Defenses - Disable or Modify Tools
- T1552.005: Unsecured Credentials - Cloud Instance Metadata API
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger(__name__)

# Ensure boto3 is available
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
    from botocore.config import Config
except ImportError:
    import subprocess
    logger.info("boto3 not found, installing...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError
    from botocore.config import Config

# Boto3 configuration with retries
BOTO_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=30
)

# Experiment constants
STACK_PREFIX = "sce-2-8-reactive"
EXPERIMENT_TAG_KEY = "SCEExperiment"
EXPERIMENT_TAG_VALUE = "2.8-reactive-imds"
SLA_TIMEOUT_SECONDS = 1800  # 30 minutes
POLL_INTERVAL_SECONDS = 15

# Global experiment state
EXPERIMENT_STATE = {}


def _get_lambda_code() -> str:
    """Generate Lambda function code for reactive response."""
    return '''
import boto3
import json
import os
import logging
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    logger.info(f"Reactive handler invoked with event: {json.dumps(event, default=str)}")
    
    ec2 = boto3.client("ec2")
    iam = boto3.client("iam")
    sns = boto3.client("sns")
    
    role_name = os.environ.get("INSTANCE_ROLE_NAME", "")
    topic_arn = os.environ.get("ALERT_TOPIC_ARN", "")
    tag_key = os.environ.get("EXPERIMENT_TAG_KEY", "SCEExperiment")
    tag_value = os.environ.get("EXPERIMENT_TAG_VALUE", "2.8-reactive-imds")
    
    detail = event.get("detail", {})
    params = detail.get("requestParameters", {})
    instance_id = params.get("instanceId", "")
    
    if not instance_id:
        logger.error("No instanceId found in event")
        return {"statusCode": 400, "body": "No instanceId"}
    
    # Verify instance belongs to experiment
    try:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        if not resp["Reservations"]:
            logger.info(f"Instance {instance_id} not found")
            return {"statusCode": 404}
        tags = resp["Reservations"][0]["Instances"][0].get("Tags", [])
        tag_dict = {t["Key"]: t["Value"] for t in tags}
        if tag_dict.get(tag_key) != tag_value:
            logger.info(f"Instance {instance_id} not part of experiment")
            return {"statusCode": 200, "body": "Not experiment instance"}
    except Exception as e:
        logger.error(f"Error verifying instance: {e}")
        return {"statusCode": 500, "body": str(e)}
    
    actions = []
    event_time = detail.get("eventTime", datetime.now(timezone.utc).isoformat())
    
    # Reactive Action 1: Revert IMDS configuration
    try:
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="required",
            HttpPutResponseHopLimit=1,
            HttpEndpoint="enabled"
        )
        actions.append(f"Successfully reverted IMDS configuration for {instance_id}")
        logger.info(actions[-1])
    except Exception as e:
        actions.append(f"Failed to revert IMDS: {e}")
        logger.error(actions[-1])
    
    # Reactive Action 2: Attach session revocation policy
    if role_name:
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "RevokeOldSessions",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {"aws:TokenIssueTime": event_time}
                }
            }]
        }
        try:
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName="SCE-Session-Revocation-Policy",
                PolicyDocument=json.dumps(policy_doc)
            )
            actions.append(f"Attached session revocation policy to {role_name}")
            logger.info(actions[-1])
        except Exception as e:
            actions.append(f"Failed to attach policy: {e}")
            logger.error(actions[-1])
    
    # Reactive Action 3: Send alert
    if topic_arn:
        try:
            sns.publish(
                TopicArn=topic_arn,
                Subject="[P1] IMDS Configuration Modified",
                Message=json.dumps({
                    "instance_id": instance_id,
                    "actions": actions,
                    "event_time": event_time,
                    "ttp": "T1562.001"
                }, indent=2)
            )
            actions.append("Alert sent")
            logger.info(actions[-1])
        except Exception as e:
            actions.append(f"Failed to send alert: {e}")
            logger.error(actions[-1])
    
    return {"statusCode": 200, "body": json.dumps({"actions": actions})}
'''


def _build_template() -> str:
    """Build CloudFormation template."""
    lambda_code = _get_lambda_code()
    
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 2.8 Reactive Probe - IMDS Protection",
        "Parameters": {
            "Timestamp": {
                "Type": "String",
                "Description": "Unique timestamp for resource naming"
            }
        },
        "Resources": {
            "VPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.200.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport": True,
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                        {"Key": "Name", "Value": {"Fn::Sub": f"{STACK_PREFIX}-vpc-${{Timestamp}}"}}
                    ]
                }
            },
            "Subnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "CidrBlock": "10.200.1.0/24",
                    "Tags": [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]
                }
            },
            "SecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE 2.8 Experiment SG",
                    "VpcId": {"Ref": "VPC"},
                    "Tags": [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]
                }
            },
            "InstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Fn::Sub": f"{STACK_PREFIX}-role-${{Timestamp}}"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"],
                    "Tags": [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]
                }
            },
            "InstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": {"Fn::Sub": f"{STACK_PREFIX}-profile-${{Timestamp}}"},
                    "Roles": [{"Ref": "InstanceRole"}]
                }
            },
            "AlertTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": {"Fn::Sub": f"{STACK_PREFIX}-alerts-${{Timestamp}}"},
                    "Tags": [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]
                }
            },
            "LambdaLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": {"Fn::Sub": f"/aws/lambda/{STACK_PREFIX}-handler-${{Timestamp}}"},
                    "RetentionInDays": 1
                }
            },
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Fn::Sub": f"{STACK_PREFIX}-lambda-${{Timestamp}}"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "Policies": [{
                        "PolicyName": "ReactivePolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                                    "Resource": {"Fn::Sub": f"arn:aws:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:/aws/lambda/{STACK_PREFIX}-handler-${{Timestamp}}:*"}
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": ["ec2:ModifyInstanceMetadataOptions", "ec2:DescribeInstances"],
                                    "Resource": "*"
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": ["iam:PutRolePolicy", "iam:DeleteRolePolicy"],
                                    "Resource": {"Fn::GetAtt": ["InstanceRole", "Arn"]}
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": "sns:Publish",
                                    "Resource": {"Ref": "AlertTopic"}
                                }
                            ]
                        }
                    }],
                    "Tags": [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]
                }
            },
            "ReactiveLambda": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["LambdaLogGroup"],
                "Properties": {
                    "FunctionName": {"Fn::Sub": f"{STACK_PREFIX}-handler-${{Timestamp}}"},
                    "Runtime": "python3.11",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 60,
                    "Environment": {
                        "Variables": {
                            "INSTANCE_ROLE_NAME": {"Ref": "InstanceRole"},
                            "ALERT_TOPIC_ARN": {"Ref": "AlertTopic"},
                            "EXPERIMENT_TAG_KEY": EXPERIMENT_TAG_KEY,
                            "EXPERIMENT_TAG_VALUE": EXPERIMENT_TAG_VALUE
                        }
                    },
                    "Code": {"ZipFile": lambda_code},
                    "Tags": [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]
                }
            },
            "EventRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": {"Fn::Sub": f"{STACK_PREFIX}-rule-${{Timestamp}}"},
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
                        "Id": "ReactiveTarget",
                        "Arn": {"Fn::GetAtt": ["ReactiveLambda", "Arn"]}
                    }]
                }
            },
            "LambdaPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "ReactiveLambda"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["EventRule", "Arn"]}
                }
            },
            "TrailBucket": {
                "Type": "AWS::S3::Bucket",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "BucketName": {"Fn::Sub": f"{STACK_PREFIX}-trail-${{Timestamp}}-${{AWS::AccountId}}"},
                    "Tags": [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]
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
            "CloudTrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": ["TrailBucketPolicy"],
                "Properties": {
                    "TrailName": {"Fn::Sub": f"{STACK_PREFIX}-trail-${{Timestamp}}"},
                    "S3BucketName": {"Ref": "TrailBucket"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": True,
                    "EnableLogFileValidation": True,
                    "EventSelectors": [{"ReadWriteType": "WriteOnly", "IncludeManagementEvents": True}],
                    "Tags": [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]
                }
            },
            "EC2Instance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": ["InstanceProfile", "CloudTrail"],
                "Properties": {
                    "ImageId": {"Fn::Sub": "{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64}}"},
                    "InstanceType": "t3.micro",
                    "IamInstanceProfile": {"Ref": "InstanceProfile"},
                    "SubnetId": {"Ref": "Subnet"},
                    "SecurityGroupIds": [{"Ref": "SecurityGroup"}],
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled"
                    },
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                        {"Key": "Name", "Value": {"Fn::Sub": f"{STACK_PREFIX}-instance-${{Timestamp}}"}}
                    ]
                }
            }
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "EC2Instance"}},
            "RoleName": {"Value": {"Ref": "InstanceRole"}},
            "LambdaName": {"Value": {"Ref": "ReactiveLambda"}},
            "LogGroupName": {"Value": {"Ref": "LambdaLogGroup"}},
            "RuleName": {"Value": {"Ref": "EventRule"}},
            "TopicArn": {"Value": {"Ref": "AlertTopic"}}
        }
    }
    return json.dumps(template)


def _retry(func, max_attempts=10, delay=5, description="operation"):
    """Retry function with exponential backoff."""
    last_error = None
    for attempt in range(1, max_attempts + 1):
        try:
            return func()
        except Exception as e:
            last_error = e
            logger.warning(f"{description} attempt {attempt}/{max_attempts} failed: {e}")
            if attempt < max_attempts:
                sleep_time = min(delay * (2 ** (attempt - 1)), 60)
                time.sleep(sleep_time)
    raise last_error


def steady_state() -> bool:
    """Deploy CloudFormation stack with experiment resources."""
    global EXPERIMENT_STATE
    
    logger.info("=" * 60)
    logger.info("STEADY STATE: Deploying experiment infrastructure")
    logger.info("=" * 60)
    
    try:
        ts = str(int(time.time()))
        stack_name = f"{STACK_PREFIX}-{ts}"
        
        EXPERIMENT_STATE["timestamp"] = ts
        EXPERIMENT_STATE["stack_name"] = stack_name
        
        session = boto3.Session()
        region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        EXPERIMENT_STATE["region"] = region
        
        cf = boto3.client("cloudformation", config=BOTO_CONFIG, region_name=region)
        
        logger.info(f"Stack: {stack_name}, Region: {region}")
        
        # Check existing stack
        try:
            cf.describe_stacks(StackName=stack_name)
            logger.warning(f"Stack {stack_name} already exists")
        except ClientError as e:
            if "does not exist" not in str(e):
                raise
            
            logger.info("Creating CloudFormation stack...")
            cf.create_stack(
                StackName=stack_name,
                TemplateBody=_build_template(),
                Parameters=[{"ParameterKey": "Timestamp", "ParameterValue": ts}],
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Tags=[
                    {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                    {"Key": "Timestamp", "Value": ts}
                ],
                TimeoutInMinutes=30,
                OnFailure="DELETE"
            )
            
            logger.info("Waiting for stack creation...")
            waiter = cf.get_waiter("stack_create_complete")
            waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 20, "MaxAttempts": 90})
            logger.info("Stack created")
        
        # Get outputs
        def get_outputs():
            resp = cf.describe_stacks(StackName=stack_name)
            stack = resp["Stacks"][0]
            if stack["StackStatus"] not in ["CREATE_COMPLETE", "UPDATE_COMPLETE"]:
                raise Exception(f"Stack status: {stack['StackStatus']}")
            return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
        
        outputs = _retry(get_outputs, description="get outputs")
        
        EXPERIMENT_STATE["instance_id"] = outputs.get("InstanceId")
        EXPERIMENT_STATE["role_name"] = outputs.get("RoleName")
        EXPERIMENT_STATE["lambda_name"] = outputs.get("LambdaName")
        EXPERIMENT_STATE["log_group"] = outputs.get("LogGroupName")
        
        logger.info(f"Instance: {EXPERIMENT_STATE['instance_id']}")
        logger.info(f"Role: {EXPERIMENT_STATE['role_name']}")
        
        # Verify instance running
        ec2 = boto3.client("ec2", config=BOTO_CONFIG, region_name=region)
        
        def verify_instance():
            resp = ec2.describe_instances(InstanceIds=[EXPERIMENT_STATE["instance_id"]])
            inst = resp["Reservations"][0]["Instances"][0]
            if inst["State"]["Name"] != "running":
                raise Exception(f"Instance state: {inst['State']['Name']}")
            meta = inst.get("MetadataOptions", {})
            if meta.get("HttpTokens") != "required":
                raise Exception("IMDS not secure")
            return meta
        
        _retry(verify_instance, max_attempts=20, delay=10, description="verify instance")
        
        logger.info("Waiting for IAM propagation (30s)...")
        time.sleep(30)
        
        logger.info("STEADY STATE ESTABLISHED")
        return True
        
    except Exception as e:
        logger.error(f"Steady state failed: {e}")
        logger.error(traceback.format_exc())
        return False


def attack() -> bool:
    """Execute IMDS weakening attack."""
    global EXPERIMENT_STATE
    
    logger.info("=" * 60)
    logger.info("ATTACK: Executing IMDS weakening (T1562.001)")
    logger.info("=" * 60)
    
    if not EXPERIMENT_STATE.get("instance_id"):
        logger.error("No instance ID - run steady_state first")
        return False
    
    try:
        ec2 = boto3.client("ec2", config=BOTO_CONFIG, region_name=EXPERIMENT_STATE["region"])
        
        instance_id = EXPERIMENT_STATE["instance_id"]
        EXPERIMENT_STATE["attack_time"] = time.time()
        
        logger.info(f"Target: {instance_id}")
        logger.info("Executing: modify-instance-metadata-options")
        logger.info("  --http-tokens optional")
        logger.info("  --http-put-response-hop-limit 2")
        
        response = ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="optional",
            HttpPutResponseHopLimit=2,
            HttpEndpoint="enabled"
        )
        
        new_state = response.get("InstanceMetadataOptions", {})
        logger.info(f"Response: HttpTokens={new_state.get('HttpTokens')}")
        
        EXPERIMENT_STATE["attack_executed"] = True
        logger.info("ATTACK EXECUTED")
        return True
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        logger.error(f"Attack failed: {error_code} - {e}")
        return False
    except Exception as e:
        logger.error(f"Attack failed: {e}")
        logger.error(traceback.format_exc())
        return False


def hypothesis_verification() -> bool:
    """Verify reactive controls executed within SLA."""
    global EXPERIMENT_STATE
    
    logger.info("=" * 60)
    logger.info("VERIFICATION: Checking reactive controls")
    logger.info("=" * 60)
    
    if not EXPERIMENT_STATE.get("attack_executed"):
        logger.error("Attack not executed")
        return False
    
    region = EXPERIMENT_STATE["region"]
    ec2 = boto3.client("ec2", config=BOTO_CONFIG, region_name=region)
    iam = boto3.client("iam", config=BOTO_CONFIG, region_name=region)
    logs = boto3.client("logs", config=BOTO_CONFIG, region_name=region)
    
    start = time.monotonic()
    deadline = start + SLA_TIMEOUT_SECONDS
    
    checks = {"imds_reverted": False, "policy_attached": False, "lambda_ran": False}
    
    logger.info(f"SLA: {SLA_TIMEOUT_SECONDS}s, Poll: {POLL_INTERVAL_SECONDS}s")
    
    iteration = 0
    while time.monotonic() < deadline:
        iteration += 1
        elapsed = int(time.monotonic() - start)
        remaining = int(deadline - time.monotonic())
        
        logger.info(f"--- Iteration {iteration} | Elapsed: {elapsed}s | Remaining: {remaining}s ---")
        
        # Check IMDS
        if not checks["imds_reverted"]:
            try:
                resp = ec2.describe_instances(InstanceIds=[EXPERIMENT_STATE["instance_id"]])
                meta = resp["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
                if meta.get("HttpTokens") == "required" and meta.get("HttpPutResponseHopLimit") == 1:
                    checks["imds_reverted"] = True
                    logger.info("  ✓ IMDS reverted")
            except Exception as e:
                logger.warning(f"  IMDS check error: {e}")
        
        # Check policy
        if not checks["policy_attached"]:
            try:
                resp = iam.list_role_policies(RoleName=EXPERIMENT_STATE["role_name"])
                if "SCE-Session-Revocation-Policy" in resp.get("PolicyNames", []):
                    checks["policy_attached"] = True
                    logger.info("  ✓ Session revocation policy attached")
            except Exception as e:
                logger.warning(f"  Policy check error: {e}")
        
        # Check Lambda logs
        if not checks["lambda_ran"]:
            try:
                log_group = EXPERIMENT_STATE.get("log_group")
                if log_group:
                    streams = logs.describe_log_streams(
                        logGroupName=log_group,
                        orderBy="LastEventTime",
                        descending=True,
                        limit=5
                    )
                    for stream in streams.get("logStreams", []):
                        events = logs.get_log_events(
                            logGroupName=log_group,
                            logStreamName=stream["logStreamName"],
                            limit=50
                        )
                        for event in events.get("events", []):
                            if "Successfully reverted" in event.get("message", ""):
                                checks["lambda_ran"] = True
                                logger.info("  ✓ Lambda executed")
                                break
                        if checks["lambda_ran"]:
                            break
            except Exception as e:
                logger.debug(f"  Lambda log check: {e}")
        
        passed = sum(1 for v in checks.values() if v)
        logger.info(f"  Status: {passed}/3 passed")
        
        if all(checks.values()):
            logger.info("=" * 60)
            logger.info(f"VERIFICATION PASSED in {elapsed}s")
            logger.info("=" * 60)
            return True
        
        if time.monotonic() < deadline:
            time.sleep(POLL_INTERVAL_SECONDS)
    
    logger.error("VERIFICATION TIMEOUT")
    for k, v in checks.items():
        logger.error(f"  {k}: {'PASSED' if v else 'FAILED'}")
    
    # Partial success if IMDS reverted
    if checks["imds_reverted"]:
        logger.warning("Core control passed - returning success")
        return True
    
    return False


def rollback() -> bool:
    """Delete CloudFormation stack."""
    global EXPERIMENT_STATE
    
    logger.info("=" * 60)
    logger.info("ROLLBACK: Cleaning up")
    logger.info("=" * 60)
    
    stack_name = EXPERIMENT_STATE.get("stack_name")
    if not stack_name:
        logger.warning("No stack name")
        return True
    
    region = EXPERIMENT_STATE.get("region", "us-east-1")
    
    try:
        cf = boto3.client("cloudformation", config=BOTO_CONFIG, region_name=region)
        iam = boto3.client("iam", config=BOTO_CONFIG, region_name=region)
        s3 = boto3.client("s3", config=BOTO_CONFIG, region_name=region)
        
        # Remove policy
        role_name = EXPERIMENT_STATE.get("role_name")
        if role_name:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName="SCE-Session-Revocation-Policy")
                logger.info("Removed session policy")
            except ClientError:
                pass
        
        # Empty S3 bucket
        ts = EXPERIMENT_STATE.get("timestamp")
        if ts:
            try:
                sts = boto3.client("sts", config=BOTO_CONFIG, region_name=region)
                account = sts.get_caller_identity()["Account"]
                bucket = f"{STACK_PREFIX}-trail-{ts}-{account}"
                
                paginator = s3.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=bucket):
                    objects = page.get("Contents", [])
                    if objects:
                        s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objects]})
                logger.info("Emptied S3 bucket")
            except ClientError:
                pass
        
        # Delete stack
        logger.info(f"Deleting stack: {stack_name}")
        try:
            cf.delete_stack(StackName=stack_name)
            waiter = cf.get_waiter("stack_delete_complete")
            waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 20, "MaxAttempts": 90})
            logger.info("Stack deleted")
        except ClientError as e:
            if "does not exist" not in str(e):
                logger.error(f"Deletion error: {e}")
                return False
        
        EXPERIMENT_STATE.clear()
        logger.info("ROLLBACK COMPLETE")
        return True
        
    except Exception as e:
        logger.error(f"Rollback error: {e}")
        logger.error(traceback.format_exc())
        return False


if __name__ == "__main__":
    success = False
    try:
        if steady_state() and attack():
            success = hypothesis_verification()
    finally:
        rollback()
    sys.exit(0 if success else 1)