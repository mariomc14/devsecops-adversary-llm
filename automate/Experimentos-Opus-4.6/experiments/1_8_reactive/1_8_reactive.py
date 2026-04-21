"""
SCE Experiment 1.8 – Reactive Probe (Revised)
Attack Steps 1.2 & 1.7: EC2 IMDS Protection Weakening via ModifyInstanceMetadataOptions

Reactive Probe Validation:
  After the attacker successfully downgrades IMDS, an automated EventBridge →
  Lambda pipeline must:
    (1) Re-enforce IMDSv2 (http-tokens=required, hop-limit=1)
    (2) Attach an inline deny-all policy to the attacker role
    (3) Publish a remediation confirmation to SNS → SQS

Fixes from previous execution:
  • Added robust retry/backoff with per-call exception handling in the polling
    loop so a transient ConnectTimeoutError does not crash the whole probe.
  • Added pre-flight checks: verify Lambda deployed, EventBridge rule active,
    and perform a test Lambda invocation before executing the attack.
  • Added diagnostic logging: query Lambda CloudWatch logs and EventBridge
    metrics during the polling loop to help diagnose pipeline failures.
  • Increased CloudTrail/EventBridge stabilisation wait to 60 s.
  • Added elapsed-time tracking per check for SLA comparison.
"""

import json
import logging
import os
import sys
import time
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError, ConnectTimeoutError, ReadTimeoutError, EndpointConnectionError
    from botocore.config import Config as BotoConfig
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError, ConnectTimeoutError, ReadTimeoutError, EndpointConnectionError
    from botocore.config import Config as BotoConfig

# ---------------------------------------------------------------------------
# Boto retry configuration – generous timeouts and retries
# ---------------------------------------------------------------------------
_BOTO_CFG = BotoConfig(
    retries={"max_attempts": 5, "mode": "adaptive"},
    connect_timeout=30,
    read_timeout=60,
)

# ---------------------------------------------------------------------------
# Global constants & mutable state
# ---------------------------------------------------------------------------
_TIMESTAMP = str(int(time.time()))
_STACK_NAME = f"sce-react-1-8-{_TIMESTAMP}"
_EXPERIMENT_TAG = "sce-experiment-1-8-reactive"
_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
_SLA_TIMEOUT = 1800
_POLL_INTERVAL = 15
_STACK_OUTPUTS: dict = {}
_ATTACK_RESULTS: dict = {}
_ATTACK_TIME: float = 0.0  # monotonic time when attack completed


def _ts():
    return time.monotonic()


# ---------------------------------------------------------------------------
# Boto client factories – each call creates a fresh client with retry config
# ---------------------------------------------------------------------------
def _cfn():
    return boto3.client("cloudformation", region_name=_REGION, config=_BOTO_CFG)


def _sts():
    return boto3.client("sts", region_name=_REGION, config=_BOTO_CFG)


def _ec2():
    return boto3.client("ec2", region_name=_REGION, config=_BOTO_CFG)


def _sqs():
    return boto3.client("sqs", region_name=_REGION, config=_BOTO_CFG)


def _iam():
    return boto3.client("iam", region_name=_REGION, config=_BOTO_CFG)


def _lambda():
    return boto3.client("lambda", region_name=_REGION, config=_BOTO_CFG)


def _events():
    return boto3.client("events", region_name=_REGION, config=_BOTO_CFG)


def _logs():
    return boto3.client("logs", region_name=_REGION, config=_BOTO_CFG)


def _cw():
    return boto3.client("cloudwatch", region_name=_REGION, config=_BOTO_CFG)


def _account_id():
    return _sts().get_caller_identity()["Account"]


# ---------------------------------------------------------------------------
# Safe API call wrapper – retries on transient network errors
# ---------------------------------------------------------------------------
def _safe_call(fn, description="API call", max_retries=3):
    """Execute fn() with retries on transient network errors."""
    for attempt in range(max_retries):
        try:
            return fn()
        except (ConnectTimeoutError, ReadTimeoutError, EndpointConnectionError) as exc:
            logger.warning("Transient error on %s (attempt %d/%d): %s",
                           description, attempt + 1, max_retries, exc)
            if attempt < max_retries - 1:
                time.sleep(5 * (attempt + 1))
            else:
                logger.error("All retries exhausted for %s", description)
                raise
        except ClientError as exc:
            raise
    return None


# ---------------------------------------------------------------------------
# Infrastructure helpers
# ---------------------------------------------------------------------------
def _get_subnet():
    ec2 = _ec2()
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
        if vpcs["Vpcs"]:
            subs = ec2.describe_subnets(
                Filters=[{"Name": "vpc-id", "Values": [vpcs["Vpcs"][0]["VpcId"]]}]
            )
            if subs["Subnets"]:
                return subs["Subnets"][0]["SubnetId"], vpcs["Vpcs"][0]["VpcId"]
    except ClientError as exc:
        logger.error("Subnet lookup: %s", exc)
    try:
        subs = ec2.describe_subnets(MaxResults=5)
        if subs["Subnets"]:
            s = subs["Subnets"][0]
            return s["SubnetId"], s["VpcId"]
    except ClientError as exc:
        logger.error("Fallback subnet: %s", exc)
    return None, None


def _get_ami():
    ec2 = _ec2()
    try:
        imgs = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": ["x86_64"]},
            ],
        )
        images = sorted(imgs["Images"], key=lambda x: x["CreationDate"], reverse=True)
        if images:
            return images[0]["ImageId"]
    except ClientError as exc:
        logger.error("AMI lookup: %s", exc)
    return None


def _wait_stack(name, target, timeout=900):
    cfn = _cfn()
    start = _ts()
    while (_ts() - start) < timeout:
        try:
            resp = cfn.describe_stacks(StackName=name)
            st = resp["Stacks"][0]["StackStatus"]
            logger.info("Stack %s → %s", name, st)
            if st == target:
                return True
            if "FAILED" in st or st == "ROLLBACK_COMPLETE":
                logger.error("Stack %s reached %s", name, st)
                try:
                    evts = cfn.describe_stack_events(StackName=name)["StackEvents"]
                    for e in evts[:15]:
                        if "FAILED" in e.get("ResourceStatus", ""):
                            logger.error("  %s: %s", e["LogicalResourceId"],
                                         e.get("ResourceStatusReason", ""))
                except Exception:
                    pass
                return False
            if st == "DELETE_COMPLETE" and target != "DELETE_COMPLETE":
                return False
        except ClientError as exc:
            if "does not exist" in str(exc):
                return target == "DELETE_COMPLETE"
            logger.warning("describe_stacks: %s", exc)
        time.sleep(15)
    logger.error("Timeout waiting for stack %s → %s", name, target)
    return False


def _stack_outputs(name):
    try:
        resp = _cfn().describe_stacks(StackName=name)
        return {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    except (ClientError, IndexError, KeyError) as exc:
        logger.error("Stack outputs: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Lambda inline code
# ---------------------------------------------------------------------------
def _lambda_code():
    return r'''
import json
import boto3
import os
import logging
import traceback

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2")
iam = boto3.client("iam")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN", "")
ATTACKER_ROLE_NAME = os.environ.get("ATTACKER_ROLE_NAME", "")
TARGET_INSTANCE_ID = os.environ.get("TARGET_INSTANCE_ID", "")


def handler(event, context):
    logger.info("Received event: %s", json.dumps(event))

    try:
        detail = event.get("detail", {})
        event_name = detail.get("eventName", "")
        req_params = detail.get("requestParameters", {})
        instance_id = req_params.get("instanceId", "")

        if event_name != "ModifyInstanceMetadataOptions":
            logger.info("Ignoring event: %s", event_name)
            return {"statusCode": 200, "body": "ignored"}

        if not instance_id:
            logger.error("No instanceId in event.")
            return {"statusCode": 400, "body": "no instance id"}

        # Only remediate our target instance
        if TARGET_INSTANCE_ID and instance_id != TARGET_INSTANCE_ID:
            logger.info("Instance %s is not our target %s, skipping.",
                        instance_id, TARGET_INSTANCE_ID)
            return {"statusCode": 200, "body": "not target"}

        # Check if this is the attacker's modification (tokens=optional)
        # Avoid infinite loop: if tokens is already required, skip
        resp_params = detail.get("responseElements", {})
        requested_tokens = req_params.get("ModifyInstanceMetadataOptionsRequest", {}).get("httpTokens", "")
        if not requested_tokens:
            requested_tokens = req_params.get("httpTokens", "")
        logger.info("Requested httpTokens value: %s", requested_tokens)

        # If someone set tokens to required, that's a remediation not an attack
        if requested_tokens == "required":
            logger.info("This is a remediation call (tokens=required), skipping.")
            return {"statusCode": 200, "body": "remediation call, skipped"}

        remediation_actions = []

        # 1. Re-enforce IMDSv2
        try:
            ec2.modify_instance_metadata_options(
                InstanceId=instance_id,
                HttpTokens="required",
                HttpEndpoint="enabled",
                HttpPutResponseHopLimit=1,
            )
            logger.info("REMEDIATION: IMDSv2 re-enforced on %s", instance_id)
            remediation_actions.append("imds_restored")
        except Exception as exc:
            logger.error("Failed to restore IMDS on %s: %s", instance_id, exc)
            remediation_actions.append("imds_restore_failed: %s" % str(exc))

        # 2. Revoke attacker role permissions
        if ATTACKER_ROLE_NAME:
            try:
                deny_policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "DenyAllReactive",
                            "Effect": "Deny",
                            "Action": "*",
                            "Resource": "*"
                        }
                    ]
                }
                iam.put_role_policy(
                    RoleName=ATTACKER_ROLE_NAME,
                    PolicyName="sce-reactive-deny-all",
                    PolicyDocument=json.dumps(deny_policy),
                )
                logger.info("REMEDIATION: Deny-all policy attached to %s", ATTACKER_ROLE_NAME)
                remediation_actions.append("role_denied")
            except Exception as exc:
                logger.error("Failed to deny role %s: %s", ATTACKER_ROLE_NAME, exc)
                remediation_actions.append("role_deny_failed: %s" % str(exc))

        # 3. Publish SNS notification
        if SNS_TOPIC_ARN:
            try:
                message = {
                    "experiment": "sce-1-8-reactive",
                    "event": "remediation_complete",
                    "instance_id": instance_id,
                    "actions": remediation_actions,
                }
                sns.publish(
                    TopicArn=SNS_TOPIC_ARN,
                    Subject="SCE 1.8 Reactive Remediation",
                    Message=json.dumps(message),
                )
                logger.info("REMEDIATION: SNS notification published.")
                remediation_actions.append("sns_notified")
            except Exception as exc:
                logger.error("SNS publish failed: %s", exc)

        return {"statusCode": 200, "body": json.dumps(remediation_actions)}

    except Exception as exc:
        logger.error("Unhandled exception: %s\n%s", exc, traceback.format_exc())
        return {"statusCode": 500, "body": str(exc)}
'''


# ---------------------------------------------------------------------------
# CloudFormation template
# ---------------------------------------------------------------------------
def _build_template(account_id, subnet_id, vpc_id, ami_id):
    short_hash = hashlib.md5(f"{_TIMESTAMP}{account_id}".encode()).hexdigest()[:8]
    trail_bucket = f"sce-react-trail-{short_hash}"
    attacker_role_name = f"sce-react-atk-{_TIMESTAMP}"
    lambda_role_name = f"sce-react-lmb-{_TIMESTAMP}"

    lambda_code = _lambda_code()

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 Reactive Probe - IMDS downgrade auto-remediation (v2)",
        "Resources": {
            "SG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE 1.8 reactive - no ingress",
                    "VpcId": vpc_id,
                    "SecurityGroupIngress": [],
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "InstanceType": "t3.micro",
                    "ImageId": ami_id,
                    "SubnetId": subnet_id,
                    "SecurityGroupIds": [{"Fn::GetAtt": ["SG", "GroupId"]}],
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpEndpoint": "enabled",
                        "HttpPutResponseHopLimit": 1,
                    },
                    "Tags": [{"Key": "Name", "Value": f"sce-1-8-react-{_TIMESTAMP}"},
                             {"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "TrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": trail_bucket,
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "TrailBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "TrailBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "CTAcl",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:GetBucketAcl",
                                "Resource": {"Fn::Sub": "arn:aws:s3:::${TrailBucket}"},
                            },
                            {
                                "Sid": "CTWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {"Fn::Sub": "arn:aws:s3:::${TrailBucket}/AWSLogs/${AWS::AccountId}/*"},
                                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                            },
                        ],
                    },
                },
            },
            "Trail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": "TrailBucketPolicy",
                "Properties": {
                    "TrailName": f"sce-react-1-8-{_TIMESTAMP}",
                    "S3BucketName": {"Ref": "TrailBucket"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": True,
                    "EnableLogFileValidation": True,
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "RemediationTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": f"sce-react-1-8-{_TIMESTAMP}",
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "RemediationQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": f"sce-react-1-8-{_TIMESTAMP}",
                    "MessageRetentionPeriod": 3600,
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "RemediationQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowSNS",
                                "Effect": "Allow",
                                "Principal": {"Service": "sns.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["RemediationQueue", "Arn"]},
                                "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "RemediationTopic"}}},
                            }
                        ],
                    },
                },
            },
            "SNSSub": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "Protocol": "sqs",
                    "TopicArn": {"Ref": "RemediationTopic"},
                    "Endpoint": {"Fn::GetAtt": ["RemediationQueue", "Arn"]},
                    "RawMessageDelivery": "false",
                },
            },
            "AttackerAllowPolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": f"sce-react-1-8-allow-{_TIMESTAMP}",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "ec2:DescribeInstances",
                                    "ec2:ModifyInstanceMetadataOptions",
                                ],
                                "Resource": "*",
                            }
                        ],
                    },
                },
            },
            "AttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": attacker_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [{"Ref": "AttackerAllowPolicy"}],
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": lambda_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "sce-react-lambda-perms",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:ModifyInstanceMetadataOptions",
                                            "ec2:DescribeInstances",
                                        ],
                                        "Resource": "*",
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": ["iam:PutRolePolicy"],
                                        "Resource": {"Fn::GetAtt": ["AttackerRole", "Arn"]},
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": "sns:Publish",
                                        "Resource": {"Ref": "RemediationTopic"},
                                    },
                                ],
                            },
                        }
                    ],
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "RemediationFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": f"sce-react-1-8-{_TIMESTAMP}",
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 120,
                    "MemorySize": 256,
                    "Environment": {
                        "Variables": {
                            "SNS_TOPIC_ARN": {"Ref": "RemediationTopic"},
                            "ATTACKER_ROLE_NAME": attacker_role_name,
                            "TARGET_INSTANCE_ID": {"Ref": "Instance"},
                        }
                    },
                    "Code": {
                        "ZipFile": lambda_code,
                    },
                    "Tags": [{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                             {"Key": "timestamp", "Value": _TIMESTAMP}],
                },
            },
            "EventRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": f"sce-react-1-8-{_TIMESTAMP}",
                    "Description": "Trigger reactive remediation on ModifyInstanceMetadataOptions",
                    "State": "ENABLED",
                    "EventPattern": {
                        "source": ["aws.ec2"],
                        "detail-type": ["AWS API Call via CloudTrail"],
                        "detail": {
                            "eventName": ["ModifyInstanceMetadataOptions"],
                        },
                    },
                    "Targets": [
                        {
                            "Id": "lambda-target",
                            "Arn": {"Fn::GetAtt": ["RemediationFunction", "Arn"]},
                        }
                    ],
                },
            },
            "LambdaInvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "RemediationFunction"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["EventRule", "Arn"]},
                },
            },
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "Instance"}},
            "AttackerRoleArn": {"Value": {"Fn::GetAtt": ["AttackerRole", "Arn"]}},
            "AttackerRoleName": {"Value": attacker_role_name},
            "QueueUrl": {"Value": {"Ref": "RemediationQueue"}},
            "TrailBucket": {"Value": {"Ref": "TrailBucket"}},
            "LambdaFunctionName": {"Value": {"Ref": "RemediationFunction"}},
            "EventRuleName": {"Value": {"Ref": "EventRule"}},
            "LambdaRoleArn": {"Value": {"Fn::GetAtt": ["LambdaRole", "Arn"]}},
        },
    }
    return json.dumps(template)


# ---------------------------------------------------------------------------
# Pre-flight verification helpers
# ---------------------------------------------------------------------------
def _verify_lambda_deployed():
    """Verify Lambda function exists and is active."""
    fn_name = _STACK_OUTPUTS.get("LambdaFunctionName", "")
    if not fn_name:
        logger.error("No LambdaFunctionName in outputs.")
        return False
    try:
        resp = _lambda().get_function(FunctionName=fn_name)
        state = resp["Configuration"]["State"]
        logger.info("Lambda %s state: %s", fn_name, state)
        if state != "Active":
            logger.warning("Lambda not Active yet, waiting...")
            time.sleep(10)
            resp = _lambda().get_function(FunctionName=fn_name)
            state = resp["Configuration"]["State"]
            logger.info("Lambda %s state after wait: %s", fn_name, state)
        return state == "Active"
    except ClientError as exc:
        logger.error("Lambda verification failed: %s", exc)
        return False


def _verify_eventbridge_rule():
    """Verify EventBridge rule is ENABLED."""
    rule_name = _STACK_OUTPUTS.get("EventRuleName", "")
    if not rule_name:
        logger.error("No EventRuleName in outputs.")
        return False
    try:
        resp = _events().describe_rule(Name=rule_name)
        state = resp["State"]
        logger.info("EventBridge rule %s state: %s", rule_name, state)
        return state == "ENABLED"
    except ClientError as exc:
        logger.error("EventBridge rule verification: %s", exc)
        return False


def _test_lambda_invocation():
    """Dry-run the Lambda with a non-matching event to verify it can execute."""
    fn_name = _STACK_OUTPUTS.get("LambdaFunctionName", "")
    if not fn_name:
        return False
    test_event = {
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.ec2",
        "detail": {
            "eventName": "DescribeInstances",
            "requestParameters": {}
        }
    }
    try:
        resp = _lambda().invoke(
            FunctionName=fn_name,
            InvocationType="RequestResponse",
            Payload=json.dumps(test_event).encode(),
        )
        status = resp["StatusCode"]
        payload = json.loads(resp["Payload"].read().decode())
        logger.info("Lambda dry-run: status=%d payload=%s", status, payload)
        if "FunctionError" in resp:
            logger.error("Lambda dry-run had FunctionError: %s", resp["FunctionError"])
            return False
        return status == 200
    except ClientError as exc:
        logger.error("Lambda dry-run invoke failed: %s", exc)
        return False


def _check_lambda_logs():
    """Check recent Lambda CloudWatch logs for errors (diagnostic)."""
    fn_name = _STACK_OUTPUTS.get("LambdaFunctionName", "")
    if not fn_name:
        return
    log_group = f"/aws/lambda/{fn_name}"
    try:
        resp = _logs().describe_log_streams(
            logGroupName=log_group,
            orderBy="LastEventTime",
            descending=True,
            limit=3,
        )
        for stream in resp.get("logStreams", []):
            stream_name = stream["logStreamName"]
            events = _logs().get_log_events(
                logGroupName=log_group,
                logStreamName=stream_name,
                limit=20,
                startFromHead=False,
            )
            for evt in events.get("events", []):
                msg = evt.get("message", "").strip()
                if msg:
                    level = "ERROR" if "ERROR" in msg or "error" in msg.lower() else "INFO"
                    logger.info("  [Lambda %s] %s", level, msg[:200])
    except ClientError as exc:
        if "ResourceNotFoundException" in str(exc):
            logger.info("  No Lambda log group yet (function may not have been invoked).")
        else:
            logger.warning("  Lambda log check: %s", exc)


# ---------------------------------------------------------------------------
# 1. steady_state
# ---------------------------------------------------------------------------
def steady_state():
    global _STACK_OUTPUTS
    logger.info("=" * 70)
    logger.info("STEADY STATE: Provisioning for SCE 1.8 Reactive Probe (v2)")
    logger.info("Stack: %s", _STACK_NAME)
    logger.info("=" * 70)

    cfn = _cfn()
    acct = _account_id()
    subnet_id, vpc_id = _get_subnet()
    if not subnet_id:
        raise RuntimeError("No subnet found.")
    ami_id = _get_ami()
    if not ami_id:
        raise RuntimeError("No AMI found.")
    logger.info("Account=%s Subnet=%s VPC=%s AMI=%s", acct, subnet_id, vpc_id, ami_id)

    tpl = _build_template(acct, subnet_id, vpc_id, ami_id)

    # Handle existing stack
    try:
        resp = cfn.describe_stacks(StackName=_STACK_NAME)
        st = resp["Stacks"][0]["StackStatus"]
        if st in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            logger.warning("Stack exists (%s). Reusing.", st)
            _STACK_OUTPUTS = _stack_outputs(_STACK_NAME)
            return True
        if "IN_PROGRESS" in st:
            _wait_stack(_STACK_NAME, "CREATE_COMPLETE")
            _STACK_OUTPUTS = _stack_outputs(_STACK_NAME)
            return True
        logger.warning("Stack in %s, deleting.", st)
        cfn.delete_stack(StackName=_STACK_NAME)
        _wait_stack(_STACK_NAME, "DELETE_COMPLETE", timeout=600)
    except ClientError as exc:
        if "does not exist" not in str(exc):
            logger.error("Stack check: %s", exc)

    logger.info("Creating stack...")
    try:
        cfn.create_stack(
            StackName=_STACK_NAME,
            TemplateBody=tpl,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[{"Key": "experiment", "Value": _EXPERIMENT_TAG},
                  {"Key": "timestamp", "Value": _TIMESTAMP}],
            TimeoutInMinutes=15,
        )
    except ClientError as exc:
        if "AlreadyExistsException" in str(exc):
            logger.warning("Stack race. Continuing.")
        else:
            raise

    if not _wait_stack(_STACK_NAME, "CREATE_COMPLETE", timeout=900):
        raise RuntimeError("Stack creation failed.")

    _STACK_OUTPUTS = _stack_outputs(_STACK_NAME)
    logger.info("Outputs: %s", _STACK_OUTPUTS)

    # Wait IAM propagation for attacker role
    role_arn = _STACK_OUTPUTS.get("AttackerRoleArn")
    if role_arn:
        start = _ts()
        while (_ts() - start) < 120:
            try:
                _sts().assume_role(RoleArn=role_arn, RoleSessionName="prop", DurationSeconds=900)
                logger.info("Attacker role assumable.")
                break
            except ClientError:
                time.sleep(10)
    else:
        raise RuntimeError("AttackerRoleArn not in outputs.")

    # Wait for instance running
    iid = _STACK_OUTPUTS.get("InstanceId")
    if iid:
        logger.info("Waiting for instance %s...", iid)
        try:
            _ec2().get_waiter("instance_running").wait(
                InstanceIds=[iid], WaiterConfig={"Delay": 15, "MaxAttempts": 40}
            )
        except WaiterError as exc:
            logger.error("Instance wait: %s", exc)
            raise
    else:
        raise RuntimeError("InstanceId not in outputs.")

    # Verify initial IMDS state
    resp = _ec2().describe_instances(InstanceIds=[iid])
    md = resp["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
    logger.info("Initial IMDS: HttpTokens=%s HopLimit=%s",
                md.get("HttpTokens"), md.get("HttpPutResponseHopLimit"))

    # Pre-flight checks
    logger.info("Running pre-flight checks...")

    if not _verify_lambda_deployed():
        logger.error("PRE-FLIGHT FAIL: Lambda function not deployed/active.")
        raise RuntimeError("Lambda pre-flight check failed.")

    if not _verify_eventbridge_rule():
        logger.error("PRE-FLIGHT FAIL: EventBridge rule not enabled.")
        raise RuntimeError("EventBridge rule pre-flight check failed.")

    if not _test_lambda_invocation():
        logger.error("PRE-FLIGHT FAIL: Lambda dry-run invocation failed.")
        raise RuntimeError("Lambda dry-run pre-flight check failed.")

    logger.info("All pre-flight checks passed.")

    # Extended stabilisation for CloudTrail → EventBridge pipeline
    logger.info("Allowing 60s for CloudTrail/EventBridge pipeline stabilisation...")
    time.sleep(60)

    logger.info("STEADY STATE complete.")
    return True


# ---------------------------------------------------------------------------
# 2. attack
# ---------------------------------------------------------------------------
def attack() -> bool:
    global _ATTACK_RESULTS, _ATTACK_TIME
    logger.info("=" * 70)
    logger.info("ATTACK: Executing steps 1.2 and 1.7")
    logger.info("=" * 70)

    role_arn = _STACK_OUTPUTS.get("AttackerRoleArn")
    iid = _STACK_OUTPUTS.get("InstanceId")
    if not role_arn or not iid:
        logger.error("Missing outputs.")
        return True

    creds = _sts().assume_role(
        RoleArn=role_arn, RoleSessionName=f"sce-atk-{_TIMESTAMP}", DurationSeconds=900
    )["Credentials"]

    ec2a = boto3.client(
        "ec2", region_name=_REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        config=_BOTO_CFG,
    )

    # --- Step 1.2: DescribeInstances ---
    logger.info("STEP 1.2: ec2:DescribeInstances (T1580)")
    s12 = {"executed": True, "success": False, "error": None}
    try:
        resp = ec2a.describe_instances(InstanceIds=[iid])
        md = resp["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
        s12["success"] = True
        s12["data"] = {"HttpTokens": md.get("HttpTokens"), "HopLimit": md.get("HttpPutResponseHopLimit")}
        logger.info("  SUCCEEDED: %s", s12["data"])
    except ClientError as exc:
        s12["error"] = str(exc)
        logger.error("  FAILED: %s", exc)
    _ATTACK_RESULTS["step_1_2"] = s12

    time.sleep(2)

    # --- Step 1.7: ModifyInstanceMetadataOptions ---
    logger.info("STEP 1.7: ec2:ModifyInstanceMetadataOptions (T1562.001)")
    s17 = {"executed": True, "success": False, "error": None}
    try:
        resp = ec2a.modify_instance_metadata_options(
            InstanceId=iid,
            HttpTokens="optional",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=2,
        )
        s17["success"] = True
        md = resp.get("InstanceMetadataOptions", {})
        s17["data"] = {"HttpTokens": md.get("HttpTokens"), "HopLimit": md.get("HttpPutResponseHopLimit")}
        logger.info("  SUCCEEDED (IMDS downgraded): %s", s17["data"])
    except ClientError as exc:
        s17["error"] = str(exc)
        logger.error("  FAILED: %s", exc)
    _ATTACK_RESULTS["step_1_7"] = s17

    _ATTACK_TIME = _ts()
    logger.info("ATTACK complete at monotonic=%.1f. Results: %s",
                _ATTACK_TIME, json.dumps(_ATTACK_RESULTS, indent=2))
    return True


# ---------------------------------------------------------------------------
# 3. hypothesis_verification
# ---------------------------------------------------------------------------
def hypothesis_verification() -> bool:
    """
    Verify three reactive outcomes within 30-minute SLA:
      CHECK 1 – IMDS restored to required / hop-limit=1
      CHECK 2 – Attacker role has inline deny-all policy
      CHECK 3 – Remediation notification on SQS
    All checks use per-call exception handling so a transient timeout
    does not abort the entire verification loop.
    """
    logger.info("=" * 70)
    logger.info("HYPOTHESIS VERIFICATION: Reactive Probe SCE 1.8 (v2)")
    logger.info("=" * 70)

    iid = _STACK_OUTPUTS.get("InstanceId", "")
    attacker_role_name = _STACK_OUTPUTS.get("AttackerRoleName", "")
    queue_url = _STACK_OUTPUTS.get("QueueUrl", "")

    checks = {
        "imds_restored": False,
        "role_denied": False,
        "sns_notification": False,
    }
    check_times = {}  # elapsed seconds when each check passed

    sla_start = _ts()
    diagnostics_last = 0.0  # last time we ran diagnostics
    diagnostics_interval = 120.0  # run diagnostics every 2 min

    while (_ts() - sla_start) < _SLA_TIMEOUT:
        elapsed = _ts() - sla_start
        remaining = _SLA_TIMEOUT - elapsed
        if all(checks.values()):
            break
        logger.info("--- Poll (%.0fs elapsed, %.0fs remaining) checks=%s ---",
                     elapsed, remaining, checks)

        # CHECK 1: IMDS restored
        if not checks["imds_restored"] and iid:
            try:
                resp = _safe_call(
                    lambda: _ec2().describe_instances(InstanceIds=[iid]),
                    "DescribeInstances for IMDS check"
                )
                if resp:
                    instances = resp.get("Reservations", [{}])[0].get("Instances", [])
                    if instances:
                        md = instances[0].get("MetadataOptions", {})
                        ht = md.get("HttpTokens", "")
                        hl = md.get("HttpPutResponseHopLimit", -1)
                        logger.info("  IMDS: HttpTokens=%s HopLimit=%s", ht, hl)
                        if ht == "required" and hl == 1:
                            checks["imds_restored"] = True
                            check_times["imds_restored"] = elapsed
                            logger.info("  CHECK 1 PASS: IMDS restored (%.0fs elapsed).", elapsed)
            except (ClientError, ConnectTimeoutError, ReadTimeoutError,
                    EndpointConnectionError) as exc:
                logger.warning("  CHECK 1 transient error: %s", exc)

        # CHECK 2: Deny-all inline policy on attacker role
        if not checks["role_denied"] and attacker_role_name:
            try:
                resp = _safe_call(
                    lambda: _iam().list_role_policies(RoleName=attacker_role_name),
                    "ListRolePolicies"
                )
                if resp:
                    policies = resp.get("PolicyNames", [])
                    if "sce-reactive-deny-all" in policies:
                        pol_resp = _safe_call(
                            lambda: _iam().get_role_policy(
                                RoleName=attacker_role_name,
                                PolicyName="sce-reactive-deny-all",
                            ),
                            "GetRolePolicy"
                        )
                        if pol_resp:
                            doc = pol_resp.get("PolicyDocument", {})
                            if isinstance(doc, str):
                                doc = json.loads(doc)
                            stmts = doc.get("Statement", [])
                            for stmt in stmts:
                                if stmt.get("Effect") == "Deny" and stmt.get("Action") == "*":
                                    checks["role_denied"] = True
                                    check_times["role_denied"] = elapsed
                                    logger.info("  CHECK 2 PASS: Deny-all policy found (%.0fs elapsed).", elapsed)
                                    break
            except (ClientError, ConnectTimeoutError, ReadTimeoutError,
                    EndpointConnectionError) as exc:
                logger.warning("  CHECK 2 transient error: %s", exc)

        # CHECK 3: SQS remediation notification
        if not checks["sns_notification"] and queue_url:
            try:
                resp = _safe_call(
                    lambda: _sqs().receive_message(
                        QueueUrl=queue_url,
                        MaxNumberOfMessages=10,
                        WaitTimeSeconds=5,
                        VisibilityTimeout=30,
                    ),
                    "SQS ReceiveMessage"
                )
                if resp:
                    for msg in resp.get("Messages", []):
                        body_str = msg.get("Body", "{}")
                        try:
                            body = json.loads(body_str)
                        except json.JSONDecodeError:
                            body = {}
                        inner_str = body.get("Message", body_str)
                        if isinstance(inner_str, str):
                            try:
                                inner = json.loads(inner_str)
                            except (json.JSONDecodeError, TypeError):
                                inner = {}
                        else:
                            inner = inner_str

                        if isinstance(inner, dict):
                            if (inner.get("event") == "remediation_complete" and
                                    inner.get("instance_id") == iid):
                                checks["sns_notification"] = True
                                check_times["sns_notification"] = elapsed
                                logger.info("  CHECK 3 PASS: Remediation notification received "
                                            "(%.0fs elapsed). Actions: %s",
                                            elapsed, inner.get("actions"))
                                try:
                                    _sqs().delete_message(
                                        QueueUrl=queue_url,
                                        ReceiptHandle=msg["ReceiptHandle"]
                                    )
                                except Exception:
                                    pass
                                break

                        full = json.dumps(body) if isinstance(body, dict) else body_str
                        if "remediation_complete" in full and iid in full:
                            checks["sns_notification"] = True
                            check_times["sns_notification"] = elapsed
                            logger.info("  CHECK 3 PASS: Remediation notification (string match, "
                                        "%.0fs elapsed).", elapsed)
                            try:
                                _sqs().delete_message(
                                    QueueUrl=queue_url,
                                    ReceiptHandle=msg["ReceiptHandle"]
                                )
                            except Exception:
                                pass
                            break
            except (ClientError, ConnectTimeoutError, ReadTimeoutError,
                    EndpointConnectionError) as exc:
                logger.warning("  CHECK 3 transient error: %s", exc)

        if all(checks.values()):
            break

        # Periodic diagnostics
        if (elapsed - diagnostics_last) >= diagnostics_interval:
            diagnostics_last = elapsed
            logger.info("  --- DIAGNOSTICS (%.0fs elapsed) ---", elapsed)
            _check_lambda_logs()
            # Check EventBridge rule invocation count
            try:
                rule_name = _STACK_OUTPUTS.get("EventRuleName", "")
                if rule_name:
                    import datetime
                    now = datetime.datetime.now(datetime.timezone.utc)
                    cw_resp = _cw().get_metric_statistics(
                        Namespace="AWS/Events",
                        MetricName="Invocations",
                        Dimensions=[{"Name": "RuleName", "Value": rule_name}],
                        StartTime=now - datetime.timedelta(minutes=30),
                        EndTime=now,
                        Period=300,
                        Statistics=["Sum"],
                    )
                    dp = cw_resp.get("Datapoints", [])
                    total = sum(d.get("Sum", 0) for d in dp)
                    logger.info("  EventBridge rule %s invocations (last 30m): %.0f", rule_name, total)
            except Exception as exc:
                logger.warning("  EventBridge metrics check: %s", exc)

        time.sleep(_POLL_INTERVAL)

    # Final evaluation
    logger.info("=" * 70)
    logger.info("VERIFICATION RESULTS:")
    all_passed = True
    for name, passed in checks.items():
        status = "PASS" if passed else "FAIL"
        elapsed_str = f" ({check_times[name]:.0f}s)" if name in check_times else ""
        logger.info("  %s: %s%s", name, status, elapsed_str)
        if not passed:
            all_passed = False

    if not all_passed:
        logger.info("--- Final diagnostics ---")
        _check_lambda_logs()

    if not checks["imds_restored"]:
        logger.error("IMDS was NOT restored to required/hop=1 within SLA.")
    if not checks["role_denied"]:
        logger.error("Attacker role did NOT receive deny-all inline policy within SLA.")
    if not checks["sns_notification"]:
        logger.error("Remediation SNS notification was NOT received on SQS within SLA.")

    total_elapsed = _ts() - sla_start
    logger.info("OVERALL: %s (total verification time: %.0fs)",
                "PASS" if all_passed else "FAIL", total_elapsed)
    logger.info("=" * 70)
    return all_passed


# ---------------------------------------------------------------------------
# 4. rollback
# ---------------------------------------------------------------------------
def rollback():
    logger.info("=" * 70)
    logger.info("ROLLBACK: Tearing down %s", _STACK_NAME)
    logger.info("=" * 70)

    cfn = _cfn()
    iid = _STACK_OUTPUTS.get("InstanceId")
    attacker_role_name = _STACK_OUTPUTS.get("AttackerRoleName")

    # Remove the inline policy that Lambda added (not managed by CFN)
    if attacker_role_name:
        try:
            _iam().delete_role_policy(
                RoleName=attacker_role_name,
                PolicyName="sce-reactive-deny-all",
            )
            logger.info("Removed reactive deny-all inline policy from %s.", attacker_role_name)
        except ClientError as exc:
            logger.warning("Remove inline policy: %s", exc)

    # Revert IMDS (best effort)
    if iid:
        try:
            _ec2().modify_instance_metadata_options(
                InstanceId=iid,
                HttpTokens="required",
                HttpEndpoint="enabled",
                HttpPutResponseHopLimit=1,
            )
            logger.info("Reverted IMDS on %s.", iid)
        except ClientError as exc:
            logger.warning("IMDS revert: %s", exc)

    # Terminate instance to speed up stack deletion
    if iid:
        try:
            _ec2().terminate_instances(InstanceIds=[iid])
            logger.info("Terminated %s.", iid)
        except ClientError as exc:
            logger.warning("Terminate: %s", exc)

    # Empty S3 bucket
    bname = _STACK_OUTPUTS.get("TrailBucket")
    if bname:
        try:
            s3 = boto3.resource("s3", region_name=_REGION)
            bucket = s3.Bucket(bname)
            bucket.objects.all().delete()
            bucket.object_versions.all().delete()
            logger.info("Emptied bucket %s.", bname)
        except ClientError as exc:
            logger.warning("Empty bucket %s: %s", bname, exc)

    # Delete stack
    try:
        cfn.delete_stack(StackName=_STACK_NAME)
        logger.info("Stack deletion initiated.")
    except ClientError as exc:
        if "does not exist" in str(exc):
            logger.info("Stack already gone.")
            return True
        logger.error("delete_stack: %s", exc)
        return False

    ok = _wait_stack(_STACK_NAME, "DELETE_COMPLETE", timeout=900)
    if ok:
        logger.info("ROLLBACK complete.")
    else:
        logger.error("ROLLBACK may have failed. Manual cleanup needed for %s.", _STACK_NAME)
    return ok


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logger.info("SCE 1.8 Reactive Probe v2 – IMDS Downgrade Auto-Remediation")
    try:
        steady_state()
        attack()
        result = hypothesis_verification()
        sys.exit(0 if result else 1)
    except Exception as exc:
        logger.exception("Unhandled: %s", exc)
        sys.exit(2)
    finally:
        try:
            rollback()
        except Exception as exc:
            logger.exception("Rollback error: %s", exc)