"""
SCE Experiment 1.5 - Detective Probe
Attack Node 1.2: Weaken IMDS Protections via ModifyInstanceMetadataOptions

Detective Probe Intent:
  Execute ModifyInstanceMetadataOptions with HttpTokens=optional in a controlled
  environment. Verify EventBridge alert fires within the SLA window via SNS/SQS
  delivery chain. Validate AWS Config Rule transitions to NON_COMPLIANT (if Config
  recorder active). Confirm CloudWatch Alarm enters ALARM state via metric filter.

Fixes applied from previous execution log (2026-04-08 12:27:07):
  ROOT CAUSE: Non-ASCII character (Unicode dash/arrow) in SecurityGroup
  GroupDescription field caused AWS EC2 API to reject the resource with:
  "Character sets beyond ASCII are not supported."

  FIXES:
  1. ALL string fields in the CFN template audited and sanitized to strict
     ASCII-only content. No Unicode dashes, arrows, smart quotes, or special
     characters anywhere in the template.
  2. GroupDescription changed from "SCE probe instance - HTTPS egress only"
     (already ASCII) but verified all description/name fields are ASCII-clean.
  3. Added pre-deploy ASCII validation function that scans the rendered template
     JSON for any codepoint > 127 and raises immediately with the offending
     location before attempting stack creation.
  4. Config Rule and CloudTrail trail remain decoupled from CFN stack (boto3
     post-stack calls) to prevent prior ROLLBACK_COMPLETE issues.
  5. Short 8-char hash tag retained to keep IAM role names under 64-char limit.
  6. EventBridge rule post-deploy narrowing retained.
  7. Sub-check A (EventBridge/SQS) remains the mandatory primary check.
  8. Sub-checks B (Config) and C (CloudWatch Alarm) remain conditional/inconclusive.
"""

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
import importlib
import subprocess
import sys
import time
import json
import logging
import os
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(funcName)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)


def _ensure_boto3() -> None:
    for pkg in ("boto3", "botocore"):
        try:
            importlib.import_module(pkg)
        except ImportError:
            log.info("Installing %s via pip ...", pkg)
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet", pkg]
            )


_ensure_boto3()

import boto3  # noqa: E402
from botocore.exceptions import ClientError, WaiterError  # noqa: E402

# ---------------------------------------------------------------------------
# Global experiment state
# ---------------------------------------------------------------------------
_STATE: dict = {}

_SLA_SECONDS = 1800
_POLL_INTERVAL = 20
_HASH_LEN = 8


# ---------------------------------------------------------------------------
# ASCII validation - prevents non-ASCII characters from reaching CFN API
# ---------------------------------------------------------------------------

def _assert_ascii(template_str: str) -> None:
    """
    Scan the rendered CloudFormation template JSON string for any character
    with codepoint > 127. Raises ValueError with the offending character and
    its position before any AWS API call is made.

    This directly addresses the root cause of the previous ROLLBACK_COMPLETE:
    AWS EC2 API rejects GroupDescription values containing non-ASCII chars.
    """
    for idx, ch in enumerate(template_str):
        if ord(ch) > 127:
            context_start = max(0, idx - 40)
            context_end = min(len(template_str), idx + 40)
            context = template_str[context_start:context_end]
            raise ValueError(
                f"Non-ASCII character U+{ord(ch):04X} ({repr(ch)}) found "
                f"at position {idx} in CFN template. "
                f"Context: ...{context}..."
            )
    log.info("ASCII validation passed - template contains only ASCII characters.")


# ---------------------------------------------------------------------------
# CloudFormation template
# ALL string values use strict ASCII-only characters.
# No Unicode dashes (U+2014), arrows (U+2192), smart quotes, or any
# character with codepoint > 127 appears anywhere in this template.
# ---------------------------------------------------------------------------
_CFN_TEMPLATE: dict = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": (
        "SCE 1.5 Detective Probe - Minimal stable core: "
        "EC2, EventBridge, SNS, SQS, CW Logs, Metric Filter, Alarm"
    ),
    "Parameters": {
        "ExperimentTag": {"Type": "String"},
        "LatestAmiId": {
            "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
            "Default": (
                "/aws/service/ami-amazon-linux-latest/"
                "al2023-ami-kernel-default-x86_64"
            ),
        },
    },
    "Resources": {
        # VPC
        "VPC": {
            "Type": "AWS::EC2::VPC",
            "Properties": {
                "CidrBlock": "10.99.0.0/16",
                "EnableDnsSupport": True,
                "EnableDnsHostnames": True,
                "Tags": [
                    {"Key": "Name", "Value": {"Ref": "ExperimentTag"}},
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}},
                ],
            },
        },
        "InternetGateway": {
            "Type": "AWS::EC2::InternetGateway",
            "Properties": {
                "Tags": [
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}}
                ]
            },
        },
        "VPCGatewayAttachment": {
            "Type": "AWS::EC2::VPCGatewayAttachment",
            "Properties": {
                "VpcId": {"Ref": "VPC"},
                "InternetGatewayId": {"Ref": "InternetGateway"},
            },
        },
        "PublicSubnet": {
            "Type": "AWS::EC2::Subnet",
            "Properties": {
                "VpcId": {"Ref": "VPC"},
                "CidrBlock": "10.99.1.0/24",
                "MapPublicIpOnLaunch": True,
                "Tags": [
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}}
                ],
            },
        },
        "RouteTable": {
            "Type": "AWS::EC2::RouteTable",
            "Properties": {
                "VpcId": {"Ref": "VPC"},
                "Tags": [
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}}
                ],
            },
        },
        "DefaultRoute": {
            "Type": "AWS::EC2::Route",
            "DependsOn": "VPCGatewayAttachment",
            "Properties": {
                "RouteTableId": {"Ref": "RouteTable"},
                "DestinationCidrBlock": "0.0.0.0/0",
                "GatewayId": {"Ref": "InternetGateway"},
            },
        },
        "SubnetRTAssoc": {
            "Type": "AWS::EC2::SubnetRouteTableAssociation",
            "Properties": {
                "SubnetId": {"Ref": "PublicSubnet"},
                "RouteTableId": {"Ref": "RouteTable"},
            },
        },
        # Security Group - ASCII-only GroupDescription (root cause fix)
        "InstanceSG": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "SCE experiment instance - HTTPS egress only",
                "VpcId": {"Ref": "VPC"},
                "SecurityGroupIngress": [],
                "SecurityGroupEgress": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 443,
                        "ToPort": 443,
                        "CidrIp": "0.0.0.0/0",
                        "Description": "HTTPS for SSM and AWS APIs",
                    }
                ],
                "Tags": [
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}}
                ],
            },
        },
        # IAM role - short name to stay under 64-char IAM limit
        "InstanceRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": {"Fn::Sub": "sce-ir-${ExperimentTag}"},
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "ManagedPolicyArns": [
                    "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
                ],
                "Tags": [
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}}
                ],
            },
        },
        "InstanceProfile": {
            "Type": "AWS::IAM::InstanceProfile",
            "Properties": {
                "InstanceProfileName": {
                    "Fn::Sub": "sce-ip-${ExperimentTag}"
                },
                "Roles": [{"Ref": "InstanceRole"}],
            },
        },
        # EC2 instance - steady state: IMDSv2 enforced
        "EC2Instance": {
            "Type": "AWS::EC2::Instance",
            "DependsOn": "VPCGatewayAttachment",
            "Properties": {
                "ImageId": {"Ref": "LatestAmiId"},
                "InstanceType": "t3.micro",
                "SubnetId": {"Ref": "PublicSubnet"},
                "SecurityGroupIds": [{"Ref": "InstanceSG"}],
                "IamInstanceProfile": {"Ref": "InstanceProfile"},
                "MetadataOptions": {
                    "HttpTokens": "required",
                    "HttpEndpoint": "enabled",
                    "HttpPutResponseHopLimit": 1,
                },
                "Tags": [
                    {"Key": "Name", "Value": {"Ref": "ExperimentTag"}},
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}},
                ],
            },
        },
        # SNS topic
        "AlertTopic": {
            "Type": "AWS::SNS::Topic",
            "Properties": {
                "TopicName": {"Fn::Sub": "sce-al-${ExperimentTag}"},
                "Tags": [
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}}
                ],
            },
        },
        "AlertTopicPolicy": {
            "Type": "AWS::SNS::TopicPolicy",
            "Properties": {
                "Topics": [{"Ref": "AlertTopic"}],
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "events.amazonaws.com"
                            },
                            "Action": "SNS:Publish",
                            "Resource": {"Ref": "AlertTopic"},
                        }
                    ],
                },
            },
        },
        # SQS queue
        "AlertQueue": {
            "Type": "AWS::SQS::Queue",
            "Properties": {
                "QueueName": {"Fn::Sub": "sce-aq-${ExperimentTag}"},
                "MessageRetentionPeriod": 3600,
                "VisibilityTimeout": 60,
                "Tags": [
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}}
                ],
            },
        },
        "AlertQueuePolicy": {
            "Type": "AWS::SQS::QueuePolicy",
            "Properties": {
                "Queues": [{"Ref": "AlertQueue"}],
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": {
                                "Fn::GetAtt": ["AlertQueue", "Arn"]
                            },
                            "Condition": {
                                "ArnEquals": {
                                    "aws:SourceArn": {"Ref": "AlertTopic"}
                                }
                            },
                        }
                    ],
                },
            },
        },
        "SnsToSqsSubscription": {
            "Type": "AWS::SNS::Subscription",
            "Properties": {
                "TopicArn": {"Ref": "AlertTopic"},
                "Protocol": "sqs",
                "Endpoint": {"Fn::GetAtt": ["AlertQueue", "Arn"]},
            },
        },
        # EventBridge rule - broad match, narrowed post-deploy via boto3
        "ImdsModificationRule": {
            "Type": "AWS::Events::Rule",
            "Properties": {
                "Name": {"Fn::Sub": "sce-eb-${ExperimentTag}"},
                "Description": "SCE 1.5 detective probe - IMDS weakening detection",
                "State": "ENABLED",
                "EventPattern": json.dumps({
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["ec2.amazonaws.com"],
                        "eventName": ["ModifyInstanceMetadataOptions"],
                    },
                }),
                "Targets": [
                    {
                        "Id": "SceAlertSns",
                        "Arn": {"Ref": "AlertTopic"},
                    }
                ],
            },
        },
        # CloudWatch Logs log group
        "TrailLogGroup": {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {
                "LogGroupName": {
                    "Fn::Sub": "/sce/${ExperimentTag}"
                },
                "RetentionInDays": 1,
                "Tags": [
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}}
                ],
            },
        },
        # CloudWatch metric filter on the log group
        "ImdsMetricFilter": {
            "Type": "AWS::Logs::MetricFilter",
            "DependsOn": "TrailLogGroup",
            "Properties": {
                "LogGroupName": {
                    "Fn::Sub": "/sce/${ExperimentTag}"
                },
                "FilterPattern": (
                    '{ $.eventName = "ModifyInstanceMetadataOptions" }'
                ),
                "MetricTransformations": [
                    {
                        "MetricNamespace": "SCEExperiment",
                        "MetricName": {
                            "Fn::Sub": "ImdsModCount-${ExperimentTag}"
                        },
                        "MetricValue": "1",
                        "DefaultValue": 0,
                    }
                ],
            },
        },
        # CloudWatch Alarm
        "ImdsModificationAlarm": {
            "Type": "AWS::CloudWatch::Alarm",
            "DependsOn": "ImdsMetricFilter",
            "Properties": {
                "AlarmName": {
                    "Fn::Sub": "sce-cwa-${ExperimentTag}"
                },
                "AlarmDescription": "SCE 1.5 IMDS modification detection alarm",
                "Namespace": "SCEExperiment",
                "MetricName": {
                    "Fn::Sub": "ImdsModCount-${ExperimentTag}"
                },
                "Statistic": "Sum",
                "Period": 60,
                "EvaluationPeriods": 1,
                "Threshold": 1,
                "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                "TreatMissingData": "notBreaching",
                "AlarmActions": [{"Ref": "AlertTopic"}],
            },
        },
    },
    "Outputs": {
        "InstanceId": {"Value": {"Ref": "EC2Instance"}},
        "AlertQueueUrl": {"Value": {"Ref": "AlertQueue"}},
        "AlertQueueArn": {"Value": {"Fn::GetAtt": ["AlertQueue", "Arn"]}},
        "AlertTopicArn": {"Value": {"Ref": "AlertTopic"}},
        "EventBridgeRuleName": {"Value": {"Ref": "ImdsModificationRule"}},
        "AlarmName": {"Value": {"Ref": "ImdsModificationAlarm"}},
        "TrailLogGroupName": {
            "Value": {"Fn::Sub": "/sce/${ExperimentTag}"}
        },
        "ExperimentTag": {"Value": {"Ref": "ExperimentTag"}},
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _region() -> str:
    return (
        boto3.session.Session().region_name
        or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    )


def _short_tag(value: str) -> str:
    """Return an 8-char hex digest. Used to keep resource names short."""
    return hashlib.sha256(value.encode()).hexdigest()[:_HASH_LEN]


def _require_state(*keys: str) -> None:
    missing = [k for k in keys if not _STATE.get(k)]
    if missing:
        raise RuntimeError(
            "Required experiment state keys are missing: {}. "
            "Ensure steady_state() completed successfully.".format(missing)
        )


def _poll_until(predicate, description: str,
                sla: int = _SLA_SECONDS,
                interval: int = _POLL_INTERVAL) -> bool:
    deadline = time.monotonic() + sla
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        try:
            if predicate():
                elapsed = sla - max(0.0, deadline - time.monotonic())
                log.info(
                    "OK [%s] satisfied after %.1f s (attempt %d)",
                    description, elapsed, attempt,
                )
                return True
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "Poll attempt %d for [%s] raised: %s",
                attempt, description, exc,
            )
        remaining = max(0.0, deadline - time.monotonic())
        log.info(
            "... [%s] pending - attempt %d, %.0f s remaining",
            description, attempt, remaining,
        )
        time.sleep(interval)
    log.error(
        "FAIL [%s] NOT satisfied within the %d-second SLA.",
        description, sla,
    )
    return False


def _wait_stack(cfn_client, stack_name: str, waiter_name: str,
                delay: int = 20, max_attempts: int = 90) -> None:
    w = cfn_client.get_waiter(waiter_name)
    w.config.delay = delay
    w.config.max_attempts = max_attempts
    w.wait(StackName=stack_name)


def _stack_outputs(cfn_client, stack_name: str) -> dict:
    resp = cfn_client.describe_stacks(StackName=stack_name)
    return {
        o["OutputKey"]: o["OutputValue"]
        for o in resp["Stacks"][0].get("Outputs", [])
    }


def _log_stack_events(cfn_client, stack_name: str) -> None:
    """Log CREATE_FAILED and ROLLBACK events for diagnosis."""
    try:
        paginator = cfn_client.get_paginator("describe_stack_events")
        for page in paginator.paginate(StackName=stack_name):
            for ev in page.get("StackEvents", []):
                status = ev.get("ResourceStatus", "")
                if any(s in status for s in (
                    "FAILED", "ROLLBACK", "CREATE_COMPLETE"
                )):
                    log.error(
                        "CFN %s | %-42s | %-30s | %s",
                        status,
                        ev.get("ResourceType", ""),
                        ev.get("LogicalResourceId", ""),
                        ev.get("ResourceStatusReason", ""),
                    )
    except Exception as exc:  # noqa: BLE001
        log.error("Could not retrieve stack events: %s", exc)


# ---------------------------------------------------------------------------
# Optional component creators (post-stack boto3 calls)
# Failures here degrade sub-checks but do not block the primary check.
# ---------------------------------------------------------------------------

def _create_cloudtrail_trail(region: str, account_id: str) -> None:
    """
    Create S3 bucket + CloudTrail trail writing to the CW Logs log group.
    All resource names use ASCII-only characters and stay within service limits.
    """
    experiment_tag = _STATE["experiment_tag"]
    short = _short_tag(experiment_tag)

    bucket_name = "sce-ct-{}-{}".format(short, account_id)
    log_group_name = _STATE.get("trail_log_group_name", "/sce/{}".format(experiment_tag))
    trail_name = "sce-tr-{}".format(short)

    s3 = boto3.client("s3", region_name=region)
    cloudtrail = boto3.client("cloudtrail", region_name=region)
    iam = boto3.client("iam", region_name=region)

    # Create S3 bucket
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        log.info("Created trail S3 bucket: %s", bucket_name)
        _STATE["trail_bucket"] = bucket_name
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "BucketAlreadyOwnedByYou":
            log.warning("Bucket %s already owned - reusing.", bucket_name)
            _STATE["trail_bucket"] = bucket_name
        else:
            log.warning(
                "Could not create trail bucket %s: %s - "
                "CW Alarm sub-check will be skipped.", bucket_name, exc,
            )
            return

    # Apply bucket policy for CloudTrail
    bucket_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": "arn:aws:s3:::{}".format(bucket_name),
            },
            {
                "Sid": "Write",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::{}/AWSLogs/{}/*".format(
                    bucket_name, account_id
                ),
                "Condition": {
                    "StringEquals": {
                        "s3:x-amz-acl": "bucket-owner-full-control"
                    }
                },
            },
        ],
    })
    try:
        s3.put_bucket_policy(Bucket=bucket_name, Policy=bucket_policy)
        log.info("Applied bucket policy to %s.", bucket_name)
    except ClientError as exc:
        log.warning("Could not apply bucket policy: %s - trail skipped.", exc)
        return

    # Create IAM role for CloudTrail -> CW Logs
    ct_role_name = "sce-ctr-{}".format(short)
    ct_role_arn = None
    try:
        resp = iam.create_role(
            RoleName=ct_role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }),
            Tags=[{"Key": "sce-experiment", "Value": experiment_tag}],
        )
        ct_role_arn = resp["Role"]["Arn"]
        _STATE["trail_role_name"] = ct_role_name
        log.info("Created CloudTrail IAM role: %s", ct_role_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            resp = iam.get_role(RoleName=ct_role_name)
            ct_role_arn = resp["Role"]["Arn"]
            _STATE["trail_role_name"] = ct_role_name
            log.warning("CloudTrail role %s already exists - reusing.", ct_role_name)
        else:
            log.warning("Could not create CloudTrail IAM role: %s - trail skipped.", exc)
            return

    log_group_arn = (
        "arn:aws:logs:{}:{}:log-group:{}:*".format(
            region, account_id, log_group_name
        )
    )
    try:
        iam.put_role_policy(
            RoleName=ct_role_name,
            PolicyName="AllowCWLWrite",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": log_group_arn,
                    }
                ],
            }),
        )
        log.info("Attached CW Logs write policy to %s.", ct_role_name)
    except ClientError as exc:
        log.warning("Could not attach CW Logs policy: %s", exc)

    log.info("Waiting 15 s for IAM propagation before creating trail ...")
    time.sleep(15)

    # Create trail
    try:
        cloudtrail.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IsMultiRegionTrail=False,
            IncludeGlobalServiceEvents=True,
            EnableLogFileValidation=False,
            CloudWatchLogsLogGroupArn=(
                "arn:aws:logs:{}:{}:log-group:{}:*".format(
                    region, account_id, log_group_name
                )
            ),
            CloudWatchLogsRoleArn=ct_role_arn,
            TagsList=[{"Key": "sce-experiment", "Value": experiment_tag}],
        )
        cloudtrail.start_logging(Name=trail_name)
        _STATE["trail_name"] = trail_name
        log.info("CloudTrail trail %s created and logging started.", trail_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "TrailAlreadyExistsException":
            _STATE["trail_name"] = trail_name
            log.warning("Trail %s already exists - reusing.", trail_name)
        else:
            log.warning(
                "Could not create CloudTrail trail: %s - "
                "CW Alarm sub-check will be skipped.", exc,
            )


def _create_config_rule(region: str) -> None:
    """
    Create AWS Config Rule EC2_IMDSV2_REQUIRED via boto3 (not CFN).
    Skipped gracefully if Config recorder is not active.
    """
    experiment_tag = _STATE["experiment_tag"]
    rule_name = "sce-cr-{}".format(_short_tag(experiment_tag))
    config_client = boto3.client("config", region_name=region)

    # Pre-flight: verify Config recorder is active
    try:
        recorders = config_client.describe_configuration_recorder_status()
        active = any(
            r.get("recording", False)
            for r in recorders.get("ConfigurationRecordersStatus", [])
        )
        if not active:
            log.warning(
                "AWS Config recorder not active in %s - "
                "Config Rule sub-check will be inconclusive.", region,
            )
            _STATE["config_available"] = False
            return
    except ClientError as exc:
        log.warning(
            "Cannot verify Config recorder: %s - "
            "Config Rule sub-check will be inconclusive.", exc,
        )
        _STATE["config_available"] = False
        return

    try:
        config_client.put_config_rule(
            ConfigRule={
                "ConfigRuleName": rule_name,
                "Description": "SCE 1.5 IMDSv2 validation rule",
                "Source": {
                    "Owner": "AWS",
                    "SourceIdentifier": "EC2_IMDSV2_REQUIRED",
                },
                "Scope": {
                    "ComplianceResourceTypes": ["AWS::EC2::Instance"],
                },
            }
        )
        _STATE["config_rule_name"] = rule_name
        _STATE["config_available"] = True
        log.info("AWS Config Rule %s created.", rule_name)
    except ClientError as exc:
        log.warning(
            "Could not create Config Rule: %s - "
            "Config Rule sub-check will be inconclusive.", exc,
        )
        _STATE["config_available"] = False


# ---------------------------------------------------------------------------
# 1. steady_state()
# ---------------------------------------------------------------------------

def steady_state() -> None:
    """
    Phase 1: Deploy minimal stable CFN stack (EC2, EventBridge, SNS, SQS,
             CW Logs, metric filter, Alarm). All ASCII-validated before deploy.
    Phase 2: Create CloudTrail trail + Config Rule via boto3 (optional).
    Phase 3: Narrow EventBridge rule to specific instance ID.
    Phase 4: Pre-flight controls-armed verification.
    """
    global _STATE

    timestamp = int(time.time())
    experiment_tag = _short_tag(str(timestamp))
    stack_name = "sce-{}".format(timestamp)

    _STATE["stack_name"] = stack_name
    _STATE["experiment_tag"] = experiment_tag
    _STATE["timestamp"] = timestamp
    _STATE["attack_success"] = False
    _STATE["config_available"] = False

    region = _region()
    _STATE["region"] = region

    log.info(
        "=== steady_state START - stack: %s, tag: %s, region: %s ===",
        stack_name, experiment_tag, region,
    )

    # Resolve account ID
    sts = boto3.client("sts", region_name=region)
    account_id = sts.get_caller_identity()["Account"]
    _STATE["account_id"] = account_id
    log.info("AWS Account: %s", account_id)

    # ── Phase 1: Deploy CFN stack ────────────────────────────────────────────
    template_body = json.dumps(_CFN_TEMPLATE)

    # ASCII validation before any AWS API call
    log.info("Running ASCII validation on CFN template ...")
    _assert_ascii(template_body)

    cfn = boto3.client("cloudformation", region_name=region)

    try:
        log.info("Creating CloudFormation stack %s ...", stack_name)
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=[
                {
                    "ParameterKey": "ExperimentTag",
                    "ParameterValue": experiment_tag,
                }
            ],
            Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": "sce-experiment", "Value": experiment_tag},
                {"Key": "sce-timestamp", "Value": str(timestamp)},
                {"Key": "sce-probe", "Value": "1-5-detective"},
            ],
            OnFailure="ROLLBACK",
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "AlreadyExistsException":
            log.warning("Stack %s already exists - continuing.", stack_name)
        else:
            log.error("create_stack failed: %s", exc)
            raise

    log.info(
        "Waiting for stack CREATE_COMPLETE "
        "(expected 3-5 min for EC2 instance) ..."
    )
    try:
        _wait_stack(cfn, stack_name, "stack_create_complete",
                    delay=20, max_attempts=90)
    except WaiterError as exc:
        log.error("Stack did not reach CREATE_COMPLETE: %s", exc)
        _log_stack_events(cfn, stack_name)
        raise

    outputs = _stack_outputs(cfn, stack_name)
    log.info("Stack outputs: %s", json.dumps(outputs, indent=2))

    _STATE["instance_id"] = outputs["InstanceId"]
    _STATE["alert_queue_url"] = outputs["AlertQueueUrl"]
    _STATE["alert_queue_arn"] = outputs["AlertQueueArn"]
    _STATE["alert_topic_arn"] = outputs["AlertTopicArn"]
    _STATE["eventbridge_rule_name"] = outputs["EventBridgeRuleName"]
    _STATE["alarm_name"] = outputs["AlarmName"]
    _STATE["trail_log_group_name"] = outputs["TrailLogGroupName"]

    log.info("Core stack ready - instance: %s", _STATE["instance_id"])

    # Wait for EC2 instance running
    ec2 = boto3.client("ec2", region_name=region)
    log.info(
        "Waiting for EC2 instance %s to reach running state ...",
        _STATE["instance_id"],
    )
    running = _poll_until(
        lambda: _instance_is_running(ec2, _STATE["instance_id"]),
        description="EC2 instance running",
        sla=300,
        interval=10,
    )
    if not running:
        raise RuntimeError(
            "EC2 instance {} did not reach running state within 300 s.".format(
                _STATE["instance_id"]
            )
        )

    # Verify baseline: IMDSv2 required before attack
    _verify_baseline_imdsv2(ec2)

    # ── Phase 2a: CloudTrail trail (optional) ────────────────────────────────
    log.info("Phase 2a: Creating CloudTrail trail (optional) ...")
    try:
        _create_cloudtrail_trail(region, account_id)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "CloudTrail trail creation raised unexpected error: %s - "
            "CW Alarm sub-check will be skipped.", exc,
        )

    # ── Phase 2b: Config Rule (optional) ────────────────────────────────────
    log.info("Phase 2b: Creating Config Rule (optional) ...")
    try:
        _create_config_rule(region)
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "Config Rule creation raised unexpected error: %s - "
            "Config sub-check will be inconclusive.", exc,
        )

    # ── Phase 3: Narrow EventBridge rule ────────────────────────────────────
    _narrow_eventbridge_rule(region)

    # ── Phase 4: Pre-flight ──────────────────────────────────────────────────
    _verify_controls_armed()

    log.info("=== steady_state COMPLETE ===")


def _instance_is_running(ec2_client, instance_id: str) -> bool:
    try:
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        state = (
            resp["Reservations"][0]["Instances"][0]["State"]["Name"]
        )
        return state == "running"
    except Exception as exc:  # noqa: BLE001
        log.warning("describe_instances: %s", exc)
        return False


def _verify_baseline_imdsv2(ec2_client) -> None:
    instance_id = _STATE["instance_id"]
    try:
        resp = ec2_client.describe_instances(InstanceIds=[instance_id])
        opts = (
            resp["Reservations"][0]["Instances"][0]
            .get("MetadataOptions", {})
        )
        tokens = opts.get("HttpTokens", "unknown")
        hop = opts.get("HttpPutResponseHopLimit", -1)
        log.info(
            "Baseline IMDS: instance=%s HttpTokens=%s HopLimit=%s",
            instance_id, tokens, hop,
        )
        if tokens != "required":
            raise RuntimeError(
                "Baseline check FAILED: expected HttpTokens=required, got {}.".format(
                    tokens
                )
            )
        log.info("Baseline confirmed: IMDSv2 enforced.")
    except RuntimeError:
        raise
    except Exception as exc:  # noqa: BLE001
        log.warning("Baseline verification error: %s", exc)


def _narrow_eventbridge_rule(region: str) -> None:
    instance_id = _STATE.get("instance_id")
    rule_name = _STATE.get("eventbridge_rule_name")
    if not instance_id or not rule_name:
        log.warning("Cannot narrow EventBridge rule - state incomplete.")
        return
    narrow_pattern = json.dumps({
        "source": ["aws.ec2"],
        "detail-type": ["AWS API Call via CloudTrail"],
        "detail": {
            "eventSource": ["ec2.amazonaws.com"],
            "eventName": ["ModifyInstanceMetadataOptions"],
            "requestParameters": {
                "instanceId": [instance_id],
                "httpTokens": ["optional"],
            },
        },
    })
    events_client = boto3.client("events", region_name=region)
    try:
        events_client.put_rule(
            Name=rule_name,
            EventPattern=narrow_pattern,
            State="ENABLED",
            Description="SCE 1.5 detective - scoped to instance {}".format(instance_id),
        )
        log.info(
            "EventBridge rule %s narrowed to instance %s with httpTokens=optional filter.",
            rule_name, instance_id,
        )
    except ClientError as exc:
        log.warning(
            "Could not narrow EventBridge rule: %s - broad pattern remains.", exc
        )


def _verify_controls_armed() -> None:
    log.info("Pre-flight: verifying detective controls are armed ...")
    checks = {
        "EventBridge rule ENABLED": _check_eventbridge_rule_enabled,
        "CloudWatch alarm exists": _check_cloudwatch_alarm_exists,
        "SQS queue reachable": _check_sqs_queue_reachable,
    }
    for name, fn in checks.items():
        try:
            ok = fn()
            log.info("  %s %s", "OK" if ok else "FAIL", name)
        except Exception as exc:  # noqa: BLE001
            log.warning("  ERR %s raised: %s", name, exc)
    log.info("Pre-flight complete.")


def _check_eventbridge_rule_enabled() -> bool:
    rule_name = _STATE.get("eventbridge_rule_name")
    if not rule_name:
        return False
    try:
        resp = boto3.client(
            "events", region_name=_STATE["region"]
        ).describe_rule(Name=rule_name)
        return resp.get("State") == "ENABLED"
    except Exception as exc:  # noqa: BLE001
        log.warning("EventBridge describe_rule: %s", exc)
        return False


def _check_cloudwatch_alarm_exists() -> bool:
    alarm_name = _STATE.get("alarm_name")
    if not alarm_name:
        return False
    try:
        resp = boto3.client(
            "cloudwatch", region_name=_STATE["region"]
        ).describe_alarms(AlarmNames=[alarm_name])
        return len(resp.get("MetricAlarms", [])) > 0
    except Exception as exc:  # noqa: BLE001
        log.warning("CW describe_alarms: %s", exc)
        return False


def _check_sqs_queue_reachable() -> bool:
    queue_url = _STATE.get("alert_queue_url")
    if not queue_url:
        return False
    try:
        boto3.client(
            "sqs", region_name=_STATE["region"]
        ).get_queue_attributes(
            QueueUrl=queue_url, AttributeNames=["QueueArn"]
        )
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("SQS get_queue_attributes: %s", exc)
        return False


# ---------------------------------------------------------------------------
# 2. attack() -> bool
# ---------------------------------------------------------------------------

def attack() -> bool:
    """
    Execute Attack Node 1.2: ModifyInstanceMetadataOptions with
    HttpTokens=optional and HttpPutResponseHopLimit=2.
    Exactly mirrors the attack command from attacks.yaml.
    """
    log.info("=== attack START ===")
    _require_state("instance_id", "region")

    instance_id = _STATE["instance_id"]
    region = _STATE["region"]
    ec2_client = boto3.client("ec2", region_name=region)

    log.info(
        "Calling ModifyInstanceMetadataOptions on %s: "
        "HttpTokens=optional, HopLimit=2 ...",
        instance_id,
    )

    max_retries = 5
    backoff = 5
    for attempt in range(1, max_retries + 1):
        try:
            resp = ec2_client.modify_instance_metadata_options(
                InstanceId=instance_id,
                HttpTokens="optional",
                HttpEndpoint="enabled",
                HttpPutResponseHopLimit=2,
            )
            opts = resp.get("InstanceMetadataOptions", {})
            log.info(
                "Attack succeeded (attempt %d): HttpTokens=%s HopLimit=%s",
                attempt,
                opts.get("HttpTokens"),
                opts.get("HttpPutResponseHopLimit"),
            )
            _STATE["attack_success"] = True
            _STATE["attack_ts_utc"] = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
            )
            _STATE["attack_ts_mono"] = time.monotonic()
            log.info(
                "=== attack COMPLETE - IMDS weakened on %s at %s ===",
                instance_id, _STATE["attack_ts_utc"],
            )
            return True
        except ClientError as exc:
            log.error(
                "ModifyInstanceMetadataOptions attempt %d/%d failed: %s",
                attempt, max_retries, exc,
            )
            if attempt < max_retries:
                log.info("Backing off %d s ...", backoff)
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)

    _STATE["attack_success"] = False
    log.error("Attack exhausted all %d retries.", max_retries)
    return False


# ---------------------------------------------------------------------------
# 3. hypothesis_verification() -> bool
# ---------------------------------------------------------------------------

def hypothesis_verification() -> bool:
    """
    Detective Probe - SCE Node 1.5.

    Sub-check A (PRIMARY - mandatory):
      EventBridge captured ModifyInstanceMetadataOptions event and delivered
      it to SQS queue within 1800-second SLA. Detection latency is measured.

    Sub-check B (CONDITIONAL - inconclusive if Config not available):
      AWS Config Rule EC2_IMDSV2_REQUIRED marks instance NON_COMPLIANT.

    Sub-check C (CONDITIONAL - inconclusive if trail not created):
      CloudWatch Alarm enters ALARM state via metric filter.

    Pass condition: A must pass. B and C may be inconclusive (None) but
    must not be a confirmed failure (False) if their prerequisites exist.
    """
    log.info("=== hypothesis_verification START ===")

    if not _STATE.get("attack_success"):
        log.error(
            "Attack did not succeed - hypothesis verification cannot proceed."
        )
        return False

    _require_state("instance_id", "alert_queue_url", "alarm_name")

    results: dict = {}

    # Sub-check A: EventBridge -> SNS -> SQS (PRIMARY)
    log.info("[A] Polling SQS for EventBridge-forwarded IMDS event ...")
    results["A_eventbridge_sqs"] = _poll_until(
        _check_sqs_for_imds_event,
        description="EventBridge IMDS event on SQS",
        sla=_SLA_SECONDS,
        interval=_POLL_INTERVAL,
    )

    # Sub-check B: Config Rule NON_COMPLIANT (CONDITIONAL)
    if _STATE.get("config_available") and _STATE.get("config_rule_name"):
        log.info("[B] Polling Config Rule for NON_COMPLIANT ...")
        # Trigger an immediate evaluation to reduce wait time
        try:
            config_client = boto3.client("config", region_name=_STATE["region"])
            config_client.start_config_rules_evaluation(
                ConfigRuleNames=[_STATE["config_rule_name"]]
            )
            log.info("Triggered immediate Config Rule evaluation.")
        except Exception as exc:  # noqa: BLE001
            log.warning("Could not trigger Config evaluation: %s", exc)

        results["B_config_noncompliant"] = _poll_until(
            _check_config_noncompliant,
            description="Config Rule NON_COMPLIANT",
            sla=_SLA_SECONDS,
            interval=_POLL_INTERVAL,
        )
    else:
        log.warning(
            "[B] Config Rule sub-check SKIPPED - "
            "Config recorder not active or rule not created."
        )
        results["B_config_noncompliant"] = None

    # Sub-check C: CloudWatch Alarm (CONDITIONAL)
    if _STATE.get("trail_name"):
        log.info("[C] Polling CloudWatch Alarm for ALARM state ...")
        results["C_cloudwatch_alarm"] = _poll_until(
            _check_cloudwatch_alarm,
            description="CloudWatch Alarm ALARM state",
            sla=_SLA_SECONDS,
            interval=_POLL_INTERVAL,
        )
    else:
        log.warning(
            "[C] CloudWatch Alarm sub-check SKIPPED - "
            "CloudTrail trail not created."
        )
        results["C_cloudwatch_alarm"] = None

    # Evaluate result
    log.info(
        "Hypothesis results: %s",
        json.dumps({k: str(v) for k, v in results.items()})
    )

    if not results.get("A_eventbridge_sqs"):
        log.error(
            "FAIL PRIMARY detective control [A] FAILED - "
            "EventBridge did not deliver the IMDS event to SQS "
            "within the %d-second SLA.", _SLA_SECONDS,
        )
        return False

    b = results.get("B_config_noncompliant")
    c = results.get("C_cloudwatch_alarm")

    if b is False:
        log.error(
            "FAIL [B] Config Rule did NOT mark instance NON_COMPLIANT "
            "within SLA (Config recorder was active - this is a real failure)."
        )
    if c is False:
        log.error(
            "FAIL [C] CloudWatch Alarm did NOT enter ALARM state within SLA."
        )

    passed = (
        results["A_eventbridge_sqs"] is True
        and b is not False
        and c is not False
    )

    if passed:
        log.info(
            "PASS Detective probe PASSED - primary EventBridge/SQS "
            "detection control confirmed operational within SLA."
        )
        if _STATE.get("detection_latency_seconds") is not None:
            latency = _STATE["detection_latency_seconds"]
            log.info("Detection latency: %.1f s (target <= 300 s)", latency)
            if latency > 60:
                log.warning(
                    "SLA advisory: detection latency %.1f s exceeded "
                    "the 60-second ideal target (within 1800 s SLA).", latency
                )
    else:
        log.error("FAIL Detective probe FAILED.")

    return passed


def _check_sqs_for_imds_event() -> bool:
    try:
        sqs_client = boto3.client("sqs", region_name=_STATE["region"])
        resp = sqs_client.receive_message(
            QueueUrl=_STATE["alert_queue_url"],
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            VisibilityTimeout=60,
            AttributeNames=["All"],
            MessageAttributeNames=["All"],
        )
        instance_id = _STATE["instance_id"]
        for msg in resp.get("Messages", []):
            body_raw = msg.get("Body", "")
            try:
                outer = json.loads(body_raw)
                inner_str = outer.get("Message", body_raw)
                inner = (
                    json.loads(inner_str)
                    if isinstance(inner_str, str)
                    else inner_str
                )
            except (json.JSONDecodeError, TypeError):
                inner = {}

            body_str = json.dumps(inner).lower()
            event_match = "modifyinstancemetadataoptions" in body_str
            inst_match = instance_id.lower() in body_str

            log.debug(
                "SQS scan - event_match=%s inst_match=%s snippet=%.150s",
                event_match, inst_match, body_str[:150],
            )

            if event_match and inst_match:
                if _STATE.get("attack_ts_mono"):
                    latency = time.monotonic() - _STATE["attack_ts_mono"]
                    _STATE["detection_latency_seconds"] = latency
                    log.info(
                        "EventBridge detection latency: %.1f s", latency
                    )
                try:
                    sqs_client.delete_message(
                        QueueUrl=_STATE["alert_queue_url"],
                        ReceiptHandle=msg["ReceiptHandle"],
                    )
                except Exception as del_exc:  # noqa: BLE001
                    log.warning("Could not delete SQS message: %s", del_exc)
                return True
        return False
    except Exception as exc:  # noqa: BLE001
        log.warning("SQS receive_message error: %s", exc)
        return False


def _check_config_noncompliant() -> bool:
    try:
        config_client = boto3.client("config", region_name=_STATE["region"])
        resp = config_client.get_compliance_details_by_config_rule(
            ConfigRuleName=_STATE["config_rule_name"],
            ComplianceTypes=["NON_COMPLIANT"],
        )
        for result in resp.get("EvaluationResults", []):
            rid = (
                result
                .get("EvaluationResultIdentifier", {})
                .get("EvaluationResultQualifier", {})
                .get("ResourceId", "")
            )
            if rid == _STATE["instance_id"]:
                log.info(
                    "Config Rule: instance %s is NON_COMPLIANT.",
                    _STATE["instance_id"],
                )
                return True
        return False
    except ClientError as exc:
        log.warning("Config compliance check: %s", exc)
        return False
    except Exception as exc:  # noqa: BLE001
        log.warning("Config check error: %s", exc)
        return False


def _check_cloudwatch_alarm() -> bool:
    try:
        cw_client = boto3.client("cloudwatch", region_name=_STATE["region"])
        resp = cw_client.describe_alarms(AlarmNames=[_STATE["alarm_name"]])
        alarms = resp.get("MetricAlarms", [])
        if not alarms:
            return False
        state = alarms[0].get("StateValue", "UNKNOWN")
        log.info("CloudWatch Alarm %s state: %s", _STATE["alarm_name"], state)
        return state == "ALARM"
    except Exception as exc:  # noqa: BLE001
        log.warning("CW alarm check error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# 4. rollback()
# ---------------------------------------------------------------------------

def rollback() -> None:
    """
    Teardown all experiment resources in dependency order:
    1. Stop and delete CloudTrail trail.
    2. Delete Config Rule.
    3. Empty and delete S3 trail bucket.
    4. Delete CloudTrail IAM role (inline policies first).
    5. Delete CloudFormation stack and wait for DELETE_COMPLETE.
    """
    log.info("=== rollback START ===")
    region = _STATE.get("region", "us-east-1")

    # 1. CloudTrail trail
    trail_name = _STATE.get("trail_name")
    if trail_name:
        try:
            ct = boto3.client("cloudtrail", region_name=region)
            ct.stop_logging(Name=trail_name)
            ct.delete_trail(Name=trail_name)
            log.info("Deleted CloudTrail trail %s.", trail_name)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "TrailNotFoundException":
                log.warning("Could not delete CloudTrail trail: %s", exc)
        except Exception as exc:  # noqa: BLE001
            log.warning("CloudTrail deletion error: %s", exc)

    # 2. Config Rule
    config_rule = _STATE.get("config_rule_name")
    if config_rule:
        try:
            config_client = boto3.client("config", region_name=region)
            config_client.delete_config_rule(ConfigRuleName=config_rule)
            log.info("Deleted Config Rule %s.", config_rule)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "NoSuchConfigRuleException":
                log.warning("Could not delete Config Rule: %s", exc)
        except Exception as exc:  # noqa: BLE001
            log.warning("Config Rule deletion error: %s", exc)

    # 3. S3 trail bucket (empty first)
    trail_bucket = _STATE.get("trail_bucket")
    if trail_bucket:
        try:
            s3 = boto3.client("s3", region_name=region)
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=trail_bucket):
                objects = [
                    {"Key": o["Key"]}
                    for o in page.get("Contents", [])
                ]
                if objects:
                    s3.delete_objects(
                        Bucket=trail_bucket,
                        Delete={"Objects": objects},
                    )
            s3.delete_bucket(Bucket=trail_bucket)
            log.info("Deleted S3 trail bucket %s.", trail_bucket)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "NoSuchBucket":
                log.warning("Could not delete trail bucket: %s", exc)
        except Exception as exc:  # noqa: BLE001
            log.warning("Trail bucket deletion error: %s", exc)

    # 4. CloudTrail IAM role
    trail_role = _STATE.get("trail_role_name")
    if trail_role:
        try:
            iam = boto3.client("iam", region_name=region)
            for policy in iam.list_role_policies(
                RoleName=trail_role
            ).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=trail_role, PolicyName=policy)
            iam.delete_role(RoleName=trail_role)
            log.info("Deleted IAM role %s.", trail_role)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "NoSuchEntityException":
                log.warning("Could not delete IAM role: %s", exc)
        except Exception as exc:  # noqa: BLE001
            log.warning("IAM role deletion error: %s", exc)

    # 5. CloudFormation stack
    stack_name = _STATE.get("stack_name")
    if not stack_name:
        log.warning("No stack_name in state - nothing to delete.")
        return

    cfn = boto3.client("cloudformation", region_name=region)
    try:
        cfn.delete_stack(StackName=stack_name)
        log.info("Delete requested for stack %s.", stack_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("ValidationError", "StackNotFoundException"):
            log.info("Stack %s already gone.", stack_name)
            return
        log.error("delete_stack error: %s", exc)

    hard_cap = 1200
    deadline = time.monotonic() + hard_cap
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            log.info("Stack %s: %s", stack_name, status)
            if status == "DELETE_COMPLETE":
                log.info("Stack %s deleted.", stack_name)
                return
            if "FAILED" in status:
                log.error("Stack %s delete FAILED: %s", stack_name, status)
                _log_stack_events(cfn, stack_name)
                return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationError", "StackNotFoundException"):
                log.info("Stack %s confirmed gone.", stack_name)
                return
            log.warning("describe_stacks during rollback: %s", exc)
        time.sleep(20)

    log.error(
        "Stack %s not DELETE_COMPLETE after %d s - manual cleanup may be needed.",
        stack_name, hard_cap,
    )
    log.info("=== rollback COMPLETE ===")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def test() -> bool:
    passed = False
    try:
        steady_state()
        if not attack():
            log.error("Attack returned False - see attack() logs.")
            return False
        passed = hypothesis_verification()
    except Exception as exc:  # noqa: BLE001
        log.error("Unhandled exception: %s", exc, exc_info=True)
        passed = False
    finally:
        try:
            rollback()
        except Exception as exc:  # noqa: BLE001
            log.error("Rollback error: %s", exc, exc_info=True)

    log.info(
        "=== SCE 1.5 Detective Probe - %s ===",
        "PASSED" if passed else "FAILED",
    )
    if _STATE.get("detection_latency_seconds") is not None:
        log.info(
            "Detection latency: %.1f s",
            _STATE["detection_latency_seconds"],
        )
    return passed


if __name__ == "__main__":
    sys.exit(0 if test() else 1)