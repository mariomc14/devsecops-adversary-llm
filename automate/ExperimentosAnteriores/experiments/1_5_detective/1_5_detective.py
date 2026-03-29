"""
SCE Experiment 1.5 -- Detective Probe
Attack Node 1.2: Weaken IMDS Configuration on Target EC2 Instance
TTP: T1578 - Modify Cloud Compute Infrastructure

Probe Intent (Detective):
    Issue the ModifyInstanceMetadataOptions API call against a production-tagged
    EC2 instance (deliberately NOT blocked so the call succeeds and generates
    a real CloudTrail event), then verify that the detective control --
    an EventBridge rule watching CloudTrail for ModifyInstanceMetadataOptions
    events -- fires within the detection SLA (60 seconds) and delivers an
    SNS notification to a subscribed SQS queue.

    ADT Node 1.3 states:
      "CloudTrail captures every ModifyInstanceMetadataOptions API call;
       EventBridge rule triggers SNS alert on any invocation in production.
       AWS Config Rule ec2-imdsv2-check flags non-compliant instance state.
       GuardDuty threat intelligence flags anomalous EC2 config changes.
       CloudWatch Logs Insights alert fires within 60 seconds of API call."

    This experiment operationalises the EventBridge + SNS + SQS detection
    path because it is fully programmable, synchronous, and produces
    verifiable evidence within the detection SLA without requiring GuardDuty
    or CloudWatch Logs Insights to be pre-configured.

Design:
    - steady_state() provisions via CloudFormation:
        * EC2 instance tagged Environment=production with IMDSv2 enforced
        * IAM attacker role with ALLOW for ec2:ModifyInstanceMetadataOptions
          (no Deny -- we WANT the call to succeed so CloudTrail records it)
        * CloudTrail trail writing management events to an S3 bucket
        * SNS topic for alert delivery
        * SQS queue subscribed to the SNS topic (for programmatic polling)
        * EventBridge rule matching ModifyInstanceMetadataOptions events
          and routing to the SNS topic
    - attack() assumes the attacker role and calls ModifyInstanceMetadataOptions
      (downgrades to IMDSv1) so a real CloudTrail event is generated.
      After confirming the call succeeded, it immediately re-hardens the
      instance (http_tokens=required, hop_limit=1) using the orchestrator's
      own credentials to minimise the exposure window.
    - hypothesis_verification() polls the SQS queue for the SNS notification
      delivered by the EventBridge rule, asserting it arrives within 60 s
      of the attack call. Also independently verifies via CloudTrail that
      the ModifyInstanceMetadataOptions event was recorded.

Lessons from previous Preventive probe runs (applied here):
    1. AMI resolved via boto3 SSM GetParameter before template construction --
       no {{resolve:ssm:...}} CFN dynamic substitution.
    2. All CFN template strings sanitised to printable ASCII (0x20-0x7E) via
       _ascii_safe() before embedding; validated with _validate_template_strings()
       before CFN submission.
    3. account_id resolved programmatically; used as literal string in trust
       policies -- no Fn::Sub tokens.
    4. Explicit non-empty output guard after CREATE_COMPLETE.
    5. Stack event capture on ROLLBACK for immediate root-cause logging.
"""

import subprocess
import sys
import time
import json
import logging
import os
import unicodedata
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("sce.1_5.detective")


def _ensure_boto3() -> None:
    try:
        import boto3  # noqa: F401
    except ImportError:
        log.info("boto3 not found -- installing via pip ...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "boto3"]
        )


_ensure_boto3()
import boto3  # noqa: E402
from botocore.exceptions import ClientError, WaiterError  # noqa: E402

# ---------------------------------------------------------------------------
# Module-level experiment state
# ---------------------------------------------------------------------------
_TIMESTAMP: int = int(time.time())
_STACK_NAME: str = "sce-experiment-{}".format(_TIMESTAMP)
_EXPERIMENT_TAG: str = "sce-1.5-detective"

# Populated by steady_state(); consumed by attack() / hypothesis_verification()
_INSTANCE_ID: str = ""
_ATTACKER_ROLE_ARN: str = ""
_SQS_QUEUE_URL: str = ""
_TRAIL_NAME: str = ""
_REGION: str = ""

# Written by attack(); read by hypothesis_verification()
_ATTACK_RESULT: dict = {}

# Detection SLA from ADT Node 1.3 (seconds)
_DETECTION_SLA_SECONDS: float = 60.0

# ---------------------------------------------------------------------------
# ASCII safety utilities (carried over from preventive probe fixes)
# ---------------------------------------------------------------------------


def _ascii_safe(value: str) -> str:
    """
    Return a copy of *value* containing only printable ASCII characters
    (codepoints 0x20-0x7E inclusive).  Fixes the run-2 ROLLBACK root cause
    where a Unicode character in GroupDescription caused an EC2 API rejection.
    """
    normalized = unicodedata.normalize("NFKD", value)
    ascii_bytes = normalized.encode("ascii", errors="ignore")
    ascii_str = ascii_bytes.decode("ascii")
    result = "".join(
        ch if (0x20 <= ord(ch) <= 0x7E) else "-"
        for ch in ascii_str
    )
    return result


def _validate_template_strings(template: dict, path: str = "root") -> None:
    """
    Recursively walk the CFN template dict and assert every string value is
    ASCII-safe.  Raises ValueError on the first violation so the problem is
    caught before submission rather than after a 3-minute rollback wait.
    """
    if isinstance(template, dict):
        for k, v in template.items():
            _validate_template_strings(v, path="{}.{}".format(path, k))
    elif isinstance(template, list):
        for i, item in enumerate(template):
            _validate_template_strings(item, path="{}[{}]".format(path, i))
    elif isinstance(template, str):
        for pos, ch in enumerate(template):
            code = ord(ch)
            if code < 0x20 or code > 0x7E:
                raise ValueError(
                    "Non-ASCII character U+{:04X} ({!r}) at template "
                    "path '{}', position {}.  Use _ascii_safe() before "
                    "embedding in the template.".format(code, ch, path, pos)
                )


# ---------------------------------------------------------------------------
# AWS / boto3 helpers
# ---------------------------------------------------------------------------


def _boto3_client(service: str, **kwargs):
    region = _REGION or _get_region()
    return boto3.client(service, region_name=region, **kwargs)


def _get_region() -> str:
    session = boto3.session.Session()
    region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    return region


def _get_account_id() -> str:
    sts = _boto3_client("sts")
    return sts.get_caller_identity()["Account"]


def _resolve_ami(region: str) -> str:
    """Resolve the latest AL2023 x86_64 AMI ID via SSM (run-1 fix)."""
    ssm = boto3.client("ssm", region_name=region)
    param_name = (
        "/aws/service/ami-amazon-linux-latest"
        "/al2023-ami-kernel-default-x86_64"
    )
    log.info("Resolving latest AL2023 AMI via SSM parameter '%s' ...", param_name)
    try:
        resp = ssm.get_parameter(Name=param_name)
        ami_id = resp["Parameter"]["Value"]
        log.info("Resolved AMI ID: %s", ami_id)
        return ami_id
    except ClientError as exc:
        log.error("Failed to resolve AMI via SSM: %s", exc)
        raise


def _short_hash() -> str:
    """Return a short deterministic hash of the timestamp for bucket naming."""
    return hashlib.md5(str(_TIMESTAMP).encode()).hexdigest()[:8]


def _build_cfn_template(ami_id: str, account_id: str, region: str) -> dict:
    """
    Build the CloudFormation template dict with all string values ASCII-safe.

    Resources:
      SCEVpc / SCESubnet / SCEIGW / SCEIGWAttach / SCERT / SCERTAssoc
        -- minimal VPC networking for the EC2 instance.

      SCESGInstance
        -- security group with no inbound rules.

      SCEInstanceRole / SCEInstanceProfile
        -- minimal IAM role for the EC2 instance (SSM messages only).

      SCETargetInstance
        -- EC2 instance tagged Environment=production with IMDSv2 enforced
           at launch.  The attack will temporarily downgrade this instance.

      SCEAttackerRole
        -- IAM role with ALLOW on ec2:ModifyInstanceMetadataOptions.
           NO Deny: the attack must succeed to generate a CloudTrail event.
           Also allows ec2:DescribeInstances and sts:GetCallerIdentity for
           verification.

      SCETrailBucket / SCETrailBucketPolicy
        -- S3 bucket to receive CloudTrail management events.
           Bucket policy satisfies CloudTrail's required permissions.

      SCETrail
        -- CloudTrail trail with management events enabled (write events).
           Captures ModifyInstanceMetadataOptions API calls.

      SCEAlertTopic
        -- SNS topic that receives EventBridge rule notifications.

      SCEAlertQueue
        -- SQS queue subscribed to the SNS topic for programmatic polling.

      SCEAlertQueuePolicy
        -- SQS queue policy allowing SNS to send messages.

      SCEDetectionRule
        -- EventBridge rule matching CloudTrail ModifyInstanceMetadataOptions
           events and routing to SCEAlertTopic.

      SCEDetectionRuleTopicPolicy
        -- SNS topic policy allowing EventBridge to publish.
    """
    # ------------------------------------------------------------------ #
    # ASCII-safe string constants                                          #
    # ------------------------------------------------------------------ #
    sg_description = _ascii_safe("SCE experiment - no inbound traffic")
    experiment_tag = _ascii_safe(_EXPERIMENT_TAG)
    timestamp_str = _ascii_safe(str(_TIMESTAMP))
    stack_name_tag = _ascii_safe(_STACK_NAME)
    instance_name_tag = _ascii_safe("sce-target-{}".format(_TIMESTAMP))
    instance_role_name = _ascii_safe("sce-instance-role-{}".format(_TIMESTAMP))
    instance_profile_name = _ascii_safe(
        "sce-instance-profile-{}".format(_TIMESTAMP)
    )
    attacker_role_name = _ascii_safe("sce-attacker-role-{}".format(_TIMESTAMP))
    stack_description = _ascii_safe(
        "SCE 1.5 Detective - IMDS weakening detection via EventBridge "
        "(run {})".format(_TIMESTAMP)
    )
    egress_description = _ascii_safe("Allow all outbound")
    # S3 bucket names must be globally unique, lowercase, 3-63 chars, DNS-safe
    bucket_name = "sce-trail-{}-{}".format(_TIMESTAMP, _short_hash())
    trail_name = _ascii_safe("sce-trail-{}".format(_TIMESTAMP))
    topic_name = _ascii_safe("sce-alert-{}".format(_TIMESTAMP))
    queue_name = _ascii_safe("sce-alert-queue-{}".format(_TIMESTAMP))
    rule_name = _ascii_safe("sce-detect-imds-{}".format(_TIMESTAMP))

    trail_bucket_arn = "arn:aws:s3:::{}".format(bucket_name)
    trail_bucket_prefix_arn = "arn:aws:s3:::{}/AWSLogs/{}/*".format(
        bucket_name, account_id
    )

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": stack_description,
        "Resources": {
            # ---------------------------------------------------------- #
            # Networking                                                   #
            # ---------------------------------------------------------- #
            "SCEVpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.99.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                    "Tags": [
                        {"Key": "Name", "Value": stack_name_tag},
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            "SCESubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "SCEVpc"},
                    "CidrBlock": "10.99.1.0/24",
                    "AvailabilityZone": {
                        "Fn::Select": [
                            "0",
                            {"Fn::GetAZs": {"Ref": "AWS::Region"}},
                        ]
                    },
                    "MapPublicIpOnLaunch": False,
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            "SCEIGW": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ]
                },
            },
            "SCEIGWAttach": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {
                    "VpcId": {"Ref": "SCEVpc"},
                    "InternetGatewayId": {"Ref": "SCEIGW"},
                },
            },
            "SCERT": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {
                    "VpcId": {"Ref": "SCEVpc"},
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            "SCERTAssoc": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "SCESubnet"},
                    "RouteTableId": {"Ref": "SCERT"},
                },
            },
            "SCESGInstance": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": sg_description,
                    "VpcId": {"Ref": "SCEVpc"},
                    "SecurityGroupIngress": [],
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "-1",
                            "CidrIp": "0.0.0.0/0",
                            "Description": egress_description,
                        }
                    ],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # EC2 instance profile (minimal)                               #
            # ---------------------------------------------------------- #
            "SCEInstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": instance_role_name,
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
                    "Policies": [
                        {
                            "PolicyName": "minimal-ssm-messages",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "ssm:UpdateInstanceInformation",
                                            "ec2messages:GetMessages",
                                        ],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            "SCEInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": instance_profile_name,
                    "Roles": [{"Ref": "SCEInstanceRole"}],
                },
            },
            # ---------------------------------------------------------- #
            # EC2 target instance: production-tagged, IMDSv2 enforced     #
            # ---------------------------------------------------------- #
            "SCETargetInstance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": ["SCEIGWAttach", "SCEInstanceProfile"],
                "Properties": {
                    "ImageId": ami_id,
                    "InstanceType": "t3.micro",
                    "SubnetId": {"Ref": "SCESubnet"},
                    "SecurityGroupIds": [{"Ref": "SCESGInstance"}],
                    "IamInstanceProfile": {"Ref": "SCEInstanceProfile"},
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpEndpoint": "enabled",
                        "HttpPutResponseHopLimit": 1,
                    },
                    "Tags": [
                        {"Key": "Name", "Value": instance_name_tag},
                        {"Key": "Environment", "Value": "production"},
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # Attacker IAM role -- ALLOW on ModifyInstanceMetadataOptions  #
            # No Deny: the attack must succeed to generate a CloudTrail    #
            # event for the detective control to observe.                  #
            # ---------------------------------------------------------- #
            "SCEAttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": attacker_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": "arn:aws:iam::{}:root".format(
                                        account_id
                                    )
                                },
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "attacker-imds-allow",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "AllowIMDSModify",
                                        "Effect": "Allow",
                                        "Action": "ec2:ModifyInstanceMetadataOptions",
                                        "Resource": "*",
                                    },
                                    {
                                        "Sid": "AllowEC2Reads",
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:DescribeInstances",
                                            "ec2:DescribeInstanceAttribute",
                                        ],
                                        "Resource": "*",
                                    },
                                    {
                                        "Sid": "AllowSelfSTS",
                                        "Effect": "Allow",
                                        "Action": "sts:GetCallerIdentity",
                                        "Resource": "*",
                                    },
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # S3 bucket for CloudTrail logs                                #
            # ---------------------------------------------------------- #
            "SCETrailBucket": {
                "Type": "AWS::S3::Bucket",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "BucketName": bucket_name,
                    "VersioningConfiguration": {"Status": "Enabled"},
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            "SCETrailBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "DependsOn": "SCETrailBucket",
                "Properties": {
                    "Bucket": {"Ref": "SCETrailBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSCloudTrailAclCheck",
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "cloudtrail.amazonaws.com"
                                },
                                "Action": "s3:GetBucketAcl",
                                "Resource": trail_bucket_arn,
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "cloudtrail.amazonaws.com"
                                },
                                "Action": "s3:PutObject",
                                "Resource": trail_bucket_prefix_arn,
                                "Condition": {
                                    "StringEquals": {
                                        "s3:x-amz-acl": "bucket-owner-full-control"
                                    }
                                },
                            },
                        ],
                    },
                },
            },
            # ---------------------------------------------------------- #
            # CloudTrail trail (management events -- write scope)          #
            # ---------------------------------------------------------- #
            "SCETrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": "SCETrailBucketPolicy",
                "Properties": {
                    "TrailName": trail_name,
                    "S3BucketName": {"Ref": "SCETrailBucket"},
                    "IsLogging": True,
                    "IncludeGlobalServiceEvents": True,
                    "IsMultiRegionTrail": False,
                    "EnableLogFileValidation": True,
                    "EventSelectors": [
                        {
                            "ReadWriteType": "WriteOnly",
                            "IncludeManagementEvents": True,
                        }
                    ],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # SNS topic for alert delivery                                  #
            # ---------------------------------------------------------- #
            "SCEAlertTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": topic_name,
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # SNS topic policy: allow EventBridge to publish               #
            # ---------------------------------------------------------- #
            "SCEDetectionRuleTopicPolicy": {
                "Type": "AWS::SNS::TopicPolicy",
                "Properties": {
                    "Topics": [{"Ref": "SCEAlertTopic"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowEventBridgePublish",
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "events.amazonaws.com"
                                },
                                "Action": "sns:Publish",
                                "Resource": {"Ref": "SCEAlertTopic"},
                            }
                        ],
                    },
                },
            },
            # ---------------------------------------------------------- #
            # SQS queue subscribed to SNS for programmatic polling         #
            # ---------------------------------------------------------- #
            "SCEAlertQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": queue_name,
                    "VisibilityTimeout": 120,
                    "MessageRetentionPeriod": 600,
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            "SCEAlertQueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "SCEAlertQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowSNSPublishToQueue",
                                "Effect": "Allow",
                                "Principal": {"Service": "sns.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["SCEAlertQueue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {"Ref": "SCEAlertTopic"}
                                    }
                                },
                            }
                        ],
                    },
                },
            },
            # ---------------------------------------------------------- #
            # SNS subscription: SCEAlertTopic -> SCEAlertQueue             #
            # ---------------------------------------------------------- #
            "SCEAlertSubscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "TopicArn": {"Ref": "SCEAlertTopic"},
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["SCEAlertQueue", "Arn"]},
                    "RawMessageDelivery": False,
                },
            },
            # ---------------------------------------------------------- #
            # EventBridge rule: match ModifyInstanceMetadataOptions events  #
            # sourced from CloudTrail and route to SNS                     #
            # ---------------------------------------------------------- #
            "SCEDetectionRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": rule_name,
                    "Description": _ascii_safe(
                        "SCE detective - detect IMDS weakening events"
                    ),
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
                            "Id": "SCEAlertTopicTarget",
                            "Arn": {"Ref": "SCEAlertTopic"},
                        }
                    ],
                },
            },
        },
        "Outputs": {
            "InstanceId": {
                "Value": {"Ref": "SCETargetInstance"},
                "Description": _ascii_safe(
                    "ID of the production-tagged EC2 instance under test"
                ),
            },
            "AttackerRoleArn": {
                "Value": {"Fn::GetAtt": ["SCEAttackerRole", "Arn"]},
                "Description": _ascii_safe("ARN of the attacker IAM role"),
            },
            "SqsQueueUrl": {
                "Value": {"Ref": "SCEAlertQueue"},
                "Description": _ascii_safe(
                    "SQS queue URL for detection notification polling"
                ),
            },
            "TrailName": {
                "Value": trail_name,
                "Description": _ascii_safe("CloudTrail trail name"),
            },
        },
    }

    return template


# ---------------------------------------------------------------------------
# CloudFormation helpers
# ---------------------------------------------------------------------------


def _wait_stack(
    cf_client,
    stack_name: str,
    waiter_name: str,
    delay: int = 20,
    max_attempts: int = 60,
) -> None:
    log.info(
        "Waiting for CloudFormation waiter '%s' on stack '%s' ...",
        waiter_name,
        stack_name,
    )
    waiter = cf_client.get_waiter(waiter_name)
    waiter.config.delay = delay
    waiter.config.max_attempts = max_attempts
    waiter.wait(StackName=stack_name)
    log.info(
        "CloudFormation waiter '%s' completed for '%s'.",
        waiter_name,
        stack_name,
    )


def _capture_stack_events(cf_client, stack_name: str) -> None:
    log.error(
        "Capturing CloudFormation stack events for '%s' to diagnose rollback ...",
        stack_name,
    )
    try:
        paginator = cf_client.get_paginator("describe_stack_events")
        for page in paginator.paginate(StackName=stack_name):
            for event in page["StackEvents"]:
                status = event.get("ResourceStatus", "")
                reason = event.get("ResourceStatusReason", "")
                resource = event.get("LogicalResourceId", "")
                resource_type = event.get("ResourceType", "")
                if "FAILED" in status or "ROLLBACK" in status:
                    log.error(
                        "  CFN EVENT [%s] %s (%s): %s",
                        status,
                        resource,
                        resource_type,
                        reason,
                    )
    except ClientError as exc:
        log.error("Could not retrieve stack events: %s", exc)


def _get_stack_outputs(cf_client, stack_name: str) -> dict:
    resp = cf_client.describe_stacks(StackName=stack_name)
    outputs = resp["Stacks"][0].get("Outputs", [])
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


def _wait_with_backoff(
    condition_fn,
    description: str,
    initial_delay: float = 2.0,
    max_delay: float = 30.0,
    timeout: float = 120.0,
) -> bool:
    deadline = time.monotonic() + timeout
    delay = initial_delay
    while time.monotonic() < deadline:
        try:
            if condition_fn():
                return True
        except Exception as exc:  # noqa: BLE001
            log.debug("Backoff poll for '%s' raised: %s", description, exc)
        log.debug("Waiting %.1fs for: %s", delay, description)
        time.sleep(delay)
        delay = min(delay * 1.5, max_delay)
    log.warning("Timeout waiting for: %s", description)
    return False


def _preflight_check() -> None:
    log.info("Running pre-flight permission checks ...")
    iam = _boto3_client("iam")
    sts = _boto3_client("sts")
    caller = sts.get_caller_identity()
    caller_arn = caller["Arn"]
    log.info("Deploying principal: %s", caller_arn)
    actions_to_check = [
        "cloudformation:CreateStack",
        "ec2:RunInstances",
        "ec2:CreateVpc",
        "ec2:CreateSecurityGroup",
        "iam:CreateRole",
        "ec2:DescribeInstances",
        "ec2:ModifyInstanceMetadataOptions",
        "sts:AssumeRole",
        "ssm:GetParameter",
        "s3:CreateBucket",
        "sns:CreateTopic",
        "sqs:CreateQueue",
        "events:PutRule",
        "cloudtrail:CreateTrail",
    ]
    try:
        resp = iam.simulate_principal_policy(
            PolicySourceArn=caller_arn,
            ActionNames=actions_to_check,
            ResourceArns=["*"],
        )
        denied = [
            r["EvalActionName"]
            for r in resp["EvaluationResults"]
            if r["EvalDecision"] != "allowed"
        ]
        if denied:
            log.warning(
                "Pre-flight: the following actions may be restricted: %s",
                denied,
            )
        else:
            log.info("Pre-flight: all required permissions appear to be allowed.")
    except ClientError as exc:
        log.warning(
            "Could not run IAM policy simulation: %s -- proceeding.", exc
        )


# ---------------------------------------------------------------------------
# Core experiment functions
# ---------------------------------------------------------------------------


def steady_state() -> None:
    """
    Provision all experiment resources via CloudFormation and validate
    the detection baseline:

    1. Verify the EventBridge rule is ENABLED before the attack.
    2. Verify the SQS queue is empty before the attack (no stale messages).
    3. Verify the EC2 instance has IMDSv2 enforced (http_tokens=required).
    4. Verify the CloudTrail trail is logging.

    Populates module globals: _INSTANCE_ID, _ATTACKER_ROLE_ARN,
    _SQS_QUEUE_URL, _TRAIL_NAME, _REGION.
    """
    global _INSTANCE_ID, _ATTACKER_ROLE_ARN, _SQS_QUEUE_URL, _TRAIL_NAME, _REGION

    log.info("=== steady_state() -- stack: %s ===", _STACK_NAME)
    _REGION = _get_region()
    log.info("Resolved AWS region: %s", _REGION)

    _preflight_check()

    ami_id = _resolve_ami(_REGION)
    account_id = _get_account_id()
    log.info("Deploying in account: %s", account_id)

    cfn_template = _build_cfn_template(ami_id, account_id, _REGION)

    log.info("Validating CloudFormation template string encoding ...")
    try:
        _validate_template_strings(cfn_template)
        log.info("Template string validation passed -- all values are ASCII-safe.")
    except ValueError as validation_exc:
        log.error(
            "Template string validation FAILED: %s -- aborting.", validation_exc
        )
        raise

    cf = _boto3_client("cloudformation")

    # ------------------------------------------------------------------ #
    # Check for pre-existing stack                                         #
    # ------------------------------------------------------------------ #
    stack_exists = False
    try:
        existing = cf.describe_stacks(StackName=_STACK_NAME)
        status = existing["Stacks"][0]["StackStatus"]
        log.warning(
            "Stack '%s' already exists with status '%s'. Continuing.",
            _STACK_NAME,
            status,
        )
        stack_exists = True
    except ClientError as exc:
        if "does not exist" in str(exc):
            stack_exists = False
        else:
            log.error("Unexpected error describing stack: %s", exc)
            raise

    if not stack_exists:
        log.info("Creating CloudFormation stack '%s' ...", _STACK_NAME)
        try:
            cf.create_stack(
                StackName=_STACK_NAME,
                TemplateBody=json.dumps(cfn_template),
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Tags=[
                    {
                        "Key": "sce-experiment",
                        "Value": _ascii_safe(_EXPERIMENT_TAG),
                    },
                    {
                        "Key": "sce-timestamp",
                        "Value": _ascii_safe(str(_TIMESTAMP)),
                    },
                ],
            )
        except ClientError as create_exc:
            log.error("Failed to initiate stack creation: %s", create_exc)
            raise

    # ------------------------------------------------------------------ #
    # Wait for CREATE_COMPLETE with event capture on failure               #
    # ------------------------------------------------------------------ #
    try:
        _wait_stack(
            cf, _STACK_NAME, "stack_create_complete", delay=20, max_attempts=90
        )
    except WaiterError as wait_exc:
        _capture_stack_events(cf, _STACK_NAME)
        log.error(
            "Stack creation did not complete. Stack events logged above. "
            "Exception: %s",
            wait_exc,
        )
        raise RuntimeError(
            "CloudFormation stack '{}' reached a terminal failure state.".format(
                _STACK_NAME
            )
        ) from wait_exc

    # ------------------------------------------------------------------ #
    # Collect and validate outputs                                         #
    # ------------------------------------------------------------------ #
    outputs = _get_stack_outputs(cf, _STACK_NAME)
    log.info("Stack outputs: %s", outputs)

    _INSTANCE_ID = outputs.get("InstanceId", "")
    _ATTACKER_ROLE_ARN = outputs.get("AttackerRoleArn", "")
    _SQS_QUEUE_URL = outputs.get("SqsQueueUrl", "")
    _TRAIL_NAME = outputs.get("TrailName", "")

    missing = [
        name
        for name, val in [
            ("InstanceId", _INSTANCE_ID),
            ("AttackerRoleArn", _ATTACKER_ROLE_ARN),
            ("SqsQueueUrl", _SQS_QUEUE_URL),
            ("TrailName", _TRAIL_NAME),
        ]
        if not val
    ]
    if missing:
        raise RuntimeError(
            "CloudFormation outputs missing or empty: {}".format(missing)
        )

    log.info(
        "Outputs validated -- InstanceId=%s | AttackerRoleArn=%s | "
        "SqsQueueUrl=%s | TrailName=%s",
        _INSTANCE_ID,
        _ATTACKER_ROLE_ARN,
        _SQS_QUEUE_URL,
        _TRAIL_NAME,
    )

    # ------------------------------------------------------------------ #
    # Baseline: EC2 instance has IMDSv2 enforced                           #
    # ------------------------------------------------------------------ #
    ec2 = _boto3_client("ec2")

    def _imdsv2_enforced() -> bool:
        resp = ec2.describe_instances(InstanceIds=[_INSTANCE_ID])
        reservations = resp.get("Reservations", [])
        if not reservations:
            return False
        opts = reservations[0]["Instances"][0].get("MetadataOptions", {})
        return (
            opts.get("HttpTokens") == "required"
            and opts.get("HttpPutResponseHopLimit", 0) == 1
        )

    if not _wait_with_backoff(
        _imdsv2_enforced,
        "IMDSv2 enforced on target instance",
        initial_delay=5.0,
        max_delay=20.0,
        timeout=180.0,
    ):
        raise RuntimeError(
            "Baseline FAILED: instance {} does not have IMDSv2 enforced "
            "before experiment starts.".format(_INSTANCE_ID)
        )
    log.info("Baseline confirmed: IMDSv2 enforced on instance %s.", _INSTANCE_ID)

    # ------------------------------------------------------------------ #
    # Baseline: CloudTrail trail is actively logging                       #
    # ------------------------------------------------------------------ #
    ct = _boto3_client("cloudtrail")

    def _trail_logging() -> bool:
        try:
            status = ct.get_trail_status(Name=_TRAIL_NAME)
            return status.get("IsLogging", False)
        except ClientError:
            return False

    if not _wait_with_backoff(
        _trail_logging,
        "CloudTrail trail is actively logging",
        initial_delay=5.0,
        max_delay=15.0,
        timeout=120.0,
    ):
        log.warning(
            "CloudTrail trail '%s' may not be logging yet -- proceeding.",
            _TRAIL_NAME,
        )
    else:
        log.info("Baseline confirmed: CloudTrail trail '%s' is logging.", _TRAIL_NAME)

    # ------------------------------------------------------------------ #
    # Baseline: SQS queue is empty (no stale detection messages)           #
    # ------------------------------------------------------------------ #
    sqs = _boto3_client("sqs")
    try:
        attrs = sqs.get_queue_attributes(
            QueueUrl=_SQS_QUEUE_URL,
            AttributeNames=["ApproximateNumberOfMessages"],
        )
        msg_count = int(
            attrs["Attributes"].get("ApproximateNumberOfMessages", "0")
        )
        if msg_count > 0:
            log.warning(
                "SQS queue has %d pre-existing message(s) -- purging before "
                "experiment to avoid false positive detection.",
                msg_count,
            )
            sqs.purge_queue(QueueUrl=_SQS_QUEUE_URL)
            # Purge takes up to 60 s; wait briefly for eventual consistency
            time.sleep(5)
        else:
            log.info("Baseline confirmed: SQS queue is empty.")
    except ClientError as exc:
        log.warning("Could not check/purge SQS queue: %s -- proceeding.", exc)

    # ------------------------------------------------------------------ #
    # IAM propagation backoff for the attacker role                        #
    # ------------------------------------------------------------------ #
    sts = _boto3_client("sts")

    def _role_assumable() -> bool:
        try:
            sts.assume_role(
                RoleArn=_ATTACKER_ROLE_ARN,
                RoleSessionName="sce-readiness-check",
                DurationSeconds=900,
            )
            return True
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            log.debug("Role not yet assumable: %s -- %s", code, exc)
            return False

    propagated = _wait_with_backoff(
        _role_assumable,
        "AttackerRole IAM policy propagation",
        initial_delay=5.0,
        max_delay=20.0,
        timeout=120.0,
    )
    if not propagated:
        log.warning(
            "IAM policy propagation check timed out -- proceeding; "
            "eventual consistency may affect attack() outcome."
        )

    log.info("steady_state() complete.")


def attack() -> bool:
    """
    Attack step (maps to Attack Node 1.2 / TTP T1578).

    Assumes the attacker role and calls ec2:ModifyInstanceMetadataOptions
    to downgrade IMDS to IMDSv1 (http_tokens=optional, hop_limit=2).

    This call is INTENTIONALLY ALLOWED (no Deny on the attacker role) so
    that a real CloudTrail management event is generated for the detective
    control to observe.

    After confirming success, the orchestrator's own credentials immediately
    re-harden the instance (http_tokens=required, hop_limit=1) to minimise
    the window during which the instance is IMDSv1-accessible.

    Records the attack timestamp in _ATTACK_RESULT for SLA measurement.

    Returns:
        True  -- attack call was issued; result captured.
        False -- precondition not met or unexpected error.
    """
    global _ATTACK_RESULT

    log.info("=== attack() -- assuming role %s ===", _ATTACKER_ROLE_ARN)

    if not _ATTACKER_ROLE_ARN:
        log.error(
            "attack() aborted: _ATTACKER_ROLE_ARN is empty. "
            "steady_state() must have failed."
        )
        _ATTACK_RESULT = {
            "executed": False,
            "error_code": "EMPTY_ROLE_ARN",
            "error_message": "AttackerRole ARN is empty.",
        }
        return False

    if not _INSTANCE_ID:
        log.error(
            "attack() aborted: _INSTANCE_ID is empty. "
            "steady_state() must have failed."
        )
        _ATTACK_RESULT = {
            "executed": False,
            "error_code": "EMPTY_INSTANCE_ID",
            "error_message": "Instance ID is empty.",
        }
        return False

    sts = _boto3_client("sts")

    # Assume attacker role
    try:
        assumed = sts.assume_role(
            RoleArn=_ATTACKER_ROLE_ARN,
            RoleSessionName="sce-attack-{}".format(_TIMESTAMP),
            DurationSeconds=900,
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        log.error("Failed to assume attacker role: %s -- %s", code, exc)
        _ATTACK_RESULT = {
            "executed": False,
            "error_code": code,
            "error_message": str(exc),
        }
        return False

    creds = assumed["Credentials"]
    log.info(
        "Assumed AttackerRole. Session: %s",
        assumed["AssumedRoleUser"]["AssumedRoleId"],
    )

    ec2_attacker = boto3.client(
        "ec2",
        region_name=_REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

    # Record the timestamp immediately before the API call for SLA measurement
    attack_epoch = int(time.time())

    log.info(
        "Calling ec2:ModifyInstanceMetadataOptions on instance %s "
        "(http_tokens=optional, hop_limit=2) -- "
        "expecting CloudTrail event to be generated ...",
        _INSTANCE_ID,
    )

    try:
        response = ec2_attacker.modify_instance_metadata_options(
            InstanceId=_INSTANCE_ID,
            HttpTokens="optional",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=2,
        )
        http_status = response["ResponseMetadata"]["HTTPStatusCode"]
        log.info(
            "ModifyInstanceMetadataOptions succeeded (HTTP %s). "
            "CloudTrail event should be generated. "
            "Instance IMDS is now IMDSv1 -- re-hardening immediately.",
            http_status,
        )
        _ATTACK_RESULT = {
            "executed": True,
            "attack_epoch": attack_epoch,
            "http_status": http_status,
            "imds_state_after_attack": response.get(
                "InstanceMetadataOptions", {}
            ),
        }
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"]["Message"]
        log.error(
            "Unexpected error from ModifyInstanceMetadataOptions: %s -- %s. "
            "The attack call was not issued; detective probe cannot be "
            "validated without a real CloudTrail event.",
            code,
            message,
        )
        _ATTACK_RESULT = {
            "executed": False,
            "attack_epoch": attack_epoch,
            "error_code": code,
            "error_message": message,
        }
        return False

    # ------------------------------------------------------------------ #
    # Immediate re-hardening: restore IMDSv2 using orchestrator creds      #
    # Minimises the window during which the instance is IMDSv1-accessible. #
    # ------------------------------------------------------------------ #
    ec2_orchestrator = _boto3_client("ec2")
    try:
        ec2_orchestrator.modify_instance_metadata_options(
            InstanceId=_INSTANCE_ID,
            HttpTokens="required",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=1,
        )
        log.info(
            "Re-hardening complete: instance %s restored to "
            "http_tokens=required, hop_limit=1.",
            _INSTANCE_ID,
        )
        _ATTACK_RESULT["re_hardened"] = True
    except ClientError as exc:
        log.warning(
            "Re-hardening call failed (non-fatal for detective probe): %s",
            exc,
        )
        _ATTACK_RESULT["re_hardened"] = False

    log.info("attack() complete. Result: %s", _ATTACK_RESULT)
    return True


def hypothesis_verification() -> bool:
    """
    Detective probe verification (SCE Node 1.5 -- Detective).

    Returns True only when BOTH hypotheses pass:

    [H1] EventBridge + SNS + SQS detection path delivered a notification
         within the 60-second detection SLA from the time of the attack call.
         Verified by polling the SQS queue for a message whose body contains
         the 'ModifyInstanceMetadataOptions' event name, arriving no later
         than _DETECTION_SLA_SECONDS after _ATTACK_RESULT['attack_epoch'].

    [H2] CloudTrail independently recorded the ModifyInstanceMetadataOptions
         API call.  Verified by querying CloudTrail LookupEvents for the
         event name scoped to the experiment window, confirming the event
         exists in the audit trail within the CloudTrail delivery window
         (up to 15 minutes; polled with backoff up to 5 minutes).

    ADT Node 1.3 reference:
      "CloudTrail captures every ModifyInstanceMetadataOptions API call;
       EventBridge rule triggers SNS alert on any invocation in production.
       CloudWatch Logs Insights alert fires within 60 seconds of API call."
    """
    log.info("=== hypothesis_verification() ===")

    all_passed = True

    # Guard against empty infrastructure globals
    if not _INSTANCE_ID or not _ATTACKER_ROLE_ARN:
        log.error(
            "hypothesis_verification() cannot proceed: infrastructure globals "
            "are empty (_INSTANCE_ID='%s', _ATTACKER_ROLE_ARN='%s'). "
            "steady_state() must have failed.",
            _INSTANCE_ID,
            _ATTACKER_ROLE_ARN,
        )
        return False

    if not _ATTACK_RESULT:
        log.error(
            "hypothesis_verification() cannot proceed: _ATTACK_RESULT is "
            "empty. attack() was never executed."
        )
        return False

    if not _ATTACK_RESULT.get("executed", False):
        log.error(
            "hypothesis_verification() cannot proceed: attack() did not "
            "successfully execute the API call. Result: %s",
            _ATTACK_RESULT,
        )
        return False

    attack_epoch = _ATTACK_RESULT.get("attack_epoch", _TIMESTAMP)

    # ------------------------------------------------------------------ #
    # H1: EventBridge -> SNS -> SQS notification within detection SLA     #
    # ------------------------------------------------------------------ #
    log.info(
        "[H1] Polling SQS queue for EventBridge detection notification "
        "(SLA: %.0f seconds) ...",
        _DETECTION_SLA_SECONDS,
    )

    sqs = _boto3_client("sqs")
    h1_passed = False
    sla_deadline = time.monotonic() + _DETECTION_SLA_SECONDS
    h1_message_body = None

    while time.monotonic() < sla_deadline:
        try:
            response = sqs.receive_message(
                QueueUrl=_SQS_QUEUE_URL,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=5,
                AttributeNames=["All"],
                MessageAttributeNames=["All"],
            )
            messages = response.get("Messages", [])

            for msg in messages:
                body_raw = msg.get("Body", "")
                # SNS wraps the EventBridge payload in an outer JSON envelope.
                # The inner 'Message' field contains the EventBridge event JSON.
                try:
                    outer = json.loads(body_raw)
                    inner_str = outer.get("Message", body_raw)
                    inner = json.loads(inner_str)
                except (json.JSONDecodeError, TypeError):
                    inner = {}
                    inner_str = body_raw

                # Check for ModifyInstanceMetadataOptions in the event
                event_name = (
                    inner.get("detail", {}).get("eventName", "")
                    or inner.get("eventName", "")
                )
                contains_event = (
                    "ModifyInstanceMetadataOptions" in inner_str
                    or event_name == "ModifyInstanceMetadataOptions"
                )

                # Check the message targets our specific instance
                request_params = inner.get("detail", {}).get(
                    "requestParameters", {}
                )
                instance_match = (
                    not _INSTANCE_ID  # accept any if ID unknown
                    or _INSTANCE_ID in inner_str
                    or request_params.get("instanceId") == _INSTANCE_ID
                )

                if contains_event and instance_match:
                    elapsed = time.time() - attack_epoch
                    log.info(
                        "[H1] PASS -- Detection notification received via "
                        "EventBridge -> SNS -> SQS %.1f seconds after attack. "
                        "SLA: %.0f s. Event name: %s",
                        elapsed,
                        _DETECTION_SLA_SECONDS,
                        event_name or "ModifyInstanceMetadataOptions",
                    )
                    h1_passed = True
                    h1_message_body = inner_str

                    # Delete the processed message
                    try:
                        sqs.delete_message(
                            QueueUrl=_SQS_QUEUE_URL,
                            ReceiptHandle=msg["ReceiptHandle"],
                        )
                    except ClientError as del_exc:
                        log.debug(
                            "Could not delete SQS message: %s", del_exc
                        )
                    break

                else:
                    # Not our event -- delete and continue polling
                    log.debug(
                        "Received unrelated SQS message (event='%s') -- "
                        "discarding.",
                        event_name,
                    )
                    try:
                        sqs.delete_message(
                            QueueUrl=_SQS_QUEUE_URL,
                            ReceiptHandle=msg["ReceiptHandle"],
                        )
                    except ClientError:
                        pass

            if h1_passed:
                break

        except ClientError as exc:
            log.error("[H1] SQS receive_message error: %s", exc)
            time.sleep(2)

    if not h1_passed:
        elapsed = time.time() - attack_epoch
        log.error(
            "[H1] FAIL -- No ModifyInstanceMetadataOptions detection "
            "notification received on SQS queue within %.0f-second SLA. "
            "Elapsed: %.1f s. "
            "EventBridge rule may not be triggering, SNS topic policy may "
            "be missing, or CloudTrail event has not yet reached EventBridge.",
            _DETECTION_SLA_SECONDS,
            elapsed,
        )
        all_passed = False
    else:
        log.debug("[H1] Message body sample: %s", str(h1_message_body)[:500])

    # ------------------------------------------------------------------ #
    # H2: CloudTrail recorded the ModifyInstanceMetadataOptions event      #
    # CloudTrail delivery can take up to 15 minutes; poll up to 5 minutes  #
    # with backoff to avoid test fragility on delivery lag.                #
    # ------------------------------------------------------------------ #
    log.info(
        "[H2] Querying CloudTrail LookupEvents for "
        "ModifyInstanceMetadataOptions (polling up to 5 minutes) ..."
    )

    ct = _boto3_client("cloudtrail")
    import datetime

    # Search from 2 minutes before the attack to now + 1 minute buffer
    start_time = datetime.datetime.utcfromtimestamp(attack_epoch - 120)
    end_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=1)

    h2_passed = False

    def _cloudtrail_event_found() -> bool:
        try:
            paginator = ct.get_paginator("lookup_events")
            for page in paginator.paginate(
                LookupAttributes=[
                    {
                        "AttributeKey": "EventName",
                        "AttributeValue": "ModifyInstanceMetadataOptions",
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
                PaginationConfig={"MaxItems": 50},
            ):
                for event in page.get("Events", []):
                    ct_event_str = event.get("CloudTrailEvent", "{}")
                    try:
                        ct_detail = json.loads(ct_event_str)
                    except json.JSONDecodeError:
                        ct_detail = {}

                    # Confirm event targets our specific instance
                    req_params = ct_detail.get("requestParameters", {})
                    event_instance_id = req_params.get("instanceId", "")

                    if (
                        event_instance_id == _INSTANCE_ID
                        or _INSTANCE_ID in ct_event_str
                    ):
                        event_time = event.get("EventTime")
                        username = ct_detail.get("userIdentity", {}).get(
                            "arn", "unknown"
                        )
                        log.info(
                            "[H2] PASS -- CloudTrail event found. "
                            "EventTime: %s | Actor: %s | InstanceId: %s",
                            event_time,
                            username,
                            event_instance_id,
                        )
                        return True
            return False
        except ClientError as exc:
            log.debug("CloudTrail lookup error: %s", exc)
            return False

    h2_passed = _wait_with_backoff(
        _cloudtrail_event_found,
        "CloudTrail event for ModifyInstanceMetadataOptions",
        initial_delay=10.0,
        max_delay=30.0,
        timeout=300.0,
    )

    if not h2_passed:
        log.error(
            "[H2] FAIL -- CloudTrail did not record a "
            "ModifyInstanceMetadataOptions event for instance %s within "
            "the 5-minute polling window. "
            "CloudTrail trail '%s' may not be delivering events, or the "
            "event has not yet propagated.",
            _INSTANCE_ID,
            _TRAIL_NAME,
        )
        all_passed = False

    # ------------------------------------------------------------------ #
    # Final verdict                                                         #
    # ------------------------------------------------------------------ #
    if all_passed:
        log.info(
            "hypothesis_verification() -> PASS. "
            "Detective control is effective: EventBridge -> SNS -> SQS "
            "delivered notification within %.0f-second SLA (H1), and "
            "CloudTrail recorded the audit event (H2).",
            _DETECTION_SLA_SECONDS,
        )
    else:
        log.error(
            "hypothesis_verification() -> FAIL. "
            "One or more detective hypotheses were not satisfied. "
            "Review [H1] and [H2] log entries above."
        )

    return all_passed


def rollback() -> None:
    """
    Complete teardown via CloudFormation stack deletion.

    Before deleting the stack, empties the S3 bucket used by CloudTrail
    (S3 buckets with versioning enabled cannot be deleted by CloudFormation
    unless they are empty; this prevents a DELETE_FAILED state).

    Tolerates stack-not-found and already-deleting states.
    Always executes even on upstream failure (called from finally block).
    """
    log.info("=== rollback() -- deleting stack '%s' ===", _STACK_NAME)

    # ------------------------------------------------------------------ #
    # Empty the CloudTrail S3 bucket before stack deletion                 #
    # CFN cannot delete a non-empty versioned S3 bucket; this prevents     #
    # DELETE_FAILED on the SCETrailBucket resource.                        #
    # ------------------------------------------------------------------ #
    bucket_name = "sce-trail-{}-{}".format(_TIMESTAMP, _short_hash())
    _empty_s3_bucket(bucket_name)

    cf = _boto3_client("cloudformation")

    try:
        status_resp = cf.describe_stacks(StackName=_STACK_NAME)
        current_status = status_resp["Stacks"][0]["StackStatus"]
        log.info("Stack '%s' current status: %s", _STACK_NAME, current_status)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info(
                "Stack '%s' does not exist -- nothing to delete.", _STACK_NAME
            )
            return
        log.error(
            "Unexpected error checking stack status during rollback: %s", exc
        )
        return

    if current_status in ("DELETE_COMPLETE", "DELETE_IN_PROGRESS"):
        log.info(
            "Stack '%s' is already in status '%s' -- skipping delete.",
            _STACK_NAME,
            current_status,
        )
        if current_status == "DELETE_IN_PROGRESS":
            try:
                _wait_stack(
                    cf,
                    _STACK_NAME,
                    "stack_delete_complete",
                    delay=20,
                    max_attempts=45,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "Error waiting for in-progress deletion of '%s': %s",
                    _STACK_NAME,
                    exc,
                )
        return

    try:
        cf.delete_stack(StackName=_STACK_NAME)
        log.info("Stack deletion initiated for '%s'.", _STACK_NAME)
    except ClientError as exc:
        log.error("Failed to initiate stack deletion: %s", exc)
        return

    try:
        _wait_stack(
            cf,
            _STACK_NAME,
            "stack_delete_complete",
            delay=20,
            max_attempts=60,
        )
        log.info("Stack '%s' deleted successfully.", _STACK_NAME)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info(
                "Stack '%s' no longer exists -- deletion confirmed.", _STACK_NAME
            )
        else:
            log.error(
                "ClientError waiting for deletion of '%s': %s", _STACK_NAME, exc
            )
    except WaiterError as exc:
        try:
            cf.describe_stacks(StackName=_STACK_NAME)
            log.error(
                "Deletion waiter failed and stack still exists for '%s': %s",
                _STACK_NAME,
                exc,
            )
        except ClientError as inner_exc:
            if "does not exist" in str(inner_exc):
                log.info(
                    "Stack '%s' confirmed deleted (waiter false alarm).",
                    _STACK_NAME,
                )
            else:
                log.error(
                    "Unexpected error confirming deletion of '%s': %s",
                    _STACK_NAME,
                    inner_exc,
                )
    except Exception as exc:  # noqa: BLE001
        log.error(
            "Unexpected error during rollback of '%s': %s", _STACK_NAME, exc
        )

    log.info("rollback() complete.")


def _empty_s3_bucket(bucket_name: str) -> None:
    """
    Delete all objects and versions from an S3 bucket so CloudFormation
    can delete the bucket resource without hitting BucketNotEmpty errors.
    Tolerates bucket-not-found (bucket may not have been created if stack
    rolled back before the S3 resource was provisioned).
    """
    log.info("Emptying S3 bucket '%s' before stack deletion ...", bucket_name)
    s3 = _boto3_client("s3")

    try:
        # Confirm the bucket exists
        s3.head_bucket(Bucket=bucket_name)
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "")
        if error_code in ("404", "NoSuchBucket"):
            log.info(
                "Bucket '%s' does not exist -- nothing to empty.", bucket_name
            )
            return
        log.warning(
            "Could not check bucket '%s': %s -- skipping empty.", bucket_name, exc
        )
        return

    # Delete all object versions (handles versioning-enabled buckets)
    try:
        versioning_paginator = s3.get_paginator("list_object_versions")
        for page in versioning_paginator.paginate(Bucket=bucket_name):
            delete_objects = []

            for version in page.get("Versions", []):
                delete_objects.append(
                    {"Key": version["Key"], "VersionId": version["VersionId"]}
                )

            for marker in page.get("DeleteMarkers", []):
                delete_objects.append(
                    {"Key": marker["Key"], "VersionId": marker["VersionId"]}
                )

            if delete_objects:
                s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={"Objects": delete_objects, "Quiet": True},
                )
                log.debug(
                    "Deleted %d object versions from '%s'.",
                    len(delete_objects),
                    bucket_name,
                )

        log.info("Bucket '%s' emptied successfully.", bucket_name)

    except ClientError as exc:
        log.warning(
            "Error emptying bucket '%s': %s -- stack deletion may fail "
            "on the S3 resource.",
            bucket_name,
            exc,
        )


# ---------------------------------------------------------------------------
# Experiment entry point
# ---------------------------------------------------------------------------


def run_experiment() -> None:
    """
    Orchestrates: steady_state -> attack -> hypothesis_verification -> rollback.
    rollback() always executes via finally block.
    """
    log.info("============================================================")
    log.info("SCE 1.5 Detective -- IMDS Weakening Detection (T1578)")
    log.info("Stack : %s", _STACK_NAME)
    log.info("============================================================")

    result = False

    try:
        steady_state()
        attack_issued = attack()

        if not attack_issued:
            log.error(
                "attack() returned False -- the attack call was not issued. "
                "Check logs for precondition failures or errors."
            )
        else:
            result = hypothesis_verification()

    except Exception as exc:  # noqa: BLE001
        log.error(
            "Unhandled exception during experiment execution: %s",
            exc,
            exc_info=True,
        )
    finally:
        rollback()

    status = "PASSED" if result else "FAILED"
    log.info("============================================================")
    log.info("SCE Experiment 1.5 Detective Probe result: %s", status)
    log.info("============================================================")

    if not result:
        sys.exit(1)


if __name__ == "__main__":
    run_experiment()