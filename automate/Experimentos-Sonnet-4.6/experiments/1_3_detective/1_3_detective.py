"""
SCE Experiment 1.3 — Detective Probe
Attack Node 1.2: Weaken IMDS Configuration on Target EC2 Instance
Probe Intent: Confirm that a ModifyInstanceMetadataOptions API call
(setting HttpTokens=optional, HopLimit=2) is captured by CloudTrail,
triggers an EventBridge rule, and produces a CloudWatch Alarm transition
to ALARM state — all within a 30-minute SLA window.

Root-cause fix applied from previous execution:
  boto3.client('cfn') -> boto3.client('cloudformation')

Environment: Clean AWS account. All resources created and destroyed by
this script via CloudFormation. No CLI arguments. No pre-existing resources.
"""

import importlib
import json
import logging
import os
import subprocess
import sys
import time

# ---------------------------------------------------------------------------
# Bootstrap logging immediately so every import-time error is captured
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Ensure boto3 is available; install at runtime if missing
# ---------------------------------------------------------------------------
def _ensure_boto3() -> None:
    global boto3
    try:
        import boto3 as _b3
        boto3 = _b3
        log.info("boto3 already available: %s", _b3.__version__)
    except ImportError:
        log.warning("boto3 not found — installing via pip...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "boto3"],
            stdout=subprocess.DEVNULL,
        )
        import boto3 as _b3
        boto3 = _b3
        log.info("boto3 installed successfully: %s", _b3.__version__)

_ensure_boto3()

# ---------------------------------------------------------------------------
# Module-level state shared across all functions
# ---------------------------------------------------------------------------
_STATE: dict = {
    "stack_name": "",
    "instance_id": "",
    "trail_name": "",
    "alarm_name": "",
    "sns_topic_arn": "",
    "rule_name": "",
    "region": "",
    "account_id": "",
    "timestamp_suffix": 0,
    "log_group_name": "",
}

# ---------------------------------------------------------------------------
# Retry / backoff helper
# ---------------------------------------------------------------------------
def _wait_until(
    condition_fn,
    description: str,
    timeout_s: int = 1800,
    poll_s: int = 15,
) -> bool:
    """
    Poll condition_fn() until it returns True or timeout_s elapses.
    Uses time.monotonic() for drift-free elapsed measurement.
    Returns True on success, False on timeout.
    """
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        try:
            if condition_fn():
                log.info(
                    "Condition met for '%s' after %d poll(s).",
                    description,
                    attempt,
                )
                return True
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "Poll attempt %d for '%s' raised: %s", attempt, description, exc
            )
        remaining = deadline - time.monotonic()
        sleep_s = min(poll_s, max(0.0, remaining))
        if sleep_s > 0:
            log.info(
                "Waiting for '%s' — attempt %d, %.0fs remaining, sleeping %.0fs ...",
                description,
                attempt,
                remaining,
                sleep_s,
            )
            time.sleep(sleep_s)
    log.error(
        "Timed out waiting for '%s' after %ds.", description, timeout_s
    )
    return False


# ---------------------------------------------------------------------------
# Pre-flight validation
# ---------------------------------------------------------------------------
def _preflight_check() -> None:
    """
    Validate AWS credentials are resolvable and the cloudformation service
    name is correct before any stack operation is attempted.
    Raises RuntimeError on unrecoverable misconfiguration.
    """
    log.info("Running pre-flight checks ...")
    # Verify credential chain
    try:
        sts = boto3.client("sts", region_name=_resolve_region_raw())
        identity = sts.get_caller_identity()
        log.info(
            "Pre-flight: credentials valid — Account=%s, Arn=%s",
            identity["Account"],
            identity["Arn"],
        )
    except Exception as exc:
        raise RuntimeError(f"Pre-flight: AWS credential chain failed: {exc}") from exc

    # Verify cloudformation service name is valid (the root cause of the prior failure)
    try:
        boto3.client("cloudformation", region_name=_resolve_region_raw())
        log.info("Pre-flight: boto3 'cloudformation' service name resolved correctly.")
    except Exception as exc:
        raise RuntimeError(
            f"Pre-flight: boto3 'cloudformation' client creation failed: {exc}"
        ) from exc

    log.info("Pre-flight checks passed.")


def _resolve_region_raw() -> str:
    """Return region from session without touching _STATE (safe for pre-flight)."""
    session = boto3.session.Session()
    return session.region_name or "us-east-1"


# ---------------------------------------------------------------------------
# CloudFormation template builder
# ---------------------------------------------------------------------------
def _build_cfn_template(suffix: int) -> dict:
    """
    Returns a minimal, self-contained CFN template that creates every resource
    needed for the detective probe experiment:

      - VPC + public subnet + IGW + route table (EC2 networking)
      - Security group (egress-only; no inbound SSH/RDP)
      - IAM instance role (SSMCore managed policy only)
      - EC2 instance profile
      - EC2 t3.micro instance with IMDSv2 enforced (steady-state baseline)
      - SNS topic to receive EventBridge / CloudWatch notifications
      - S3 bucket + bucket policy for CloudTrail log delivery
      - CloudWatch Logs group for CloudTrail → CW Logs delivery
      - IAM role allowing CloudTrail to write to the CW Logs group
      - CloudTrail trail (single-region, CW Logs delivery enabled)
      - CloudWatch metric filter on the log group (ModifyInstanceMetadataOptions)
      - CloudWatch alarm on the metric filter output
      - EventBridge rule matching ModifyInstanceMetadataOptions → SNS target
      - SNS topic policy allowing EventBridge and CloudWatch to publish

    All resource names and the S3 bucket name embed the suffix for uniqueness.
    """
    trail_bucket = f"sce-ct-bucket-{suffix}"
    trail_name = f"sce-trail-{suffix}"
    sns_name = f"sce-sns-{suffix}"
    rule_name = f"sce-eb-rule-{suffix}"
    alarm_name = f"sce-alarm-{suffix}"
    log_group = f"sce-cw-log-{suffix}"
    role_name = f"sce-ec2-role-{suffix}"
    instance_profile_name = f"sce-ec2-profile-{suffix}"
    cw_logs_role_name = f"sce-ct-cw-role-{suffix}"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": (
            f"SCE Experiment 1.3 Detective Probe resources — suffix {suffix}"
        ),
        "Parameters": {
            "LatestAmiId": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": (
                    "/aws/service/ami-amazon-linux-latest/"
                    "amzn2-ami-hvm-x86_64-gp2"
                ),
            }
        },
        "Resources": {
            # ── Networking ──────────────────────────────────────────────────
            "SCEVpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                    "Tags": [{"Key": "SCE", "Value": str(suffix)}],
                },
            },
            "SCESubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "SCEVpc"},
                    "CidrBlock": "10.0.1.0/24",
                    "MapPublicIpOnLaunch": True,
                    "Tags": [{"Key": "SCE", "Value": str(suffix)}],
                },
            },
            "SCEIGW": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {
                    "Tags": [{"Key": "SCE", "Value": str(suffix)}]
                },
            },
            "SCEVPCGatewayAttachment": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {
                    "VpcId": {"Ref": "SCEVpc"},
                    "InternetGatewayId": {"Ref": "SCEIGW"},
                },
            },
            "SCERouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {
                    "VpcId": {"Ref": "SCEVpc"},
                    "Tags": [{"Key": "SCE", "Value": str(suffix)}],
                },
            },
            "SCEDefaultRoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "SCEVPCGatewayAttachment",
                "Properties": {
                    "RouteTableId": {"Ref": "SCERouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "SCEIGW"},
                },
            },
            "SCESubnetRTAssoc": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "SCESubnet"},
                    "RouteTableId": {"Ref": "SCERouteTable"},
                },
            },
            "SCESecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE experiment SG — no SSH, no RDP",
                    "VpcId": {"Ref": "SCEVpc"},
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "-1",
                            "CidrIp": "0.0.0.0/0",
                            "Description": "Allow all outbound for SSM",
                        }
                    ],
                    "Tags": [{"Key": "SCE", "Value": str(suffix)}],
                },
            },
            # ── IAM for EC2 instance ─────────────────────────────────────────
            "SCEInstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
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
                    "Tags": [{"Key": "SCE", "Value": str(suffix)}],
                },
            },
            "SCEInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": instance_profile_name,
                    "Roles": [{"Ref": "SCEInstanceRole"}],
                },
            },
            # ── EC2 Instance with IMDSv2 enforced (steady-state baseline) ────
            "SCEInstance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": {"Ref": "LatestAmiId"},
                    "InstanceType": "t3.micro",
                    "SubnetId": {"Ref": "SCESubnet"},
                    "SecurityGroupIds": [{"Ref": "SCESecurityGroup"}],
                    "IamInstanceProfile": {"Ref": "SCEInstanceProfile"},
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpEndpoint": "enabled",
                        "HttpPutResponseHopLimit": 1,
                    },
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": f"sce-instance-{suffix}",
                        },
                        {"Key": "SCE", "Value": str(suffix)},
                    ],
                },
            },
            # ── S3 bucket for CloudTrail log delivery ────────────────────────
            "SCETrailBucket": {
                "Type": "AWS::S3::Bucket",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "BucketName": trail_bucket,
                    "LifecycleConfiguration": {
                        "Rules": [
                            {
                                "Id": "expire-1d",
                                "Status": "Enabled",
                                "ExpirationInDays": 1,
                            }
                        ]
                    },
                    "Tags": [{"Key": "SCE", "Value": str(suffix)}],
                },
            },
            "SCETrailBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
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
                                "Resource": {
                                    "Fn::Sub": (
                                        "arn:aws:s3:::${SCETrailBucket}"
                                    )
                                },
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "cloudtrail.amazonaws.com"
                                },
                                "Action": "s3:PutObject",
                                "Resource": {
                                    "Fn::Sub": (
                                        "arn:aws:s3:::${SCETrailBucket}"
                                        "/AWSLogs/*"
                                    )
                                },
                                "Condition": {
                                    "StringEquals": {
                                        "s3:x-amz-acl": (
                                            "bucket-owner-full-control"
                                        )
                                    }
                                },
                            },
                        ],
                    },
                },
            },
            # ── CloudWatch Logs group for CloudTrail → CW Logs delivery ──────
            "SCELogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": log_group,
                    "RetentionInDays": 1,
                    "Tags": [{"Key": "SCE", "Value": str(suffix)}],
                },
            },
            # ── IAM role allowing CloudTrail to write to the CW Logs group ───
            "SCECWLogsRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": cw_logs_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "cloudtrail.amazonaws.com"
                                },
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "CWLogsWrite",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                        ],
                                        "Resource": {
                                            "Fn::Sub": (
                                                "arn:aws:logs:"
                                                "${AWS::Region}:"
                                                "${AWS::AccountId}"
                                                f":log-group:{log_group}:*"
                                            )
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": [{"Key": "SCE", "Value": str(suffix)}],
                },
            },
            # ── CloudTrail trail ─────────────────────────────────────────────
            "SCETrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": ["SCETrailBucketPolicy"],
                "Properties": {
                    "TrailName": trail_name,
                    "S3BucketName": {"Ref": "SCETrailBucket"},
                    "IsLogging": True,
                    "IncludeGlobalServiceEvents": True,
                    "IsMultiRegionTrail": False,
                    "EnableLogFileValidation": True,
                    "CloudWatchLogsLogGroupArn": {
                        "Fn::GetAtt": ["SCELogGroup", "Arn"]
                    },
                    "CloudWatchLogsRoleArn": {
                        "Fn::GetAtt": ["SCECWLogsRole", "Arn"]
                    },
                    "Tags": [{"Key": "SCE", "Value": str(suffix)}],
                },
            },
            # ── SNS topic for EventBridge and CloudWatch notifications ────────
            "SCESNSTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": sns_name,
                    "Tags": [{"Key": "SCE", "Value": str(suffix)}],
                },
            },
            "SCESNSTopicPolicy": {
                "Type": "AWS::SNS::TopicPolicy",
                "Properties": {
                    "Topics": [{"Ref": "SCESNSTopic"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowEventBridge",
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "events.amazonaws.com"
                                },
                                "Action": "sns:Publish",
                                "Resource": {"Ref": "SCESNSTopic"},
                            },
                            {
                                "Sid": "AllowCloudWatch",
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "cloudwatch.amazonaws.com"
                                },
                                "Action": "sns:Publish",
                                "Resource": {"Ref": "SCESNSTopic"},
                            },
                        ],
                    },
                },
            },
            # ── EventBridge rule — matches ModifyInstanceMetadataOptions ──────
            "SCEEventRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": rule_name,
                    "Description": (
                        "Detect ModifyInstanceMetadataOptions API calls "
                        "via CloudTrail — SCE 1.3 Detective Probe"
                    ),
                    "State": "ENABLED",
                    "EventPattern": json.dumps(
                        {
                            "source": ["aws.ec2"],
                            "detail-type": [
                                "AWS API Call via CloudTrail"
                            ],
                            "detail": {
                                "eventName": [
                                    "ModifyInstanceMetadataOptions"
                                ]
                            },
                        }
                    ),
                    "Targets": [
                        {
                            "Id": "SNSTarget",
                            "Arn": {"Ref": "SCESNSTopic"},
                        }
                    ],
                },
            },
            # ── CloudWatch Metric Filter on CloudTrail log group ─────────────
            "SCEMetricFilter": {
                "Type": "AWS::Logs::MetricFilter",
                "DependsOn": ["SCETrail"],
                "Properties": {
                    "LogGroupName": log_group,
                    "FilterPattern": (
                        '{ $.eventName = "ModifyInstanceMetadataOptions" }'
                    ),
                    "MetricTransformations": [
                        {
                            "MetricNamespace": f"SCE/{suffix}",
                            "MetricName": "IMDSWeakeningAttempts",
                            "MetricValue": "1",
                            "DefaultValue": 0,
                        }
                    ],
                },
            },
            # ── CloudWatch Alarm on the metric filter ────────────────────────
            "SCEAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": alarm_name,
                    "AlarmDescription": (
                        "Fires when ModifyInstanceMetadataOptions is called "
                        "— SCE Detective Probe 1.3"
                    ),
                    "Namespace": f"SCE/{suffix}",
                    "MetricName": "IMDSWeakeningAttempts",
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "TreatMissingData": "notBreaching",
                    "AlarmActions": [{"Ref": "SCESNSTopic"}],
                    "OKActions": [{"Ref": "SCESNSTopic"}],
                    "Tags": [{"Key": "SCE", "Value": str(suffix)}],
                },
            },
        },
        "Outputs": {
            "InstanceId": {
                "Description": "EC2 instance used in the experiment",
                "Value": {"Ref": "SCEInstance"},
            },
            "TrailName": {
                "Description": "CloudTrail trail name",
                "Value": trail_name,
            },
            "AlarmName": {
                "Description": "CloudWatch alarm name",
                "Value": alarm_name,
            },
            "SNSTopicArn": {
                "Description": "SNS topic ARN",
                "Value": {"Ref": "SCESNSTopic"},
            },
            "EventRuleName": {
                "Description": "EventBridge rule name",
                "Value": rule_name,
            },
            "LogGroupName": {
                "Description": "CloudWatch Logs group for CloudTrail",
                "Value": log_group,
            },
        },
    }
    return template


# ---------------------------------------------------------------------------
# Boto3 client factories — all use 'cloudformation' (root-cause fix)
# ---------------------------------------------------------------------------
def _cfn_client():
    """
    CloudFormation client.
    IMPORTANT: service name is 'cloudformation', NOT 'cfn'.
    This was the root cause of the previous execution failure.
    """
    return boto3.client("cloudformation", region_name=_STATE["region"])


def _ec2_client():
    return boto3.client("ec2", region_name=_STATE["region"])


def _cw_client():
    return boto3.client("cloudwatch", region_name=_STATE["region"])


def _ct_client():
    return boto3.client("cloudtrail", region_name=_STATE["region"])


def _logs_client():
    return boto3.client("logs", region_name=_STATE["region"])


def _sns_client():
    return boto3.client("sns", region_name=_STATE["region"])


def _s3_client():
    return boto3.client("s3", region_name=_STATE["region"])


def _eb_client():
    return boto3.client("events", region_name=_STATE["region"])


# ---------------------------------------------------------------------------
# Region / account helpers
# ---------------------------------------------------------------------------
def _resolve_region() -> str:
    session = boto3.session.Session()
    region = session.region_name or "us-east-1"
    log.info("Using AWS region: %s", region)
    return region


def _resolve_account_id() -> str:
    sts = boto3.client("sts", region_name=_STATE["region"])
    identity = sts.get_caller_identity()
    account_id = identity["Account"]
    log.info("AWS account ID: %s", account_id)
    return account_id


# ---------------------------------------------------------------------------
# Stack helpers
# ---------------------------------------------------------------------------
def _stack_exists(stack_name: str) -> bool:
    cfn = _cfn_client()
    try:
        resp = cfn.describe_stacks(StackName=stack_name)
        statuses = [s["StackStatus"] for s in resp["Stacks"]]
        log.info(
            "Stack '%s' exists with status(es): %s", stack_name, statuses
        )
        return True
    except cfn.exceptions.ClientError:
        return False
    except Exception as exc:  # noqa: BLE001
        log.warning("Error checking stack existence: %s", exc)
        return False


def _wait_stack_complete(stack_name: str, operation: str = "CREATE") -> bool:
    """
    Wait for stack CREATE_COMPLETE or DELETE_COMPLETE.
    Terminal failure states stop polling immediately.
    30-minute SLA enforced via _wait_until().
    """
    terminal_success = {
        "CREATE": "CREATE_COMPLETE",
        "DELETE": "DELETE_COMPLETE",
        "UPDATE": "UPDATE_COMPLETE",
    }[operation]
    terminal_failures = {
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
        "DELETE_FAILED",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_ROLLBACK_FAILED",
    }
    cfn = _cfn_client()

    def _check() -> bool:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            log.info("Stack '%s' status: %s", stack_name, status)
            if status == terminal_success:
                return True
            if status in terminal_failures:
                raise RuntimeError(
                    f"Stack '{stack_name}' reached terminal failure "
                    f"state: {status}"
                )
            return False
        except cfn.exceptions.ClientError as exc:
            # During DELETE, the stack disappears — treat as success
            if operation == "DELETE" and "does not exist" in str(exc):
                return True
            raise

    return _wait_until(
        _check,
        f"Stack {operation}_COMPLETE for '{stack_name}'",
        timeout_s=1800,
        poll_s=20,
    )


def _populate_state_from_outputs(stack_name: str) -> None:
    """Read CFN stack outputs into the module-level _STATE dict."""
    cfn = _cfn_client()
    resp = cfn.describe_stacks(StackName=stack_name)
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in resp["Stacks"][0].get("Outputs", [])
    }
    _STATE["instance_id"] = outputs.get("InstanceId", "")
    _STATE["trail_name"] = outputs.get("TrailName", "")
    _STATE["alarm_name"] = outputs.get("AlarmName", "")
    _STATE["sns_topic_arn"] = outputs.get("SNSTopicArn", "")
    _STATE["rule_name"] = outputs.get("EventRuleName", "")
    _STATE["log_group_name"] = outputs.get("LogGroupName", "")
    log.info("Populated _STATE from CFN outputs: %s", outputs)

    # Guard: fail loudly if any critical key is missing
    for key in ("instance_id", "trail_name", "alarm_name", "rule_name",
                "log_group_name"):
        if not _STATE[key]:
            raise RuntimeError(
                f"CFN output '{key}' is missing from stack '{stack_name}'. "
                "Stack creation may have partially failed."
            )


# ===========================================================================
# 1. PREPARATION — steady_state()
# ===========================================================================
def steady_state() -> None:
    """
    Provision all experiment infrastructure via CloudFormation.

    Establishes the pre-attack steady state:
      - EC2 instance running with IMDSv2 enforced (HttpTokens=required, HopLimit=1)
      - CloudTrail trail active and delivering to CloudWatch Logs
      - EventBridge rule ENABLED and matching ModifyInstanceMetadataOptions events
      - CloudWatch metric filter and alarm deployed
      - SNS topic ready to receive notifications

    All resources are tagged and namespaced with a unique timestamp suffix.
    """
    log.info("=== steady_state() — begin ===")

    # Resolve AWS context
    _STATE["region"] = _resolve_region()
    _STATE["account_id"] = _resolve_account_id()

    # Run pre-flight checks (validates 'cloudformation' service name)
    _preflight_check()

    _STATE["timestamp_suffix"] = int(time.time())
    suffix = _STATE["timestamp_suffix"]
    stack_name = f"sce-experiment-{suffix}"
    _STATE["stack_name"] = stack_name
    log.info("Stack name: %s", stack_name)

    # Gracefully handle the (unlikely) case of an existing stack
    if _stack_exists(stack_name):
        log.warning(
            "Stack '%s' already exists — continuing with existing stack.",
            stack_name,
        )
        _populate_state_from_outputs(stack_name)
        return

    # Build and serialize CFN template
    template = _build_cfn_template(suffix)
    template_body = json.dumps(template)

    # Create the CloudFormation stack
    cfn = _cfn_client()
    log.info("Creating CloudFormation stack '%s' ...", stack_name)
    try:
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            OnFailure="ROLLBACK",
            Tags=[
                {
                    "Key": "SCE-Experiment",
                    "Value": "1_3_detective",
                },
                {
                    "Key": "SCE-Timestamp",
                    "Value": str(suffix),
                },
            ],
        )
    except cfn.exceptions.AlreadyExistsException:
        log.warning(
            "Stack '%s' already exists (race condition) — continuing.",
            stack_name,
        )

    # Wait for stack creation to complete (30-minute SLA)
    success = _wait_stack_complete(stack_name, "CREATE")
    if not success:
        raise RuntimeError(
            f"Stack creation did not complete within SLA: {stack_name}"
        )

    # Populate module state from CFN outputs — fails loudly if keys missing
    _populate_state_from_outputs(stack_name)

    # ── Verify baseline IMDS configuration on the provisioned instance ───
    ec2 = _ec2_client()
    instance_id = _STATE["instance_id"]
    log.info(
        "Verifying baseline IMDS configuration on instance %s ...",
        instance_id,
    )

    def _imds_enforced() -> bool:
        resp = ec2.describe_instances(InstanceIds=[instance_id])
        opts = (
            resp["Reservations"][0]["Instances"][0]
            .get("MetadataOptions", {})
        )
        http_tokens = opts.get("HttpTokens", "")
        hop_limit = opts.get("HttpPutResponseHopLimit", 0)
        state = opts.get("State", "")
        log.info(
            "IMDS options — HttpTokens=%s HopLimit=%s State=%s",
            http_tokens,
            hop_limit,
            state,
        )
        return (
            state == "applied"
            and http_tokens == "required"
            and hop_limit == 1
        )

    imds_ok = _wait_until(
        _imds_enforced,
        "IMDS baseline verified (HttpTokens=required, HopLimit=1)",
        timeout_s=300,
        poll_s=15,
    )
    if not imds_ok:
        raise RuntimeError(
            f"Instance {instance_id} did not reach expected baseline "
            "IMDS state within 5 minutes."
        )

    # ── Verify CloudTrail trail is actively logging ───────────────────────
    ct = _ct_client()
    trail_name = _STATE["trail_name"]
    log.info(
        "Verifying CloudTrail trail '%s' is active ...", trail_name
    )

    def _trail_logging() -> bool:
        resp = ct.get_trail_status(Name=trail_name)
        is_logging = resp.get("IsLogging", False)
        log.info("Trail '%s' IsLogging=%s", trail_name, is_logging)
        return is_logging

    trail_ok = _wait_until(
        _trail_logging,
        "CloudTrail trail active",
        timeout_s=300,
        poll_s=15,
    )
    if not trail_ok:
        raise RuntimeError(
            f"CloudTrail trail '{trail_name}' did not reach IsLogging=True "
            "within 5 minutes."
        )

    # ── Verify EventBridge rule is ENABLED ────────────────────────────────
    eb = _eb_client()
    rule_name = _STATE["rule_name"]
    log.info(
        "Verifying EventBridge rule '%s' is ENABLED ...", rule_name
    )
    rule_resp = eb.describe_rule(Name=rule_name)
    rule_state = rule_resp.get("State", "DISABLED")
    if rule_state != "ENABLED":
        raise RuntimeError(
            f"EventBridge rule '{rule_name}' is not ENABLED "
            f"(state={rule_state})."
        )
    log.info(
        "EventBridge rule '%s' confirmed ENABLED.", rule_name
    )

    log.info("=== steady_state() — complete ===")


# ===========================================================================
# 2. ATTACK — attack()
# ===========================================================================
def attack() -> bool:
    """
    Execute Attack Node 1.2 exactly as specified in the ADT:

      aws ec2 modify-instance-metadata-options \\
        --instance-id <INSTANCE_ID> \\
        --http-tokens optional \\
        --http-endpoint enabled \\
        --http-put-response-hop-limit 2

    Implemented via boto3 EC2 API. Operates strictly on the EC2 instance
    provisioned in steady_state(). Simulates the adversary downgrading IMDS
    protection to enable IMDSv1 credential harvesting from co-resident
    containers or SSRF-vulnerable applications (T1578).

    Returns True if the API call succeeded (attack executed), False otherwise.
    """
    log.info("=== attack() — begin ===")

    instance_id = _STATE.get("instance_id", "")
    if not instance_id:
        log.error(
            "attack(): instance_id missing from _STATE. "
            "steady_state() must complete successfully before attack() is called."
        )
        return False

    ec2 = _ec2_client()
    log.info(
        "Issuing ModifyInstanceMetadataOptions on instance %s — "
        "setting HttpTokens=optional, HopLimit=2 (TTP: T1578)",
        instance_id,
    )

    try:
        resp = ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="optional",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=2,
        )
        new_opts = resp.get("InstanceMetadataOptions", {})
        log.info(
            "ModifyInstanceMetadataOptions succeeded. "
            "New IMDS options: %s",
            new_opts,
        )

        # Record the attack timestamp for MTTD measurement in verification
        _STATE["attack_time_monotonic"] = time.monotonic()
        _STATE["attack_time_utc"] = time.time()
        log.info(
            "Attack step 1.2 complete — IMDS weakened to IMDSv1-optional, "
            "HopLimit=2. CloudTrail will record this event."
        )
        return True

    except Exception as exc:  # noqa: BLE001
        log.error(
            "attack(): ModifyInstanceMetadataOptions failed: %s", exc
        )
        return False


# ===========================================================================
# 3. HYPOTHESIS VERIFICATION — hypothesis_verification()
# ===========================================================================
def hypothesis_verification() -> bool:
    """
    Detective Probe Verification for SCE Experiment 1.3, Attack Node 1.2.

    Validates ALL THREE detection signals within the 30-minute SLA window,
    directly corresponding to Detective Safeguard 1.4 in the ADT:

      Signal A — CloudTrail event in CloudWatch Logs:
        The ModifyInstanceMetadataOptions event appears in the CloudWatch
        Logs group associated with the trail (filter_log_events with
        instance-scoped pattern).

      Signal B — EventBridge rule invocation:
        The EventBridge rule matching ModifyInstanceMetadataOptions registers
        at least one invocation in the AWS/Events Invocations metric.

      Signal C — CloudWatch Alarm in ALARM state:
        The CloudWatch alarm built on the CW Logs metric filter transitions
        from OK/INSUFFICIENT_DATA to ALARM state.

    MTTD is measured from attack() completion to first signal confirmation.
    All three signals must be confirmed for the probe to return True.

    Returns True (probe PASSED) only when all signals confirmed within SLA.
    Returns False (probe FAILED) if any signal is absent after 1800s.
    """
    log.info("=== hypothesis_verification() — begin ===")

    instance_id = _STATE.get("instance_id", "")
    alarm_name = _STATE.get("alarm_name", "")
    rule_name = _STATE.get("rule_name", "")
    log_group_name = _STATE.get("log_group_name", "")
    attack_time_monotonic = _STATE.get("attack_time_monotonic", None)

    # Guard: require instance_id — fail descriptively, not silently
    if not instance_id:
        log.error(
            "hypothesis_verification(): instance_id missing from _STATE. "
            "This indicates steady_state() did not complete successfully. "
            "Ensure steady_state() runs before hypothesis_verification()."
        )
        return False

    if not all([alarm_name, rule_name, log_group_name]):
        log.error(
            "hypothesis_verification(): one or more required state keys "
            "are missing: alarm_name='%s', rule_name='%s', "
            "log_group_name='%s'.",
            alarm_name, rule_name, log_group_name,
        )
        return False

    results: dict[str, bool] = {
        "signal_a_cloudtrail_log": False,
        "signal_b_eventbridge_invocation": False,
        "signal_c_cloudwatch_alarm": False,
    }
    signal_mttd: dict[str, float] = {}

    # ── Signal A: CloudTrail event delivered to CloudWatch Logs ──────────
    logs = _logs_client()
    log.info(
        "Signal A: polling CloudWatch Logs group '%s' for "
        "ModifyInstanceMetadataOptions event on instance %s ...",
        log_group_name,
        instance_id,
    )

    def _cloudtrail_event_in_logs() -> bool:
        try:
            # Structured filter: eventName must match AND instanceId must match
            # This reduces false-positive risk in shared accounts
            filter_pattern = (
                '{ $.eventName = "ModifyInstanceMetadataOptions" '
                f'&& $.requestParameters.instanceId = "{instance_id}" }}'
            )
            response = logs.filter_log_events(
                logGroupName=log_group_name,
                filterPattern=filter_pattern,
                limit=10,
            )
            events = response.get("events", [])
            if events:
                elapsed = (
                    time.monotonic() - attack_time_monotonic
                    if attack_time_monotonic
                    else -1
                )
                log.info(
                    "Signal A CONFIRMED — %d CloudTrail log event(s) found "
                    "for instance %s. MTTD=%.1fs",
                    len(events),
                    instance_id,
                    elapsed,
                )
                signal_mttd["signal_a"] = elapsed
                return True
            return False
        except Exception as exc:  # noqa: BLE001
            log.warning("Signal A poll error: %s", exc)
            return False

    results["signal_a_cloudtrail_log"] = _wait_until(
        _cloudtrail_event_in_logs,
        "Signal A: CloudTrail event in CloudWatch Logs",
        timeout_s=1800,
        poll_s=30,
    )

    # ── Signal B: EventBridge rule invocation metric ──────────────────────
    import datetime

    cw = _cw_client()
    log.info(
        "Signal B: checking EventBridge rule '%s' Invocations metric ...",
        rule_name,
    )

    def _eventbridge_invoked() -> bool:
        try:
            end = datetime.datetime.utcnow()
            # Look back 40 minutes to cover full SLA window plus buffer
            start = end - datetime.timedelta(minutes=40)
            resp = cw.get_metric_statistics(
                Namespace="AWS/Events",
                MetricName="Invocations",
                Dimensions=[{"Name": "RuleName", "Value": rule_name}],
                StartTime=start,
                EndTime=end,
                Period=3600,
                Statistics=["Sum"],
            )
            datapoints = resp.get("Datapoints", [])
            total = sum(dp["Sum"] for dp in datapoints)
            log.info(
                "Signal B — EventBridge Invocations for rule '%s': %.0f",
                rule_name,
                total,
            )
            if total >= 1:
                elapsed = (
                    time.monotonic() - attack_time_monotonic
                    if attack_time_monotonic
                    else -1
                )
                log.info(
                    "Signal B CONFIRMED — EventBridge rule '%s' fired. "
                    "MTTD=%.1fs",
                    rule_name,
                    elapsed,
                )
                signal_mttd["signal_b"] = elapsed
                return True
            return False
        except Exception as exc:  # noqa: BLE001
            log.warning("Signal B poll error: %s", exc)
            return False

    results["signal_b_eventbridge_invocation"] = _wait_until(
        _eventbridge_invoked,
        "Signal B: EventBridge rule invocation",
        timeout_s=1800,
        poll_s=30,
    )

    # ── Signal C: CloudWatch Alarm in ALARM state ─────────────────────────
    log.info(
        "Signal C: polling CloudWatch Alarm '%s' for ALARM state ...",
        alarm_name,
    )

    def _alarm_fired() -> bool:
        try:
            resp = cw.describe_alarms(AlarmNames=[alarm_name])
            alarms = resp.get("MetricAlarms", [])
            if not alarms:
                log.warning(
                    "Signal C — alarm '%s' not found in describe_alarms.",
                    alarm_name,
                )
                return False
            state = alarms[0].get("StateValue", "INSUFFICIENT_DATA")
            log.info(
                "Signal C — alarm '%s' state: %s", alarm_name, state
            )
            if state == "ALARM":
                elapsed = (
                    time.monotonic() - attack_time_monotonic
                    if attack_time_monotonic
                    else -1
                )
                log.info(
                    "Signal C CONFIRMED — alarm '%s' transitioned to ALARM. "
                    "MTTD=%.1fs",
                    alarm_name,
                    elapsed,
                )
                signal_mttd["signal_c"] = elapsed
                return True
            return False
        except Exception as exc:  # noqa: BLE001
            log.warning("Signal C poll error: %s", exc)
            return False

    results["signal_c_cloudwatch_alarm"] = _wait_until(
        _alarm_fired,
        "Signal C: CloudWatch Alarm in ALARM state",
        timeout_s=1800,
        poll_s=30,
    )

    # ── MTTD summary report ───────────────────────────────────────────────
    log.info("=== MTTD Summary ===")
    for sig, elapsed in signal_mttd.items():
        log.info(
            "  %s detected in %.1f seconds (%.1f minutes)",
            sig,
            elapsed,
            elapsed / 60,
        )

    # ── Final verdict ─────────────────────────────────────────────────────
    log.info("=== hypothesis_verification() — results ===")
    for signal, passed in results.items():
        status = "PASS" if passed else "FAIL"
        log.info("  %-40s: %s", signal, status)

    all_passed = all(results.values())
    if all_passed:
        log.info(
            "DETECTIVE PROBE 1.3 PASSED — all three detection signals "
            "confirmed within the 30-minute SLA window."
        )
    else:
        failed = [k for k, v in results.items() if not v]
        log.error(
            "DETECTIVE PROBE 1.3 FAILED — the following signals were NOT "
            "detected within the 30-minute SLA window: %s",
            failed,
        )
    return all_passed


# ===========================================================================
# 4. ROLLBACK — rollback()
# ===========================================================================
def rollback() -> None:
    """
    Delete the CloudFormation stack and all resources created in steady_state().

    Safe and idempotent:
      - Empties the CloudTrail S3 bucket before stack deletion (CFN cannot
        delete non-empty S3 buckets).
      - Tolerates missing stacks (StackNotFound is not an error).
      - Waits for complete deletion with the 30-minute SLA.
      - Always called in the experiment's finally block.
    """
    log.info("=== rollback() — begin ===")

    stack_name = _STATE.get("stack_name", "")
    if not stack_name:
        log.warning(
            "rollback(): no stack_name in _STATE — nothing to tear down."
        )
        return

    # Empty the S3 bucket first (prevents CFN deletion failure)
    _empty_trail_bucket()

    cfn = _cfn_client()

    if not _stack_exists(stack_name):
        log.info(
            "Stack '%s' does not exist — rollback already complete.",
            stack_name,
        )
        return

    log.info("Deleting CloudFormation stack '%s' ...", stack_name)
    try:
        cfn.delete_stack(StackName=stack_name)
    except Exception as exc:  # noqa: BLE001
        log.error(
            "rollback(): error initiating stack deletion for '%s': %s",
            stack_name,
            exc,
        )
        return

    success = _wait_stack_complete(stack_name, "DELETE")
    if success:
        log.info(
            "Stack '%s' deleted successfully.", stack_name
        )
    else:
        log.error(
            "Stack '%s' deletion did not complete within the 30-minute SLA. "
            "Manual cleanup may be required. Stack name: %s",
            stack_name,
            stack_name,
        )

    log.info("=== rollback() — complete ===")


def _empty_trail_bucket() -> None:
    """
    Remove all objects and delete markers from the CloudTrail S3 bucket
    so CloudFormation can delete it. Silently skips if the bucket does
    not exist or if the suffix is unavailable.
    """
    suffix = _STATE.get("timestamp_suffix", "")
    if not suffix:
        log.warning(
            "_empty_trail_bucket(): timestamp_suffix not set — "
            "cannot determine bucket name. Skipping."
        )
        return

    bucket_name = f"sce-ct-bucket-{suffix}"
    s3 = _s3_client()
    log.info(
        "Emptying S3 bucket '%s' before stack deletion ...", bucket_name
    )

    try:
        # Delete versioned objects and delete markers
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objects_to_delete = []
            for version in page.get("Versions", []):
                objects_to_delete.append(
                    {
                        "Key": version["Key"],
                        "VersionId": version["VersionId"],
                    }
                )
            for marker in page.get("DeleteMarkers", []):
                objects_to_delete.append(
                    {
                        "Key": marker["Key"],
                        "VersionId": marker["VersionId"],
                    }
                )
            if objects_to_delete:
                s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={
                        "Objects": objects_to_delete,
                        "Quiet": True,
                    },
                )

        # Delete unversioned objects (belt-and-suspenders)
        paginator2 = s3.get_paginator("list_objects_v2")
        for page in paginator2.paginate(Bucket=bucket_name):
            objects = [
                {"Key": obj["Key"]}
                for obj in page.get("Contents", [])
            ]
            if objects:
                s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={"Objects": objects, "Quiet": True},
                )

        log.info("Bucket '%s' emptied successfully.", bucket_name)

    except s3.exceptions.NoSuchBucket:
        log.info(
            "Bucket '%s' does not exist — skipping empty.", bucket_name
        )
    except Exception as exc:  # noqa: BLE001
        log.warning(
            "_empty_trail_bucket(): error emptying bucket '%s': %s",
            bucket_name,
            exc,
        )


# ===========================================================================
# Direct execution entrypoint
# ===========================================================================
def _run_experiment() -> None:
    """
    Runs the full experiment sequence (steady_state → attack →
    hypothesis_verification) with guaranteed rollback in the finally block.
    Mirrors the execution order that chaostoolkit follows via the manifest.
    """
    log.info(
        "╔══════════════════════════════════════════════════════════════╗"
    )
    log.info(
        "║  SCE Experiment 1.3 — Detective Probe — Direct Execution     ║"
    )
    log.info(
        "╚══════════════════════════════════════════════════════════════╝"
    )
    try:
        steady_state()
        attack_result = attack()
        if not attack_result:
            log.error(
                "Attack step returned False — hypothesis verification "
                "may be inconclusive. Proceeding anyway."
            )
        probe_result = hypothesis_verification()
        if probe_result:
            log.info("EXPERIMENT RESULT: PASSED ✓")
        else:
            log.error("EXPERIMENT RESULT: FAILED ✗")
    finally:
        rollback()


if __name__ == "__main__":
    _run_experiment()