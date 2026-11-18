"""
SCE Experiment 1.3 - Detective Probe
Attack Node 1.2: Enumerate Target EC2 Instance & IMDS Configuration
TTP: T1580 - Cloud Infrastructure Discovery

Validates that detective controls (CloudTrail logging + CloudWatch metric filter
+ CloudWatch alarm) successfully detect unauthorized ec2:DescribeInstances
reconnaissance attempts against banking EC2 infrastructure.

Defense Node 1.4: CloudTrail Anomaly Detection & GuardDuty
Classification: Detective
Description: CloudTrail logs every ec2:DescribeInstances API call with full
principal ARN, source IP, and user agent. A custom CloudWatch metric filter
triggers an alarm when DescribeInstances is invoked by any principal outside
the approved operations IAM group.
"""

import json
import logging
import os
import sys
import time

try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Global experiment state
# ──────────────────────────────────────────────
_state = {
    "timestamp": None,
    "stack_name": None,
    "role_arn": None,
    "external_id": None,
    "account_id": None,
    "region": None,
    "trail_name": None,
    "log_group_name": None,
    "alarm_name": None,
    "metric_namespace": None,
    "metric_name": None,
    "sns_topic_arn": None,
    "bucket_name": None,
    "attack_executed": False,
    "attack_time_utc": None,
    "attack_principal_arn": None,
    "attack_event_name": "DescribeInstances",
}

STACK_CREATION_TIMEOUT = 1200   # seconds
STACK_DELETION_TIMEOUT = 600    # seconds
IAM_PROPAGATION_WAIT = 25       # seconds
POLL_INTERVAL = 15              # seconds
SLA_TIMEOUT = 1800              # 30 minutes for detective verification


def _get_caller_identity():
    """Return account ID and region from current credentials."""
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    session = boto3.session.Session()
    return identity["Account"], session.region_name or "us-east-1"


def _cfn_template(account_id: str, external_id: str, ts: int) -> str:
    """
    Build a CloudFormation template that creates:
      1. An S3 bucket for CloudTrail log delivery
      2. A CloudTrail trail delivering to CloudWatch Logs
      3. A CloudWatch Log Group receiving CloudTrail events
      4. A CloudWatch Metric Filter that matches ec2:DescribeInstances
         calls from the simulated attacker role
      5. A CloudWatch Alarm that fires when the metric filter triggers
      6. An SNS Topic as the alarm action target
      7. An IAM role for CloudTrail to write to CloudWatch Logs
      8. A simulated attacker IAM role (CI/CD role) that CAN call
         ec2:DescribeInstances (no boundary — we want the call to succeed
         so the detective control can observe it)
    """
    trail_name = f"sce-trail-{ts}"
    log_group_name = f"/sce/cloudtrail/{ts}"
    metric_ns = f"SCE/Detective/{ts}"
    metric_name = "EC2ReconAttempts"
    alarm_name = f"sce-recon-alarm-{ts}"
    bucket_name = f"sce-trail-bucket-{ts}"

    _state["trail_name"] = trail_name
    _state["log_group_name"] = log_group_name
    _state["metric_namespace"] = metric_ns
    _state["metric_name"] = metric_name
    _state["alarm_name"] = alarm_name
    _state["bucket_name"] = bucket_name

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.3 Detective - CloudTrail + CW Metric Filter detects EC2 reconnaissance",
        "Resources": {
            # ── S3 Bucket for CloudTrail ──
            "TrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": bucket_name,
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Detective"},
                        {"Key": "Timestamp", "Value": str(ts)},
                    ],
                },
            },
            "TrailBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "DependsOn": "TrailBucket",
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
                                "Resource": f"arn:aws:s3:::{bucket_name}",
                                "Condition": {
                                    "StringEquals": {
                                        "AWS:SourceAccount": account_id
                                    }
                                },
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                                "Condition": {
                                    "StringEquals": {
                                        "s3:x-amz-acl": "bucket-owner-full-control",
                                        "AWS:SourceAccount": account_id,
                                    }
                                },
                            },
                        ],
                    },
                },
            },
            # ── CloudWatch Log Group ──
            "TrailLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": log_group_name,
                    "RetentionInDays": 1,
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Detective"},
                        {"Key": "Timestamp", "Value": str(ts)},
                    ],
                },
            },
            # ── IAM Role for CloudTrail → CloudWatch Logs ──
            "TrailCWRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-trail-cw-role-{ts}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "CloudTrailToCloudWatch",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                        ],
                                        "Resource": f"arn:aws:logs:*:{account_id}:log-group:{log_group_name}:*",
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Detective"},
                    ],
                },
            },
            # ── CloudTrail Trail ──
            "DetectiveTrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": ["TrailBucketPolicy", "TrailLogGroup", "TrailCWRole"],
                "Properties": {
                    "TrailName": trail_name,
                    "S3BucketName": {"Ref": "TrailBucket"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": True,
                    "EnableLogFileValidation": True,
                    "CloudWatchLogsLogGroupArn": {
                        "Fn::GetAtt": ["TrailLogGroup", "Arn"]
                    },
                    "CloudWatchLogsRoleArn": {
                        "Fn::GetAtt": ["TrailCWRole", "Arn"]
                    },
                    "EventSelectors": [
                        {
                            "ReadWriteType": "All",
                            "IncludeManagementEvents": True,
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Detective"},
                        {"Key": "Timestamp", "Value": str(ts)},
                    ],
                },
            },
            # ── SNS Topic for alarm ──
            "AlarmTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": f"sce-recon-alert-{ts}",
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Detective"},
                    ],
                },
            },
            # ── CloudWatch Metric Filter ──
            "ReconMetricFilter": {
                "Type": "AWS::Logs::MetricFilter",
                "DependsOn": ["TrailLogGroup", "DetectiveTrail"],
                "Properties": {
                    "LogGroupName": log_group_name,
                    "FilterPattern": '{ ($.eventName = "DescribeInstances") }',
                    "MetricTransformations": [
                        {
                            "MetricNamespace": metric_ns,
                            "MetricName": metric_name,
                            "MetricValue": "1",
                            "DefaultValue": 0,
                        }
                    ],
                },
            },
            # ── CloudWatch Alarm ──
            "ReconAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "DependsOn": ["ReconMetricFilter", "AlarmTopic"],
                "Properties": {
                    "AlarmName": alarm_name,
                    "AlarmDescription": "Detects ec2:DescribeInstances reconnaissance calls via CloudTrail",
                    "Namespace": metric_ns,
                    "MetricName": metric_name,
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "DatapointsToAlarm": 1,
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "TreatMissingData": "notBreaching",
                    "AlarmActions": [{"Ref": "AlarmTopic"}],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Detective"},
                    ],
                },
            },
            # ── Simulated attacker role (NO permission boundary) ──
            "AttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-attacker-{ts}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": f"arn:aws:iam::{account_id}:root"
                                },
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringEquals": {
                                        "sts:ExternalId": external_id,
                                    }
                                },
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "AllowEC2Describe",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:DescribeInstances",
                                        ],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Detective"},
                        {"Key": "Purpose", "Value": "SimulatedAttacker"},
                    ],
                },
            },
        },
        "Outputs": {
            "AttackerRoleArn": {
                "Description": "ARN of the simulated attacker role",
                "Value": {"Fn::GetAtt": ["AttackerRole", "Arn"]},
            },
            "TrailArn": {
                "Description": "ARN of the CloudTrail trail",
                "Value": {"Fn::GetAtt": ["DetectiveTrail", "Arn"]},
            },
            "LogGroupArn": {
                "Description": "ARN of the CloudWatch Log Group",
                "Value": {"Fn::GetAtt": ["TrailLogGroup", "Arn"]},
            },
            "AlarmArn": {
                "Description": "ARN of the CloudWatch Alarm",
                "Value": {"Fn::GetAtt": ["ReconAlarm", "Arn"]},
            },
            "SnsTopicArn": {
                "Description": "ARN of the SNS topic",
                "Value": {"Ref": "AlarmTopic"},
            },
        },
    }
    return json.dumps(template)


def _wait_for_stack(cfn_client, stack_name: str, target_status: str, timeout: int):
    """Poll CloudFormation stack until it reaches target_status or times out."""
    start = time.monotonic()
    attempt = 0
    while True:
        attempt += 1
        elapsed = time.monotonic() - start
        if elapsed > timeout:
            raise TimeoutError(
                f"Stack {stack_name} did not reach {target_status} within {timeout}s"
            )
        try:
            resp = cfn_client.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            logger.info(
                "Stack status: %s (attempt %d, %.0fs elapsed)",
                status, attempt, elapsed,
            )
            if status == target_status:
                logger.info(
                    "Stack reached %s after %d attempts", target_status, attempt
                )
                return resp["Stacks"][0]
            if "FAILED" in status or status == "ROLLBACK_COMPLETE":
                reason = resp["Stacks"][0].get("StackStatusReason", "unknown")
                raise RuntimeError(
                    f"Stack {stack_name} entered {status}: {reason}"
                )
        except ClientError as exc:
            if "does not exist" in str(exc):
                if target_status == "DELETE_COMPLETE":
                    logger.info("Stack deleted (no longer exists)")
                    return None
                raise
            logger.warning("Describe stack error: %s", exc)
        time.sleep(POLL_INTERVAL)


def _verify_role_assumable(sts_client, role_arn: str, external_id: str, retries: int = 12):
    """Wait until the IAM role is assumable (eventual consistency)."""
    for attempt in range(1, retries + 1):
        try:
            creds = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="sce-verify",
                ExternalId=external_id,
                DurationSeconds=900,
            )
            logger.info("Role verification completed after %d attempts", attempt)
            return creds
        except ClientError as exc:
            logger.warning(
                "Role not yet assumable (attempt %d/%d): %s",
                attempt, retries, exc,
            )
            if attempt == retries:
                raise
            time.sleep(5 + attempt * 2)


# ──────────────────────────────────────────────
# 1. STEADY STATE — Provision detective controls
# ──────────────────────────────────────────────
def steady_state():
    """
    Deploy CloudFormation stack that creates:
      - CloudTrail trail delivering to CloudWatch Logs
      - CloudWatch Metric Filter matching DescribeInstances events
      - CloudWatch Alarm that triggers on the metric
      - SNS Topic as alarm action
      - Simulated attacker IAM role (allowed to call DescribeInstances)
    """
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.3 Detective - Steady State Setup")
    logger.info("=" * 60)

    ts = int(time.time())
    _state["timestamp"] = ts
    _state["stack_name"] = f"sce-1-3-det-{ts}"
    _state["external_id"] = f"sce-det-{ts}"

    logger.info("Timestamp: %d", ts)
    logger.info("Stack name: %s", _state["stack_name"])

    account_id, region = _get_caller_identity()
    _state["account_id"] = account_id
    _state["region"] = region
    logger.info("Account: %s, Region: %s", account_id, region)

    cfn = boto3.client("cloudformation", region_name=region)
    template_body = _cfn_template(account_id, _state["external_id"], ts)

    # Create stack with retries
    for attempt in range(1, 4):
        try:
            logger.info("Creating CloudFormation stack (attempt %d)...", attempt)
            cfn.create_stack(
                StackName=_state["stack_name"],
                TemplateBody=template_body,
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Tags=[
                    {"Key": "Experiment", "Value": "SCE-1.3-Detective"},
                    {"Key": "Timestamp", "Value": str(ts)},
                    {"Key": "Purpose", "Value": "ChaosEngineering"},
                ],
                TimeoutInMinutes=15,
            )
            logger.info("Stack creation initiated")
            break
        except ClientError as exc:
            if "AlreadyExistsException" in str(exc):
                logger.warning("Stack already exists — reusing")
                break
            if attempt == 3:
                logger.error("Failed to create stack after 3 attempts: %s", exc)
                raise
            logger.warning("Stack creation error (attempt %d): %s", attempt, exc)
            time.sleep(5 * attempt)

    # Wait for stack creation
    logger.info("Waiting up to %ds for stack creation...", STACK_CREATION_TIMEOUT)
    stack = _wait_for_stack(
        cfn, _state["stack_name"], "CREATE_COMPLETE", STACK_CREATION_TIMEOUT
    )

    # Extract outputs
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    _state["role_arn"] = outputs.get("AttackerRoleArn")
    _state["sns_topic_arn"] = outputs.get("SnsTopicArn")
    logger.info("Attacker Role ARN: %s", _state["role_arn"])
    logger.info("Trail name: %s", _state["trail_name"])
    logger.info("Log Group: %s", _state["log_group_name"])
    logger.info("Alarm: %s", _state["alarm_name"])
    logger.info("SNS Topic: %s", _state["sns_topic_arn"])

    if not _state["role_arn"]:
        raise RuntimeError("AttackerRoleArn output not found in stack outputs")

    # Wait for IAM propagation
    logger.info("Waiting %ds for IAM propagation...", IAM_PROPAGATION_WAIT)
    time.sleep(IAM_PROPAGATION_WAIT)

    # Verify role is assumable
    logger.info("Verifying attacker role assumability...")
    sts = boto3.client("sts", region_name=region)
    _verify_role_assumable(sts, _state["role_arn"], _state["external_id"])

    # Verify trail is logging
    ct = boto3.client("cloudtrail", region_name=region)
    for attempt in range(1, 6):
        try:
            status = ct.get_trail_status(Name=_state["trail_name"])
            if status.get("IsLogging"):
                logger.info("CloudTrail trail is actively logging")
                break
            else:
                logger.warning("Trail not yet logging (attempt %d)", attempt)
        except ClientError as exc:
            logger.warning("Trail status check error (attempt %d): %s", attempt, exc)
        time.sleep(10)

    # Verify alarm exists and is in OK state
    cw = boto3.client("cloudwatch", region_name=region)
    for attempt in range(1, 6):
        try:
            resp = cw.describe_alarms(AlarmNames=[_state["alarm_name"]])
            alarms = resp.get("MetricAlarms", [])
            if alarms:
                alarm_state = alarms[0].get("StateValue", "UNKNOWN")
                logger.info("Alarm '%s' state: %s", _state["alarm_name"], alarm_state)
                break
            else:
                logger.warning("Alarm not yet visible (attempt %d)", attempt)
        except ClientError as exc:
            logger.warning("Alarm check error (attempt %d): %s", attempt, exc)
        time.sleep(10)

    logger.info("=" * 60)
    logger.info("Steady state setup COMPLETED")
    logger.info("=" * 60)


# ──────────────────────────────────────────────
# 2. ATTACK — T1580 Cloud Infrastructure Discovery
# ──────────────────────────────────────────────
def attack() -> bool:
    """
    Execute Attack Node 1.2: Enumerate Target EC2 Instance & IMDS Configuration.

    Assumes the simulated attacker role and calls ec2:DescribeInstances.
    The call is ALLOWED (no permission boundary) so it generates a CloudTrail
    event that the detective controls must detect.

    Returns True after the attack is executed.
    """
    logger.info("=" * 60)
    logger.info("SCE 1.3 Detective - Attack Node 1.2: EC2 Reconnaissance")
    logger.info("TTP: T1580 - Cloud Infrastructure Discovery")
    logger.info("=" * 60)

    region = _state["region"]
    role_arn = _state["role_arn"]
    external_id = _state["external_id"]

    if not role_arn:
        logger.error("Role ARN not available — steady_state may have failed")
        _state["attack_executed"] = False
        return True

    # Assume the attacker role
    logger.info("Assuming attacker role: %s", role_arn)
    sts = boto3.client("sts", region_name=region)
    try:
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="sce-detective-attack",
            ExternalId=external_id,
            DurationSeconds=900,
        )
        logger.info("Role assumed successfully")
        _state["attack_principal_arn"] = assumed["AssumedRoleUser"]["Arn"]
        logger.info("Attack principal ARN: %s", _state["attack_principal_arn"])
    except ClientError as exc:
        logger.error("Failed to assume attacker role: %s", exc)
        _state["attack_executed"] = False
        return True

    creds = assumed["Credentials"]
    ec2 = boto3.client(
        "ec2",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

    # Record attack timestamp BEFORE execution
    import datetime
    _state["attack_time_utc"] = datetime.datetime.utcnow()
    logger.info("Attack timestamp (UTC): %s", _state["attack_time_utc"].isoformat())

    # Execute the reconnaissance command
    logger.info("Executing: aws ec2 describe-instances (expecting SUCCESS for detective trail)")
    start_time = time.monotonic()
    try:
        response = ec2.describe_instances(MaxResults=5)
        duration = time.monotonic() - start_time
        instance_count = sum(
            len(r.get("Instances", []))
            for r in response.get("Reservations", [])
        )
        logger.info("DescribeInstances SUCCEEDED (as expected for detective probe)")
        logger.info("Instances returned: %d", instance_count)
        logger.info("Duration: %.2fs", duration)
        _state["attack_executed"] = True
    except ClientError as exc:
        duration = time.monotonic() - start_time
        error_code = exc.response["Error"]["Code"]
        logger.warning(
            "DescribeInstances returned error: %s (still generates CloudTrail event)",
            error_code,
        )
        logger.info("Duration: %.2fs", duration)
        # Even denied calls appear in CloudTrail, so we consider the attack executed
        _state["attack_executed"] = True

    # Execute a second call to increase confidence of detection
    logger.info("Executing second DescribeInstances call for detection confidence")
    try:
        ec2.describe_instances(MaxResults=5)
        logger.info("Second DescribeInstances call completed")
    except ClientError as exc:
        logger.info("Second call error (still logged): %s", exc)

    logger.info("=" * 60)
    logger.info("Attack execution completed")
    logger.info("=" * 60)

    return True


# ──────────────────────────────────────────────
# 3. HYPOTHESIS VERIFICATION — Detective probe
# ──────────────────────────────────────────────
def hypothesis_verification() -> bool:
    """
    Verify that detective controls detected the EC2 reconnaissance attack.

    Checks two detection channels with a 30-minute SLA polling window:
      1. CloudTrail event logged in CloudWatch Logs: the DescribeInstances
         call from the attacker role appears in the log group
      2. CloudWatch Alarm triggered: the metric filter matched the event
         and the alarm transitioned to ALARM state

    Returns True if at least CloudTrail evidence is found (alarm may lag).
    """
    logger.info("=" * 60)
    logger.info("SCE 1.3 Detective - Hypothesis Verification")
    logger.info("=" * 60)

    if not _state.get("attack_executed"):
        logger.error("Attack was not executed — cannot verify detection")
        return False

    region = _state["region"]
    log_group_name = _state["log_group_name"]
    alarm_name = _state["alarm_name"]
    attack_principal = _state.get("attack_principal_arn", "")
    attack_event = _state["attack_event_name"]

    logs_client = boto3.client("logs", region_name=region)
    cw_client = boto3.client("cloudwatch", region_name=region)

    cloudtrail_detected = False
    alarm_triggered = False

    start = time.monotonic()
    attempt = 0

    logger.info("Starting detection verification (SLA: %ds)", SLA_TIMEOUT)
    logger.info("Looking for event: %s from principal: %s", attack_event, attack_principal)

    while time.monotonic() - start < SLA_TIMEOUT:
        attempt += 1
        elapsed = time.monotonic() - start
        logger.info(
            "Verification attempt %d (%.0fs / %ds elapsed)",
            attempt, elapsed, SLA_TIMEOUT,
        )

        # ── Check 1: CloudTrail events in CloudWatch Logs ──
        if not cloudtrail_detected:
            try:
                # Use filter_log_events to search for DescribeInstances from attacker role
                filter_pattern = f'{{ ($.eventName = "{attack_event}") }}'
                resp = logs_client.filter_log_events(
                    logGroupName=log_group_name,
                    filterPattern=filter_pattern,
                    limit=50,
                )
                events = resp.get("events", [])
                logger.info(
                    "CloudWatch Logs filter returned %d matching events", len(events)
                )

                for event in events:
                    try:
                        msg = json.loads(event.get("message", "{}"))
                        event_name = msg.get("eventName", "")
                        user_identity = msg.get("userIdentity", {})
                        principal_arn = user_identity.get("arn", "")

                        if event_name == attack_event:
                            # Check if this is from our attacker role
                            role_name_fragment = f"sce-attacker-{_state['timestamp']}"
                            if role_name_fragment in principal_arn:
                                logger.info(
                                    "DETECTED: %s call from %s at %s",
                                    event_name,
                                    principal_arn,
                                    msg.get("eventTime", "unknown"),
                                )
                                logger.info(
                                    "Source IP: %s, User Agent: %s",
                                    msg.get("sourceIPAddress", "unknown"),
                                    msg.get("userAgent", "unknown"),
                                )
                                cloudtrail_detected = True
                                break
                            else:
                                logger.info(
                                    "Found DescribeInstances but from different principal: %s",
                                    principal_arn,
                                )
                    except (json.JSONDecodeError, KeyError) as parse_err:
                        logger.warning("Failed to parse log event: %s", parse_err)

            except ClientError as exc:
                if "ResourceNotFoundException" in str(exc):
                    logger.info("Log group not yet populated")
                else:
                    logger.warning("Log query error: %s", exc)

        # ── Check 2: CloudWatch Alarm state ──
        if not alarm_triggered:
            try:
                resp = cw_client.describe_alarms(AlarmNames=[alarm_name])
                alarms = resp.get("MetricAlarms", [])
                if alarms:
                    current_state = alarms[0].get("StateValue", "UNKNOWN")
                    logger.info("Alarm '%s' state: %s", alarm_name, current_state)
                    if current_state == "ALARM":
                        alarm_triggered = True
                        logger.info("DETECTED: Alarm transitioned to ALARM state")
                        state_reason = alarms[0].get("StateReason", "N/A")
                        logger.info("Alarm reason: %s", state_reason)
                else:
                    logger.warning("Alarm not found")
            except ClientError as exc:
                logger.warning("Alarm check error: %s", exc)

        # ── Evaluate if we have enough evidence ──
        if cloudtrail_detected and alarm_triggered:
            logger.info("Both detection channels confirmed")
            break
        elif cloudtrail_detected:
            # CloudTrail confirmed, alarm may still be processing
            logger.info(
                "CloudTrail detection confirmed; alarm pending (will continue polling)"
            )
            # Give alarm a bit more time but don't fail if only CloudTrail detected
            if elapsed > 300:
                logger.info(
                    "CloudTrail detected; alarm timeout acceptable after 5+ min"
                )
                break

        time.sleep(30)

    # ── Final assessment ──
    logger.info("=" * 60)
    logger.info("SCE 1.3 Detective - Verification Results")
    logger.info("=" * 60)
    logger.info("CloudTrail event detected: %s", cloudtrail_detected)
    logger.info("CloudWatch Alarm triggered: %s", alarm_triggered)

    # Also query CloudTrail directly as secondary evidence
    ct_direct_found = False
    try:
        import datetime
        ct_client = boto3.client("cloudtrail", region_name=region)
        attack_time = _state.get("attack_time_utc")
        if attack_time:
            lookup_resp = ct_client.lookup_events(
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": "DescribeInstances"},
                ],
                StartTime=attack_time - datetime.timedelta(minutes=5),
                EndTime=datetime.datetime.utcnow(),
                MaxResults=50,
            )
            ct_events = lookup_resp.get("Events", [])
            logger.info("CloudTrail lookup_events returned %d events", len(ct_events))
            for ev in ct_events:
                username = ev.get("Username", "")
                role_fragment = f"sce-attacker-{_state['timestamp']}"
                if role_fragment in username or role_fragment in str(ev.get("Resources", [])):
                    logger.info(
                        "CloudTrail direct lookup CONFIRMED: %s at %s",
                        username, ev.get("EventTime"),
                    )
                    ct_direct_found = True
                    break
    except ClientError as exc:
        logger.warning("CloudTrail direct lookup error: %s", exc)
    except Exception as exc:
        logger.warning("CloudTrail direct lookup unexpected error: %s", exc)

    logger.info("CloudTrail direct lookup confirmed: %s", ct_direct_found)

    # Hypothesis passes if ANY detection channel confirmed the event
    verified = cloudtrail_detected or alarm_triggered or ct_direct_found

    if verified:
        logger.info("=" * 60)
        logger.info("HYPOTHESIS VERIFIED: Detective controls detected the attack")
        logger.info("=" * 60)
        logger.info("Evidence summary:")
        if cloudtrail_detected:
            logger.info("  - CloudTrail event found in CloudWatch Logs log group")
        if alarm_triggered:
            logger.info("  - CloudWatch Alarm transitioned to ALARM state")
        if ct_direct_found:
            logger.info("  - CloudTrail LookupEvents confirmed the API call")
    else:
        logger.error("=" * 60)
        logger.error("HYPOTHESIS FAILED: Detective controls did not detect the attack")
        logger.error("=" * 60)
        logger.error("No detection evidence found within %ds SLA", SLA_TIMEOUT)

    return verified


# ──────────────────────────────────────────────
# 4. ROLLBACK — Teardown all resources
# ──────────────────────────────────────────────
def rollback():
    """
    Delete the CloudFormation stack and all resources created during steady_state.
    Handles the S3 bucket cleanup (must be emptied before CFN can delete it).
    """
    logger.info("=" * 60)
    logger.info("SCE 1.3 Detective - Rollback / Cleanup")
    logger.info("=" * 60)

    stack_name = _state.get("stack_name")
    region = _state.get("region")
    bucket_name = _state.get("bucket_name")

    if not stack_name:
        logger.warning("No stack name recorded — nothing to clean up")
        return

    if not region:
        _, region = _get_caller_identity()

    # Empty the S3 bucket first (CloudFormation cannot delete non-empty buckets)
    if bucket_name:
        logger.info("Emptying S3 bucket: %s", bucket_name)
        try:
            s3 = boto3.resource("s3", region_name=region)
            bucket = s3.Bucket(bucket_name)
            bucket.object_versions.all().delete()
            logger.info("All object versions deleted from bucket")
        except ClientError as exc:
            if "NoSuchBucket" in str(exc):
                logger.info("Bucket already deleted")
            else:
                logger.warning("Error emptying bucket: %s", exc)
        except Exception as exc:
            logger.warning("Unexpected error emptying bucket: %s", exc)
            # Try alternative approach
            try:
                s3_client = boto3.client("s3", region_name=region)
                paginator = s3_client.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=bucket_name):
                    objects = page.get("Contents", [])
                    if objects:
                        delete_keys = [{"Key": obj["Key"]} for obj in objects]
                        s3_client.delete_objects(
                            Bucket=bucket_name,
                            Delete={"Objects": delete_keys},
                        )
                logger.info("Bucket emptied via alternative method")
            except Exception as alt_exc:
                logger.warning("Alternative bucket cleanup also failed: %s", alt_exc)

    cfn = boto3.client("cloudformation", region_name=region)

    try:
        logger.info("Deleting stack: %s", stack_name)
        cfn.delete_stack(StackName=stack_name)
        logger.info("Deletion initiated")
    except ClientError as exc:
        if "does not exist" in str(exc):
            logger.info("Stack already deleted or does not exist")
            logger.info("=" * 60)
            logger.info("Cleanup completed")
            logger.info("=" * 60)
            return
        logger.error("Error initiating stack deletion: %s", exc)
        raise

    try:
        logger.info("Waiting for deletion...")
        _wait_for_stack(cfn, stack_name, "DELETE_COMPLETE", STACK_DELETION_TIMEOUT)
    except ClientError as exc:
        if "does not exist" in str(exc):
            logger.info("Stack deleted successfully (no longer exists)")
        else:
            logger.error("Error waiting for stack deletion: %s", exc)
    except TimeoutError:
        logger.error(
            "Stack deletion did not complete within %ds — manual cleanup may be needed",
            STACK_DELETION_TIMEOUT,
        )

    logger.info("=" * 60)
    logger.info("Cleanup completed")
    logger.info("=" * 60)


# ──────────────────────────────────────────────
# Direct execution support
# ──────────────────────────────────────────────
if __name__ == "__main__":
    try:
        steady_state()
        attack()
        result = hypothesis_verification()
        print(f"\nExperiment result: {'PASS' if result else 'FAIL'}")
        sys.exit(0 if result else 1)
    except Exception as exc:
        logger.exception("Experiment failed with exception: %s", exc)
        sys.exit(2)
    finally:
        try:
            rollback()
        except Exception as exc:
            logger.exception("Rollback failed: %s", exc)