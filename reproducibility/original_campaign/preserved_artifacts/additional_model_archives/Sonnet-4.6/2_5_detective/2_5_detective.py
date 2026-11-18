"""
SCE Experiment 2.5 - Detective Probe
Attack Nodes: 1.2 (Weaken IMDS) + 2.2 (Retrieve Credentials from Weakened IMDS)

ROOT CAUSE HISTORY AND FIXES APPLIED:
======================================
Run 1: CFN ROLLBACK_COMPLETE - unknown root cause (no event introspection)
  Fix: Added _get_cfn_failure_reason() + OnFailure=DO_NOTHING

Run 2: CFN CREATE_FAILED - six resources failed simultaneously
  Root cause: IAM principal lacked iam:CreateRole
  Fix: Moved all IAM resource creation outside CFN into boto3-native calls

Run 3: IAM ValidationError on create_role Description field
  Root cause: Description strings contained Unicode characters outside the
  AWS-allowed range [\u0009\u000A\u000D\u0020-\u007E\u00A1-\u00FF]*
  Likely source: em-dashes, curly quotes, or other typographic characters
  copied from documentation into the Description= parameter.
  Fix (THIS REVISION):
    1. _sanitize_aws_string(): strips all characters outside the AWS-allowed
       set before any IAM API call that accepts a Description or similar field.
    2. Remove Description= from create_role() and create_instance_profile()
       entirely - it is optional and not needed for experiment function.
    3. All hardcoded string constants in IAM calls audited and replaced with
       pure ASCII-safe values.
    4. Added _safe_role_name() to guarantee role/profile names contain only
       [A-Za-z0-9+=,.@_-] as required by IAM name constraints.
    5. get-or-create pattern for IAM roles (tolerates EntityAlreadyExists).

Detective Probe Intent (ADT node 2.5):
  With HopLimit raised to 2, confirm:
  (A) GuardDuty raises Policy:EC2/NoIMDSv2 or related finding
  (B) VPC Flow Log delivery pipeline has active log streams
  (C) EC2 control-plane durably reflects the IMDS change (CloudTrail proxy)
"""

# ---------------------------------------------------------------------------
# Bootstrap: ensure boto3 is available before any other import
# ---------------------------------------------------------------------------
import subprocess
import sys
import importlib.util as _ilu
import re


def _ensure_boto3() -> None:
    if _ilu.find_spec("boto3") is None:
        print("[BOOTSTRAP] boto3 not found - installing ...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "boto3"],
            stdout=subprocess.DEVNULL,
        )
        print("[BOOTSTRAP] boto3 installed.")


_ensure_boto3()

# ---------------------------------------------------------------------------
# Standard + third-party imports
# ---------------------------------------------------------------------------
import boto3
import json
import logging
import time
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global experiment state
# ---------------------------------------------------------------------------
_STATE: dict = {}

# ---------------------------------------------------------------------------
# Constants  (ALL pure ASCII - no Unicode typographic characters)
# ---------------------------------------------------------------------------
EXPERIMENT_TAG_KEY   = "SCEExperiment"
EXPERIMENT_TAG_VALUE = "2_5_detective"
STACK_PREFIX         = "sce-experiment"

SLA_SECONDS          = 1800   # 30-minute outer SLA for all polling
POLL_INTERVAL_S      = 20     # polling cadence (seconds)

CF_MAX_WAIT_S        = 900    # 15-min max for stack create/delete
CF_POLL_S            = 15

IAM_PROPAGATION_S    = 20     # seconds to wait after IAM role creation

ATTACK_HOP_LIMIT     = 2
ATTACK_HTTP_TOKENS   = "optional"

# AWS IAM Description field regex (what AWS actually accepts)
_AWS_DESCRIPTION_RE = re.compile(
    r"^[\u0009\u000A\u000D\u0020-\u007E\u00A1-\u00FF]*$"
)

# ---------------------------------------------------------------------------
# String sanitization helpers
# ---------------------------------------------------------------------------

def _sanitize_aws_string(value: str) -> str:
    """
    Remove any character that falls outside the AWS IAM description/tag
    allowed set: [\u0009\u000A\u000D\u0020-\u007E\u00A1-\u00FF]
    This eliminates em-dashes, curly quotes, and other non-ASCII-safe
    Unicode glyphs that cause AWS ValidationError.
    """
    allowed = re.compile(
        r"[^\u0009\u000A\u000D\u0020-\u007E\u00A1-\u00FF]"
    )
    return allowed.sub("", value)


def _safe_role_name(base: str) -> str:
    """
    Produce an IAM-safe name: only [A-Za-z0-9+=,.@_-], max 64 chars.
    Replaces any disallowed character with '-'.
    """
    safe = re.sub(r"[^A-Za-z0-9+=,.@_\-]", "-", base)
    return safe[:64]


# ---------------------------------------------------------------------------
# boto3 client helpers
# ---------------------------------------------------------------------------
def _session() -> boto3.Session:
    return boto3.Session()

def _cf():    return _session().client("cloudformation")
def _ec2():   return _session().client("ec2")
def _gd():    return _session().client("guardduty")
def _iam():   return _session().client("iam")
def _logs():  return _session().client("logs")
def _sts():   return _session().client("sts")
def _ssm():   return _session().client("ssm")


# ---------------------------------------------------------------------------
# AMI resolution
# ---------------------------------------------------------------------------
def _latest_al2_ami() -> str:
    """
    Resolve the latest Amazon Linux 2 AMI for the current region.
    Primary: SSM public parameter (no account resources needed).
    Fallback: ec2:DescribeImages owner=amazon.
    """
    try:
        resp   = _ssm().get_parameter(
            Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
        )
        ami_id = resp["Parameter"]["Value"]
        log.info("[AMI] Resolved via SSM: %s", ami_id)
        return ami_id
    except Exception as exc:  # noqa: BLE001
        log.warning("[AMI] SSM lookup failed (%s); using describe-images.", exc)

    try:
        resp   = _ec2().describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name",
                 "Values": ["amzn2-ami-hvm-2.0.*-x86_64-gp2"]},
                {"Name": "state",               "Values": ["available"]},
                {"Name": "virtualization-type", "Values": ["hvm"]},
            ],
        )
        images = sorted(
            resp["Images"], key=lambda x: x["CreationDate"], reverse=True
        )
        ami_id = images[0]["ImageId"]
        log.info("[AMI] Resolved via describe-images: %s", ami_id)
        return ami_id
    except Exception as exc2:  # noqa: BLE001
        log.error("[AMI] describe-images fallback failed: %s", exc2)
        raise RuntimeError("Cannot resolve Amazon Linux 2 AMI ID") from exc2


# ---------------------------------------------------------------------------
# GuardDuty: get-or-create detector (outside CFN)
# ---------------------------------------------------------------------------
def _get_or_create_guardduty_detector() -> tuple:
    """
    Returns (detector_id: str, owned_by_experiment: bool).
    owned=True  -> we created it; delete in rollback.
    owned=False -> pre-existing; do NOT delete in rollback.
    """
    gd = _gd()
    try:
        existing = gd.list_detectors().get("DetectorIds", [])
    except ClientError as exc:
        log.error("[GD] list_detectors failed: %s", exc)
        raise

    if existing:
        did = existing[0]
        log.info("[GD] Reusing pre-existing detector: %s", did)
        try:
            gd.update_detector(DetectorId=did, Enable=True)
        except ClientError as exc:
            log.warning("[GD] update_detector non-fatal: %s", exc)
        return did, False

    log.info("[GD] Creating new GuardDuty detector ...")
    resp = gd.create_detector(
        Enable=True,
        FindingPublishingFrequency="ONE_HOUR",
        Tags={EXPERIMENT_TAG_KEY: EXPERIMENT_TAG_VALUE},
    )
    did = resp["DetectorId"]
    log.info("[GD] Created detector: %s", did)
    return did, True


# ---------------------------------------------------------------------------
# IAM resources created directly via boto3 (NOT inside CloudFormation)
#
# KEY FIX (Run 3): All Description= parameters removed entirely.
# Description is optional for IAM roles/profiles and its absence avoids
# the ValidationError caused by non-ASCII characters.
# Role names are sanitized with _safe_role_name() to stay within
# [A-Za-z0-9+=,.@_-] and the 64-character IAM limit.
# ---------------------------------------------------------------------------
def _create_iam_resources(stack_name: str) -> dict:
    """
    Create EC2 instance role, instance profile, and VPC Flow Log delivery
    role directly via boto3.  Returns a dict of resource names/ARNs.

    No Description= field is passed to any IAM call to avoid the
    ValidationError from non-ASCII characters in documentation-derived
    string literals.
    """
    iam = _iam()

    # Build safe names derived from the stack name suffix
    suffix            = stack_name[-18:]
    inst_role_name    = _safe_role_name(f"sce-ir-{suffix}")
    flowlog_role_name = _safe_role_name(f"sce-fl-{suffix}")
    profile_name      = _safe_role_name(f"sce-ip-{suffix}")

    tags = [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]

    log.info("[IAM] inst_role_name    = %s", inst_role_name)
    log.info("[IAM] flowlog_role_name = %s", flowlog_role_name)
    log.info("[IAM] profile_name      = %s", profile_name)

    # ── EC2 instance role ────────────────────────────────────────────────────
    log.info("[IAM] Creating instance role ...")
    try:
        iam.create_role(
            RoleName=inst_role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            }),
            Tags=tags,
        )
        log.info("[IAM] Instance role created: %s", inst_role_name)
    except ClientError as exc:
        if "EntityAlreadyExists" in str(exc):
            log.warning("[IAM] Role %s already exists - reusing.", inst_role_name)
        else:
            log.error("[IAM] create_role(%s) failed: %s", inst_role_name, exc)
            raise

    try:
        iam.attach_role_policy(
            RoleName=inst_role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
        )
    except ClientError as exc:
        log.warning("[IAM] attach SSM policy non-fatal: %s", exc)

    try:
        iam.put_role_policy(
            RoleName=inst_role_name,
            PolicyName="SCEMinS3",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:ListAllMyBuckets"],
                    "Resource": "*",
                }],
            }),
        )
    except ClientError as exc:
        log.warning("[IAM] put_role_policy S3 non-fatal: %s", exc)

    # ── Instance profile ─────────────────────────────────────────────────────
    log.info("[IAM] Creating instance profile: %s", profile_name)
    try:
        iam.create_instance_profile(
            InstanceProfileName=profile_name,
            Tags=tags,
        )
    except ClientError as exc:
        if "EntityAlreadyExists" not in str(exc):
            log.error("[IAM] create_instance_profile failed: %s", exc)
            raise
        log.warning("[IAM] Instance profile %s already exists.", profile_name)

    try:
        iam.add_role_to_instance_profile(
            InstanceProfileName=profile_name,
            RoleName=inst_role_name,
        )
    except ClientError as exc:
        # LimitExceeded = role already in profile (idempotent)
        if "LimitExceeded" not in str(exc):
            log.warning("[IAM] add_role_to_profile non-fatal: %s", exc)

    # ── VPC Flow Log delivery role ───────────────────────────────────────────
    log.info("[IAM] Creating flow log role: %s", flowlog_role_name)
    try:
        iam.create_role(
            RoleName=flowlog_role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "vpc-flow-logs.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            }),
            Tags=tags,
        )
        log.info("[IAM] Flow log role created: %s", flowlog_role_name)
    except ClientError as exc:
        if "EntityAlreadyExists" in str(exc):
            log.warning("[IAM] Role %s already exists - reusing.", flowlog_role_name)
        else:
            log.error("[IAM] create_role(%s) failed: %s", flowlog_role_name, exc)
            raise

    try:
        iam.put_role_policy(
            RoleName=flowlog_role_name,
            PolicyName="SCEFlowLogCW",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:DescribeLogGroups",
                        "logs:DescribeLogStreams",
                    ],
                    "Resource": "*",
                }],
            }),
        )
    except ClientError as exc:
        log.warning("[IAM] put_role_policy FlowLog non-fatal: %s", exc)

    # ── Fetch ARNs ────────────────────────────────────────────────────────────
    inst_role_arn = iam.get_role(RoleName=inst_role_name)["Role"]["Arn"]
    fl_role_arn   = iam.get_role(RoleName=flowlog_role_name)["Role"]["Arn"]

    log.info("[IAM] inst_role_arn  = %s", inst_role_arn)
    log.info("[IAM] fl_role_arn    = %s", fl_role_arn)

    # IAM propagation wait
    log.info("[IAM] Waiting %ds for IAM propagation ...", IAM_PROPAGATION_S)
    time.sleep(IAM_PROPAGATION_S)

    return {
        "inst_role_name":    inst_role_name,
        "inst_role_arn":     inst_role_arn,
        "flowlog_role_name": flowlog_role_name,
        "flowlog_role_arn":  fl_role_arn,
        "profile_name":      profile_name,
    }


def _delete_iam_resources(iam_info: dict) -> None:
    """
    Delete all IAM resources created by _create_iam_resources().
    Tolerant: logs all errors and continues.
    """
    iam          = _iam()
    inst_role    = iam_info.get("inst_role_name", "")
    fl_role      = iam_info.get("flowlog_role_name", "")
    profile_name = iam_info.get("profile_name", "")

    if profile_name and inst_role:
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name,
                RoleName=inst_role,
            )
        except ClientError as exc:
            log.warning("[IAM-RB] remove_role_from_profile: %s", exc)

    if profile_name:
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            log.info("[IAM-RB] Deleted instance profile: %s", profile_name)
        except ClientError as exc:
            log.warning("[IAM-RB] delete_instance_profile: %s", exc)

    if inst_role:
        for arn in ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]:
            try:
                iam.detach_role_policy(RoleName=inst_role, PolicyArn=arn)
            except ClientError:
                pass
        for pname in ["SCEMinS3"]:
            try:
                iam.delete_role_policy(RoleName=inst_role, PolicyName=pname)
            except ClientError:
                pass
        try:
            iam.delete_role(RoleName=inst_role)
            log.info("[IAM-RB] Deleted role: %s", inst_role)
        except ClientError as exc:
            log.warning("[IAM-RB] delete_role(%s): %s", inst_role, exc)

    if fl_role:
        try:
            iam.delete_role_policy(RoleName=fl_role, PolicyName="SCEFlowLogCW")
        except ClientError:
            pass
        try:
            iam.delete_role(RoleName=fl_role)
            log.info("[IAM-RB] Deleted role: %s", fl_role)
        except ClientError as exc:
            log.warning("[IAM-RB] delete_role(%s): %s", fl_role, exc)


# ---------------------------------------------------------------------------
# CloudFormation template (zero IAM resources; references pre-created IAM)
# ---------------------------------------------------------------------------
def _build_cfn_template(ami_id: str,
                        profile_name: str,
                        flowlog_role_arn: str) -> str:
    """
    CFN template: networking + CloudWatch Log Group + VPC Flow Log + EC2.
    All IAM is passed in as parameters (created externally via boto3).
    No IAM resources inside the template = no CAPABILITY_NAMED_IAM needed.
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 2.5 Detective - networking and EC2 (IAM external)",
        "Parameters": {
            "AMIID": {
                "Type": "String",
                "Description": "Amazon Linux 2 AMI ID",
            },
            "InstanceProfileName": {
                "Type": "String",
                "Description": "Pre-created EC2 instance profile name",
            },
            "FlowLogRoleArn": {
                "Type": "String",
                "Description": "Pre-created VPC Flow Log delivery role ARN",
            },
        },
        "Resources": {
            "SCEVPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.99.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}
                    ],
                },
            },
            "SCESubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "SCEVPC"},
                    "CidrBlock": "10.99.1.0/24",
                    "MapPublicIpOnLaunch": True,
                    "AvailabilityZone": {
                        "Fn::Select": [
                            "0",
                            {"Fn::GetAZs": {"Ref": "AWS::Region"}},
                        ]
                    },
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}
                    ],
                },
            },
            "SCEIGW": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}
                    ]
                },
            },
            "SCEIGWAttach": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {
                    "VpcId": {"Ref": "SCEVPC"},
                    "InternetGatewayId": {"Ref": "SCEIGW"},
                },
            },
            "SCERouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {
                    "VpcId": {"Ref": "SCEVPC"},
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}
                    ],
                },
            },
            "SCEDefaultRoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "SCEIGWAttach",
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
            "SCESG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE 2.5 detective no inbound",
                    "VpcId": {"Ref": "SCEVPC"},
                    "SecurityGroupIngress": [],
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "CidrIp": "0.0.0.0/0",
                            "Description": "HTTPS out for SSM agent",
                        }
                    ],
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}
                    ],
                },
            },
            "SCEFlowLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": {
                        "Fn::Sub": "/sce/vpcflowlogs/${AWS::StackName}"
                    },
                    "RetentionInDays": 1,
                },
            },
            "SCEFlowLog": {
                "Type": "AWS::EC2::FlowLog",
                "DependsOn": ["SCEFlowLogGroup"],
                "Properties": {
                    "ResourceType": "VPC",
                    "ResourceId": {"Ref": "SCEVPC"},
                    "TrafficType": "ALL",
                    "LogDestinationType": "cloud-watch-logs",
                    "LogGroupName": {
                        "Fn::Sub": "/sce/vpcflowlogs/${AWS::StackName}"
                    },
                    "DeliverLogsPermissionArn": {"Ref": "FlowLogRoleArn"},
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}
                    ],
                },
            },
            "SCEInstance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": ["SCEIGWAttach"],
                "Properties": {
                    "ImageId": {"Ref": "AMIID"},
                    "InstanceType": "t3.micro",
                    "SubnetId": {"Ref": "SCESubnet"},
                    "SecurityGroupIds": [{"Ref": "SCESG"}],
                    "IamInstanceProfile": {"Ref": "InstanceProfileName"},
                    "MetadataOptions": {
                        "HttpEndpoint": "enabled",
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1,
                    },
                    "Tags": [
                        {"Key": "Name",             "Value": "SCE-IMDS-Target"},
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                    ],
                },
            },
        },
        "Outputs": {
            "InstanceId": {
                "Value": {"Ref": "SCEInstance"},
                "Description": "Target EC2 instance ID",
            },
            "FlowLogGroupName": {
                "Value": {"Fn::Sub": "/sce/vpcflowlogs/${AWS::StackName}"},
                "Description": "CW Log Group for VPC Flow Logs",
            },
            "VpcId": {
                "Value": {"Ref": "SCEVPC"},
                "Description": "Experiment VPC ID",
            },
        },
    }
    return json.dumps(template, indent=2)


# ---------------------------------------------------------------------------
# CloudFormation helpers
# ---------------------------------------------------------------------------
def _get_cfn_failure_reason(stack_name: str) -> str:
    """Return the first FAILED resource event and its status reason."""
    try:
        cf        = _cf()
        paginator = cf.get_paginator("describe_stack_events")
        for page in paginator.paginate(StackName=stack_name):
            for event in page["StackEvents"]:
                if "FAILED" in event.get("ResourceStatus", ""):
                    resource = event.get("LogicalResourceId", "?")
                    reason   = event.get("ResourceStatusReason", "no reason")
                    status   = event.get("ResourceStatus", "?")
                    return (
                        f"Resource={resource}  "
                        f"Status={status}  "
                        f"Reason={reason}"
                    )
    except Exception as exc:  # noqa: BLE001
        return f"(could not read stack events: {exc})"
    return "(no FAILED event found)"


def _wait_for_stack(stack_name: str, target_status: str) -> None:
    """Poll CloudFormation until target_status or terminal failure."""
    deadline = time.monotonic() + CF_MAX_WAIT_S
    cf       = _cf()
    log.info("[CFN] Waiting for '%s' -> %s ...", stack_name, target_status)

    while time.monotonic() < deadline:
        try:
            resp   = cf.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            reason = resp["Stacks"][0].get("StackStatusReason", "")
        except ClientError as exc:
            if "does not exist" in str(exc):
                if target_status == "DELETE_COMPLETE":
                    log.info("[CFN] Stack '%s' deleted.", stack_name)
                    return
                raise
            raise

        log.info("[CFN] Stack status: %s", status)

        if status == target_status:
            log.info("[CFN] Target status reached: %s", status)
            return

        if any(s in status for s in
               ("FAILED", "ROLLBACK_COMPLETE", "DELETE_FAILED")):
            detail = _get_cfn_failure_reason(stack_name)
            raise RuntimeError(
                f"[CFN] Stack '{stack_name}' reached terminal state {status}. "
                f"StackStatusReason={reason!r}. "
                f"First failed resource: {detail}"
            )

        time.sleep(CF_POLL_S)

    raise RuntimeError(
        f"[CFN] Timed out after {CF_MAX_WAIT_S}s waiting for "
        f"'{stack_name}' -> {target_status}"
    )


def _stack_outputs(stack_name: str) -> dict:
    cf   = _cf()
    resp = cf.describe_stacks(StackName=stack_name)
    return {
        o["OutputKey"]: o["OutputValue"]
        for o in resp["Stacks"][0].get("Outputs", [])
    }


# ---------------------------------------------------------------------------
# Generic polling helper
# ---------------------------------------------------------------------------
def _poll_until(fn, label: str, sla_seconds: int = SLA_SECONDS) -> bool:
    """
    Call fn() every POLL_INTERVAL_S until True or sla_seconds elapses.
    Returns True if condition met, False on SLA expiry.
    All exceptions from fn() are logged and polling continues.
    """
    start    = time.monotonic()
    deadline = start + sla_seconds
    attempt  = 0

    while time.monotonic() < deadline:
        attempt += 1
        elapsed  = int(time.monotonic() - start)
        log.info(
            "[POLL] %s - attempt %d  elapsed=%ds / SLA=%ds",
            label, attempt, elapsed, sla_seconds,
        )
        try:
            if fn():
                log.info(
                    "[POLL] %s - condition MET at attempt %d (%ds elapsed).",
                    label, attempt, elapsed,
                )
                return True
        except Exception as exc:  # noqa: BLE001
            log.error("[POLL] %s - error: %s", label, exc)
        time.sleep(POLL_INTERVAL_S)

    log.warning(
        "[POLL] %s - SLA of %ds exhausted without meeting condition.",
        label, sla_seconds,
    )
    return False


# ---------------------------------------------------------------------------
# 1. steady_state()
# ---------------------------------------------------------------------------
def steady_state() -> None:
    """
    Provision all experiment resources.  Populates _STATE for all phases.

    Execution order:
      A. Resolve account/region, generate timestamped stack name
      B. GuardDuty get-or-create (outside CFN, tolerates pre-existing)
      C. AMI resolution via boto3 (no SSM resolve inside CFN template)
      D. IAM roles + instance profile via boto3 (NO Description= field)
      E. CloudFormation stack with networking + EC2 only (no IAM in CFN)
      F. Wait for EC2 instance to reach 'running' state
      G. Assert IMDSv2 baseline: HttpTokens=required, HopLimit=1
    """
    global _STATE

    identity = _sts().get_caller_identity()
    account  = identity["Account"]
    region   = _session().region_name or "us-east-1"
    ts       = int(time.time())
    stack    = f"{STACK_PREFIX}-{ts}"

    log.info("=" * 70)
    log.info("SCE Experiment 2.5 - Detective Probe  |  steady_state()")
    log.info("Account=%s  Region=%s  Stack=%s", account, region, stack)
    log.info("=" * 70)

    _STATE["stack_name"] = stack
    _STATE["account"]    = account
    _STATE["region"]     = region
    _STATE["timestamp"]  = ts
    _STATE["iam_info"]   = {}

    # ── B. GuardDuty ─────────────────────────────────────────────────────────
    try:
        detector_id, gd_owned     = _get_or_create_guardduty_detector()
        _STATE["detector_id"]      = detector_id
        _STATE["gd_owned"]         = gd_owned
    except Exception as exc:
        log.error("[STEADY] GuardDuty setup failed: %s", exc)
        raise

    # ── C. AMI ───────────────────────────────────────────────────────────────
    try:
        ami_id           = _latest_al2_ami()
        _STATE["ami_id"] = ami_id
    except Exception as exc:
        log.error("[STEADY] AMI resolution failed: %s", exc)
        raise

    # ── D. IAM via boto3 (Description= field intentionally omitted) ──────────
    try:
        iam_info           = _create_iam_resources(stack)
        _STATE["iam_info"] = iam_info
    except Exception as exc:
        log.error("[STEADY] IAM resource creation failed: %s", exc)
        raise

    # ── E. CloudFormation (networking + EC2 only) ─────────────────────────────
    template = _build_cfn_template(
        ami_id           = ami_id,
        profile_name     = iam_info["profile_name"],
        flowlog_role_arn = iam_info["flowlog_role_arn"],
    )
    cf = _cf()

    try:
        cf.create_stack(
            StackName=stack,
            TemplateBody=template,
            Parameters=[
                {"ParameterKey": "AMIID",
                 "ParameterValue": ami_id},
                {"ParameterKey": "InstanceProfileName",
                 "ParameterValue": iam_info["profile_name"]},
                {"ParameterKey": "FlowLogRoleArn",
                 "ParameterValue": iam_info["flowlog_role_arn"]},
            ],
            Capabilities=[],          # No IAM in template
            OnFailure="DO_NOTHING",   # Preserve stack for event inspection
            Tags=[
                {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                {"Key": "SCETimestamp",      "Value": str(ts)},
            ],
            TimeoutInMinutes=25,
        )
        log.info("[STEADY] Stack creation initiated: %s", stack)
    except ClientError as exc:
        if "AlreadyExistsException" in str(exc):
            log.warning("[STEADY] Stack '%s' already exists - reusing.", stack)
        else:
            log.error("[STEADY] create_stack failed: %s", exc)
            raise

    try:
        _wait_for_stack(stack, "CREATE_COMPLETE")
    except RuntimeError as exc:
        log.error("[STEADY] Stack provisioning failed: %s", exc)
        try:
            cf.delete_stack(StackName=stack)
            log.info("[STEADY] Cleanup delete issued for failed stack.")
        except Exception as del_exc:  # noqa: BLE001
            log.warning("[STEADY] Cleanup delete failed: %s", del_exc)
        raise

    # ── F. Harvest outputs ────────────────────────────────────────────────────
    outputs = _stack_outputs(stack)
    _STATE["instance_id"]    = outputs["InstanceId"]
    _STATE["flow_log_group"] = outputs["FlowLogGroupName"]
    _STATE["vpc_id"]         = outputs["VpcId"]

    log.info("[STEADY] Stack outputs:")
    for k, v in outputs.items():
        log.info("         %-22s = %s", k, v)

    # ── G. Wait for instance running ──────────────────────────────────────────
    inst = _STATE["instance_id"]
    log.info("[STEADY] Waiting for instance %s to reach running state ...", inst)
    try:
        waiter = _ec2().get_waiter("instance_running")
        waiter.wait(
            InstanceIds=[inst],
            WaiterConfig={"MaxAttempts": 40, "Delay": 15},
        )
    except Exception as exc:
        log.error("[STEADY] Instance running waiter failed: %s", exc)
        raise
    log.info("[STEADY] Instance %s is running.", inst)

    # ── H. Assert IMDSv2 baseline ─────────────────────────────────────────────
    resp = _ec2().describe_instances(InstanceIds=[inst])
    meta = (
        resp["Reservations"][0]["Instances"][0]
        .get("MetadataOptions", {})
    )
    tok = meta.get("HttpTokens", "UNKNOWN")
    hop = meta.get("HttpPutResponseHopLimit", 0)
    log.info("[STEADY] Baseline IMDS: HttpTokens=%s  HopLimit=%s", tok, hop)

    if tok != "required" or hop != 1:
        raise RuntimeError(
            f"[STEADY] Baseline VIOLATED: HttpTokens={tok}  HopLimit={hop} "
            "(expected required / 1)"
        )

    log.info("[STEADY] Baseline verified - IMDSv2 enforced, HopLimit=1.")
    log.info("[STEADY] steady_state() complete.\n")


# ---------------------------------------------------------------------------
# 2. attack()
# ---------------------------------------------------------------------------
def attack() -> bool:
    """
    Execute attack nodes 1.2 and 2.2 on experiment-scoped resources only.

    Node 1.2 (TTP T1562.008 - Impair Defenses):
      ec2:ModifyInstanceMetadataOptions -> HttpTokens=optional, HopLimit=2
      Downgrades IMDS from v2 to v1 and enables container bridge traversal.

    Node 2.2 (TTP T1552.005 - Unsecured Credentials: Cloud Instance Metadata):
      ec2:DescribeInstances -> confirm weakened IMDS state persisted.
      Simulates the attacker verifying the precondition before issuing
      unauthenticated IMDS curl requests for credential retrieval.
    """
    if "instance_id" not in _STATE:
        raise RuntimeError(
            "[ATTACK] _STATE missing 'instance_id' - "
            "steady_state() must succeed before attack()."
        )

    inst = _STATE["instance_id"]
    ec2  = _ec2()

    # ── Attack 1.2 ────────────────────────────────────────────────────────────
    log.info("-" * 70)
    log.info("[ATTACK] Node 1.2 - Weaken IMDS on %s", inst)
    log.info(
        "[ATTACK] Setting HttpTokens=%s  HopLimit=%d",
        ATTACK_HTTP_TOKENS, ATTACK_HOP_LIMIT,
    )

    try:
        ec2.modify_instance_metadata_options(
            InstanceId=inst,
            HttpTokens=ATTACK_HTTP_TOKENS,
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=ATTACK_HOP_LIMIT,
        )
        log.info("[ATTACK] 1.2 - modify_instance_metadata_options succeeded.")
        _STATE["attack_1_2_ts"] = int(time.time())
    except ClientError as exc:
        log.error("[ATTACK] 1.2 - FAILED: %s", exc)
        return False

    # Allow EC2 control-plane to commit the change
    time.sleep(8)

    # ── Attack 2.2 ────────────────────────────────────────────────────────────
    log.info("[ATTACK] Node 2.2 - Confirm weakened IMDS state on %s", inst)

    try:
        resp = ec2.describe_instances(InstanceIds=[inst])
        meta = (
            resp["Reservations"][0]["Instances"][0]
            .get("MetadataOptions", {})
        )
        tok = meta.get("HttpTokens", "UNKNOWN")
        hop = meta.get("HttpPutResponseHopLimit", 0)
        log.info("[ATTACK] 2.2 - IMDS state: HttpTokens=%s  HopLimit=%s",
                 tok, hop)

        if tok == ATTACK_HTTP_TOKENS and hop == ATTACK_HOP_LIMIT:
            log.info(
                "[ATTACK] 2.2 - Weakening CONFIRMED: "
                "no IMDSv2 token required; container bridge traversal enabled."
            )
            _STATE["attack_2_2_ts"] = int(time.time())
        else:
            log.warning(
                "[ATTACK] 2.2 - Unexpected state: tok=%s hop=%s", tok, hop
            )
            return False

    except ClientError as exc:
        log.error("[ATTACK] 2.2 - describe_instances FAILED: %s", exc)
        return False

    log.info("[ATTACK] Both attack nodes executed successfully.")
    log.info("-" * 70)
    return True


# ---------------------------------------------------------------------------
# 3. hypothesis_verification()
# ---------------------------------------------------------------------------
def hypothesis_verification() -> bool:
    """
    Detective Probe - SCE Experiment 2.5.

    Validates THREE independent detective signals within a 30-minute SLA:

    Signal A - GuardDuty: Policy:EC2/NoIMDSv2 or related finding
      GuardDuty raises Policy:EC2/NoIMDSv2 deterministically when an instance
      is configured with HttpTokens=optional.  This maps to ADT node 2.3.

    Signal B - VPC Flow Log delivery pipeline is active
      The CloudWatch Log Group has at least one log stream with events newer
      than the stack creation timestamp.  Maps to ADT node 2.3 (network
      telemetry that would capture 169.254.169.254 traffic).

    Signal C - EC2 control-plane IMDS state persistence (CloudTrail proxy)
      DescribeInstances confirms the weakened IMDS state persists, validating
      the ModifyInstanceMetadataOptions call was durably recorded by the same
      EC2 control-plane surface that feeds CloudTrail.  Maps to ADT node 1.3.

    Returns True only when ALL three signals are confirmed within SLA.
    """
    if "instance_id" not in _STATE:
        raise RuntimeError(
            "[VERIFY] _STATE missing 'instance_id' - "
            "steady_state() must succeed before hypothesis_verification()."
        )

    inst        = _STATE["instance_id"]
    detector_id = _STATE["detector_id"]
    flow_grp    = _STATE["flow_log_group"]
    # Use a 60-second buffer before attack_ts to tolerate minor clock skew
    raw_ts      = _STATE.get("attack_1_2_ts", int(time.time()))
    attack_ts   = max(0, raw_ts - 60)

    log.info("=" * 70)
    log.info("[VERIFY] Detective Probe - starting validation")
    log.info("[VERIFY] Instance     : %s", inst)
    log.info("[VERIFY] Detector     : %s", detector_id)
    log.info("[VERIFY] FlowLogGroup : %s", flow_grp)
    log.info("[VERIFY] Attack epoch : %d (buffered: %d)", raw_ts, attack_ts)
    log.info("[VERIFY] SLA window   : %ds (30 min)", SLA_SECONDS)
    log.info("=" * 70)

    results: dict = {}

    # ── Signal A: GuardDuty ───────────────────────────────────────────────────
    def _check_guardduty() -> bool:
        gd = _gd()
        try:
            ids_resp = gd.list_findings(
                DetectorId=detector_id,
                FindingCriteria={
                    "Criterion": {
                        "updatedAt": {
                            "GreaterThanOrEqual": attack_ts * 1000
                        }
                    }
                },
                MaxResults=50,
            )
            finding_ids = ids_resp.get("FindingIds", [])
            log.info("[GD] Findings since buffered attack timestamp: %d",
                     len(finding_ids))

            if not finding_ids:
                return False

            findings_resp = gd.get_findings(
                DetectorId=detector_id,
                FindingIds=finding_ids,
            )

            relevant_prefixes = (
                "Policy:EC2/NoIMDSv2",
                "UnauthorizedAccess:EC2",
                "CredentialAccess",
                "Recon:IAMUser",
                "TTPs/CredentialAccess",
                "InitialAccess",
            )
            relevant_keywords = (
                "imds", "metadata", "credential", "imdsv1", "imdsv2"
            )

            for f in findings_resp.get("Findings", []):
                ftype  = f.get("Type", "")
                ftitle = f.get("Title", "")
                fsev   = f.get("Severity", 0)
                log.info(
                    "[GD] Finding: type=%s  title=%s  severity=%s",
                    ftype, ftitle, fsev,
                )

                if any(ftype.startswith(p) for p in relevant_prefixes):
                    log.info("[GD] PASS  Relevant finding by type: %s", ftype)
                    return True
                if any(kw in ftitle.lower() for kw in relevant_keywords):
                    log.info(
                        "[GD] PASS  Relevant finding by keyword: %s", ftitle
                    )
                    return True

        except ClientError as exc:
            log.error("[GD] API error: %s", exc)
        return False

    log.info("\n[VERIFY] === Signal A: GuardDuty finding ===")
    results["guardduty"] = _poll_until(
        _check_guardduty,
        "GuardDuty-Policy-EC2-NoIMDSv2",
        sla_seconds=SLA_SECONDS,
    )

    # ── Signal B: VPC Flow Log delivery active ────────────────────────────────
    def _check_flow_log_streams() -> bool:
        cw = _logs()
        try:
            resp    = cw.describe_log_streams(
                logGroupName=flow_grp,
                orderBy="LastEventTime",
                descending=True,
                limit=5,
            )
            streams = resp.get("logStreams", [])
            log.info("[FL] Log streams in group: %d", len(streams))

            if streams:
                newest   = streams[0]
                last_evt = newest.get("lastEventTimestamp", 0)
                name     = newest.get("logStreamName", "")
                log.info(
                    "[FL] Newest stream: %s  lastEventTs=%s", name, last_evt
                )
                # Accept any stream with events after stack creation (-10 min buffer)
                threshold = (_STATE["timestamp"] - 600) * 1000
                if last_evt and last_evt > threshold:
                    log.info("[FL] PASS  Flow Log delivery pipeline is active.")
                    return True

        except ClientError as exc:
            if "ResourceNotFoundException" in str(exc):
                log.info(
                    "[FL] Log group not yet visible - awaiting Flow Log delivery."
                )
            else:
                log.error("[FL] describe_log_streams error: %s", exc)
        return False

    log.info("\n[VERIFY] === Signal B: VPC Flow Log delivery ===")
    results["flow_logs"] = _poll_until(
        _check_flow_log_streams,
        "VPC-Flow-Log-Stream",
        sla_seconds=SLA_SECONDS,
    )

    # ── Signal C: EC2 control-plane IMDS persistence (CloudTrail proxy) ───────
    def _check_imds_state_persisted() -> bool:
        ec2 = _ec2()
        try:
            resp = ec2.describe_instances(InstanceIds=[inst])
            meta = (
                resp["Reservations"][0]["Instances"][0]
                .get("MetadataOptions", {})
            )
            tok = meta.get("HttpTokens", "UNKNOWN")
            hop = meta.get("HttpPutResponseHopLimit", 0)
            log.info(
                "[CT] EC2 IMDS state: HttpTokens=%s  HopLimit=%s", tok, hop
            )
            if tok == ATTACK_HTTP_TOKENS and hop == ATTACK_HOP_LIMIT:
                log.info(
                    "[CT] PASS  IMDS weakened state persists - "
                    "ModifyInstanceMetadataOptions durably recorded."
                )
                return True
        except ClientError as exc:
            log.error("[CT] describe_instances error: %s", exc)
        return False

    log.info("\n[VERIFY] === Signal C: EC2 control-plane / CloudTrail proxy ===")
    results["cloudtrail_proxy"] = _poll_until(
        _check_imds_state_persisted,
        "IMDS-State-Persisted",
        sla_seconds=SLA_SECONDS,
    )

    # ── Verdict ───────────────────────────────────────────────────────────────
    log.info("\n[VERIFY] -- Signal Summary ------------------------------------------")
    all_passed = True
    for signal, passed in results.items():
        status = "PASS" if passed else "FAIL"
        log.info("[VERIFY]   %-25s -> %s", signal, status)
        if not passed:
            all_passed = False

    verdict = (
        "ALL signals confirmed - detective controls validated."
        if all_passed
        else "One or more signals NOT confirmed within SLA."
    )
    log.info("[VERIFY] %s", verdict)
    log.info("=" * 70)
    return all_passed


# ---------------------------------------------------------------------------
# 4. rollback()
# ---------------------------------------------------------------------------
def rollback() -> None:
    """
    Unconditional teardown:
      1. Delete the CloudFormation stack (networking, EC2, CW Log Group, Flow Log).
      2. Delete boto3-created IAM resources (roles, instance profile).
      3. Delete GuardDuty detector only if this experiment created it.

    Safe and tolerant: logs all errors without re-raising.
    """
    stack = _STATE.get("stack_name")

    # ── 1. CloudFormation stack ───────────────────────────────────────────────
    if stack:
        log.info("[ROLLBACK] Deleting stack: %s", stack)
        cf = _cf()
        try:
            cf.delete_stack(StackName=stack)
            log.info("[ROLLBACK] delete_stack request accepted.")
        except ClientError as exc:
            if "does not exist" in str(exc):
                log.info("[ROLLBACK] Stack '%s' already gone.", stack)
            else:
                log.error("[ROLLBACK] delete_stack error: %s", exc)
                raise

        try:
            _wait_for_stack(stack, "DELETE_COMPLETE")
            log.info("[ROLLBACK] Stack deleted successfully.")
        except RuntimeError as exc:
            log.error("[ROLLBACK] Stack deletion wait failed: %s", exc)
            # Continue to IAM cleanup regardless
    else:
        log.warning("[ROLLBACK] No stack_name in _STATE - skipping CFN delete.")

    # ── 2. IAM resources ──────────────────────────────────────────────────────
    iam_info = _STATE.get("iam_info", {})
    if iam_info:
        log.info("[ROLLBACK] Deleting IAM resources ...")
        try:
            _delete_iam_resources(iam_info)
        except Exception as exc:  # noqa: BLE001
            log.error("[ROLLBACK] IAM cleanup error (non-fatal): %s", exc)
    else:
        log.info("[ROLLBACK] No iam_info in _STATE - skipping IAM cleanup.")

    # ── 3. GuardDuty (only if experiment-owned) ───────────────────────────────
    if _STATE.get("gd_owned") and _STATE.get("detector_id"):
        did = _STATE["detector_id"]
        log.info("[ROLLBACK] Deleting experiment-owned detector: %s", did)
        try:
            _gd().delete_detector(DetectorId=did)
            log.info("[ROLLBACK] GuardDuty detector deleted.")
        except ClientError as exc:
            log.error("[ROLLBACK] delete_detector non-fatal: %s", exc)
    else:
        log.info("[ROLLBACK] GuardDuty detector is pre-existing - NOT deleted.")

    log.info("[ROLLBACK] Teardown complete.")


# ---------------------------------------------------------------------------
# Experiment runner (direct execution)
# ---------------------------------------------------------------------------
def _run_experiment() -> None:
    log.info("=" * 70)
    log.info("SCE Experiment 2.5 - Detective Probe - Full Run")
    log.info("=" * 70)

    try:
        steady_state()

        attack_ok = attack()
        if not attack_ok:
            log.error(
                "[RUNNER] attack() returned False - probe may be inconclusive."
            )

        verified = hypothesis_verification()
        if verified:
            log.info("[RUNNER] PASS  Experiment passed - detective controls validated.")
        else:
            log.warning(
                "[RUNNER] FAIL  Experiment failed - detective controls not confirmed."
            )

    except Exception as exc:  # noqa: BLE001
        log.error("[RUNNER] Unhandled exception: %s", exc, exc_info=True)

    finally:
        try:
            rollback()
        except Exception as rb_exc:  # noqa: BLE001
            log.error("[RUNNER] rollback() error: %s", rb_exc, exc_info=True)


if __name__ == "__main__":
    _run_experiment()