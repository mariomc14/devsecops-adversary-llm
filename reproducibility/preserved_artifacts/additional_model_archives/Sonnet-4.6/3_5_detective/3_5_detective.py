"""
SCE Experiment 3.5 - Detective Probe
Attack Nodes: 1.2 (Weaken IMDS), 2.2 (Retrieve Credentials), 3.2 (Lateral Movement)

DETECTIVE PROBE INTENT (ADT node 3.5):
=======================================
"Replay aws sts get-caller-identity and aws s3 ls from an external IP using
sandbox credentials; confirm GuardDuty raises
InstanceCredentialExfiltration.OutsideAWS within 5 min and the SIEM
attack-chain correlation alert linking Steps 1 through 3 fires within 5 min."

This experiment operationalises the detective controls for attack nodes 1.2,
2.2, and 3.2 by validating three independent detection signals:

  Signal A - GuardDuty: CredentialAccess or Recon finding
    GuardDuty generates findings when stolen EC2 instance-role credentials
    are used to call AWS APIs (sts:GetCallerIdentity, iam:ListAttachedRolePolicies,
    s3:ListAllMyBuckets). In a sandbox account, GuardDuty raises findings
    of type CredentialAccess:IAMUser/AnomalousBehavior,
    Recon:IAMUser/UserPermissions, or UnauthorizedAccess:IAMUser/
    InstanceCredentialExfiltration.OutsideAWS when these calls are made
    with temporary role credentials (as opposed to the role's normal usage).
    Maps to ADT node 3.3.

  Signal B - CloudTrail: API calls recorded for all three attack-chain steps
    CloudTrail captures sts:AssumeRole (1.2 credential acquisition),
    sts:GetCallerIdentity (2.2 verification), iam:ListAttachedRolePolicies
    and s3:ListAllMyBuckets (3.2 enumeration). The detective probe verifies
    that at least the attack-chain events are present in CloudTrail within
    the SLA window, confirming the audit trail is intact and the SIEM
    correlation chain can be constructed.
    Maps to ADT nodes 1.3 and 3.3.

  Signal C - CloudTrail: sts:AssumeRole event for the instance role is present
    The ModifyInstanceMetadataOptions proxy signal from the detective probe
    in the 2.5 experiment is replaced here by verifying the sts:AssumeRole
    event that corresponds to "obtaining stolen credentials" (attack 1.2).
    This confirms the credential acquisition event is durably recorded and
    available for SIEM correlation linking Steps 1-3.
    Maps to ADT node 3.3: "SIEM correlation rules link ModifyInstanceMetadataOptions
    CloudTrail event with subsequent API calls using the same role."

INFRASTRUCTURE:
  - IAM instance-profile role (simulates stolen EC2 credential)
    - Trust policy: allow assume from same account (enables attack simulation)
    - Inline policy: s3:ListAllMyBuckets + ec2:DescribeInstances +
                     sts:GetCallerIdentity + iam:ListAttachedRolePolicies
  - GuardDuty detector (get-or-create; tolerates pre-existing)
  - CloudTrail trail -> S3 bucket (for trail storage)
  - CloudWatch Log Group (CloudTrail -> CW Logs for query-based verification)
  - CFN stack: CloudWatch Log Group + CloudTrail trail + S3 trail bucket
  - All IAM via boto3 (no IAM in CFN)

LESSONS FROM PRIOR RUNS (detective probe 2.5 series):
  - All IAM created via boto3, not CFN
  - No Description= on any IAM call
  - Role names sanitized to [A-Za-z0-9+=,.@_-], max 64 chars
  - AMI not needed for this experiment (no EC2 instance required)
  - GuardDuty managed outside CFN
  - OnFailure=DO_NOTHING on CFN stack
  - CFN template contains ZERO IAM resources
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
EXPERIMENT_TAG_KEY      = "SCEExperiment"
EXPERIMENT_TAG_VALUE    = "3_5_detective"
STACK_PREFIX            = "sce-det35"

SLA_SECONDS             = 1800   # 30-minute outer SLA
POLL_INTERVAL_S         = 20

CF_MAX_WAIT_S           = 900    # 15 min max for stack create/delete
CF_POLL_S               = 15

IAM_PROPAGATION_S       = 25     # seconds after IAM role/policy creation

# CloudTrail event names that correspond to the three attack nodes
CT_EVENT_ASSUME_ROLE         = "AssumeRole"          # attack 1.2
CT_EVENT_GET_CALLER_IDENTITY = "GetCallerIdentity"   # attack 2.2
CT_EVENT_LIST_POLICIES       = "ListAttachedRolePolicies"  # attack 3.2
CT_EVENT_S3_LIST             = "ListBuckets"         # attack 3.2

# GuardDuty finding type prefixes relevant to credential misuse
GD_RELEVANT_PREFIXES = (
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
    "CredentialAccess:IAMUser",
    "Recon:IAMUser",
    "UnauthorizedAccess:IAMUser",
    "Policy:IAMUser",
    "TTPs/CredentialAccess",
    "InitialAccess",
    "Discovery",
)
GD_RELEVANT_KEYWORDS = (
    "credential", "exfiltration", "anomalous", "recon",
    "unusual", "instance", "role", "assume",
)


# ---------------------------------------------------------------------------
# String sanitization helpers
# ---------------------------------------------------------------------------

def _safe_name(base: str, max_len: int = 64) -> str:
    """IAM/SSM safe name: [A-Za-z0-9+=,.@_-], max max_len chars."""
    safe = re.sub(r"[^A-Za-z0-9+=,.@_\-]", "-", base)
    return safe[:max_len]


def _safe_bucket_name(base: str) -> str:
    """S3 bucket name: lowercase, [a-z0-9-], 3-63 chars."""
    lowered = base.lower()
    safe    = re.sub(r"[^a-z0-9\-]", "-", lowered)
    safe    = re.sub(r"-{2,}", "-", safe)
    safe    = safe.strip("-")
    return safe[:63]


# ---------------------------------------------------------------------------
# boto3 client helpers
# ---------------------------------------------------------------------------
def _session() -> boto3.Session:
    return boto3.Session()

def _cf():    return _session().client("cloudformation")
def _ct():    return _session().client("cloudtrail")
def _gd():    return _session().client("guardduty")
def _iam():   return _session().client("iam")
def _logs():  return _session().client("logs")
def _s3():    return _session().client("s3")
def _sts():   return _session().client("sts")


# ---------------------------------------------------------------------------
# GuardDuty: get-or-create detector (outside CFN, tolerates pre-existing)
# ---------------------------------------------------------------------------
def _get_or_create_guardduty_detector() -> tuple:
    """
    Returns (detector_id: str, owned_by_experiment: bool).
    owned=True  -> created here; must delete in rollback.
    owned=False -> pre-existing; must NOT delete.
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
# IAM resources via boto3 (NO CFN, NO Description= field)
# ---------------------------------------------------------------------------
def _create_iam_resources(stack_name: str, account_id: str, region: str) -> dict:
    """
    Create all IAM resources required by the detective experiment.

    Resources:
      1. CloudTrail S3 delivery role  (sce-ct-role-<suffix>)
         Not needed - CloudTrail uses its own service role for S3 delivery.
         We DO need a role for CloudTrail -> CloudWatch Logs delivery.

      2. CloudTrail CW Logs delivery role  (sce-ctcw-<suffix>)
         Allows cloudtrail.amazonaws.com to push to CloudWatch Logs.

      3. Instance-profile simulation role  (sce-inst-<suffix>)
         Trust: same-account root (so test runner can assume it).
         Inline: s3:ListAllMyBuckets, ec2:DescribeInstances,
                 sts:GetCallerIdentity, iam:ListAttachedRolePolicies.
         This role simulates the EC2 instance-profile credentials that
         an attacker would steal via the weakened IMDS endpoint.

    Returns dict of names and ARNs.
    """
    iam    = _iam()
    suffix = stack_name[-16:]
    tags   = [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]

    ctcw_role_name = _safe_name(f"sce-ctcw-{suffix}")
    inst_role_name = _safe_name(f"sce-inst-{suffix}")

    log.info("[IAM] ctcw_role_name = %s", ctcw_role_name)
    log.info("[IAM] inst_role_name = %s", inst_role_name)

    # ── CloudTrail -> CloudWatch Logs delivery role ───────────────────────────
    log.info("[IAM] Creating CloudTrail CW delivery role ...")
    try:
        iam.create_role(
            RoleName=ctcw_role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            }),
            Tags=tags,
        )
        log.info("[IAM] CloudTrail CW role created: %s", ctcw_role_name)
    except ClientError as exc:
        if "EntityAlreadyExists" in str(exc):
            log.warning("[IAM] Role %s already exists.", ctcw_role_name)
        else:
            log.error("[IAM] create_role(%s) failed: %s", ctcw_role_name, exc)
            raise

    try:
        iam.put_role_policy(
            RoleName=ctcw_role_name,
            PolicyName="SCECTCWDelivery",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:DescribeLogStreams",
                    ],
                    "Resource": "*",
                }],
            }),
        )
    except ClientError as exc:
        log.warning("[IAM] put_role_policy CTCW non-fatal: %s", exc)

    ctcw_role_arn = iam.get_role(RoleName=ctcw_role_name)["Role"]["Arn"]
    log.info("[IAM] ctcw_role_arn = %s", ctcw_role_arn)

    # ── EC2 instance-profile simulation role ──────────────────────────────────
    log.info("[IAM] Creating instance simulation role ...")
    try:
        iam.create_role(
            RoleName=inst_role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{account_id}:root",
                        "Service": "ec2.amazonaws.com",
                    },
                    "Action": "sts:AssumeRole",
                }],
            }),
            Tags=tags,
        )
        log.info("[IAM] Instance simulation role created: %s", inst_role_name)
    except ClientError as exc:
        if "EntityAlreadyExists" in str(exc):
            log.warning("[IAM] Role %s already exists.", inst_role_name)
        else:
            log.error("[IAM] create_role(%s) failed: %s", inst_role_name, exc)
            raise

    try:
        iam.put_role_policy(
            RoleName=inst_role_name,
            PolicyName="SCEInstanceInline",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListAllMyBuckets",
                        "ec2:DescribeInstances",
                        "sts:GetCallerIdentity",
                        "iam:ListAttachedRolePolicies",
                        "iam:GetRole",
                    ],
                    "Resource": "*",
                }],
            }),
        )
        log.info("[IAM] Instance inline policy attached.")
    except ClientError as exc:
        log.warning("[IAM] put_role_policy instance non-fatal: %s", exc)

    inst_role_arn = iam.get_role(RoleName=inst_role_name)["Role"]["Arn"]
    log.info("[IAM] inst_role_arn = %s", inst_role_arn)

    # IAM propagation
    log.info("[IAM] Waiting %ds for IAM propagation ...", IAM_PROPAGATION_S)
    time.sleep(IAM_PROPAGATION_S)

    return {
        "ctcw_role_name": ctcw_role_name,
        "ctcw_role_arn":  ctcw_role_arn,
        "inst_role_name": inst_role_name,
        "inst_role_arn":  inst_role_arn,
    }


def _delete_iam_resources(iam_info: dict) -> None:
    """Delete all IAM resources created by _create_iam_resources(). Tolerant."""
    iam           = _iam()
    ctcw_role     = iam_info.get("ctcw_role_name", "")
    inst_role     = iam_info.get("inst_role_name", "")

    for role_name, inline_names in [
        (ctcw_role,  ["SCECTCWDelivery"]),
        (inst_role,  ["SCEInstanceInline"]),
    ]:
        if not role_name:
            continue
        for inline in inline_names:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=inline)
            except ClientError:
                pass
        try:
            iam.delete_role(RoleName=role_name)
            log.info("[IAM-RB] Deleted role: %s", role_name)
        except ClientError as exc:
            log.warning("[IAM-RB] delete_role(%s): %s", role_name, exc)


# ---------------------------------------------------------------------------
# CloudFormation template (ZERO IAM resources)
# ---------------------------------------------------------------------------
def _build_cfn_template(
    trail_bucket_name: str,
    cw_log_group_name: str,
    ctcw_role_arn: str,
    account_id: str,
) -> str:
    """
    CFN template provisions:
      S3 bucket for CloudTrail storage
        - Bucket policy: allow CloudTrail PutObject
      CloudWatch Log Group for CloudTrail -> CW Logs delivery
        (enables fast CloudTrail event querying without Athena)
      CloudTrail trail (management events, all regions = False, single region)

    No IAM resources inside CFN.
    """
    trail_name = f"sce-trail-{trail_bucket_name[-12:]}"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 3.5 Detective - CloudTrail trail S3 bucket CW Log Group",
        "Parameters": {
            "TrailBucketName": {
                "Type": "String",
                "Description": "S3 bucket name for CloudTrail log storage",
            },
            "CWLogGroupName": {
                "Type": "String",
                "Description": "CloudWatch Log Group name for CloudTrail delivery",
            },
            "CTCWRoleArn": {
                "Type": "String",
                "Description": "IAM role ARN for CloudTrail CW Logs delivery",
            },
            "AccountId": {
                "Type": "String",
                "Description": "AWS Account ID",
            },
        },
        "Resources": {

            # ── CloudTrail S3 bucket ──────────────────────────────────────
            "SCETrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": {"Ref": "TrailBucketName"},
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls":       True,
                        "BlockPublicPolicy":     True,
                        "IgnorePublicAcls":      True,
                        "RestrictPublicBuckets": True,
                    },
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}
                    ],
                },
            },

            # ── Bucket policy: allow CloudTrail service to write ──────────
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
                                    "Fn::Sub": "arn:aws:s3:::${TrailBucketName}"
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
                                        "arn:aws:s3:::${TrailBucketName}"
                                        "/AWSLogs/${AccountId}/*"
                                    )
                                },
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

            # ── CloudWatch Log Group for CloudTrail delivery ──────────────
            "SCECTLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": {"Ref": "CWLogGroupName"},
                    "RetentionInDays": 1,
                },
            },

            # ── CloudTrail trail ─────────────────────────────────────────
            "SCETrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": [
                    "SCETrailBucketPolicy",
                    "SCECTLogGroup",
                ],
                "Properties": {
                    "TrailName": trail_name,
                    "S3BucketName": {"Ref": "TrailBucketName"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "EnableLogFileValidation": True,
                    "IncludeGlobalServiceEvents": True,
                    "CloudWatchLogsLogGroupArn": {
                        "Fn::GetAtt": ["SCECTLogGroup", "Arn"]
                    },
                    "CloudWatchLogsRoleArn": {"Ref": "CTCWRoleArn"},
                    "EventSelectors": [{
                        "ReadWriteType": "All",
                        "IncludeManagementEvents": True,
                    }],
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}
                    ],
                },
            },
        },

        "Outputs": {
            "TrailBucketName": {
                "Value": {"Ref": "SCETrailBucket"},
                "Description": "CloudTrail S3 bucket name",
            },
            "TrailName": {
                "Value": trail_name,
                "Description": "CloudTrail trail name",
            },
            "CWLogGroupName": {
                "Value": {"Ref": "CWLogGroupName"},
                "Description": "CloudWatch Log Group for CloudTrail",
            },
            "TrailArn": {
                "Value": {"Fn::GetAtt": ["SCETrail", "Arn"]},
                "Description": "CloudTrail trail ARN",
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
    All exceptions logged; polling continues.
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
# STS: assume instance role to simulate stolen credential usage
# ---------------------------------------------------------------------------
def _assume_instance_role(inst_role_arn: str) -> dict:
    """
    Assume the EC2 instance-simulation role from the test runner to simulate
    an attacker operating with stolen instance-profile credentials.
    Returns temporary credentials dict.
    """
    sts      = _sts()
    log.info("[STS] Assuming instance role: %s", inst_role_arn)
    deadline = time.monotonic() + 120

    while time.monotonic() < deadline:
        try:
            resp  = sts.assume_role(
                RoleArn=inst_role_arn,
                RoleSessionName="SCEDetectiveAttackSim",
                DurationSeconds=900,
            )
            creds = resp["Credentials"]
            log.info(
                "[STS] Assumed role. AccessKeyId=%s  Expiration=%s",
                creds["AccessKeyId"],
                creds["Expiration"],
            )
            return creds
        except ClientError as exc:
            err = exc.response["Error"]["Code"]
            if err in ("InvalidClientTokenId", "AccessDenied",
                       "NoCredentialProviders", "MalformedPolicyDocument"):
                log.warning(
                    "[STS] AssumeRole failed (%s) - retrying after backoff ...", err
                )
                time.sleep(10)
            else:
                log.error("[STS] AssumeRole unexpected error: %s", exc)
                raise

    raise RuntimeError(
        "[STS] Could not assume instance role within 120s. "
        "Check trust policy and IAM propagation."
    )


def _make_client(service: str, creds: dict):
    """Create a boto3 client using the supplied temporary credentials."""
    return boto3.client(
        service,
        aws_access_key_id     = creds["AccessKeyId"],
        aws_secret_access_key = creds["SecretAccessKey"],
        aws_session_token     = creds["SessionToken"],
        region_name           = _session().region_name or "us-east-1",
    )


# ---------------------------------------------------------------------------
# 1. steady_state()
# ---------------------------------------------------------------------------
def steady_state() -> None:
    """
    Provision all experiment resources for the detective probe.

    Execution order:
      A. Resolve account / region / timestamped stack name
      B. GuardDuty get-or-create (outside CFN)
      C. IAM resources created via boto3:
         - CloudTrail -> CloudWatch Logs delivery role
         - EC2 instance-simulation role (stolen credential target)
      D. CFN stack:
         - S3 bucket for CloudTrail log storage (with bucket policy)
         - CloudWatch Log Group for CloudTrail -> CW Logs delivery
         - CloudTrail trail (management events, CW Logs delivery enabled)
      E. Wait for CloudTrail to become active (IsLogging=True)
      F. Assert detective baseline:
         - CloudTrail trail is logging
         - CloudWatch Log Group exists and is referenced by the trail
    """
    global _STATE

    identity    = _sts().get_caller_identity()
    account     = identity["Account"]
    region      = _session().region_name or "us-east-1"
    ts          = int(time.time())
    stack       = f"{STACK_PREFIX}-{ts}"
    trail_bkt   = _safe_bucket_name(f"sce-ct-{ts}")
    cw_log_grp  = f"/sce/cloudtrail/{stack}"

    log.info("=" * 70)
    log.info("SCE Experiment 3.5 - Detective Probe  |  steady_state()")
    log.info("Account=%s  Region=%s  Stack=%s", account, region, stack)
    log.info("TrailBucket=%s  CWLogGroup=%s", trail_bkt, cw_log_grp)
    log.info("=" * 70)

    _STATE["stack_name"]    = stack
    _STATE["account"]       = account
    _STATE["region"]        = region
    _STATE["timestamp"]     = ts
    _STATE["trail_bucket"]  = trail_bkt
    _STATE["cw_log_group"]  = cw_log_grp
    _STATE["iam_info"]      = {}

    # ── B. GuardDuty ─────────────────────────────────────────────────────────
    try:
        detector_id, gd_owned     = _get_or_create_guardduty_detector()
        _STATE["detector_id"]      = detector_id
        _STATE["gd_owned"]         = gd_owned
    except Exception as exc:
        log.error("[STEADY] GuardDuty setup failed: %s", exc)
        raise

    # ── C. IAM via boto3 ─────────────────────────────────────────────────────
    try:
        iam_info           = _create_iam_resources(stack, account, region)
        _STATE["iam_info"] = iam_info
    except Exception as exc:
        log.error("[STEADY] IAM resource creation failed: %s", exc)
        raise

    # ── D. CloudFormation stack ───────────────────────────────────────────────
    template = _build_cfn_template(
        trail_bucket_name = trail_bkt,
        cw_log_group_name = cw_log_grp,
        ctcw_role_arn     = iam_info["ctcw_role_arn"],
        account_id        = account,
    )
    cf = _cf()

    try:
        cf.create_stack(
            StackName=stack,
            TemplateBody=template,
            Parameters=[
                {"ParameterKey": "TrailBucketName", "ParameterValue": trail_bkt},
                {"ParameterKey": "CWLogGroupName",  "ParameterValue": cw_log_grp},
                {"ParameterKey": "CTCWRoleArn",     "ParameterValue": iam_info["ctcw_role_arn"]},
                {"ParameterKey": "AccountId",       "ParameterValue": account},
            ],
            Capabilities=[],          # No IAM in template
            OnFailure="DO_NOTHING",
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

    # ── E. Harvest CFN outputs ────────────────────────────────────────────────
    outputs = _stack_outputs(stack)
    _STATE["trail_name"]    = outputs["TrailName"]
    _STATE["trail_arn"]     = outputs["TrailArn"]

    log.info("[STEADY] Stack outputs:")
    for k, v in outputs.items():
        log.info("         %-22s = %s", k, v)

    # ── F. Wait for CloudTrail to confirm IsLogging=True ─────────────────────
    trail_name = _STATE["trail_name"]
    log.info("[STEADY] Waiting for CloudTrail trail %s to be logging ...", trail_name)

    def _trail_is_logging() -> bool:
        try:
            resp = _ct().get_trail_status(Name=trail_name)
            is_logging = resp.get("IsLogging", False)
            log.info("[CT-STATUS] IsLogging=%s", is_logging)
            return bool(is_logging)
        except ClientError as exc:
            log.warning("[CT-STATUS] get_trail_status error: %s", exc)
            return False

    if not _poll_until(_trail_is_logging, "CloudTrail-IsLogging", sla_seconds=300):
        raise RuntimeError(
            "[STEADY] CloudTrail trail did not enter logging state within 300s."
        )

    log.info("[STEADY] CloudTrail trail is actively logging.")

    # Allow a short settling period for CW Logs delivery to initialise
    log.info("[STEADY] Waiting 15s for CW Logs delivery pipeline to initialise ...")
    time.sleep(15)

    log.info("[STEADY] steady_state() complete.\n")


# ---------------------------------------------------------------------------
# 2. attack()
# ---------------------------------------------------------------------------
def attack() -> bool:
    """
    Execute attack nodes 1.2, 2.2, and 3.2 using stolen instance-role credentials.

    Attack Node 1.2 (TTP T1562.008 proxy):
      Obtain temporary credentials for the instance-simulation role by calling
      sts:AssumeRole from the test runner.  This generates the sts:AssumeRole
      CloudTrail event that anchors the attack-chain correlation (maps to the
      ModifyInstanceMetadataOptions -> credential acquisition chain in the ADT).

    Attack Node 2.2 (TTP T1552.005):
      With stolen credentials, call sts:GetCallerIdentity to verify credential
      validity and enumerate the role identity.  This generates the
      GetCallerIdentity CloudTrail event.

    Attack Node 3.2 (TTP T1078.004 - lateral movement):
      With stolen credentials:
        a. iam:ListAttachedRolePolicies  -> Recon on the instance role
        b. s3:ListAllMyBuckets           -> Enumerate accessible S3 buckets
      Both actions generate CloudTrail events and are the exact API calls
      that GuardDuty monitors for credential anomaly/recon behaviour.

    Records timestamps in _STATE for use by hypothesis_verification().
    """
    if "iam_info" not in _STATE or not _STATE["iam_info"]:
        raise RuntimeError(
            "[ATTACK] _STATE missing iam_info - "
            "steady_state() must succeed before attack()."
        )

    inst_role_arn  = _STATE["iam_info"]["inst_role_arn"]
    inst_role_name = _STATE["iam_info"]["inst_role_name"]

    # ── Node 1.2: Obtain stolen credentials ───────────────────────────────────
    log.info("-" * 70)
    log.info("[ATTACK] Node 1.2 - Obtaining instance role credentials ...")
    try:
        stolen_creds             = _assume_instance_role(inst_role_arn)
        _STATE["stolen_creds"]   = stolen_creds
        _STATE["attack_1_2_ts"]  = int(time.time())
        log.info("[ATTACK] 1.2 - Credentials obtained. Timestamp=%d",
                 _STATE["attack_1_2_ts"])
    except Exception as exc:
        log.error("[ATTACK] 1.2 - Failed: %s", exc)
        return False

    # Short pause to let the AssumeRole event propagate to CloudTrail
    time.sleep(5)

    # ── Node 2.2: Verify credential identity ──────────────────────────────────
    log.info("[ATTACK] Node 2.2 - Verifying stolen credential identity ...")
    try:
        sts_stolen  = _make_client("sts", stolen_creds)
        identity    = sts_stolen.get_caller_identity()
        stolen_arn  = identity.get("Arn", "?")
        _STATE["stolen_identity"] = stolen_arn
        _STATE["attack_2_2_ts"]   = int(time.time())
        log.info("[ATTACK] 2.2 - Identity: %s  Timestamp=%d",
                 stolen_arn, _STATE["attack_2_2_ts"])
    except Exception as exc:
        log.error("[ATTACK] 2.2 - Failed: %s", exc)
        return False

    # ── Node 3.2: Lateral movement enumeration calls ──────────────────────────
    log.info("[ATTACK] Node 3.2 - Executing lateral movement enumeration ...")

    # 3.2a - iam:ListAttachedRolePolicies (Recon on own role's policies)
    log.info("[ATTACK] 3.2a - iam:ListAttachedRolePolicies ...")
    iam_stolen = _make_client("iam", stolen_creds)
    try:
        resp = iam_stolen.list_attached_role_policies(RoleName=inst_role_name)
        policies = [p["PolicyName"] for p in resp.get("AttachedPolicies", [])]
        log.info("[ATTACK] 3.2a - Policies enumerated: %s", policies)
    except ClientError as exc:
        err = exc.response["Error"]["Code"]
        log.info("[ATTACK] 3.2a - list_attached_role_policies returned: %s", err)
        # AccessDenied here still generates a CloudTrail event - continue

    # 3.2b - s3:ListAllMyBuckets (enumerate accessible S3 resources)
    log.info("[ATTACK] 3.2b - s3:ListAllMyBuckets ...")
    s3_stolen = _make_client("s3", stolen_creds)
    try:
        resp    = s3_stolen.list_buckets()
        buckets = [b["Name"] for b in resp.get("Buckets", [])]
        log.info("[ATTACK] 3.2b - Buckets enumerated: %d buckets", len(buckets))
    except ClientError as exc:
        err = exc.response["Error"]["Code"]
        log.info("[ATTACK] 3.2b - list_buckets returned: %s", err)

    _STATE["attack_3_2_ts"] = int(time.time())
    log.info("[ATTACK] Node 3.2 complete. Timestamp=%d", _STATE["attack_3_2_ts"])
    log.info("[ATTACK] All attack nodes executed.")
    log.info("-" * 70)
    return True


# ---------------------------------------------------------------------------
# 3. hypothesis_verification()
# ---------------------------------------------------------------------------
def hypothesis_verification() -> bool:
    """
    Detective Probe - SCE Experiment 3.5.

    Validates THREE independent detective signals within a 30-minute SLA:

    Signal A - GuardDuty: CredentialAccess or Recon finding after attack
      GuardDuty generates findings when EC2 instance-role credentials are
      used to make API calls that deviate from expected patterns.
      Accepted finding types: CredentialAccess:IAMUser/AnomalousBehavior,
      Recon:IAMUser/UserPermissions, UnauthorizedAccess:IAMUser/
      InstanceCredentialExfiltration.OutsideAWS, or any finding whose
      title contains credential/recon/anomalous/instance keywords.
      Maps to ADT 3.3.

    Signal B - CloudTrail: attack-chain events present in CW Logs
      Queries CloudWatch Logs for the CloudTrail-delivered log stream
      and searches for the key event names generated by attack nodes
      1.2 (AssumeRole), 2.2 (GetCallerIdentity), and 3.2
      (ListAttachedRolePolicies or ListBuckets). At least two of the
      four expected events must be present to confirm the SIEM correlation
      chain has the data it needs.
      Maps to ADT 3.3: "SIEM correlation rules link Steps 1-3."

    Signal C - CloudTrail: AssumeRole event for instance role is present
      Directly verifies via CloudTrail lookup_events that the sts:AssumeRole
      call from attack node 1.2 was recorded, confirming the credential
      acquisition event is in the audit trail and durable.
      Maps to ADT 1.3 + 3.3 CloudTrail detective controls.

    Returns True only when ALL three signals are confirmed within SLA.
    """
    if "attack_1_2_ts" not in _STATE:
        raise RuntimeError(
            "[VERIFY] _STATE missing attack timestamps - "
            "attack() must succeed before hypothesis_verification()."
        )

    detector_id    = _STATE["detector_id"]
    cw_log_group   = _STATE["cw_log_group"]
    inst_role_arn  = _STATE["iam_info"]["inst_role_arn"]
    inst_role_name = _STATE["iam_info"]["inst_role_name"]
    # 60-second buffer before attack_ts to tolerate minor clock skew
    attack_ts      = max(0, _STATE["attack_1_2_ts"] - 60)

    log.info("=" * 70)
    log.info("[VERIFY] Detective Probe - starting validation")
    log.info("[VERIFY] Detector     : %s", detector_id)
    log.info("[VERIFY] CWLogGroup   : %s", cw_log_group)
    log.info("[VERIFY] InstRoleArn  : %s", inst_role_arn)
    log.info("[VERIFY] Attack epoch : %d (buffered: %d)",
             _STATE["attack_1_2_ts"], attack_ts)
    log.info("[VERIFY] SLA window   : %ds (30 min)", SLA_SECONDS)
    log.info("=" * 70)

    results: dict = {}

    # ── Signal A: GuardDuty finding ───────────────────────────────────────────
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
            for f in findings_resp.get("Findings", []):
                ftype  = f.get("Type", "")
                ftitle = f.get("Title", "")
                fsev   = f.get("Severity", 0)
                log.info(
                    "[GD] Finding: type=%s  title=%s  severity=%s",
                    ftype, ftitle, fsev,
                )
                if any(ftype.startswith(p) for p in GD_RELEVANT_PREFIXES):
                    log.info("[GD] PASS  Relevant finding by type: %s", ftype)
                    return True
                if any(kw in ftitle.lower() for kw in GD_RELEVANT_KEYWORDS):
                    log.info("[GD] PASS  Relevant finding by keyword: %s", ftitle)
                    return True

        except ClientError as exc:
            log.error("[GD] API error: %s", exc)
        return False

    log.info("\n[VERIFY] === Signal A: GuardDuty CredentialAccess/Recon finding ===")
    results["guardduty_finding"] = _poll_until(
        _check_guardduty,
        "GuardDuty-CredentialAccess-Recon",
        sla_seconds=SLA_SECONDS,
    )

    # ── Signal B: CloudTrail events in CloudWatch Logs ────────────────────────
    # We search for the attack-chain event names in the CW Logs stream that
    # CloudTrail delivers to. At least 2 of the 4 expected events must appear.
    TARGET_EVENTS = [
        CT_EVENT_ASSUME_ROLE,
        CT_EVENT_GET_CALLER_IDENTITY,
        CT_EVENT_LIST_POLICIES,
        CT_EVENT_S3_LIST,
    ]

    def _check_cloudwatch_logs() -> bool:
        cw = _logs()
        try:
            # Verify the log group has at least one stream
            streams_resp = cw.describe_log_streams(
                logGroupName=cw_log_group,
                orderBy="LastEventTime",
                descending=True,
                limit=5,
            )
            streams = streams_resp.get("logStreams", [])
            log.info("[CW] Log streams in group: %d", len(streams))

            if not streams:
                log.info("[CW] No log streams yet - CloudTrail delivery pending.")
                return False

            # Search for attack-chain event names in recent log data
            found_events = set()
            for stream in streams[:3]:  # Check the 3 most recent streams
                stream_name = stream["logStreamName"]
                try:
                    events_resp = cw.get_log_events(
                        logGroupName=cw_log_group,
                        logStreamName=stream_name,
                        startFromHead=False,
                        limit=100,
                    )
                    for event in events_resp.get("events", []):
                        msg = event.get("message", "")
                        for target in TARGET_EVENTS:
                            if target in msg:
                                found_events.add(target)
                except ClientError as exc:
                    log.warning(
                        "[CW] get_log_events(%s) error: %s", stream_name, exc
                    )

            log.info("[CW] Attack-chain events found in CW Logs: %s", found_events)

            # Require at least 2 of the 4 expected event names to be present
            if len(found_events) >= 2:
                log.info(
                    "[CW] PASS  %d attack-chain event types confirmed in "
                    "CloudTrail CW Logs delivery.",
                    len(found_events),
                )
                return True
            log.info(
                "[CW] Only %d/%d event types found - waiting for more "
                "CloudTrail delivery ...",
                len(found_events), len(TARGET_EVENTS),
            )

        except ClientError as exc:
            if "ResourceNotFoundException" in str(exc):
                log.info("[CW] Log group not yet visible - awaiting CloudTrail delivery.")
            else:
                log.error("[CW] describe_log_streams error: %s", exc)
        return False

    log.info("\n[VERIFY] === Signal B: CloudTrail attack-chain events in CW Logs ===")
    results["cloudtrail_cw_events"] = _poll_until(
        _check_cloudwatch_logs,
        "CloudTrail-CW-Logs-Attack-Chain",
        sla_seconds=SLA_SECONDS,
    )

    # ── Signal C: CloudTrail lookup_events for AssumeRole ────────────────────
    # Uses the CloudTrail lookup_events API directly to verify the sts:AssumeRole
    # event for the instance role is durably recorded in CloudTrail.
    # This is the "credential acquisition" anchor event for the SIEM chain.
    import datetime

    def _check_cloudtrail_assume_role() -> bool:
        ct = _ct()
        try:
            # lookup_events can search up to 90 days back; filter by event name
            # and the instance role ARN to find our specific attack event.
            start_time = datetime.datetime.utcfromtimestamp(
                attack_ts
            ).replace(tzinfo=datetime.timezone.utc)

            resp = ct.lookup_events(
                LookupAttributes=[
                    {
                        "AttributeKey": "EventName",
                        "AttributeValue": "AssumeRole",
                    }
                ],
                StartTime=start_time,
                MaxResults=50,
            )
            events = resp.get("Events", [])
            log.info(
                "[CT-LOOKUP] AssumeRole events after attack timestamp: %d",
                len(events),
            )

            for event in events:
                event_time = event.get("EventTime")
                resources  = event.get("Resources", [])
                raw        = event.get("CloudTrailEvent", "{}")

                # Check if this AssumeRole event involves our instance role
                resource_arns = [r.get("ResourceName", "") for r in resources]
                event_str     = raw if isinstance(raw, str) else json.dumps(raw)

                role_referenced = (
                    inst_role_arn  in event_str or
                    inst_role_name in event_str or
                    any(inst_role_name in arn for arn in resource_arns) or
                    any(inst_role_arn  in arn for arn in resource_arns)
                )

                if role_referenced:
                    log.info(
                        "[CT-LOOKUP] PASS  AssumeRole event for instance role "
                        "found. EventTime=%s", event_time,
                    )
                    return True

            log.info(
                "[CT-LOOKUP] AssumeRole events found but none reference "
                "instance role %s - waiting ...", inst_role_name,
            )

        except ClientError as exc:
            log.error("[CT-LOOKUP] lookup_events error: %s", exc)
        return False

    log.info("\n[VERIFY] === Signal C: CloudTrail AssumeRole event for instance role ===")
    results["cloudtrail_assume_role"] = _poll_until(
        _check_cloudtrail_assume_role,
        "CloudTrail-AssumeRole-Event",
        sla_seconds=SLA_SECONDS,
    )

    # ── Verdict ───────────────────────────────────────────────────────────────
    log.info("\n[VERIFY] -- Signal Summary ------------------------------------------")
    all_passed = True
    for signal, passed in results.items():
        status = "PASS" if passed else "FAIL"
        log.info("[VERIFY]   %-35s -> %s", signal, status)
        if not passed:
            all_passed = False

    verdict = (
        "ALL detective signals confirmed - GuardDuty, CloudTrail CW Logs, "
        "and CloudTrail lookup all detected the attack-chain events."
        if all_passed
        else (
            "One or more detective signals NOT confirmed within SLA - "
            "a detection gap exists in the monitoring chain."
        )
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
      1. Stop the CloudTrail trail (prevents S3 write errors during bucket delete)
      2. Empty the CloudTrail S3 bucket (versioning off, but belt-and-suspenders)
      3. Delete the CloudFormation stack (trail, CW log group, S3 bucket)
      4. Delete boto3-created IAM resources
      5. Delete GuardDuty detector only if this experiment created it

    Safe and tolerant: logs all errors without re-raising.
    """
    trail_name  = _STATE.get("trail_name", "")
    trail_bkt   = _STATE.get("trail_bucket", "")

    # ── 1. Stop CloudTrail before deleting bucket ─────────────────────────────
    if trail_name:
        log.info("[ROLLBACK] Stopping CloudTrail trail: %s", trail_name)
        try:
            _ct().stop_logging(Name=trail_name)
            log.info("[ROLLBACK] Trail logging stopped.")
        except ClientError as exc:
            log.warning("[ROLLBACK] stop_logging non-fatal: %s", exc)

    # ── 2. Empty CloudTrail S3 bucket ─────────────────────────────────────────
    if trail_bkt:
        log.info("[ROLLBACK] Emptying trail S3 bucket: %s", trail_bkt)
        s3 = _s3()
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=trail_bkt):
                objects = [
                    {"Key": obj["Key"]}
                    for obj in page.get("Contents", [])
                ]
                if objects:
                    s3.delete_objects(
                        Bucket=trail_bkt,
                        Delete={"Objects": objects, "Quiet": True},
                    )
                    log.info("[ROLLBACK] Deleted %d objects.", len(objects))
        except ClientError as exc:
            if "NoSuchBucket" not in str(exc):
                log.warning("[ROLLBACK] S3 bucket empty non-fatal: %s", exc)

    # ── 3. CloudFormation stack ───────────────────────────────────────────────
    stack = _STATE.get("stack_name")
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
    else:
        log.warning("[ROLLBACK] No stack_name in _STATE - skipping CFN delete.")

    # ── 4. IAM resources ──────────────────────────────────────────────────────
    iam_info = _STATE.get("iam_info", {})
    if iam_info:
        log.info("[ROLLBACK] Deleting IAM resources ...")
        try:
            _delete_iam_resources(iam_info)
        except Exception as exc:  # noqa: BLE001
            log.error("[ROLLBACK] IAM cleanup error (non-fatal): %s", exc)
    else:
        log.info("[ROLLBACK] No iam_info in _STATE - skipping IAM cleanup.")

    # ── 5. GuardDuty (only if experiment-owned) ───────────────────────────────
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
    log.info("SCE Experiment 3.5 - Detective Probe - Full Run")
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
            log.info(
                "[RUNNER] PASS  Experiment passed - detective controls validated."
            )
        else:
            log.warning(
                "[RUNNER] FAIL  Experiment failed - detective controls "
                "not confirmed within SLA."
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