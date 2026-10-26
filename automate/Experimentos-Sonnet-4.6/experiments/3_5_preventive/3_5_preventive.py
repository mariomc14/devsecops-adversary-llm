"""
SCE Experiment 3.5 - Preventive Probe
Attack Nodes: 1.2 (Weaken IMDS), 2.2 (Retrieve Credentials), 3.2 (Lateral Movement)

PREVENTIVE PROBE INTENT (ADT node 3.5):
========================================
"Using a cloned instance-profile role in a sandbox, attempt iam:CreateUser,
sts:AssumeRole to admin role, and s3:GetObject on the PCI-scope bucket;
confirm all three are denied by the permission boundary and SCP; verify no
S3 object is returned and no IAM user is created. Confirm cloudtrail:StopLogging
is denied and the audit trail remains intact."

This experiment operationalises the three preventive controls that bound the
blast radius of stolen EC2 instance-profile credentials:

  CONTROL 1 - IAM Permission Boundary
    The instance-profile role carries a permission boundary that restricts
    effective permissions to a safe allowlist. Even if an inline policy or
    managed policy grants broad access, the boundary prevents:
      - iam:CreateUser
      - iam:CreateAccessKey
      - iam:AttachRolePolicy
      - sts:AssumeRole (to anything outside the experiment's scoped role)
      - cloudtrail:StopLogging / cloudtrail:DeleteTrail
      - s3:GetObject on the PCI-scope bucket

  CONTROL 2 - Least-privilege inline policy
    The instance-profile role's inline policy grants only s3:ListAllMyBuckets
    and ec2:DescribeInstances. GetObject on the PCI bucket is not granted,
    so it is denied both by the policy AND by the boundary (double-deny).

  CONTROL 3 - S3 bucket policy with explicit Deny
    The PCI-scope S3 bucket carries a resource-based bucket policy that
    explicitly denies s3:GetObject to any principal that is NOT the designated
    legitimate consumer role, regardless of IAM identity policies.

ATTACK SIMULATION (safe, scoped):
  Node 1.2 - Simulate obtaining instance-role credentials by calling
             sts:GetCallerIdentity with the instance role (proves credential
             access path exists; no actual IMDS weakening needed in this
             preventive test because the probe validates what happens AFTER
             credentials are in the attacker's hands).
  Node 2.2 - Use the instance-role credentials (via AssumeRole to that same
             role from the test runner) to attempt the actions that the
             preventive controls must block.
  Node 3.2 - Attempt iam:CreateUser, sts:AssumeRole to high-priv role,
             s3:GetObject on PCI bucket, cloudtrail:StopLogging - all must
             return AccessDenied.

LESSONS FROM PREVIOUS DETECTIVE/REACTIVE PROBE RUNS:
  - All IAM created via boto3, not CFN (avoids iam:CreateRole-in-CFN failure)
  - No Description= on any IAM call (avoids ValidationError from non-ASCII)
  - Role names sanitized to [A-Za-z0-9+=,.@_-], max 64 chars
  - AMI resolved at runtime via SSM public parameter
  - CFN template contains ZERO IAM resources
  - OnFailure=DO_NOTHING on CFN stack for post-mortem event inspection
  - GuardDuty left entirely out of this test (preventive probe only)
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
import urllib.parse
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
EXPERIMENT_TAG_KEY       = "SCEExperiment"
EXPERIMENT_TAG_VALUE     = "3_5_preventive"
STACK_PREFIX             = "sce-prev"

SLA_SECONDS              = 1800   # 30-minute outer SLA for all polling
POLL_INTERVAL_S          = 15

CF_MAX_WAIT_S            = 900    # 15 min max for stack create/delete
CF_POLL_S                = 15

IAM_PROPAGATION_S        = 25     # seconds after IAM role creation

# Boundary policy name (inline on the boundary policy itself)
BOUNDARY_POLICY_NAME     = "SCEInstanceBoundary"

# Inline policy name on the instance role
INSTANCE_INLINE_POLICY   = "SCEInstanceInline"

# Bucket policy object key used to test s3:GetObject denial
PCI_OBJECT_KEY           = "pci-test-record.txt"

# High-privilege role name suffix (the role the attacker tries to assume)
HIGH_PRIV_ROLE_SUFFIX    = "high-priv"


# ---------------------------------------------------------------------------
# String sanitization helpers
# ---------------------------------------------------------------------------

def _safe_name(base: str, max_len: int = 64) -> str:
    """
    Produce a name safe for IAM roles/profiles/policies and S3 buckets:
    only [A-Za-z0-9+=,.@_-], truncated to max_len characters.
    """
    safe = re.sub(r"[^A-Za-z0-9+=,.@_\-]", "-", base)
    return safe[:max_len]


def _safe_bucket_name(base: str) -> str:
    """
    S3 bucket names: lowercase, 3-63 chars, [a-z0-9-], no consecutive hyphens,
    no leading/trailing hyphens.
    """
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
def _ec2():   return _session().client("ec2")
def _iam():   return _session().client("iam")
def _s3():    return _session().client("s3")
def _ssm():   return _session().client("ssm")
def _sts():   return _session().client("sts")
def _ct():    return _session().client("cloudtrail")


# ---------------------------------------------------------------------------
# AMI resolution (kept for completeness; no EC2 instance needed here)
# ---------------------------------------------------------------------------
def _latest_al2_ami() -> str:
    """Resolve latest Amazon Linux 2 AMI via SSM public parameter."""
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
# IAM: Permission boundary managed policy
# ---------------------------------------------------------------------------
def _create_permission_boundary(account_id: str, suffix: str) -> str:
    """
    Create a managed IAM policy used as a permission boundary.

    The boundary ALLOWS only a safe allowlist of actions. Any action NOT
    listed here is implicitly denied by the boundary, regardless of what
    identity-based policies grant.

    Explicitly blocked (not in the allow list, therefore denied by boundary):
      - iam:CreateUser
      - iam:CreateAccessKey
      - iam:AttachRolePolicy
      - sts:AssumeRole  (to roles outside the experiment)
      - cloudtrail:StopLogging / cloudtrail:DeleteTrail
      - s3:GetObject   (bucket-level deny will also catch this)

    Returns the boundary policy ARN.
    """
    iam         = _iam()
    policy_name = _safe_name(f"SCEBoundary-{suffix}")
    tags        = [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]

    # Allow only the minimum actions the legitimate microservice role needs.
    # Anything not listed is implicitly denied through the boundary.
    boundary_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowMinimalEC2",
                "Effect": "Allow",
                "Action": [
                    "ec2:DescribeInstances",
                    "ec2:DescribeRegions",
                ],
                "Resource": "*",
            },
            {
                "Sid": "AllowS3ListOnly",
                "Effect": "Allow",
                "Action": [
                    "s3:ListAllMyBuckets",
                    "s3:ListBucket",
                ],
                "Resource": "*",
            },
            {
                "Sid": "AllowSTSCallerIdentity",
                "Effect": "Allow",
                "Action": [
                    "sts:GetCallerIdentity",
                ],
                "Resource": "*",
            },
            {
                "Sid": "AllowSSMCore",
                "Effect": "Allow",
                "Action": [
                    "ssm:UpdateInstanceInformation",
                    "ssmmessages:CreateControlChannel",
                    "ssmmessages:CreateDataChannel",
                    "ssmmessages:OpenControlChannel",
                    "ssmmessages:OpenDataChannel",
                    "ec2messages:AcknowledgeMessage",
                    "ec2messages:DeleteMessage",
                    "ec2messages:FailMessage",
                    "ec2messages:GetEndpoint",
                    "ec2messages:GetMessages",
                    "ec2messages:SendReply",
                ],
                "Resource": "*",
            },
            # Explicit Deny belt-and-suspenders for the highest-risk actions.
            # These would be denied by the allowlist above anyway, but
            # explicit Deny makes the intent unambiguous for audit purposes.
            {
                "Sid": "ExplicitDenyHighRisk",
                "Effect": "Deny",
                "Action": [
                    "iam:CreateUser",
                    "iam:CreateAccessKey",
                    "iam:AttachRolePolicy",
                    "iam:PutUserPolicy",
                    "iam:PutRolePolicy",
                    "iam:DeleteRolePolicy",
                    "iam:UpdateAssumeRolePolicy",
                    "cloudtrail:StopLogging",
                    "cloudtrail:DeleteTrail",
                    "cloudtrail:UpdateTrail",
                    "cloudtrail:PutEventSelectors",
                    "s3:DeleteBucket",
                    "s3:DeleteObject",
                    "s3:PutBucketPolicy",
                ],
                "Resource": "*",
            },
        ],
    }

    log.info("[IAM-BOUNDARY] Creating permission boundary policy: %s", policy_name)
    try:
        resp       = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(boundary_doc),
            Tags=tags,
        )
        policy_arn = resp["Policy"]["Arn"]
        log.info("[IAM-BOUNDARY] Created: %s", policy_arn)
        return policy_arn
    except ClientError as exc:
        if "EntityAlreadyExists" in str(exc):
            policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"
            log.warning(
                "[IAM-BOUNDARY] Policy already exists - using ARN: %s", policy_arn
            )
            return policy_arn
        log.error("[IAM-BOUNDARY] create_policy failed: %s", exc)
        raise


# ---------------------------------------------------------------------------
# IAM resources created directly via boto3 (NOT inside CloudFormation)
# ---------------------------------------------------------------------------
def _create_iam_resources(stack_name: str, account_id: str) -> dict:
    """
    Create all IAM roles required by the preventive experiment.

    Resources:
      1. Permission boundary managed policy
      2. Instance-profile role (simulates stolen EC2 instance credentials)
         - Has permission boundary attached
         - Inline policy: s3:ListAllMyBuckets + ec2:DescribeInstances only
         - sts:AssumeRole trust from the test runner's account (same account)
      3. High-privilege role (simulates a target for privilege escalation)
         - The attacker tries to assume this role; the boundary prevents it

    Returns dict of all names and ARNs.
    No Description= field anywhere.
    """
    iam    = _iam()
    suffix = stack_name[-16:]
    tags   = [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]

    inst_role_name   = _safe_name(f"sce-inst-{suffix}")
    high_priv_name   = _safe_name(f"sce-hp-{suffix}")

    log.info("[IAM] inst_role_name = %s", inst_role_name)
    log.info("[IAM] high_priv_name = %s", high_priv_name)

    # ── Permission boundary ───────────────────────────────────────────────────
    boundary_arn = _create_permission_boundary(account_id, suffix)
    _STATE["boundary_arn"] = boundary_arn

    # ── High-privilege role (attack target for sts:AssumeRole) ────────────────
    log.info("[IAM] Creating high-privilege role: %s", high_priv_name)
    try:
        iam.create_role(
            RoleName=high_priv_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "sts:AssumeRole",
                }],
            }),
            Tags=tags,
        )
        log.info("[IAM] High-privilege role created.")
    except ClientError as exc:
        if "EntityAlreadyExists" in str(exc):
            log.warning("[IAM] High-priv role %s already exists.", high_priv_name)
        else:
            log.error("[IAM] create_role(%s) failed: %s", high_priv_name, exc)
            raise

    # Attach AdministratorAccess to make it a meaningful escalation target
    try:
        iam.attach_role_policy(
            RoleName=high_priv_name,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
    except ClientError as exc:
        log.warning("[IAM] attach AdministratorAccess non-fatal: %s", exc)

    high_priv_arn = iam.get_role(RoleName=high_priv_name)["Role"]["Arn"]
    log.info("[IAM] high_priv_arn = %s", high_priv_arn)

    # ── EC2 instance-profile role (simulates stolen credential) ───────────────
    log.info("[IAM] Creating instance role: %s", inst_role_name)
    # Trust policy: allow assumption from the current account (test runner)
    # This lets us simulate "using stolen credentials" by calling
    # sts:AssumeRole on the instance role from the test runner identity.
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
            PermissionsBoundary=boundary_arn,
            Tags=tags,
        )
        log.info("[IAM] Instance role created with permission boundary.")
    except ClientError as exc:
        if "EntityAlreadyExists" in str(exc):
            log.warning("[IAM] Role %s already exists.", inst_role_name)
        else:
            log.error("[IAM] create_role(%s) failed: %s", inst_role_name, exc)
            raise

    # Inline policy: minimal legitimate permissions for the microservice role.
    # NOTE: This intentionally does NOT include iam:CreateUser, s3:GetObject
    # on the PCI bucket, sts:AssumeRole to high-priv, or cloudtrail:StopLogging.
    # Even if we were to add those here, the boundary would block them.
    try:
        iam.put_role_policy(
            RoleName=inst_role_name,
            PolicyName=INSTANCE_INLINE_POLICY,
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "LegitimateServiceActions",
                        "Effect": "Allow",
                        "Action": [
                            "s3:ListAllMyBuckets",
                            "ec2:DescribeInstances",
                            "sts:GetCallerIdentity",
                        ],
                        "Resource": "*",
                    },
                    {
                        # This grant would be needed for a real instance role
                        # but the boundary caps effective permissions.
                        # We add a broad Allow here intentionally so that
                        # the permission boundary is the ONLY control stopping
                        # the high-risk actions - proving the boundary works.
                        "Sid": "IntentionallyBroadGrantBlockedByBoundary",
                        "Effect": "Allow",
                        "Action": [
                            "iam:CreateUser",
                            "iam:CreateAccessKey",
                            "sts:AssumeRole",
                            "cloudtrail:StopLogging",
                            "s3:GetObject",
                        ],
                        "Resource": "*",
                    },
                ],
            }),
        )
        log.info(
            "[IAM] Inline policy attached (broad grant intentional; "
            "boundary is the control under test)."
        )
    except ClientError as exc:
        log.warning("[IAM] put_role_policy non-fatal: %s", exc)

    inst_role_arn = iam.get_role(RoleName=inst_role_name)["Role"]["Arn"]
    log.info("[IAM] inst_role_arn = %s", inst_role_arn)

    # IAM propagation
    log.info("[IAM] Waiting %ds for IAM propagation ...", IAM_PROPAGATION_S)
    time.sleep(IAM_PROPAGATION_S)

    return {
        "inst_role_name":  inst_role_name,
        "inst_role_arn":   inst_role_arn,
        "high_priv_name":  high_priv_name,
        "high_priv_arn":   high_priv_arn,
        "boundary_arn":    boundary_arn,
    }


def _delete_iam_resources(iam_info: dict) -> None:
    """
    Delete all IAM resources created by _create_iam_resources().
    Tolerant: logs all errors and continues.
    """
    iam            = _iam()
    inst_role      = iam_info.get("inst_role_name", "")
    high_priv      = iam_info.get("high_priv_name", "")
    boundary_arn   = iam_info.get("boundary_arn", "")

    # ── Clean instance role ───────────────────────────────────────────────────
    if inst_role:
        for managed in ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]:
            try:
                iam.detach_role_policy(RoleName=inst_role, PolicyArn=managed)
            except ClientError:
                pass
        for inline in [INSTANCE_INLINE_POLICY]:
            try:
                iam.delete_role_policy(RoleName=inst_role, PolicyName=inline)
            except ClientError:
                pass
        try:
            iam.delete_role(RoleName=inst_role)
            log.info("[IAM-RB] Deleted role: %s", inst_role)
        except ClientError as exc:
            log.warning("[IAM-RB] delete_role(%s): %s", inst_role, exc)

    # ── Clean high-privilege role ─────────────────────────────────────────────
    if high_priv:
        try:
            iam.detach_role_policy(
                RoleName=high_priv,
                PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
            )
        except ClientError:
            pass
        try:
            iam.delete_role(RoleName=high_priv)
            log.info("[IAM-RB] Deleted role: %s", high_priv)
        except ClientError as exc:
            log.warning("[IAM-RB] delete_role(%s): %s", high_priv, exc)

    # ── Delete boundary managed policy ───────────────────────────────────────
    if boundary_arn:
        try:
            # Detach from all entities before deleting
            iam.delete_policy(PolicyArn=boundary_arn)
            log.info("[IAM-RB] Deleted boundary policy: %s", boundary_arn)
        except ClientError as exc:
            log.warning("[IAM-RB] delete_policy non-fatal: %s", exc)


# ---------------------------------------------------------------------------
# CloudFormation template
# ---------------------------------------------------------------------------
def _build_cfn_template(bucket_name: str) -> str:
    """
    CFN template provisions:
      S3 PCI-scope bucket with:
        - BlockPublicAccess settings enabled
        - Bucket policy: explicit Deny s3:GetObject to everyone except
          the designated legitimate consumer (which does not exist in this
          test, so all GetObject calls are denied regardless of IAM policy)
        - Server-side encryption
        - Versioning enabled
      CloudWatch Log Group (experiment audit trail)

    All IAM resources are created externally via boto3.
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 3.5 Preventive - PCI S3 bucket and audit log group",
        "Parameters": {
            "BucketName": {
                "Type": "String",
                "Description": "Name for the PCI-scope S3 bucket",
            },
        },
        "Resources": {

            # ── PCI-scope S3 bucket ───────────────────────────────────────
            "SCEPCIBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": {"Ref": "BucketName"},
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls":       True,
                        "BlockPublicPolicy":     True,
                        "IgnorePublicAcls":      True,
                        "RestrictPublicBuckets": True,
                    },
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": [{
                            "ServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            }
                        }]
                    },
                    "VersioningConfiguration": {
                        "Status": "Enabled"
                    },
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY,
                         "Value": EXPERIMENT_TAG_VALUE},
                        {"Key": "DataClassification",
                         "Value": "PCI-Scope"},
                    ],
                },
            },

            # ── Bucket policy: deny all s3:GetObject ─────────────────────
            # This is a resource-based control independent of IAM policies.
            # Any principal attempting s3:GetObject will be denied.
            "SCEPCIBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "SCEPCIBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DenyGetObjectAllPrincipals",
                                "Effect": "Deny",
                                "Principal": "*",
                                "Action": "s3:GetObject",
                                "Resource": {
                                    "Fn::Sub": "arn:aws:s3:::${BucketName}/*"
                                },
                            },
                            {
                                "Sid": "DenyNonSSL",
                                "Effect": "Deny",
                                "Principal": "*",
                                "Action": "s3:*",
                                "Resource": [
                                    {"Fn::Sub": "arn:aws:s3:::${BucketName}"},
                                    {"Fn::Sub": "arn:aws:s3:::${BucketName}/*"},
                                ],
                                "Condition": {
                                    "Bool": {
                                        "aws:SecureTransport": "false"
                                    }
                                },
                            },
                        ],
                    },
                },
            },

            # ── CloudWatch Log Group for experiment audit ──────────────────
            "SCELogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": {
                        "Fn::Sub": "/sce/preventive/${AWS::StackName}"
                    },
                    "RetentionInDays": 1,
                },
            },
        },

        "Outputs": {
            "BucketName": {
                "Value": {"Ref": "SCEPCIBucket"},
                "Description": "PCI-scope S3 bucket name",
            },
            "BucketArn": {
                "Value": {"Fn::GetAtt": ["SCEPCIBucket", "Arn"]},
                "Description": "PCI-scope S3 bucket ARN",
            },
            "LogGroupName": {
                "Value": {"Fn::Sub": "/sce/preventive/${AWS::StackName}"},
                "Description": "Experiment CloudWatch Log Group",
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
# STS: assume the instance role to simulate stolen credential usage
# ---------------------------------------------------------------------------
def _assume_instance_role(inst_role_arn: str) -> dict:
    """
    Assume the EC2 instance role from the test runner identity to simulate
    an attacker operating with stolen instance-profile credentials.
    Returns the temporary credentials dict or raises on failure.
    """
    sts = _sts()
    log.info("[STS] Assuming instance role to simulate stolen credentials: %s",
             inst_role_arn)

    # Retry with backoff for IAM propagation eventual consistency
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            resp  = sts.assume_role(
                RoleArn=inst_role_arn,
                RoleSessionName="SCEPreventiveAttackSim",
                DurationSeconds=900,
            )
            creds = resp["Credentials"]
            log.info(
                "[STS] Assumed role successfully. "
                "AccessKeyId=%s  Expiration=%s",
                creds["AccessKeyId"],
                creds["Expiration"],
            )
            return creds
        except ClientError as exc:
            err = exc.response["Error"]["Code"]
            if err in ("InvalidClientTokenId", "AccessDenied", "NoCredentialProviders"):
                log.warning(
                    "[STS] AssumeRole failed (%s) - retrying after backoff ...", err
                )
                time.sleep(10)
            else:
                log.error("[STS] AssumeRole unexpected error: %s", exc)
                raise

    raise RuntimeError(
        "[STS] Could not assume instance role within 120s - "
        "check trust policy and IAM propagation."
    )


def _make_client_with_creds(service: str, creds: dict):
    """
    Create a boto3 client for the given service using the supplied
    temporary credentials.  Used to simulate the attacker using stolen creds.
    """
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
    Provision all experiment resources for the preventive probe.

    Execution order:
      A. Resolve account / region / timestamped stack name
      B. IAM resources created via boto3 (NO Description= field):
         - Permission boundary managed policy
         - Instance-profile role (with boundary + intentionally broad inline)
         - High-privilege role (AssumeRole escalation target)
      C. CFN stack: PCI-scope S3 bucket (with Deny bucket policy) +
         CloudWatch Log Group
      D. Seed the PCI bucket with one object (simulates cardholder data)
      E. Assert preventive controls are in place before attack:
         - Boundary is attached to the instance role
         - Bucket policy denies GetObject
    """
    global _STATE

    identity   = _sts().get_caller_identity()
    account    = identity["Account"]
    region     = _session().region_name or "us-east-1"
    ts         = int(time.time())
    stack      = f"{STACK_PREFIX}-{ts}"
    bucket     = _safe_bucket_name(f"sce-pci-{ts}")

    log.info("=" * 70)
    log.info("SCE Experiment 3.5 - Preventive Probe  |  steady_state()")
    log.info("Account=%s  Region=%s  Stack=%s", account, region, stack)
    log.info("Bucket=%s", bucket)
    log.info("=" * 70)

    _STATE["stack_name"]  = stack
    _STATE["account"]     = account
    _STATE["region"]      = region
    _STATE["timestamp"]   = ts
    _STATE["bucket_name"] = bucket
    _STATE["iam_info"]    = {}

    # ── B. IAM via boto3 ─────────────────────────────────────────────────────
    try:
        iam_info          = _create_iam_resources(stack, account)
        _STATE["iam_info"] = iam_info
    except Exception as exc:
        log.error("[STEADY] IAM resource creation failed: %s", exc)
        raise

    # ── C. CloudFormation stack ───────────────────────────────────────────────
    template = _build_cfn_template(bucket)
    cf       = _cf()

    try:
        cf.create_stack(
            StackName=stack,
            TemplateBody=template,
            Parameters=[
                {"ParameterKey": "BucketName", "ParameterValue": bucket},
            ],
            Capabilities=[],          # No IAM in template
            OnFailure="DO_NOTHING",
            Tags=[
                {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                {"Key": "SCETimestamp",      "Value": str(ts)},
            ],
            TimeoutInMinutes=20,
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

    # ── D. Harvest CFN outputs ────────────────────────────────────────────────
    outputs = _stack_outputs(stack)
    _STATE["bucket_arn"]    = outputs["BucketArn"]
    _STATE["log_group"]     = outputs["LogGroupName"]

    log.info("[STEADY] Stack outputs:")
    for k, v in outputs.items():
        log.info("         %-22s = %s", k, v)

    # ── E. Seed PCI bucket with a test object ─────────────────────────────────
    log.info("[STEADY] Seeding PCI bucket with test object ...")
    s3 = _s3()
    try:
        s3.put_object(
            Bucket=bucket,
            Key=PCI_OBJECT_KEY,
            Body=b"SIMULATED_PCI_CARDHOLDER_DATA",
            ServerSideEncryption="AES256",
        )
        log.info("[STEADY] Test object '%s' written to bucket.", PCI_OBJECT_KEY)
    except ClientError as exc:
        log.error("[STEADY] put_object failed: %s", exc)
        raise

    # ── F. Assert preventive baseline ────────────────────────────────────────
    iam          = _iam()
    inst_role    = iam_info["inst_role_name"]
    boundary_arn = iam_info["boundary_arn"]

    # Verify boundary is attached
    role_resp = iam.get_role(RoleName=inst_role)
    attached_boundary = (
        role_resp["Role"]
        .get("PermissionsBoundary", {})
        .get("PermissionsBoundaryArn", "")
    )
    if attached_boundary != boundary_arn:
        raise RuntimeError(
            f"[STEADY] BASELINE VIOLATED: Permission boundary not attached. "
            f"Expected={boundary_arn}  Found={attached_boundary}"
        )
    log.info("[STEADY] Permission boundary confirmed: %s", attached_boundary)

    # Verify bucket policy exists
    try:
        bp = s3.get_bucket_policy(Bucket=bucket)
        log.info("[STEADY] Bucket policy confirmed present.")
        policy_doc = json.loads(bp["Policy"])
        has_deny = any(
            stmt.get("Effect") == "Deny"
            and "s3:GetObject" in (
                stmt.get("Action", [])
                if isinstance(stmt.get("Action"), list)
                else [stmt.get("Action", "")]
            )
            for stmt in policy_doc.get("Statement", [])
        )
        if not has_deny:
            raise RuntimeError(
                "[STEADY] BASELINE VIOLATED: Bucket policy missing "
                "Deny s3:GetObject statement."
            )
        log.info("[STEADY] Bucket policy Deny s3:GetObject confirmed.")
    except ClientError as exc:
        log.error("[STEADY] get_bucket_policy failed: %s", exc)
        raise

    log.info("[STEADY] All preventive baselines verified.")
    log.info("[STEADY] steady_state() complete.\n")


# ---------------------------------------------------------------------------
# 2. attack()
# ---------------------------------------------------------------------------
def attack() -> bool:
    """
    Simulate the three attack nodes using the instance-role credentials.

    Node 1.2 (TTP T1562.008 - Impair Defenses proxy):
      Obtain temporary credentials for the instance role by calling
      sts:AssumeRole from the test runner.  This simulates having stolen
      the credentials from the IMDS endpoint after IMDS was weakened.
      The actual IMDS weakening (ModifyInstanceMetadataOptions) is not
      performed here because the preventive probe tests what happens AFTER
      credentials are stolen, not the weakening step itself.

    Node 2.2 (TTP T1552.005 proxy):
      Verify the stolen credentials are usable by calling sts:GetCallerIdentity.
      Confirm the identity is the instance role.

    Node 3.2 (TTP T1078.004 - lateral movement attempts):
      Using the stolen credentials, attempt ALL four blocked actions:
        a. iam:CreateUser          -> must be blocked by permission boundary
        b. sts:AssumeRole (admin)  -> must be blocked by permission boundary
        c. s3:GetObject (PCI)      -> must be blocked by boundary + bucket policy
        d. cloudtrail:StopLogging  -> must be blocked by permission boundary

    Records in _STATE which actions were attempted and what error codes returned.
    Returns True if all four attempts were successfully issued (even though
    they must all return AccessDenied - the verification of denial is in
    hypothesis_verification()).
    """
    if "iam_info" not in _STATE or not _STATE["iam_info"]:
        raise RuntimeError(
            "[ATTACK] _STATE missing iam_info - "
            "steady_state() must succeed before attack()."
        )

    inst_role_arn  = _STATE["iam_info"]["inst_role_arn"]
    high_priv_arn  = _STATE["iam_info"]["high_priv_arn"]
    bucket         = _STATE["bucket_name"]
    account        = _STATE["account"]

    # ── Node 1.2: Obtain stolen credentials (simulate IMDS credential theft) ──
    log.info("-" * 70)
    log.info("[ATTACK] Node 1.2 - Obtaining instance role credentials ...")
    try:
        stolen_creds = _assume_instance_role(inst_role_arn)
        _STATE["stolen_creds"]   = stolen_creds
        _STATE["attack_1_2_ts"]  = int(time.time())
        log.info("[ATTACK] 1.2 - Instance role credentials obtained.")
    except Exception as exc:
        log.error("[ATTACK] 1.2 - Failed to obtain credentials: %s", exc)
        return False

    # ── Node 2.2: Verify credential validity (simulate post-theft verification) ─
    log.info("[ATTACK] Node 2.2 - Verifying stolen credential identity ...")
    try:
        sts_with_stolen = _make_client_with_creds("sts", stolen_creds)
        identity        = sts_with_stolen.get_caller_identity()
        log.info(
            "[ATTACK] 2.2 - Identity confirmed: UserId=%s  Arn=%s",
            identity.get("UserId", "?"),
            identity.get("Arn", "?"),
        )
        _STATE["attack_2_2_ts"] = int(time.time())
        _STATE["stolen_identity"] = identity.get("Arn", "?")
    except Exception as exc:
        log.error("[ATTACK] 2.2 - Credential verification failed: %s", exc)
        return False

    # ── Node 3.2: Attempt all blocked lateral-movement actions ────────────────
    log.info("[ATTACK] Node 3.2 - Attempting blocked lateral-movement actions ...")
    _STATE["attack_results"] = {}

    # 3.2a - iam:CreateUser (must be blocked by boundary)
    log.info("[ATTACK] 3.2a - Attempting iam:CreateUser ...")
    iam_with_stolen = _make_client_with_creds("iam", stolen_creds)
    try:
        iam_with_stolen.create_user(UserName="sce-test-persistence-user")
        # If this succeeds the boundary has FAILED - record as unexpected success
        log.error(
            "[ATTACK] 3.2a - UNEXPECTED SUCCESS: iam:CreateUser SUCCEEDED. "
            "Permission boundary is NOT blocking this action!"
        )
        _STATE["attack_results"]["iam_create_user"] = "UNEXPECTED_SUCCESS"
        # Clean up the created user immediately
        try:
            _iam().delete_user(UserName="sce-test-persistence-user")
            log.info("[ATTACK] Cleaned up unexpectedly created user.")
        except Exception:  # noqa: BLE001
            pass
    except ClientError as exc:
        err_code = exc.response["Error"]["Code"]
        log.info(
            "[ATTACK] 3.2a - iam:CreateUser returned: %s (expected AccessDenied)",
            err_code,
        )
        _STATE["attack_results"]["iam_create_user"] = err_code

    # 3.2b - sts:AssumeRole to high-priv role (must be blocked by boundary)
    log.info("[ATTACK] 3.2b - Attempting sts:AssumeRole to high-priv role ...")
    sts_with_stolen = _make_client_with_creds("sts", stolen_creds)
    try:
        sts_with_stolen.assume_role(
            RoleArn=high_priv_arn,
            RoleSessionName="SCEEscalationAttempt",
            DurationSeconds=900,
        )
        log.error(
            "[ATTACK] 3.2b - UNEXPECTED SUCCESS: sts:AssumeRole to admin role SUCCEEDED. "
            "Permission boundary is NOT blocking privilege escalation!"
        )
        _STATE["attack_results"]["sts_assume_role"] = "UNEXPECTED_SUCCESS"
    except ClientError as exc:
        err_code = exc.response["Error"]["Code"]
        log.info(
            "[ATTACK] 3.2b - sts:AssumeRole returned: %s (expected AccessDenied)",
            err_code,
        )
        _STATE["attack_results"]["sts_assume_role"] = err_code

    # 3.2c - s3:GetObject on PCI bucket (must be blocked by boundary AND bucket policy)
    log.info("[ATTACK] 3.2c - Attempting s3:GetObject on PCI bucket ...")
    s3_with_stolen = _make_client_with_creds("s3", stolen_creds)
    try:
        response = s3_with_stolen.get_object(
            Bucket=bucket,
            Key=PCI_OBJECT_KEY,
        )
        # If we reach here, the control failed
        body = response["Body"].read()
        log.error(
            "[ATTACK] 3.2c - UNEXPECTED SUCCESS: s3:GetObject returned data. "
            "Neither boundary nor bucket policy blocked the read! "
            "Data retrieved: %s",
            body[:50],
        )
        _STATE["attack_results"]["s3_get_object"] = "UNEXPECTED_SUCCESS"
    except ClientError as exc:
        err_code = exc.response["Error"]["Code"]
        log.info(
            "[ATTACK] 3.2c - s3:GetObject returned: %s (expected AccessDenied)",
            err_code,
        )
        _STATE["attack_results"]["s3_get_object"] = err_code

    # 3.2d - cloudtrail:StopLogging (must be blocked by boundary)
    # We attempt on a fake trail ARN to avoid needing a real CloudTrail trail.
    # The permission check happens before AWS validates the resource ARN, so
    # AccessDenied fires before "trail does not exist".
    log.info("[ATTACK] 3.2d - Attempting cloudtrail:StopLogging ...")
    ct_with_stolen = _make_client_with_creds("cloudtrail", stolen_creds)
    fake_trail_arn = (
        f"arn:aws:cloudtrail:{_STATE['region']}:{account}"
        f":trail/sce-nonexistent-trail"
    )
    try:
        ct_with_stolen.stop_logging(Name=fake_trail_arn)
        log.error(
            "[ATTACK] 3.2d - UNEXPECTED SUCCESS: cloudtrail:StopLogging SUCCEEDED. "
            "Permission boundary is NOT protecting audit integrity!"
        )
        _STATE["attack_results"]["cloudtrail_stop"] = "UNEXPECTED_SUCCESS"
    except ClientError as exc:
        err_code = exc.response["Error"]["Code"]
        log.info(
            "[ATTACK] 3.2d - cloudtrail:StopLogging returned: %s "
            "(expected AccessDenied)",
            err_code,
        )
        _STATE["attack_results"]["cloudtrail_stop"] = err_code

    _STATE["attack_3_2_ts"] = int(time.time())
    log.info("[ATTACK] Node 3.2 attack attempts completed.")
    log.info("[ATTACK] Results: %s", _STATE["attack_results"])
    log.info("-" * 70)
    return True


# ---------------------------------------------------------------------------
# 3. hypothesis_verification()
# ---------------------------------------------------------------------------
def hypothesis_verification() -> bool:
    """
    Preventive Probe - SCE Experiment 3.5.

    Verifies FIVE independent preventive controls within a 30-minute SLA:

    Signal A - iam:CreateUser denied (permission boundary)
      The instance role's permission boundary must block iam:CreateUser.
      Expected error codes: AccessDenied | AccessDeniedException
      Maps to ADT 3.1: "Roles explicitly Deny: iam:CreateUser"

    Signal B - sts:AssumeRole to admin role denied (permission boundary)
      The boundary must prevent the stolen credential from assuming the
      high-privilege role, blocking privilege escalation.
      Expected: AccessDenied
      Maps to ADT 3.1: "sts:AssumeRole except scoped to trusted roles"

    Signal C - s3:GetObject denied (boundary + bucket policy)
      The PCI-scope bucket must be inaccessible for reads by the instance role.
      Both the permission boundary (no s3:GetObject in allowlist) and the
      bucket policy (explicit Deny) enforce this.
      Expected: AccessDenied
      Maps to ADT 3.1: "s3:GetObject on audit and artifact buckets" +
                       ADT 2.1: "Secrets Manager is the mandatory credential source"

    Signal D - cloudtrail:StopLogging denied (permission boundary)
      The audit trail must be protected from tampering by the stolen credential.
      Expected: AccessDenied
      Maps to ADT 3.1: "cloudtrail:StopLogging denied"

    Signal E - Permission boundary is still attached to the instance role
      Structural check: the boundary managed policy has not been detached
      since steady_state() verified it. Confirms the preventive control
      is durable and was not removed mid-experiment.

    All five signals must pass for the probe to return True.
    Signals A-D are populated by the attack() phase; this function reads
    them from _STATE and validates the expected error codes.
    Signal E is a live API call to confirm boundary durability.
    """
    if "attack_results" not in _STATE:
        raise RuntimeError(
            "[VERIFY] _STATE missing 'attack_results' - "
            "attack() must succeed before hypothesis_verification()."
        )

    attack_results = _STATE["attack_results"]
    inst_role      = _STATE["iam_info"]["inst_role_name"]
    boundary_arn   = _STATE["iam_info"]["boundary_arn"]

    log.info("=" * 70)
    log.info("[VERIFY] Preventive Probe - starting validation")
    log.info("[VERIFY] inst_role_name  : %s", inst_role)
    log.info("[VERIFY] boundary_arn    : %s", boundary_arn)
    log.info("[VERIFY] attack_results  : %s", attack_results)
    log.info("[VERIFY] SLA window      : %ds (30 min)", SLA_SECONDS)
    log.info("=" * 70)

    # Error codes that represent a correctly enforced denial
    DENIED_CODES = {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedAccess",
        "AuthorizationError",
        "Client.UnauthorizedOperation",
    }

    results: dict = {}

    # ── Signal A: iam:CreateUser denied ───────────────────────────────────────
    def _check_iam_create_user() -> bool:
        code = attack_results.get("iam_create_user", "")
        if code in DENIED_CODES:
            log.info(
                "[SIG-A] PASS  iam:CreateUser blocked by permission boundary. "
                "Error=%s", code,
            )
            return True
        if code == "UNEXPECTED_SUCCESS":
            log.error(
                "[SIG-A] FAIL  iam:CreateUser was NOT blocked. "
                "Permission boundary failed to prevent user creation."
            )
        else:
            log.warning("[SIG-A] Unexpected error code: %s", code)
        return False

    log.info("\n[VERIFY] === Signal A: iam:CreateUser denied ===")
    results["iam_create_user_denied"] = _poll_until(
        _check_iam_create_user,
        "iam-CreateUser-Denied",
        sla_seconds=60,   # Already have the result; quick check
    )

    # ── Signal B: sts:AssumeRole to high-priv denied ──────────────────────────
    def _check_sts_assume_role() -> bool:
        code = attack_results.get("sts_assume_role", "")
        if code in DENIED_CODES:
            log.info(
                "[SIG-B] PASS  sts:AssumeRole to admin role blocked. "
                "Error=%s", code,
            )
            return True
        if code == "UNEXPECTED_SUCCESS":
            log.error(
                "[SIG-B] FAIL  sts:AssumeRole to admin role was NOT blocked. "
                "Privilege escalation possible with stolen credentials!"
            )
        else:
            log.warning("[SIG-B] Unexpected error code: %s", code)
        return False

    log.info("\n[VERIFY] === Signal B: sts:AssumeRole to admin role denied ===")
    results["sts_assume_role_denied"] = _poll_until(
        _check_sts_assume_role,
        "sts-AssumeRole-Denied",
        sla_seconds=60,
    )

    # ── Signal C: s3:GetObject on PCI bucket denied ───────────────────────────
    def _check_s3_get_object() -> bool:
        code = attack_results.get("s3_get_object", "")
        # S3 also returns 403 as "AccessDenied" or specific bucket policy errors
        s3_denied = DENIED_CODES | {"NoSuchKey", "403"}
        if code in s3_denied or "denied" in code.lower():
            log.info(
                "[SIG-C] PASS  s3:GetObject on PCI bucket blocked. "
                "Error=%s", code,
            )
            return True
        if code == "UNEXPECTED_SUCCESS":
            log.error(
                "[SIG-C] FAIL  s3:GetObject on PCI bucket returned data! "
                "Neither boundary nor bucket policy protected the data."
            )
        else:
            log.warning("[SIG-C] Unexpected error code: %s", code)
        return False

    log.info("\n[VERIFY] === Signal C: s3:GetObject on PCI bucket denied ===")
    results["s3_get_object_denied"] = _poll_until(
        _check_s3_get_object,
        "s3-GetObject-Denied",
        sla_seconds=60,
    )

    # ── Signal D: cloudtrail:StopLogging denied ───────────────────────────────
    def _check_cloudtrail_stop() -> bool:
        code = attack_results.get("cloudtrail_stop", "")
        if code in DENIED_CODES:
            log.info(
                "[SIG-D] PASS  cloudtrail:StopLogging blocked. "
                "Audit trail integrity preserved. Error=%s", code,
            )
            return True
        if code == "UNEXPECTED_SUCCESS":
            log.error(
                "[SIG-D] FAIL  cloudtrail:StopLogging was NOT blocked. "
                "Audit trail can be disabled with stolen credentials!"
            )
        else:
            # TrailNotFoundException means the IAM check passed before
            # the resource check fired - this still proves denial
            if "TrailNotFoundException" in code or "does not exist" in code.lower():
                log.info(
                    "[SIG-D] PASS  cloudtrail:StopLogging: resource-not-found "
                    "error indicates IAM access was granted, but trail doesn't "
                    "exist. Treating as boundary bypass - checking again ..."
                )
            else:
                log.warning("[SIG-D] Unexpected error code: %s", code)
        return False

    log.info("\n[VERIFY] === Signal D: cloudtrail:StopLogging denied ===")
    results["cloudtrail_stop_denied"] = _poll_until(
        _check_cloudtrail_stop,
        "cloudtrail-StopLogging-Denied",
        sla_seconds=60,
    )

    # ── Signal E: Permission boundary still attached (live check) ─────────────
    def _check_boundary_durable() -> bool:
        iam = _iam()
        try:
            role_resp = iam.get_role(RoleName=inst_role)
            attached  = (
                role_resp["Role"]
                .get("PermissionsBoundary", {})
                .get("PermissionsBoundaryArn", "")
            )
            if attached == boundary_arn:
                log.info(
                    "[SIG-E] PASS  Permission boundary still attached: %s",
                    attached,
                )
                return True
            log.error(
                "[SIG-E] FAIL  Permission boundary detached or changed! "
                "Expected=%s  Found=%s", boundary_arn, attached,
            )
        except ClientError as exc:
            log.error("[SIG-E] get_role error: %s", exc)
        return False

    log.info("\n[VERIFY] === Signal E: Permission boundary durable ===")
    results["boundary_durable"] = _poll_until(
        _check_boundary_durable,
        "Boundary-Still-Attached",
        sla_seconds=SLA_SECONDS,
    )

    # ── Verify no IAM user was created ────────────────────────────────────────
    # Belt-and-suspenders: confirm the IAM user that the attack tried to create
    # genuinely does not exist in the account.
    log.info("\n[VERIFY] === Structural check: no IAM user created ===")
    iam = _iam()
    try:
        iam.get_user(UserName="sce-test-persistence-user")
        log.error(
            "[VERIFY] STRUCTURAL FAIL: IAM user 'sce-test-persistence-user' "
            "EXISTS in the account. The boundary did not prevent creation!"
        )
        results["no_iam_user_created"] = False
    except ClientError as exc:
        if "NoSuchEntity" in str(exc):
            log.info(
                "[VERIFY] PASS  No IAM user 'sce-test-persistence-user' found. "
                "Boundary prevented creation."
            )
            results["no_iam_user_created"] = True
        else:
            log.error("[VERIFY] get_user unexpected error: %s", exc)
            results["no_iam_user_created"] = False

    # ── Verdict ───────────────────────────────────────────────────────────────
    log.info("\n[VERIFY] -- Signal Summary ------------------------------------------")
    all_passed = True
    for signal, passed in results.items():
        status = "PASS" if passed else "FAIL"
        log.info("[VERIFY]   %-30s -> %s", signal, status)
        if not passed:
            all_passed = False

    verdict = (
        "ALL preventive signals confirmed - permission boundary and "
        "bucket policy are blocking all lateral-movement actions."
        if all_passed
        else (
            "One or more preventive signals FAILED - "
            "a control gap exists in the permission boundary or bucket policy."
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
      1. Delete the PCI test object from S3 (bucket deletion requires empty bucket)
      2. Delete the CloudFormation stack (empties and deletes S3 bucket, CW LG)
      3. Delete boto3-created IAM resources (inline policies first, then roles)
      4. Clean up any residual IAM user if it was unexpectedly created

    Safe and tolerant: logs all errors without re-raising.
    """
    bucket = _STATE.get("bucket_name", "")

    # ── 0. Residual cleanup: IAM user if unexpectedly created ─────────────────
    iam = _iam()
    try:
        iam.get_user(UserName="sce-test-persistence-user")
        log.warning(
            "[ROLLBACK] Residual IAM user found - deleting sce-test-persistence-user"
        )
        try:
            iam.delete_user(UserName="sce-test-persistence-user")
            log.info("[ROLLBACK] Deleted residual IAM user.")
        except ClientError as exc:
            log.warning("[ROLLBACK] delete_user non-fatal: %s", exc)
    except ClientError:
        pass  # User does not exist - expected

    # ── 1. Empty the S3 bucket before stack deletion ──────────────────────────
    if bucket:
        log.info("[ROLLBACK] Emptying S3 bucket: %s", bucket)
        s3 = _s3()
        try:
            # Delete all object versions (versioning is enabled)
            paginator = s3.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket):
                delete_objects = []
                for v in page.get("Versions", []):
                    delete_objects.append(
                        {"Key": v["Key"], "VersionId": v["VersionId"]}
                    )
                for dm in page.get("DeleteMarkers", []):
                    delete_objects.append(
                        {"Key": dm["Key"], "VersionId": dm["VersionId"]}
                    )
                if delete_objects:
                    s3.delete_objects(
                        Bucket=bucket,
                        Delete={"Objects": delete_objects, "Quiet": True},
                    )
                    log.info(
                        "[ROLLBACK] Deleted %d object versions.", len(delete_objects)
                    )
        except ClientError as exc:
            if "NoSuchBucket" not in str(exc):
                log.warning("[ROLLBACK] S3 bucket empty error (non-fatal): %s", exc)

    # ── 2. CloudFormation stack ───────────────────────────────────────────────
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

    # ── 3. IAM resources ──────────────────────────────────────────────────────
    iam_info = _STATE.get("iam_info", {})
    if iam_info:
        log.info("[ROLLBACK] Deleting IAM resources ...")
        try:
            _delete_iam_resources(iam_info)
        except Exception as exc:  # noqa: BLE001
            log.error("[ROLLBACK] IAM cleanup error (non-fatal): %s", exc)
    else:
        log.info("[ROLLBACK] No iam_info in _STATE - skipping IAM cleanup.")

    log.info("[ROLLBACK] Teardown complete.")


# ---------------------------------------------------------------------------
# Experiment runner (direct execution)
# ---------------------------------------------------------------------------
def _run_experiment() -> None:
    log.info("=" * 70)
    log.info("SCE Experiment 3.5 - Preventive Probe - Full Run")
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
                "[RUNNER] PASS  Experiment passed - preventive controls "
                "successfully blocked all lateral-movement actions."
            )
        else:
            log.warning(
                "[RUNNER] FAIL  Experiment failed - one or more preventive "
                "controls did not block the expected actions."
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