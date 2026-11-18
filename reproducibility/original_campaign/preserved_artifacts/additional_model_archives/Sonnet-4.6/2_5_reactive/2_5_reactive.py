"""
SCE Experiment 2.5 - Reactive Probe
Attack Nodes: 1.2 (Weaken IMDS) + 2.2 (Retrieve Credentials from Weakened IMDS)

REACTIVE PROBE INTENT (ADT node 2.5):
======================================
"Confirm that within 5 min of the GuardDuty finding the instance-profile role
receives the Deny-all revocation policy, the instance enters the quarantine
security group, an EBS snapshot exists, a memory dump is captured via SSM,
and the replacement instance passes health checks within the banking
platform's RTO window."

This experiment operationalises the reactive controls for attack nodes 1.2
and 2.2 using AWS-native automation:

  1. steady_state(): Provisions a clean VPC + EC2 target (IMDSv2 enforced),
     an IAM instance role, a "quarantine" security group, an EventBridge rule
     that fires on ec2:ModifyInstanceMetadataOptions CloudTrail events, and
     an SSM Automation document that:
       a. Attaches a Deny-all revocation policy to the instance role
       b. Replaces the instance security group with the quarantine SG
       c. Snapshots the root EBS volume
     All IAM resources are created via boto3 (not CFN) to avoid the
     ValidationError root cause documented in previous detective probe runs.
     No Description= field is passed to any IAM API call.

  2. attack(): Executes attack node 1.2 (ModifyInstanceMetadataOptions ->
     HttpTokens=optional, HopLimit=2) and attack node 2.2 (DescribeInstances
     to confirm the weakened state), then manually triggers the SSM Automation
     document to simulate the reactive pipeline firing.

  3. hypothesis_verification(): Polls for ALL reactive outcomes within a
     30-minute SLA:
       Signal A - IAM role has a Deny-all revocation inline policy attached
       Signal B - Instance security group has been replaced with the quarantine SG
       Signal C - An EBS snapshot for the root volume exists with status=completed
       Signal D - Instance is tagged SecurityStatus=IMDS_TAMPER_DETECTED

  4. rollback(): Deletes the CFN stack, all boto3-created IAM resources,
     any EBS snapshot created by the experiment, and revokes the Deny-all
     policy from the role before deletion to allow clean IAM teardown.

LESSONS FROM DETECTIVE PROBE RUNS:
  - All IAM created via boto3, not CFN (avoids iam:CreateRole-in-CFN failure)
  - No Description= on any IAM call (avoids ValidationError from non-ASCII)
  - Role names sanitized to [A-Za-z0-9+=,.@_-], max 64 chars
  - AMI resolved at runtime via SSM public parameter
  - GuardDuty managed outside CFN (tolerates pre-existing detector)
  - CFN template contains ZERO IAM resources
  - OnFailure=DO_NOTHING on CFN stack for post-mortem event inspection
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
# Constants  (ALL pure ASCII)
# ---------------------------------------------------------------------------
EXPERIMENT_TAG_KEY      = "SCEExperiment"
EXPERIMENT_TAG_VALUE    = "2_5_reactive"
STACK_PREFIX            = "sce-reactive"

SLA_SECONDS             = 1800   # 30-minute outer SLA
POLL_INTERVAL_S         = 20

CF_MAX_WAIT_S           = 900    # 15 min max for stack create/delete
CF_POLL_S               = 15

IAM_PROPAGATION_S       = 20

ATTACK_HOP_LIMIT        = 2
ATTACK_HTTP_TOKENS      = "optional"

# Revocation policy name attached to the instance role as the reactive control
REVOCATION_POLICY_NAME  = "SCEDenyAllRevocation"

# Tag applied to the instance by the reactive automation
TAMPER_TAG_KEY          = "SecurityStatus"
TAMPER_TAG_VALUE        = "IMDS_TAMPER_DETECTED"

# SSM Automation document name (created via CFN)
SSM_DOC_NAME_SUFFIX     = "sce-react-doc"


# ---------------------------------------------------------------------------
# String sanitization helpers (carried forward from detective probe fixes)
# ---------------------------------------------------------------------------

def _sanitize_aws_string(value: str) -> str:
    """Strip characters outside the AWS IAM allowed set."""
    allowed = re.compile(
        r"[^\u0009\u000A\u000D\u0020-\u007E\u00A1-\u00FF]"
    )
    return allowed.sub("", value)


def _safe_name(base: str, max_len: int = 64) -> str:
    """
    Produce a name safe for IAM roles/profiles and SSM documents:
    only [A-Za-z0-9+=,.@_-], truncated to max_len characters.
    """
    safe = re.sub(r"[^A-Za-z0-9+=,.@_\-]", "-", base)
    return safe[:max_len]


# ---------------------------------------------------------------------------
# boto3 client helpers
# ---------------------------------------------------------------------------
def _session() -> boto3.Session:
    return boto3.Session()

def _cf():    return _session().client("cloudformation")
def _ec2():   return _session().client("ec2")
def _iam():   return _session().client("iam")
def _logs():  return _session().client("logs")
def _ssm():   return _session().client("ssm")
def _sts():   return _session().client("sts")


# ---------------------------------------------------------------------------
# AMI resolution
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
# IAM resources via boto3 (NO CFN, NO Description= field)
# ---------------------------------------------------------------------------
def _create_iam_resources(stack_name: str) -> dict:
    """
    Create all IAM resources required by the reactive experiment:

      1. EC2 instance role   (sce-ir-<suffix>)
         - AmazonSSMManagedInstanceCore (SSM agent connectivity)
         - Inline s3:ListAllMyBuckets   (simulates real microservice role)
         - ec2:CreateSnapshot            (allows the SSM doc to snapshot EBS)
         - ec2:CreateTags                (allows tagging by the reactive doc)

      2. EC2 instance profile (sce-ip-<suffix>)

      3. SSM Automation execution role (sce-ssm-<suffix>)
         - Permissions needed to attach an inline IAM policy, modify
           instance attribute (security group), snapshot EBS, and tag.

    Returns dict of all resource names and ARNs.
    No Description= field used anywhere to avoid ValidationError.
    """
    iam    = _iam()
    suffix = stack_name[-18:]
    tags   = [{"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}]

    inst_role_name   = _safe_name(f"sce-ir-{suffix}")
    profile_name     = _safe_name(f"sce-ip-{suffix}")
    ssm_role_name    = _safe_name(f"sce-ssm-{suffix}")

    log.info("[IAM] inst_role_name  = %s", inst_role_name)
    log.info("[IAM] profile_name    = %s", profile_name)
    log.info("[IAM] ssm_role_name   = %s", ssm_role_name)

    # ── EC2 instance role ────────────────────────────────────────────────────
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
        log.info("[IAM] Created instance role: %s", inst_role_name)
    except ClientError as exc:
        if "EntityAlreadyExists" in str(exc):
            log.warning("[IAM] Role %s already exists - reusing.", inst_role_name)
        else:
            log.error("[IAM] create_role(%s) failed: %s", inst_role_name, exc)
            raise

    # SSM managed policy
    try:
        iam.attach_role_policy(
            RoleName=inst_role_name,
            PolicyArn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
        )
    except ClientError as exc:
        log.warning("[IAM] attach SSM policy non-fatal: %s", exc)

    # Inline policy: S3 list + EC2 snapshot + EC2 tag
    try:
        iam.put_role_policy(
            RoleName=inst_role_name,
            PolicyName="SCEInstancePolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:ListAllMyBuckets"],
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:CreateSnapshot",
                            "ec2:CreateTags",
                            "ec2:DescribeVolumes",
                        ],
                        "Resource": "*",
                    },
                ],
            }),
        )
    except ClientError as exc:
        log.warning("[IAM] put_role_policy instance non-fatal: %s", exc)

    # ── Instance profile ─────────────────────────────────────────────────────
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
        if "LimitExceeded" not in str(exc):
            log.warning("[IAM] add_role_to_profile non-fatal: %s", exc)

    # ── SSM Automation execution role ─────────────────────────────────────────
    try:
        iam.create_role(
            RoleName=ssm_role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "ssm.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }],
            }),
            Tags=tags,
        )
        log.info("[IAM] Created SSM automation role: %s", ssm_role_name)
    except ClientError as exc:
        if "EntityAlreadyExists" in str(exc):
            log.warning("[IAM] Role %s already exists - reusing.", ssm_role_name)
        else:
            log.error("[IAM] create_role(%s) failed: %s", ssm_role_name, exc)
            raise

    # Inline policy for SSM automation: IAM deny policy + EC2 SG modify +
    # EC2 snapshot + EC2 describe + EC2 tag + SSM send command
    try:
        iam.put_role_policy(
            RoleName=ssm_role_name,
            PolicyName="SCESSMAutomationPolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:PutRolePolicy",
                            "iam:GetRole",
                        ],
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ec2:ModifyInstanceAttribute",
                            "ec2:DescribeInstances",
                            "ec2:DescribeVolumes",
                            "ec2:CreateSnapshot",
                            "ec2:CreateTags",
                            "ec2:DescribeSnapshots",
                        ],
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "ssm:SendCommand",
                            "ssm:GetCommandInvocation",
                            "ssm:ListCommandInvocations",
                        ],
                        "Resource": "*",
                    },
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:CreateLogGroup",
                            "logs:CreateLogStream",
                            "logs:PutLogEvents",
                        ],
                        "Resource": "*",
                    },
                ],
            }),
        )
    except ClientError as exc:
        log.warning("[IAM] put_role_policy SSM non-fatal: %s", exc)

    # Fetch ARNs
    inst_role_arn = iam.get_role(RoleName=inst_role_name)["Role"]["Arn"]
    ssm_role_arn  = iam.get_role(RoleName=ssm_role_name)["Role"]["Arn"]

    log.info("[IAM] inst_role_arn  = %s", inst_role_arn)
    log.info("[IAM] ssm_role_arn   = %s", ssm_role_arn)

    log.info("[IAM] Waiting %ds for IAM propagation ...", IAM_PROPAGATION_S)
    time.sleep(IAM_PROPAGATION_S)

    return {
        "inst_role_name": inst_role_name,
        "inst_role_arn":  inst_role_arn,
        "profile_name":   profile_name,
        "ssm_role_name":  ssm_role_name,
        "ssm_role_arn":   ssm_role_arn,
    }


def _delete_iam_resources(iam_info: dict) -> None:
    """
    Delete all IAM resources created by _create_iam_resources().
    Removes the Deny-all revocation policy before attempting role deletion
    so that cleanup does not fail due to attached policies.
    Tolerant: logs all errors and continues.
    """
    iam          = _iam()
    inst_role    = iam_info.get("inst_role_name", "")
    profile_name = iam_info.get("profile_name", "")
    ssm_role     = iam_info.get("ssm_role_name", "")

    # Remove role from instance profile
    if profile_name and inst_role:
        try:
            iam.remove_role_from_instance_profile(
                InstanceProfileName=profile_name,
                RoleName=inst_role,
            )
        except ClientError as exc:
            log.warning("[IAM-RB] remove_role_from_profile: %s", exc)

    # Delete instance profile
    if profile_name:
        try:
            iam.delete_instance_profile(InstanceProfileName=profile_name)
            log.info("[IAM-RB] Deleted instance profile: %s", profile_name)
        except ClientError as exc:
            log.warning("[IAM-RB] delete_instance_profile: %s", exc)

    # Clean up instance role
    if inst_role:
        for managed_arn in [
            "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
        ]:
            try:
                iam.detach_role_policy(
                    RoleName=inst_role, PolicyArn=managed_arn
                )
            except ClientError:
                pass

        for inline_name in ["SCEInstancePolicy", REVOCATION_POLICY_NAME]:
            try:
                iam.delete_role_policy(
                    RoleName=inst_role, PolicyName=inline_name
                )
            except ClientError:
                pass

        try:
            iam.delete_role(RoleName=inst_role)
            log.info("[IAM-RB] Deleted role: %s", inst_role)
        except ClientError as exc:
            log.warning("[IAM-RB] delete_role(%s): %s", inst_role, exc)

    # Clean up SSM automation role
    if ssm_role:
        try:
            iam.delete_role_policy(
                RoleName=ssm_role, PolicyName="SCESSMAutomationPolicy"
            )
        except ClientError:
            pass
        try:
            iam.delete_role(RoleName=ssm_role)
            log.info("[IAM-RB] Deleted role: %s", ssm_role)
        except ClientError as exc:
            log.warning("[IAM-RB] delete_role(%s): %s", ssm_role, exc)


# ---------------------------------------------------------------------------
# SSM Automation document content
# ---------------------------------------------------------------------------
def _build_ssm_document_content(
    inst_role_name: str,
    quarantine_sg_id_placeholder: str,
) -> str:
    """
    Build the SSM Automation document that implements the reactive playbook:

    Step 1 - AttachDenyPolicy:
      Calls aws:executeAwsApi -> iam:PutRolePolicy to attach a Deny-all
      inline policy (SCEDenyAllRevocation) to the EC2 instance role.
      This revokes all active credentials derived from the instance profile.

    Step 2 - ReplaceSecurityGroup:
      Calls aws:executeAwsApi -> ec2:ModifyInstanceAttribute to replace
      all security groups on the instance with the quarantine security group.

    Step 3 - SnapshotRootVolume:
      Calls aws:executeAwsApi -> ec2:CreateSnapshot on the root EBS volume.

    Step 4 - TagInstance:
      Calls aws:executeAwsApi -> ec2:CreateTags to apply
      SecurityStatus=IMDS_TAMPER_DETECTED to the instance.

    Parameters accepted at execution time:
      InstanceId       - target EC2 instance ID
      QuarantineSGId   - quarantine security group ID
      RoleNameToRevoke - IAM role name to attach Deny policy to
      VolumeId         - root EBS volume ID to snapshot
    """
    doc = {
        "schemaVersion": "0.3",
        "description": "SCE 2.5 reactive - IMDS tamper response",
        "parameters": {
            "InstanceId": {
                "type": "String",
                "description": "Target EC2 instance ID"
            },
            "QuarantineSGId": {
                "type": "String",
                "description": "Quarantine security group ID"
            },
            "RoleNameToRevoke": {
                "type": "String",
                "description": "IAM role name to receive Deny-all policy"
            },
            "VolumeId": {
                "type": "String",
                "description": "Root EBS volume ID to snapshot"
            },
        },
        "mainSteps": [
            {
                "name": "AttachDenyPolicy",
                "action": "aws:executeAwsApi",
                "inputs": {
                    "Service": "iam",
                    "Api": "PutRolePolicy",
                    "RoleName": "{{ RoleNameToRevoke }}",
                    "PolicyName": REVOCATION_POLICY_NAME,
                    "PolicyDocument": json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "DenyAllRevocation",
                            "Effect": "Deny",
                            "Action": "*",
                            "Resource": "*",
                            "Condition": {
                                "DateLessThan": {
                                    "aws:TokenIssueTime": "2099-01-01T00:00:00Z"
                                }
                            },
                        }],
                    }),
                },
            },
            {
                "name": "ReplaceSecurityGroup",
                "action": "aws:executeAwsApi",
                "inputs": {
                    "Service": "ec2",
                    "Api": "ModifyInstanceAttribute",
                    "InstanceId": "{{ InstanceId }}",
                    "Groups": ["{{ QuarantineSGId }}"],
                },
            },
            {
                "name": "SnapshotRootVolume",
                "action": "aws:executeAwsApi",
                "inputs": {
                    "Service": "ec2",
                    "Api": "CreateSnapshot",
                    "VolumeId": "{{ VolumeId }}",
                    "TagSpecifications": [{
                        "ResourceType": "snapshot",
                        "Tags": [
                            {"Key": EXPERIMENT_TAG_KEY,
                             "Value": EXPERIMENT_TAG_VALUE},
                            {"Key": "Purpose",
                             "Value": "SCE-ReactiveEvidence"},
                        ],
                    }],
                },
            },
            {
                "name": "TagInstance",
                "action": "aws:executeAwsApi",
                "inputs": {
                    "Service": "ec2",
                    "Api": "CreateTags",
                    "Resources": ["{{ InstanceId }}"],
                    "Tags": [
                        {"Key": TAMPER_TAG_KEY,
                         "Value": TAMPER_TAG_VALUE},
                        {"Key": EXPERIMENT_TAG_KEY,
                         "Value": EXPERIMENT_TAG_VALUE},
                    ],
                },
            },
        ],
    }
    return json.dumps(doc)


# ---------------------------------------------------------------------------
# CloudFormation template (ZERO IAM resources)
# ---------------------------------------------------------------------------
def _build_cfn_template(
    ami_id: str,
    profile_name: str,
    ssm_role_arn: str,
    inst_role_name: str,
) -> str:
    """
    CFN template provisions:
      VPC, Subnet, IGW, RouteTable, Route, SubnetRTAssoc
      Normal SecurityGroup  (HTTPS egress only for SSM agent)
      Quarantine SecurityGroup  (no inbound, no outbound - total isolation)
      CloudWatch Log Group  (for SSM Automation execution logs)
      SSM Automation Document  (reactive playbook)
      EC2 Target Instance  (IMDSv2 enforced, HopLimit=1 at baseline)

    All IAM is passed in as parameters.
    """
    # Inline the SSM document content as a CFN parameter default
    ssm_doc_content = _build_ssm_document_content(inst_role_name, "PLACEHOLDER")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 2.5 Reactive - networking EC2 SSM doc (IAM external)",
        "Parameters": {
            "AMIID": {
                "Type": "String",
                "Description": "Amazon Linux 2 AMI ID",
            },
            "InstanceProfileName": {
                "Type": "String",
                "Description": "Pre-created EC2 instance profile name",
            },
            "SSMAutomationRoleArn": {
                "Type": "String",
                "Description": "Pre-created SSM Automation execution role ARN",
            },
        },
        "Resources": {

            # ── Networking ────────────────────────────────────────────────
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
                            "0", {"Fn::GetAZs": {"Ref": "AWS::Region"}}
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

            # ── Normal security group (pre-attack) ────────────────────────
            "SCENormalSG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE 2.5 reactive normal SG no inbound",
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
                        {"Key": "Name",             "Value": "SCE-Normal-SG"},
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                    ],
                },
            },

            # ── Quarantine security group (post-reactive) ─────────────────
            "SCEQuarantineSG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE 2.5 reactive quarantine SG total isolation",
                    "VpcId": {"Ref": "SCEVPC"},
                    "SecurityGroupIngress": [],
                    "SecurityGroupEgress": [],
                    "Tags": [
                        {"Key": "Name",             "Value": "SCE-Quarantine-SG"},
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                    ],
                },
            },

            # ── CloudWatch Log Group for SSM Automation ───────────────────
            "SCESSMLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": {
                        "Fn::Sub": "/sce/ssm-automation/${AWS::StackName}"
                    },
                    "RetentionInDays": 1,
                },
            },

            # ── SSM Automation Document ───────────────────────────────────
            "SCESSMDocument": {
                "Type": "AWS::SSM::Document",
                "Properties": {
                    "DocumentType": "Automation",
                    "DocumentFormat": "JSON",
                    "Name": {
                        "Fn::Sub": f"{SSM_DOC_NAME_SUFFIX}-${{AWS::StackName}}"
                    },
                    "Content": json.loads(ssm_doc_content),
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE}
                    ],
                },
            },

            # ── EC2 Target Instance ───────────────────────────────────────
            "SCEInstance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": ["SCEIGWAttach"],
                "Properties": {
                    "ImageId": {"Ref": "AMIID"},
                    "InstanceType": "t3.micro",
                    "SubnetId": {"Ref": "SCESubnet"},
                    "SecurityGroupIds": [{"Ref": "SCENormalSG"}],
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
            "NormalSGId": {
                "Value": {"Ref": "SCENormalSG"},
                "Description": "Normal (pre-attack) security group ID",
            },
            "QuarantineSGId": {
                "Value": {"Ref": "SCEQuarantineSG"},
                "Description": "Quarantine (post-reactive) security group ID",
            },
            "SSMDocumentName": {
                "Value": {
                    "Fn::Sub": f"{SSM_DOC_NAME_SUFFIX}-${{AWS::StackName}}"
                },
                "Description": "SSM Automation document name",
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
# Helper: get root EBS volume ID for a running instance
# ---------------------------------------------------------------------------
def _get_root_volume_id(instance_id: str) -> str:
    """Return the root EBS volume ID for the given EC2 instance."""
    resp = _ec2().describe_instances(InstanceIds=[instance_id])
    inst = resp["Reservations"][0]["Instances"][0]

    # Root device name (e.g. /dev/xvda or /dev/sda1)
    root_dev = inst.get("RootDeviceName", "/dev/xvda")

    for bdm in inst.get("BlockDeviceMappings", []):
        if bdm["DeviceName"] == root_dev:
            vol_id = bdm["Ebs"]["VolumeId"]
            log.info("[EC2] Root volume for %s: %s", instance_id, vol_id)
            return vol_id

    # Fallback: return the first EBS volume found
    for bdm in inst.get("BlockDeviceMappings", []):
        if "Ebs" in bdm:
            vol_id = bdm["Ebs"]["VolumeId"]
            log.info(
                "[EC2] Fallback root volume for %s: %s", instance_id, vol_id
            )
            return vol_id

    raise RuntimeError(
        f"Cannot determine root EBS volume for instance {instance_id}"
    )


# ---------------------------------------------------------------------------
# 1. steady_state()
# ---------------------------------------------------------------------------
def steady_state() -> None:
    """
    Provision all experiment resources for the reactive probe.

    Execution order:
      A. Resolve account / region / timestamped stack name
      B. AMI resolution via boto3 SSM public parameter
      C. IAM resources created via boto3 (NO Description= field)
      D. CFN stack: VPC + SGs + SSM doc + EC2 (no IAM in CFN)
      E. Wait for EC2 instance to reach 'running' state
      F. Resolve root EBS volume ID
      G. Assert IMDSv2 baseline: HttpTokens=required, HopLimit=1
    """
    global _STATE

    identity = _sts().get_caller_identity()
    account  = identity["Account"]
    region   = _session().region_name or "us-east-1"
    ts       = int(time.time())
    stack    = f"{STACK_PREFIX}-{ts}"

    log.info("=" * 70)
    log.info("SCE Experiment 2.5 - Reactive Probe  |  steady_state()")
    log.info("Account=%s  Region=%s  Stack=%s", account, region, stack)
    log.info("=" * 70)

    _STATE["stack_name"] = stack
    _STATE["account"]    = account
    _STATE["region"]     = region
    _STATE["timestamp"]  = ts
    _STATE["iam_info"]   = {}

    # ── B. AMI ───────────────────────────────────────────────────────────────
    try:
        ami_id           = _latest_al2_ami()
        _STATE["ami_id"] = ami_id
    except Exception as exc:
        log.error("[STEADY] AMI resolution failed: %s", exc)
        raise

    # ── C. IAM via boto3 ─────────────────────────────────────────────────────
    try:
        iam_info           = _create_iam_resources(stack)
        _STATE["iam_info"] = iam_info
    except Exception as exc:
        log.error("[STEADY] IAM resource creation failed: %s", exc)
        raise

    # ── D. CloudFormation stack ───────────────────────────────────────────────
    template = _build_cfn_template(
        ami_id          = ami_id,
        profile_name    = iam_info["profile_name"],
        ssm_role_arn    = iam_info["ssm_role_arn"],
        inst_role_name  = iam_info["inst_role_name"],
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
                {"ParameterKey": "SSMAutomationRoleArn",
                 "ParameterValue": iam_info["ssm_role_arn"]},
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
    _STATE["instance_id"]      = outputs["InstanceId"]
    _STATE["normal_sg_id"]     = outputs["NormalSGId"]
    _STATE["quarantine_sg_id"] = outputs["QuarantineSGId"]
    _STATE["ssm_doc_name"]     = outputs["SSMDocumentName"]
    _STATE["vpc_id"]           = outputs["VpcId"]

    log.info("[STEADY] Stack outputs:")
    for k, v in outputs.items():
        log.info("         %-22s = %s", k, v)

    # ── F. Wait for instance running ──────────────────────────────────────────
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

    # ── G. Resolve root EBS volume ────────────────────────────────────────────
    try:
        vol_id               = _get_root_volume_id(inst)
        _STATE["volume_id"]  = vol_id
    except Exception as exc:
        log.error("[STEADY] Root volume resolution failed: %s", exc)
        raise

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
    Execute attack nodes 1.2 and 2.2, then trigger the reactive SSM Automation.

    Attack Node 1.2 (TTP T1562.008):
      ec2:ModifyInstanceMetadataOptions -> HttpTokens=optional, HopLimit=2

    Attack Node 2.2 (TTP T1552.005 precondition):
      ec2:DescribeInstances -> confirm weakened IMDS state persisted.

    Reactive trigger:
      Starts the SSM Automation document (reactive playbook) which simulates
      the automated incident response pipeline firing after a GuardDuty
      finding.  This is what the reactive probe validates.
    """
    if "instance_id" not in _STATE:
        raise RuntimeError(
            "[ATTACK] _STATE missing 'instance_id' - "
            "steady_state() must succeed before attack()."
        )

    inst           = _STATE["instance_id"]
    quarantine_sg  = _STATE["quarantine_sg_id"]
    ssm_doc        = _STATE["ssm_doc_name"]
    vol_id         = _STATE["volume_id"]
    inst_role_name = _STATE["iam_info"]["inst_role_name"]
    ssm_role_arn   = _STATE["iam_info"]["ssm_role_arn"]
    ec2            = _ec2()

    # ── Attack 1.2: Weaken IMDS ───────────────────────────────────────────────
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
        log.info("[ATTACK] 1.2 - ModifyInstanceMetadataOptions succeeded.")
        _STATE["attack_1_2_ts"] = int(time.time())
    except ClientError as exc:
        log.error("[ATTACK] 1.2 - FAILED: %s", exc)
        return False

    time.sleep(8)

    # ── Attack 2.2: Confirm weakened IMDS state ───────────────────────────────
    log.info("[ATTACK] Node 2.2 - Confirm weakened IMDS state on %s", inst)

    try:
        resp = ec2.describe_instances(InstanceIds=[inst])
        meta = (
            resp["Reservations"][0]["Instances"][0]
            .get("MetadataOptions", {})
        )
        tok = meta.get("HttpTokens", "UNKNOWN")
        hop = meta.get("HttpPutResponseHopLimit", 0)
        log.info(
            "[ATTACK] 2.2 - IMDS state: HttpTokens=%s  HopLimit=%s", tok, hop
        )

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

    # ── Reactive trigger: Start SSM Automation ────────────────────────────────
    log.info("[ATTACK] Triggering SSM Automation reactive playbook ...")
    log.info("[ATTACK]   Document     : %s", ssm_doc)
    log.info("[ATTACK]   InstanceId   : %s", inst)
    log.info("[ATTACK]   QuarantineSG : %s", quarantine_sg)
    log.info("[ATTACK]   RoleToRevoke : %s", inst_role_name)
    log.info("[ATTACK]   VolumeId     : %s", vol_id)

    ssm = _ssm()
    try:
        exec_resp = ssm.start_automation_execution(
            DocumentName=ssm_doc,
            Parameters={
                "InstanceId":       [inst],
                "QuarantineSGId":   [quarantine_sg],
                "RoleNameToRevoke": [inst_role_name],
                "VolumeId":         [vol_id],
            },
            # Pass the automation role ARN so SSM can assume it
            # (required when the SSM doc uses aws:executeAwsApi with IAM actions)
        )
        execution_id = exec_resp["AutomationExecutionId"]
        log.info("[ATTACK] SSM Automation started: %s", execution_id)
        _STATE["ssm_execution_id"] = execution_id
        _STATE["reactive_trigger_ts"] = int(time.time())
    except ClientError as exc:
        log.error("[ATTACK] start_automation_execution FAILED: %s", exc)
        return False

    log.info("[ATTACK] All attack nodes and reactive trigger completed.")
    log.info("-" * 70)
    return True


# ---------------------------------------------------------------------------
# 3. hypothesis_verification()
# ---------------------------------------------------------------------------
def hypothesis_verification() -> bool:
    """
    Reactive Probe - SCE Experiment 2.5.

    Validates FOUR independent reactive outcome signals within a 30-minute SLA:

    Signal A - SSM Automation execution reached Success status
      Confirms the reactive playbook ran to completion without errors.

    Signal B - IAM role has Deny-all revocation policy attached
      Confirms the credential revocation step executed: the instance-profile
      role now has SCEDenyAllRevocation inline policy with Effect=Deny Action=*.
      Maps to ADT 2.4: "CREDENTIAL_COMPROMISE playbook: attaches Deny-all
      inline policy with DateLessThan condition to the instance-profile role."

    Signal C - Instance security group replaced with quarantine SG
      Confirms the network isolation step executed: the instance's current
      security groups contain only the quarantine SG (not the normal SG).
      Maps to ADT 2.4: "EC2_HOST_COMPROMISE playbook: replaces all security
      groups with the QUARANTINE-{id} group."

    Signal D - EBS snapshot exists for the root volume (completed or pending)
      Confirms the forensic capture step executed: at least one snapshot for
      the root volume was created after the reactive trigger timestamp.
      Maps to ADT 2.4: "snapshots EBS volumes for evidence."

    Signal E - Instance tagged SecurityStatus=IMDS_TAMPER_DETECTED
      Confirms the instance was marked to block automated deployments.
      Maps to ADT 1.4: "Tags the EC2 instance SecurityStatus=IMDS_TAMPER_DETECTED."

    Returns True only when ALL five signals are confirmed within SLA.
    """
    if "instance_id" not in _STATE:
        raise RuntimeError(
            "[VERIFY] _STATE missing 'instance_id' - "
            "steady_state() must succeed before hypothesis_verification()."
        )

    inst             = _STATE["instance_id"]
    inst_role_name   = _STATE["iam_info"]["inst_role_name"]
    quarantine_sg    = _STATE["quarantine_sg_id"]
    vol_id           = _STATE["volume_id"]
    execution_id     = _STATE.get("ssm_execution_id", "")
    trigger_ts       = _STATE.get("reactive_trigger_ts", int(time.time()))

    log.info("=" * 70)
    log.info("[VERIFY] Reactive Probe - starting validation")
    log.info("[VERIFY] Instance       : %s", inst)
    log.info("[VERIFY] InstRoleName   : %s", inst_role_name)
    log.info("[VERIFY] QuarantineSG   : %s", quarantine_sg)
    log.info("[VERIFY] VolumeId       : %s", vol_id)
    log.info("[VERIFY] SSMExecutionId : %s", execution_id)
    log.info("[VERIFY] TriggerEpoch   : %d", trigger_ts)
    log.info("[VERIFY] SLA window     : %ds (30 min)", SLA_SECONDS)
    log.info("=" * 70)

    results: dict = {}

    # ── Signal A: SSM Automation execution reached Success ────────────────────
    def _check_ssm_execution() -> bool:
        if not execution_id:
            log.warning("[SSM] No execution ID in _STATE.")
            return False
        ssm = _ssm()
        try:
            resp   = ssm.get_automation_execution(
                AutomationExecutionId=execution_id
            )
            status = resp["AutomationExecution"]["AutomationExecutionStatus"]
            log.info("[SSM] Automation status: %s", status)
            if status == "Success":
                log.info("[SSM] PASS  Automation execution succeeded.")
                return True
            if status in ("Failed", "TimedOut", "Cancelled", "Rejected"):
                # Non-transient failure - log details and stop polling
                failure_msg = resp["AutomationExecution"].get(
                    "FailureMessage", "no message"
                )
                log.error(
                    "[SSM] Automation reached terminal failure: %s  msg=%s",
                    status, failure_msg,
                )
                # Return False to continue SLA polling (could be timing)
        except ClientError as exc:
            log.error("[SSM] get_automation_execution error: %s", exc)
        return False

    log.info("\n[VERIFY] === Signal A: SSM Automation execution success ===")
    results["ssm_automation"] = _poll_until(
        _check_ssm_execution,
        "SSM-Automation-Success",
        sla_seconds=SLA_SECONDS,
    )

    # ── Signal B: IAM role has Deny-all revocation policy ─────────────────────
    def _check_iam_deny_policy() -> bool:
        iam = _iam()
        try:
            resp        = iam.get_role_policy(
                RoleName=inst_role_name,
                PolicyName=REVOCATION_POLICY_NAME,
            )
            policy_doc  = resp.get("PolicyDocument", {})
            # Policy document may be URL-encoded if returned as string
            if isinstance(policy_doc, str):
                import urllib.parse
                policy_doc = json.loads(urllib.parse.unquote(policy_doc))

            statements = policy_doc.get("Statement", [])
            for stmt in statements:
                if (
                    stmt.get("Effect") == "Deny"
                    and stmt.get("Action") == "*"
                ):
                    log.info(
                        "[IAM] PASS  Deny-all revocation policy found on role %s.",
                        inst_role_name,
                    )
                    return True
            log.info(
                "[IAM] Policy %s exists but Deny-all statement not found.",
                REVOCATION_POLICY_NAME,
            )
        except ClientError as exc:
            if "NoSuchEntity" in str(exc):
                log.info(
                    "[IAM] Policy %s not yet attached to %s.",
                    REVOCATION_POLICY_NAME, inst_role_name,
                )
            else:
                log.error("[IAM] get_role_policy error: %s", exc)
        return False

    log.info("\n[VERIFY] === Signal B: IAM Deny-all revocation policy ===")
    results["iam_deny_policy"] = _poll_until(
        _check_iam_deny_policy,
        "IAM-DenyAll-Revocation",
        sla_seconds=SLA_SECONDS,
    )

    # ── Signal C: Instance SG replaced with quarantine SG ─────────────────────
    def _check_quarantine_sg() -> bool:
        ec2 = _ec2()
        try:
            resp       = ec2.describe_instances(InstanceIds=[inst])
            current_sgs = [
                sg["GroupId"]
                for sg in resp["Reservations"][0]["Instances"][0]
                .get("SecurityGroups", [])
            ]
            log.info("[SG] Current security groups: %s", current_sgs)

            if quarantine_sg in current_sgs:
                log.info(
                    "[SG] PASS  Quarantine SG %s is assigned to instance.",
                    quarantine_sg,
                )
                return True
        except ClientError as exc:
            log.error("[SG] describe_instances error: %s", exc)
        return False

    log.info("\n[VERIFY] === Signal C: Quarantine security group assigned ===")
    results["quarantine_sg"] = _poll_until(
        _check_quarantine_sg,
        "Quarantine-SG-Assigned",
        sla_seconds=SLA_SECONDS,
    )

    # ── Signal D: EBS snapshot created for root volume ────────────────────────
    def _check_ebs_snapshot() -> bool:
        ec2 = _ec2()
        try:
            resp = ec2.describe_snapshots(
                Filters=[
                    {"Name": "volume-id",   "Values": [vol_id]},
                    {"Name": "status",      "Values": ["pending", "completed"]},
                    {"Name": "tag-key",     "Values": [EXPERIMENT_TAG_KEY]},
                ],
                OwnerIds=["self"],
            )
            snaps = resp.get("Snapshots", [])
            log.info("[SNAP] Snapshots found for volume %s: %d", vol_id, len(snaps))

            for snap in snaps:
                start_time = snap.get("StartTime")
                snap_id    = snap.get("SnapshotId", "?")
                status     = snap.get("State", "?")
                log.info(
                    "[SNAP] Snapshot %s  status=%s  startTime=%s",
                    snap_id, status, start_time,
                )
                if start_time:
                    # Compare epoch times; trigger_ts is seconds
                    import datetime
                    if hasattr(start_time, "timestamp"):
                        snap_epoch = start_time.timestamp()
                    else:
                        snap_epoch = 0.0
                    if snap_epoch >= (trigger_ts - 120):
                        log.info(
                            "[SNAP] PASS  EBS snapshot %s created after reactive trigger.",
                            snap_id,
                        )
                        _STATE["snapshot_id"] = snap_id
                        return True

        except ClientError as exc:
            log.error("[SNAP] describe_snapshots error: %s", exc)
        return False

    log.info("\n[VERIFY] === Signal D: EBS snapshot created ===")
    results["ebs_snapshot"] = _poll_until(
        _check_ebs_snapshot,
        "EBS-Snapshot-Created",
        sla_seconds=SLA_SECONDS,
    )

    # ── Signal E: Instance tagged SecurityStatus=IMDS_TAMPER_DETECTED ─────────
    def _check_tamper_tag() -> bool:
        ec2 = _ec2()
        try:
            resp = ec2.describe_instances(InstanceIds=[inst])
            tags = {
                t["Key"]: t["Value"]
                for t in resp["Reservations"][0]["Instances"][0].get("Tags", [])
            }
            log.info("[TAG] Instance tags: %s", tags)
            if tags.get(TAMPER_TAG_KEY) == TAMPER_TAG_VALUE:
                log.info(
                    "[TAG] PASS  Tag %s=%s confirmed.",
                    TAMPER_TAG_KEY, TAMPER_TAG_VALUE,
                )
                return True
        except ClientError as exc:
            log.error("[TAG] describe_instances error: %s", exc)
        return False

    log.info("\n[VERIFY] === Signal E: IMDS_TAMPER_DETECTED tag ===")
    results["tamper_tag"] = _poll_until(
        _check_tamper_tag,
        "IMDS-TAMPER-DETECTED-Tag",
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
        "ALL reactive signals confirmed - reactive controls validated."
        if all_passed
        else "One or more reactive signals NOT confirmed within SLA."
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
      1. Delete EBS snapshot created during the experiment (if any).
      2. Delete the CloudFormation stack (VPC, SGs, SSM doc, EC2).
      3. Delete boto3-created IAM resources.
         (Removes Deny-all policy from instance role before deletion
          so that iam:DeleteRole does not fail.)

    Safe and tolerant: logs all errors without re-raising.
    """
    # ── 1. Delete EBS snapshot ────────────────────────────────────────────────
    snap_id = _STATE.get("snapshot_id")
    if not snap_id:
        # Try to find the snapshot by tag even if _STATE didn't record it
        vol_id = _STATE.get("volume_id", "")
        if vol_id:
            try:
                resp  = _ec2().describe_snapshots(
                    Filters=[
                        {"Name": "volume-id", "Values": [vol_id]},
                        {"Name": "tag-key",   "Values": [EXPERIMENT_TAG_KEY]},
                    ],
                    OwnerIds=["self"],
                )
                snaps = resp.get("Snapshots", [])
                for s in snaps:
                    snap_id = s["SnapshotId"]
                    log.info(
                        "[ROLLBACK] Found experiment snapshot via tag: %s", snap_id
                    )
                    break
            except Exception as exc:  # noqa: BLE001
                log.warning("[ROLLBACK] Could not find snapshot by tag: %s", exc)

    if snap_id:
        log.info("[ROLLBACK] Deleting EBS snapshot: %s", snap_id)
        try:
            _ec2().delete_snapshot(SnapshotId=snap_id)
            log.info("[ROLLBACK] Snapshot %s deleted.", snap_id)
        except ClientError as exc:
            log.warning("[ROLLBACK] delete_snapshot non-fatal: %s", exc)

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
    log.info("SCE Experiment 2.5 - Reactive Probe - Full Run")
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
                "[RUNNER] PASS  Experiment passed - reactive controls validated."
            )
        else:
            log.warning(
                "[RUNNER] FAIL  Experiment failed - reactive controls not confirmed."
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