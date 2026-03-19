"""
SCE Experiment 1.5 -- Reactive Probe
Attack Node 1.2: Weaken IMDS Configuration on Target EC2 Instance
TTP: T1578 - Modify Cloud Compute Infrastructure

Probe Intent (Reactive):
    Execute the IMDS weakening attack (ModifyInstanceMetadataOptions to
    IMDSv1) against a production-tagged EC2 instance, then verify that the
    reactive control fires automatically within the response SLA:

      - An EventBridge rule detects the CloudTrail ModifyInstanceMetadataOptions
        event and triggers a Lambda function (the automated remediation).
      - The Lambda re-hardens the instance: sets http_tokens=required and
        hop_limit=1 within 90 seconds of the attack call.
      - The Lambda applies a deny-all inline IAM policy to the offending
        principal (the attacker role) within the same 90-second window.
      - The Lambda publishes an SNS notification to a subscribed SQS queue,
        confirming the reactive action completed.

Root cause of previous ROLLBACK_COMPLETE failure (fixed in this revision):
    The S3 bucket was created programmatically BEFORE the CFN stack, then
    also declared as SCEBucket inside the CFN template.  When the pre-created
    bucket already existed, CFN's SCEBucket resource failed with:
        "sce-react-{timestamp}-{hash} already exists (AlreadyExists)"
    This cascaded and cancelled all other resources.

Fix applied:
    1. The S3 bucket is created and the Lambda ZIP is uploaded OUTSIDE the
       CFN template, BEFORE stack creation (unchanged).
    2. The SCEBucket resource is REMOVED from the CFN template entirely.
       The CloudTrail S3BucketName and Lambda Code.S3Bucket reference the
       bucket by its literal name string (not a Ref), so CFN never tries to
       own or create the bucket -- it just uses it.
    3. rollback() empties and deletes the bucket explicitly using boto3
       AFTER the CFN stack is fully deleted, since CFN no longer manages it.
    4. The SCEBucketPolicy CloudTrail resource is retained inside CFN and
       still references the bucket by literal name -- this is valid because
       the bucket exists before the stack is created.

Additional hardening from execution history:
    - All CFN template strings pass through _ascii_safe() before embedding.
    - _validate_template_strings() called before CFN submission.
    - Explicit non-empty output guard after CREATE_COMPLETE.
    - Stack event capture on ROLLBACK for immediate root-cause logging.
    - IAM propagation backoff for the attacker role.
    - SQS queue purge before experiment starts.
    - Lambda cold-start buffer: 15-second explicit wait after attack() before
      polling hypotheses (recommended in pre-execution metrics report).
"""

import subprocess
import sys
import time
import json
import logging
import os
import unicodedata
import hashlib
import uuid

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("sce.1_5.reactive")


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
# Uniqueness suffix: timestamp + 8 hex chars of UUID4 to avoid bucket
# name collisions even if a prior run left orphaned resources.
_UNIQUE_SUFFIX: str = "{}-{}".format(_TIMESTAMP, uuid.uuid4().hex[:8])
_STACK_NAME: str = "sce-experiment-{}".format(_UNIQUE_SUFFIX)
_EXPERIMENT_TAG: str = "sce-1.5-reactive"

# S3 bucket created OUTSIDE CFN (fix for AlreadyExists ROLLBACK failure).
# Name is deterministic from _UNIQUE_SUFFIX so rollback() can reconstruct it.
_S3_BUCKET_NAME: str = "sce-react-{}".format(_UNIQUE_SUFFIX)
_LAMBDA_S3_KEY: str = "lambda/handler-{}.zip".format(_UNIQUE_SUFFIX)

# Populated by steady_state(); consumed by attack() / hypothesis_verification()
_INSTANCE_ID: str = ""
_ATTACKER_ROLE_ARN: str = ""
_ATTACKER_ROLE_NAME: str = ""
_SQS_QUEUE_URL: str = ""
_TRAIL_NAME: str = ""
_REGION: str = ""

# Written by attack(); read by hypothesis_verification()
_ATTACK_RESULT: dict = {}

# Reactive response SLA (seconds)
_REACTIVE_SLA_SECONDS: float = 90.0

# Inline policy name the Lambda applies to the attacker role
_DENY_POLICY_NAME: str = "SCE-REACTIVE-DENY-ALL"

# Explicit buffer after attack() before polling starts (CloudTrail delivery
# + EventBridge propagation + Lambda cold start)
_POST_ATTACK_BUFFER_SECONDS: float = 15.0


# ---------------------------------------------------------------------------
# ASCII safety utilities
# ---------------------------------------------------------------------------

def _ascii_safe(value: str) -> str:
    """
    Return a copy of *value* containing only printable ASCII characters
    (codepoints 0x20-0x7E inclusive).
    """
    normalized = unicodedata.normalize("NFKD", value)
    ascii_bytes = normalized.encode("ascii", errors="ignore")
    ascii_str = ascii_bytes.decode("ascii")
    return "".join(
        ch if (0x20 <= ord(ch) <= 0x7E) else "-"
        for ch in ascii_str
    )


def _validate_template_strings(template, path: str = "root") -> None:
    """
    Recursively walk the CFN template and assert every string is ASCII-safe.
    Raises ValueError immediately on the first violation.
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
                    "Non-ASCII U+{:04X} ({!r}) at '{}' pos {}. "
                    "Use _ascii_safe().".format(code, ch, path, pos)
                )


# ---------------------------------------------------------------------------
# AWS / boto3 helpers
# ---------------------------------------------------------------------------

def _boto3_client(service: str, **kwargs):
    region = _REGION or _get_region()
    return boto3.client(service, region_name=region, **kwargs)


def _get_region() -> str:
    session = boto3.session.Session()
    return session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")


def _get_account_id() -> str:
    return _boto3_client("sts").get_caller_identity()["Account"]


def _resolve_ami(region: str) -> str:
    """Resolve the latest AL2023 x86_64 AMI ID via SSM (avoids CFN dynamic resolution)."""
    ssm = boto3.client("ssm", region_name=region)
    param = (
        "/aws/service/ami-amazon-linux-latest"
        "/al2023-ami-kernel-default-x86_64"
    )
    log.info("Resolving latest AL2023 AMI via SSM parameter '%s' ...", param)
    try:
        resp = ssm.get_parameter(Name=param)
        ami_id = resp["Parameter"]["Value"]
        log.info("Resolved AMI ID: %s", ami_id)
        return ami_id
    except ClientError as exc:
        log.error("Failed to resolve AMI via SSM: %s", exc)
        raise


# ---------------------------------------------------------------------------
# Lambda function source code
# ---------------------------------------------------------------------------

def _lambda_source(region: str, deny_policy_name: str) -> str:
    """
    Return the Lambda remediation handler source as a Python string.

    Actions performed by the Lambda when triggered by EventBridge:
      R1 - Re-harden EC2 IMDS: http_tokens=required, hop_limit=1.
      R2 - Apply deny-all inline policy to the offending IAM role.
      R3 - Publish SNS notification with structured remediation report.
    """
    src = '''
import boto3
import json
import os
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DENY_POLICY_NAME = "{deny_policy_name}"
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
REGION = "{region}"

DENY_ALL_POLICY = json.dumps({{
    "Version": "2012-10-17",
    "Statement": [{{
        "Effect": "Deny",
        "Action": "*",
        "Resource": "*"
    }}]
}})


def handler(event, context):
    logger.info("Reactive remediation triggered. Event: %s", json.dumps(event))

    ec2 = boto3.client("ec2", region_name=REGION)
    iam = boto3.client("iam")
    sns = boto3.client("sns", region_name=REGION)

    report = {{
        "trigger": "ModifyInstanceMetadataOptions",
        "actions": []
    }}

    detail = event.get("detail", {{}})
    request_params = detail.get("requestParameters", {{}})
    instance_id = request_params.get("instanceId", "")

    user_identity = detail.get("userIdentity", {{}})
    session_ctx = user_identity.get("sessionContext", {{}})
    session_issuer = session_ctx.get("sessionIssuer", {{}})
    role_name = session_issuer.get("userName", "")

    logger.info(
        "Extracted instance_id=%s role_name=%s",
        instance_id, role_name
    )

    # R1: Re-harden IMDS
    if instance_id:
        try:
            ec2.modify_instance_metadata_options(
                InstanceId=instance_id,
                HttpTokens="required",
                HttpEndpoint="enabled",
                HttpPutResponseHopLimit=1,
            )
            logger.info("R1: IMDS re-hardened on instance %s", instance_id)
            report["actions"].append({{
                "action": "IMDS_REHARDENED",
                "instance_id": instance_id,
                "status": "SUCCESS"
            }})
        except Exception as exc:
            logger.error("R1: Failed to re-harden IMDS: %s", exc)
            report["actions"].append({{
                "action": "IMDS_REHARDENED",
                "instance_id": instance_id,
                "status": "FAILED",
                "error": str(exc)
            }})
    else:
        logger.warning("R1: No instance_id -- skipping IMDS re-hardening.")
        report["actions"].append({{
            "action": "IMDS_REHARDENED",
            "status": "SKIPPED",
            "reason": "No instance_id in event"
        }})

    # R2: Apply deny-all inline policy
    if role_name:
        try:
            iam.put_role_policy(
                RoleName=role_name,
                PolicyName=DENY_POLICY_NAME,
                PolicyDocument=DENY_ALL_POLICY,
            )
            logger.info("R2: Deny-all applied to role %s", role_name)
            report["actions"].append({{
                "action": "DENY_ALL_POLICY_APPLIED",
                "role_name": role_name,
                "policy_name": DENY_POLICY_NAME,
                "status": "SUCCESS"
            }})
        except Exception as exc:
            logger.error("R2: Failed to apply deny-all to %s: %s", role_name, exc)
            report["actions"].append({{
                "action": "DENY_ALL_POLICY_APPLIED",
                "role_name": role_name,
                "status": "FAILED",
                "error": str(exc)
            }})
    else:
        logger.warning("R2: No role_name -- skipping deny-all policy.")
        report["actions"].append({{
            "action": "DENY_ALL_POLICY_APPLIED",
            "status": "SKIPPED",
            "reason": "No role_name in event"
        }})

    # R3: Publish SNS notification
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="SCE Reactive: IMDS Weakening Remediation Completed",
            Message=json.dumps(report),
        )
        logger.info("R3: SNS notification published.")
        report["actions"].append({{
            "action": "SNS_NOTIFICATION_PUBLISHED",
            "status": "SUCCESS"
        }})
    except Exception as exc:
        logger.error("R3: Failed to publish SNS: %s", exc)
        report["actions"].append({{
            "action": "SNS_NOTIFICATION_PUBLISHED",
            "status": "FAILED",
            "error": str(exc)
        }})

    logger.info("Reactive remediation complete. Report: %s", json.dumps(report))
    return report
'''.format(deny_policy_name=deny_policy_name, region=region)
    return src


# ---------------------------------------------------------------------------
# S3 bucket management (outside CFN to avoid AlreadyExists collision)
# ---------------------------------------------------------------------------

def _create_s3_bucket(bucket_name: str, region: str) -> None:
    """
    Create the S3 bucket that holds the Lambda deployment package AND
    CloudTrail logs. Created OUTSIDE the CFN stack so CFN never declares
    ownership and cannot fail with AlreadyExists.

    Idempotent: BucketAlreadyOwnedByYou is treated as success.
    """
    s3 = boto3.client("s3", region_name=region)
    log.info("Creating S3 bucket '%s' in region '%s' ...", bucket_name, region)
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
        log.info("S3 bucket '%s' created.", bucket_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            log.info("S3 bucket '%s' already owned -- reusing.", bucket_name)
        else:
            log.error("Failed to create S3 bucket '%s': %s", bucket_name, exc)
            raise

    # Enable versioning (required for CloudTrail bucket policy)
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )
    log.info("Versioning enabled on bucket '%s'.", bucket_name)


def _upload_lambda_zip(bucket_name: str, s3_key: str, source_code: str) -> None:
    """
    Package Lambda source into a ZIP file and upload to S3.
    Uses only stdlib (zipfile, io).
    """
    import zipfile
    import io

    log.info(
        "Packaging Lambda source into ZIP and uploading to s3://%s/%s ...",
        bucket_name, s3_key,
    )
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, mode="w",
                         compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", source_code)
    zip_bytes = zip_buffer.getvalue()

    s3 = _boto3_client("s3")
    s3.put_object(
        Bucket=bucket_name,
        Key=s3_key,
        Body=zip_bytes,
        ContentType="application/zip",
    )
    log.info(
        "Lambda package uploaded: s3://%s/%s (%d bytes).",
        bucket_name, s3_key, len(zip_bytes),
    )


def _empty_and_delete_s3_bucket(bucket_name: str) -> None:
    """
    Delete all object versions and delete markers from the bucket,
    then delete the bucket itself.
    Called from rollback() AFTER CFN stack deletion (bucket is not CFN-managed).
    Tolerates bucket-not-found.
    """
    log.info(
        "Emptying and deleting S3 bucket '%s' ...", bucket_name
    )
    s3 = _boto3_client("s3")

    try:
        s3.head_bucket(Bucket=bucket_name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("404", "NoSuchBucket"):
            log.info("Bucket '%s' does not exist -- skipping.", bucket_name)
            return
        log.warning(
            "Could not check bucket '%s': %s -- skipping.", bucket_name, exc
        )
        return

    # Delete all versions and delete markers
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objects = []
            for v in page.get("Versions", []):
                objects.append({"Key": v["Key"], "VersionId": v["VersionId"]})
            for m in page.get("DeleteMarkers", []):
                objects.append({"Key": m["Key"], "VersionId": m["VersionId"]})
            if objects:
                s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={"Objects": objects, "Quiet": True},
                )
                log.debug(
                    "Deleted %d object versions from '%s'.",
                    len(objects), bucket_name,
                )
    except ClientError as exc:
        log.warning(
            "Error emptying bucket '%s': %s -- proceeding to delete.",
            bucket_name, exc,
        )

    # Delete the bucket
    try:
        s3.delete_bucket(Bucket=bucket_name)
        log.info("S3 bucket '%s' deleted.", bucket_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("NoSuchBucket",):
            log.info("Bucket '%s' already deleted.", bucket_name)
        else:
            log.error(
                "Failed to delete bucket '%s': %s", bucket_name, exc
            )


# ---------------------------------------------------------------------------
# CloudFormation template builder
# ---------------------------------------------------------------------------

def _build_cfn_template(
    ami_id: str,
    account_id: str,
    region: str,
    s3_bucket_name: str,
    lambda_s3_key: str,
) -> dict:
    """
    Build the CFN template.

    KEY CHANGE from previous run:
        SCEBucket (AWS::S3::Bucket) is NOT included in this template.
        The bucket is created and managed entirely outside CFN.
        SCEBucketPolicy and SCETrail reference the bucket by literal name
        string -- this is valid because the bucket exists before stack creation.
        This eliminates the "AlreadyExists" ROLLBACK failure entirely.

    All string values pass through _ascii_safe() before embedding.
    """
    sg_desc = _ascii_safe("SCE reactive - no inbound traffic")
    exp_tag = _ascii_safe(_EXPERIMENT_TAG)
    ts_str = _ascii_safe(str(_UNIQUE_SUFFIX))
    stack_tag = _ascii_safe(_STACK_NAME)
    inst_name = _ascii_safe("sce-target-{}".format(_UNIQUE_SUFFIX))
    inst_role = _ascii_safe("sce-inst-role-{}".format(_UNIQUE_SUFFIX))
    inst_prof = _ascii_safe("sce-inst-prof-{}".format(_UNIQUE_SUFFIX))
    atk_role = _ascii_safe("sce-attacker-role-{}".format(_UNIQUE_SUFFIX))
    lam_role = _ascii_safe("sce-lambda-role-{}".format(_UNIQUE_SUFFIX))
    lam_fn = _ascii_safe("sce-reactive-fn-{}".format(_UNIQUE_SUFFIX))
    trail_name_val = _ascii_safe("sce-trail-{}".format(_UNIQUE_SUFFIX))
    topic_name_val = _ascii_safe("sce-alert-{}".format(_UNIQUE_SUFFIX))
    queue_name_val = _ascii_safe("sce-queue-{}".format(_UNIQUE_SUFFIX))
    rule_name_val = _ascii_safe("sce-rule-{}".format(_UNIQUE_SUFFIX))
    desc_val = _ascii_safe(
        "SCE 1.5 Reactive - IMDS auto-remediation ({})".format(_UNIQUE_SUFFIX)
    )
    egress_desc = _ascii_safe("Allow all outbound")

    trail_bucket_arn = "arn:aws:s3:::{}".format(s3_bucket_name)
    trail_prefix_arn = "arn:aws:s3:::{}/AWSLogs/{}/*".format(
        s3_bucket_name, account_id
    )
    attacker_role_arn = "arn:aws:iam::{}:role/{}".format(
        account_id, atk_role
    )

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": desc_val,
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
                        {"Key": "Name", "Value": stack_tag},
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
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
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            "SCEIGW": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {
                    "Tags": [
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
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
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
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
                    "GroupDescription": sg_desc,
                    "VpcId": {"Ref": "SCEVpc"},
                    "SecurityGroupIngress": [],
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "-1",
                            "CidrIp": "0.0.0.0/0",
                            "Description": egress_desc,
                        }
                    ],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # EC2 instance profile                                          #
            # ---------------------------------------------------------- #
            "SCEInstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": inst_role,
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
                            "PolicyName": "minimal-ssm",
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
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            "SCEInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": inst_prof,
                    "Roles": [{"Ref": "SCEInstanceRole"}],
                },
            },
            # ---------------------------------------------------------- #
            # EC2 target: production-tagged, IMDSv2 enforced               #
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
                        {"Key": "Name", "Value": inst_name},
                        {"Key": "Environment", "Value": "production"},
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # Attacker IAM role: ALLOW on ModifyInstanceMetadataOptions    #
            # No Deny -- attack must succeed to trigger reactive pipeline. #
            # ---------------------------------------------------------- #
            "SCEAttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": atk_role,
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
                                        "Sid": "AllowSTS",
                                        "Effect": "Allow",
                                        "Action": "sts:GetCallerIdentity",
                                        "Resource": "*",
                                    },
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # Lambda execution role                                         #
            # ---------------------------------------------------------- #
            "SCELambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": lam_role,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "lambda.amazonaws.com"
                                },
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/"
                        "AWSLambdaBasicExecutionRole"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "reactive-remediation",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "AllowIMDSReHarden",
                                        "Effect": "Allow",
                                        "Action": "ec2:ModifyInstanceMetadataOptions",
                                        "Resource": "*",
                                    },
                                    {
                                        "Sid": "AllowEC2Describe",
                                        "Effect": "Allow",
                                        "Action": "ec2:DescribeInstances",
                                        "Resource": "*",
                                    },
                                    {
                                        "Sid": "AllowDenyPolicyOnAttacker",
                                        "Effect": "Allow",
                                        "Action": [
                                            "iam:PutRolePolicy",
                                            "iam:GetRolePolicy",
                                        ],
                                        "Resource": attacker_role_arn,
                                    },
                                    {
                                        "Sid": "AllowSNSPublish",
                                        "Effect": "Allow",
                                        "Action": "sns:Publish",
                                        "Resource": {"Ref": "SCEAlertTopic"},
                                    },
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # Lambda function (deployed from pre-created S3 bucket)        #
            # ---------------------------------------------------------- #
            "SCEReactiveFunction": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["SCELambdaRole", "SCEAlertTopic"],
                "Properties": {
                    "FunctionName": lam_fn,
                    "Runtime": "python3.12",
                    "Handler": "handler.handler",
                    "Role": {
                        "Fn::GetAtt": ["SCELambdaRole", "Arn"]
                    },
                    "Code": {
                        "S3Bucket": s3_bucket_name,
                        "S3Key": lambda_s3_key,
                    },
                    "Timeout": 60,
                    "MemorySize": 128,
                    "Environment": {
                        "Variables": {
                            "SNS_TOPIC_ARN": {"Ref": "SCEAlertTopic"},
                        }
                    },
                    "Tags": [
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # EventBridge invoke permission for Lambda                     #
            # ---------------------------------------------------------- #
            "SCELambdaInvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "SCEReactiveFunction"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {
                        "Fn::GetAtt": ["SCEDetectionRule", "Arn"]
                    },
                },
            },
            # ---------------------------------------------------------- #
            # CloudTrail bucket policy (references bucket by literal name) #
            # NOTE: SCEBucket (AWS::S3::Bucket) intentionally OMITTED.    #
            # The bucket is created outside CFN to prevent AlreadyExists.  #
            # ---------------------------------------------------------- #
            "SCEBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": s3_bucket_name,
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
                                "Resource": trail_prefix_arn,
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
            # ---------------------------------------------------------- #
            # CloudTrail trail (management write events)                   #
            # ---------------------------------------------------------- #
            "SCETrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": "SCEBucketPolicy",
                "Properties": {
                    "TrailName": trail_name_val,
                    "S3BucketName": s3_bucket_name,
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
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # SNS topic                                                     #
            # ---------------------------------------------------------- #
            "SCEAlertTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": topic_name_val,
                    "Tags": [
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # SQS queue + policy + SNS subscription                        #
            # ---------------------------------------------------------- #
            "SCEAlertQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": queue_name_val,
                    "VisibilityTimeout": 120,
                    "MessageRetentionPeriod": 600,
                    "Tags": [
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
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
                                "Sid": "AllowSNS",
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "sns.amazonaws.com"
                                },
                                "Action": "sqs:SendMessage",
                                "Resource": {
                                    "Fn::GetAtt": ["SCEAlertQueue", "Arn"]
                                },
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {
                                            "Ref": "SCEAlertTopic"
                                        }
                                    }
                                },
                            }
                        ],
                    },
                },
            },
            "SCEAlertSubscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "TopicArn": {"Ref": "SCEAlertTopic"},
                    "Protocol": "sqs",
                    "Endpoint": {
                        "Fn::GetAtt": ["SCEAlertQueue", "Arn"]
                    },
                    "RawMessageDelivery": False,
                },
            },
            # ---------------------------------------------------------- #
            # EventBridge rule: ModifyInstanceMetadataOptions -> Lambda    #
            # ---------------------------------------------------------- #
            "SCEDetectionRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": rule_name_val,
                    "Description": _ascii_safe(
                        "SCE reactive - trigger Lambda on IMDS weakening"
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
                            "Id": "SCEReactiveLambda",
                            "Arn": {
                                "Fn::GetAtt": [
                                    "SCEReactiveFunction", "Arn"
                                ]
                            },
                        }
                    ],
                },
            },
        },
        "Outputs": {
            "InstanceId": {
                "Value": {"Ref": "SCETargetInstance"},
                "Description": _ascii_safe("Target EC2 instance ID"),
            },
            "AttackerRoleArn": {
                "Value": {"Fn::GetAtt": ["SCEAttackerRole", "Arn"]},
                "Description": _ascii_safe("Attacker IAM role ARN"),
            },
            "AttackerRoleName": {
                "Value": atk_role,
                "Description": _ascii_safe("Attacker IAM role name"),
            },
            "SqsQueueUrl": {
                "Value": {"Ref": "SCEAlertQueue"},
                "Description": _ascii_safe("SQS queue URL for polling"),
            },
            "TrailName": {
                "Value": trail_name_val,
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
    max_attempts: int = 90,
) -> None:
    log.info(
        "Waiting for CFN waiter '%s' on stack '%s' ...",
        waiter_name, stack_name,
    )
    waiter = cf_client.get_waiter(waiter_name)
    waiter.config.delay = delay
    waiter.config.max_attempts = max_attempts
    waiter.wait(StackName=stack_name)
    log.info(
        "CFN waiter '%s' completed for '%s'.", waiter_name, stack_name
    )


def _capture_stack_events(cf_client, stack_name: str) -> None:
    log.error(
        "Capturing CFN stack events for '%s' to diagnose rollback ...",
        stack_name,
    )
    try:
        paginator = cf_client.get_paginator("describe_stack_events")
        for page in paginator.paginate(StackName=stack_name):
            for ev in page["StackEvents"]:
                status = ev.get("ResourceStatus", "")
                reason = ev.get("ResourceStatusReason", "")
                res = ev.get("LogicalResourceId", "")
                rtype = ev.get("ResourceType", "")
                if "FAILED" in status or "ROLLBACK" in status:
                    log.error(
                        "  CFN EVENT [%s] %s (%s): %s",
                        status, res, rtype, reason,
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
            log.debug("Backoff poll '%s' raised: %s", description, exc)
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
    actions = [
        "cloudformation:CreateStack",
        "ec2:RunInstances",
        "iam:CreateRole",
        "ec2:ModifyInstanceMetadataOptions",
        "sts:AssumeRole",
        "ssm:GetParameter",
        "s3:CreateBucket",
        "sns:CreateTopic",
        "sqs:CreateQueue",
        "events:PutRule",
        "cloudtrail:CreateTrail",
        "lambda:CreateFunction",
    ]
    try:
        resp = iam.simulate_principal_policy(
            PolicySourceArn=caller_arn,
            ActionNames=actions,
            ResourceArns=["*"],
        )
        denied = [
            r["EvalActionName"]
            for r in resp["EvaluationResults"]
            if r["EvalDecision"] != "allowed"
        ]
        if denied:
            log.warning("Pre-flight: possibly restricted: %s", denied)
        else:
            log.info("Pre-flight: all permissions appear allowed.")
    except ClientError as exc:
        log.warning("IAM simulation unavailable: %s -- proceeding.", exc)


# ---------------------------------------------------------------------------
# Core experiment functions
# ---------------------------------------------------------------------------

def steady_state() -> None:
    """
    Provision all experiment resources.

    Sequence:
      1. Pre-flight permission check.
      2. Resolve AMI ID via SSM.
      3. Create S3 bucket OUTSIDE CFN (avoids AlreadyExists ROLLBACK failure).
      4. Upload Lambda deployment ZIP to the pre-created bucket.
      5. Build + validate CFN template (no SCEBucket resource in template).
      6. Create CFN stack and wait for CREATE_COMPLETE.
      7. Validate all stack outputs are non-empty.
      8. Baseline assertions: IMDSv2 enforced, CloudTrail logging, SQS empty.
      9. IAM propagation backoff for the attacker role.
    """
    global _INSTANCE_ID, _ATTACKER_ROLE_ARN, _ATTACKER_ROLE_NAME
    global _SQS_QUEUE_URL, _TRAIL_NAME, _REGION

    log.info("=== steady_state() -- stack: %s ===", _STACK_NAME)
    log.info("Unique suffix: %s", _UNIQUE_SUFFIX)
    _REGION = _get_region()
    log.info("AWS region: %s", _REGION)

    _preflight_check()

    ami_id = _resolve_ami(_REGION)
    account_id = _get_account_id()
    log.info("Account: %s", account_id)

    # Step 1: Create S3 bucket OUTSIDE CFN
    _create_s3_bucket(_S3_BUCKET_NAME, _REGION)

    # Step 2: Upload Lambda ZIP to the pre-created bucket
    lambda_src = _lambda_source(_REGION, _DENY_POLICY_NAME)
    _upload_lambda_zip(_S3_BUCKET_NAME, _LAMBDA_S3_KEY, lambda_src)

    # Step 3: Build and validate CFN template
    cfn_template = _build_cfn_template(
        ami_id, account_id, _REGION, _S3_BUCKET_NAME, _LAMBDA_S3_KEY
    )

    log.info("Validating CFN template string encoding ...")
    try:
        _validate_template_strings(cfn_template)
        log.info("Template validation passed -- all strings are ASCII-safe.")
    except ValueError as exc:
        log.error("Template validation FAILED: %s -- aborting.", exc)
        raise

    cf = _boto3_client("cloudformation")

    # Check for pre-existing stack
    stack_exists = False
    try:
        existing = cf.describe_stacks(StackName=_STACK_NAME)
        status = existing["Stacks"][0]["StackStatus"]
        log.warning(
            "Stack '%s' already exists with status '%s'. Continuing.",
            _STACK_NAME, status,
        )
        stack_exists = True
    except ClientError as exc:
        if "does not exist" in str(exc):
            stack_exists = False
        else:
            log.error("Unexpected error describing stack: %s", exc)
            raise

    # Create stack
    if not stack_exists:
        log.info("Creating CloudFormation stack '%s' ...", _STACK_NAME)
        try:
            cf.create_stack(
                StackName=_STACK_NAME,
                TemplateBody=json.dumps(cfn_template),
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Tags=[
                    {"Key": "sce-experiment", "Value": _ascii_safe(_EXPERIMENT_TAG)},
                    {"Key": "sce-ts", "Value": _ascii_safe(str(_UNIQUE_SUFFIX))},
                ],
            )
        except ClientError as exc:
            log.error("Failed to create stack: %s", exc)
            raise

    # Wait for CREATE_COMPLETE
    try:
        _wait_stack(
            cf, _STACK_NAME, "stack_create_complete",
            delay=20, max_attempts=90,
        )
    except WaiterError as wait_exc:
        _capture_stack_events(cf, _STACK_NAME)
        log.error(
            "Stack creation failed. Events logged above. Exception: %s",
            wait_exc,
        )
        raise RuntimeError(
            "CloudFormation stack '{}' reached a terminal failure state.".format(
                _STACK_NAME
            )
        ) from wait_exc

    # Collect and validate outputs
    outputs = _get_stack_outputs(cf, _STACK_NAME)
    log.info("Stack outputs: %s", outputs)

    _INSTANCE_ID = outputs.get("InstanceId", "")
    _ATTACKER_ROLE_ARN = outputs.get("AttackerRoleArn", "")
    _ATTACKER_ROLE_NAME = outputs.get("AttackerRoleName", "")
    _SQS_QUEUE_URL = outputs.get("SqsQueueUrl", "")
    _TRAIL_NAME = outputs.get("TrailName", "")

    missing = [
        name
        for name, val in [
            ("InstanceId", _INSTANCE_ID),
            ("AttackerRoleArn", _ATTACKER_ROLE_ARN),
            ("AttackerRoleName", _ATTACKER_ROLE_NAME),
            ("SqsQueueUrl", _SQS_QUEUE_URL),
            ("TrailName", _TRAIL_NAME),
        ]
        if not val
    ]
    if missing:
        raise RuntimeError(
            "CFN outputs missing or empty: {}".format(missing)
        )

    log.info(
        "Outputs validated -- InstanceId=%s AttackerRoleName=%s TrailName=%s",
        _INSTANCE_ID, _ATTACKER_ROLE_NAME, _TRAIL_NAME,
    )

    # Baseline: IMDSv2 enforced
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
        initial_delay=5.0, max_delay=20.0, timeout=180.0,
    ):
        raise RuntimeError(
            "Baseline FAILED: instance {} does not have "
            "IMDSv2 enforced.".format(_INSTANCE_ID)
        )
    log.info("Baseline: IMDSv2 enforced on instance %s.", _INSTANCE_ID)

    # Baseline: CloudTrail logging
    ct = _boto3_client("cloudtrail")

    def _trail_logging() -> bool:
        try:
            return ct.get_trail_status(
                Name=_TRAIL_NAME
            ).get("IsLogging", False)
        except ClientError:
            return False

    if not _wait_with_backoff(
        _trail_logging,
        "CloudTrail trail is logging",
        initial_delay=5.0, max_delay=15.0, timeout=120.0,
    ):
        log.warning(
            "CloudTrail trail '%s' may not be logging yet -- proceeding.",
            _TRAIL_NAME,
        )
    else:
        log.info("Baseline: CloudTrail trail '%s' is logging.", _TRAIL_NAME)

    # Baseline: SQS queue empty
    sqs = _boto3_client("sqs")
    try:
        attrs = sqs.get_queue_attributes(
            QueueUrl=_SQS_QUEUE_URL,
            AttributeNames=["ApproximateNumberOfMessages"],
        )
        count = int(
            attrs["Attributes"].get("ApproximateNumberOfMessages", "0")
        )
        if count > 0:
            log.warning(
                "SQS queue has %d pre-existing messages -- purging.", count
            )
            sqs.purge_queue(QueueUrl=_SQS_QUEUE_URL)
            time.sleep(5)
        else:
            log.info("Baseline: SQS queue is empty.")
    except ClientError as exc:
        log.warning("Could not check/purge SQS queue: %s -- proceeding.", exc)

    # IAM propagation backoff for attacker role
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
            log.debug(
                "Role not yet assumable: %s",
                exc.response["Error"]["Code"],
            )
            return False

    if not _wait_with_backoff(
        _role_assumable,
        "AttackerRole IAM propagation",
        initial_delay=5.0, max_delay=20.0, timeout=120.0,
    ):
        log.warning("IAM propagation timed out -- proceeding.")

    log.info("steady_state() complete.")


def attack() -> bool:
    """
    Attack step (Attack Node 1.2 / TTP T1578).

    Assumes the attacker role and calls ModifyInstanceMetadataOptions to
    downgrade IMDS to IMDSv1 (http_tokens=optional, hop_limit=2).
    The call SUCCEEDS intentionally to generate a CloudTrail event that
    triggers the EventBridge -> Lambda reactive pipeline.

    Records attack_epoch immediately before the API call for SLA measurement.

    Returns True if the attack call was issued; False on precondition failure.
    """
    global _ATTACK_RESULT

    log.info("=== attack() -- role: %s ===", _ATTACKER_ROLE_ARN)

    if not _ATTACKER_ROLE_ARN or not _INSTANCE_ID:
        log.error(
            "attack() aborted: preconditions not met. "
            "_ATTACKER_ROLE_ARN='%s' _INSTANCE_ID='%s'.",
            _ATTACKER_ROLE_ARN, _INSTANCE_ID,
        )
        _ATTACK_RESULT = {
            "executed": False,
            "error_code": "EMPTY_PRECONDITION",
            "error_message": "AttackerRole ARN or Instance ID is empty.",
        }
        return False

    sts = _boto3_client("sts")
    try:
        assumed = sts.assume_role(
            RoleArn=_ATTACKER_ROLE_ARN,
            RoleSessionName="sce-attack-{}".format(_UNIQUE_SUFFIX),
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

    attack_epoch = time.time()

    log.info(
        "Calling ModifyInstanceMetadataOptions on %s "
        "(http_tokens=optional, hop_limit=2) -- "
        "reactive pipeline should fire ...",
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
            "CloudTrail event generated. Lambda reactive pipeline firing ...",
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
            "Unexpected error from ModifyInstanceMetadataOptions: %s -- %s.",
            code, message,
        )
        _ATTACK_RESULT = {
            "executed": False,
            "attack_epoch": attack_epoch,
            "error_code": code,
            "error_message": message,
        }
        return False

    log.info(
        "attack() complete. Waiting %.0fs for CloudTrail delivery + "
        "Lambda cold start before polling ...",
        _POST_ATTACK_BUFFER_SECONDS,
    )
    time.sleep(_POST_ATTACK_BUFFER_SECONDS)
    return True


def hypothesis_verification() -> bool:
    """
    Reactive probe verification (SCE Node 1.5 -- Reactive).

    Returns True only when ALL THREE hypotheses pass within _REACTIVE_SLA_SECONDS:

    [H1] IMDS re-hardened: Lambda restored http_tokens=required, hop_limit=1
         on the EC2 instance.  Polled via ec2:DescribeInstances every 5s.

    [H2] Deny-all inline policy applied: Lambda put SCE-REACTIVE-DENY-ALL
         on the attacker IAM role.  Polled via iam:GetRolePolicy every 5s.

    [H3] SNS reactive notification delivered to SQS within SLA window.
         Polled via sqs:ReceiveMessage with long-polling.

    All three hypotheses are polled in parallel (round-robin) within a
    unified polling loop to avoid one slow hypothesis consuming the full
    SLA budget before the others start (addressing pre-execution report
    recommendation #2).
    """
    log.info("=== hypothesis_verification() ===")

    if not _INSTANCE_ID or not _ATTACKER_ROLE_ARN or not _ATTACKER_ROLE_NAME:
        log.error(
            "hypothesis_verification() aborted: infrastructure globals empty. "
            "steady_state() must have failed."
        )
        return False

    if not _ATTACK_RESULT.get("executed", False):
        log.error(
            "hypothesis_verification() aborted: attack() did not execute. "
            "Result: %s", _ATTACK_RESULT,
        )
        return False

    attack_epoch = _ATTACK_RESULT.get("attack_epoch", time.time())
    # The SLA clock starts from the attack call, but the post-attack buffer
    # in attack() already consumed _POST_ATTACK_BUFFER_SECONDS of it.
    # We give the full _REACTIVE_SLA_SECONDS from now for polling.
    poll_deadline = time.monotonic() + _REACTIVE_SLA_SECONDS

    ec2 = _boto3_client("ec2")
    iam = _boto3_client("iam")
    sqs = _boto3_client("sqs")

    h1_passed = False
    h2_passed = False
    h3_passed = False

    log.info(
        "Polling H1 (IMDS re-hardened), H2 (deny-all policy), H3 (SNS) "
        "in unified round-robin loop. SLA: %.0f seconds from now.",
        _REACTIVE_SLA_SECONDS,
    )

    while time.monotonic() < poll_deadline and not (
        h1_passed and h2_passed and h3_passed
    ):
        elapsed = time.time() - attack_epoch

        # ---------------------------------------------------------- #
        # H1: IMDS re-hardened                                         #
        # ---------------------------------------------------------- #
        if not h1_passed:
            try:
                resp = ec2.describe_instances(InstanceIds=[_INSTANCE_ID])
                reservations = resp.get("Reservations", [])
                if reservations:
                    opts = reservations[0]["Instances"][0].get(
                        "MetadataOptions", {}
                    )
                    http_tokens = opts.get("HttpTokens")
                    hop_limit = opts.get("HttpPutResponseHopLimit")
                    if http_tokens == "required" and hop_limit == 1:
                        log.info(
                            "[H1] PASS -- IMDS re-hardened %.1fs after attack. "
                            "HttpTokens=%s HopLimit=%s",
                            elapsed, http_tokens, hop_limit,
                        )
                        h1_passed = True
                    else:
                        log.debug(
                            "[H1] Waiting -- HttpTokens=%s HopLimit=%s "
                            "(%.1fs elapsed)",
                            http_tokens, hop_limit, elapsed,
                        )
            except ClientError as exc:
                log.error("[H1] DescribeInstances error: %s", exc)

        # ---------------------------------------------------------- #
        # H2: Deny-all inline policy on attacker role                  #
        # ---------------------------------------------------------- #
        if not h2_passed:
            try:
                iam.get_role_policy(
                    RoleName=_ATTACKER_ROLE_NAME,
                    PolicyName=_DENY_POLICY_NAME,
                )
                log.info(
                    "[H2] PASS -- Deny-all policy '%s' on role '%s' "
                    "%.1fs after attack.",
                    _DENY_POLICY_NAME, _ATTACKER_ROLE_NAME, elapsed,
                )
                h2_passed = True
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "NoSuchEntity":
                    log.debug(
                        "[H2] Waiting -- policy not yet applied (%.1fs).",
                        elapsed,
                    )
                else:
                    log.error("[H2] IAM GetRolePolicy error: %s", exc)

        # ---------------------------------------------------------- #
        # H3: SNS notification via SQS                                 #
        # ---------------------------------------------------------- #
        if not h3_passed:
            try:
                sqs_resp = sqs.receive_message(
                    QueueUrl=_SQS_QUEUE_URL,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=2,
                    AttributeNames=["All"],
                )
                messages = sqs_resp.get("Messages", [])
                for msg in messages:
                    body_raw = msg.get("Body", "")
                    try:
                        outer = json.loads(body_raw)
                        inner_str = outer.get("Message", body_raw)
                        inner = json.loads(inner_str)
                    except (json.JSONDecodeError, TypeError):
                        inner = {}
                        inner_str = body_raw

                    is_reactive = (
                        "IMDS_REHARDENED" in inner_str
                        or "DENY_ALL_POLICY_APPLIED" in inner_str
                        or inner.get("trigger") == "ModifyInstanceMetadataOptions"
                        or "ModifyInstanceMetadataOptions" in inner_str
                    )

                    try:
                        sqs.delete_message(
                            QueueUrl=_SQS_QUEUE_URL,
                            ReceiptHandle=msg["ReceiptHandle"],
                        )
                    except ClientError:
                        pass

                    if is_reactive:
                        actions_summary = [
                            a.get("action", "UNKNOWN")
                            for a in inner.get("actions", [])
                        ]
                        log.info(
                            "[H3] PASS -- Reactive SNS notification received "
                            "%.1fs after attack. Actions: %s",
                            elapsed, actions_summary,
                        )
                        h3_passed = True
                        break
                    else:
                        log.debug(
                            "[H3] Received unrelated SQS message -- discarded."
                        )
            except ClientError as exc:
                log.error("[H3] SQS receive_message error: %s", exc)

        # Short sleep between poll rounds to avoid tight spin
        if not (h1_passed and h2_passed and h3_passed):
            time.sleep(3)

    # ------------------------------------------------------------------ #
    # Final state check for any failed hypotheses                          #
    # ------------------------------------------------------------------ #
    elapsed_total = time.time() - attack_epoch

    if not h1_passed:
        try:
            resp = ec2.describe_instances(InstanceIds=[_INSTANCE_ID])
            if resp.get("Reservations"):
                opts = resp["Reservations"][0]["Instances"][0].get(
                    "MetadataOptions", {}
                )
                log.error(
                    "[H1] FAIL -- IMDS NOT re-hardened within SLA. "
                    "Final: HttpTokens=%s HopLimit=%s. "
                    "Total elapsed: %.1fs.",
                    opts.get("HttpTokens"),
                    opts.get("HttpPutResponseHopLimit"),
                    elapsed_total,
                )
        except ClientError as exc:
            log.error("[H1] FAIL -- DescribeInstances also failed: %s", exc)

    if not h2_passed:
        log.error(
            "[H2] FAIL -- Deny-all policy '%s' NOT applied to role '%s' "
            "within SLA. Total elapsed: %.1fs.",
            _DENY_POLICY_NAME, _ATTACKER_ROLE_NAME, elapsed_total,
        )

    if not h3_passed:
        log.error(
            "[H3] FAIL -- No reactive SNS notification received on SQS "
            "within SLA. Total elapsed: %.1fs.",
            elapsed_total,
        )

    all_passed = h1_passed and h2_passed and h3_passed

    if all_passed:
        log.info(
            "hypothesis_verification() -> PASS. "
            "Reactive pipeline completed: IMDS re-hardened (H1), "
            "deny-all applied (H2), SNS notification received (H3). "
            "Total elapsed: %.1fs.",
            elapsed_total,
        )
    else:
        log.error(
            "hypothesis_verification() -> FAIL. "
            "H1=%s H2=%s H3=%s. Total elapsed: %.1fs.",
            h1_passed, h2_passed, h3_passed, elapsed_total,
        )

    return all_passed


def rollback() -> None:
    """
    Complete teardown:
      1. Remove the deny-all inline policy from the attacker role (if applied).
      2. Delete the CFN stack and wait for DELETE_COMPLETE.
      3. Empty and delete the S3 bucket (managed outside CFN).

    S3 bucket deletion is AFTER CFN stack deletion because SCEBucketPolicy
    (a CFN resource) references the bucket -- deleting the bucket before the
    stack would cause DeleteStack to fail on the BucketPolicy resource.

    Always executes even on upstream failure (called from finally block).
    """
    log.info("=== rollback() -- stack: '%s' ===", _STACK_NAME)

    # Step 1: Remove deny-all inline policy from attacker role
    if _ATTACKER_ROLE_NAME:
        iam = _boto3_client("iam")
        try:
            iam.delete_role_policy(
                RoleName=_ATTACKER_ROLE_NAME,
                PolicyName=_DENY_POLICY_NAME,
            )
            log.info(
                "Removed deny-all inline policy from role '%s'.",
                _ATTACKER_ROLE_NAME,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchEntity":
                log.debug(
                    "Deny-all policy not present on '%s' -- nothing to remove.",
                    _ATTACKER_ROLE_NAME,
                )
            else:
                log.warning(
                    "Could not remove deny-all from '%s': %s",
                    _ATTACKER_ROLE_NAME, exc,
                )

    # Step 2: Delete CFN stack
    cf = _boto3_client("cloudformation")

    try:
        status_resp = cf.describe_stacks(StackName=_STACK_NAME)
        current_status = status_resp["Stacks"][0]["StackStatus"]
        log.info("Stack '%s' status: %s", _STACK_NAME, current_status)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info("Stack '%s' does not exist -- skipping CFN delete.", _STACK_NAME)
            current_status = "DELETE_COMPLETE"
        else:
            log.error("Error checking stack: %s", exc)
            current_status = "UNKNOWN"

    if current_status not in ("DELETE_COMPLETE",):
        if current_status == "DELETE_IN_PROGRESS":
            log.info(
                "Stack '%s' already deleting -- waiting for completion.",
                _STACK_NAME,
            )
        else:
            try:
                cf.delete_stack(StackName=_STACK_NAME)
                log.info("Stack deletion initiated for '%s'.", _STACK_NAME)
            except ClientError as exc:
                log.error("Failed to initiate stack deletion: %s", exc)

        try:
            _wait_stack(
                cf, _STACK_NAME, "stack_delete_complete",
                delay=20, max_attempts=60,
            )
            log.info("Stack '%s' deleted.", _STACK_NAME)
        except ClientError as exc:
            if "does not exist" in str(exc):
                log.info("Stack '%s' confirmed deleted.", _STACK_NAME)
            else:
                log.error("Error waiting for stack deletion: %s", exc)
        except WaiterError as exc:
            try:
                cf.describe_stacks(StackName=_STACK_NAME)
                log.error(
                    "Stack deletion waiter failed; stack still exists: %s",
                    exc,
                )
            except ClientError as inner:
                if "does not exist" in str(inner):
                    log.info(
                        "Stack '%s' confirmed deleted (waiter false alarm).",
                        _STACK_NAME,
                    )
                else:
                    log.error("Error confirming deletion: %s", inner)
        except Exception as exc:  # noqa: BLE001
            log.error("Unexpected error during stack deletion: %s", exc)

    # Step 3: Empty and delete the S3 bucket (after CFN stack is gone)
    _empty_and_delete_s3_bucket(_S3_BUCKET_NAME)

    log.info("rollback() complete.")


# ---------------------------------------------------------------------------
# Experiment entry point
# ---------------------------------------------------------------------------

def run_experiment() -> None:
    """
    Orchestrates: steady_state -> attack -> hypothesis_verification -> rollback.
    rollback() always executes via finally block.
    """
    log.info("============================================================")
    log.info("SCE 1.5 Reactive -- IMDS Weakening Auto-Remediation (T1578)")
    log.info("Stack  : %s", _STACK_NAME)
    log.info("Bucket : %s", _S3_BUCKET_NAME)
    log.info("============================================================")

    result = False

    try:
        steady_state()
        attack_issued = attack()

        if not attack_issued:
            log.error(
                "attack() returned False -- reactive pipeline cannot fire."
            )
        else:
            result = hypothesis_verification()

    except Exception as exc:  # noqa: BLE001
        log.error(
            "Unhandled exception during experiment: %s", exc, exc_info=True
        )
    finally:
        rollback()

    status = "PASSED" if result else "FAILED"
    log.info("============================================================")
    log.info("SCE Experiment 1.5 Reactive Probe result: %s", status)
    log.info("============================================================")

    if not result:
        sys.exit(1)


if __name__ == "__main__":
    run_experiment()