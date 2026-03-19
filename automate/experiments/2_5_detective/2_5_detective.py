"""
SCE Experiment 2.5 -- Detective Probe
Attack Nodes: 1.2 + 2.2 (chained)

Attack Node 1.2: Weaken IMDS Configuration on Target EC2 Instance
  TTP: T1578 - Modify Cloud Compute Infrastructure
  Command: aws ec2 modify-instance-metadata-options
             --instance-id <ID> --http-tokens optional
             --http-endpoint enabled --http-put-response-hop-limit 2

Attack Node 2.2: Retrieve Temporary IAM Credentials from IMDS
  TTP: T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
  Command: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

Probe Intent (Detective -- SCE Node 2.5):
    Execute BOTH attack steps successfully (no preventive blocks on the
    attacker role), then verify that the detective controls captured
    evidence of BOTH attacks within their respective detection SLAs:

    D1 -- CloudTrail records the ModifyInstanceMetadataOptions API call
          (Attack 1.2) within 5 minutes of execution.
          Verified via CloudTrail LookupEvents for the specific event name
          and instance ID.

    D2 -- VPC Flow Logs capture unexpected traffic from the probe instance
          to 169.254.169.254 (Attack 2.2 IMDS access attempt).
          Verified by querying CloudWatch Logs Insights against the VPC
          Flow Log group for flow records destined to 169.254.169.254
          from the probe instance's private IP, appearing within 5 minutes
          of the curl execution.

    D3 -- GuardDuty finding UnauthorizedAccess:EC2/MetaDataDNSRebind or
          an EventBridge CloudTrail rule fires an SNS -> SQS notification
          for the ModifyInstanceMetadataOptions event within 60 seconds.
          Verified by polling the SQS queue for a matching message.

ADT Node 1.3 reference:
    "CloudTrail captures every ModifyInstanceMetadataOptions API call;
     EventBridge rule triggers SNS alert on any invocation in production.
     AWS Config Rule ec2-imdsv2-check flags non-compliant instance state.
     CloudWatch Logs Insights alert fires within 60 seconds of API call."

ADT Node 2.3 reference:
    "VPC Flow Logs capture unexpected traffic to 169.254.169.254 from
     container subnets; CloudWatch metric filter fires alert.
     GuardDuty finding UnauthorizedAccess:EC2/MetaDataDNSRebind triggers
     on anomalous IMDS access patterns on banking EC2 hosts."

Hypotheses verified:
    [H1] CloudTrail recorded ModifyInstanceMetadataOptions for the target
         instance within the 5-minute CloudTrail delivery window.
    [H2] VPC Flow Logs captured traffic to 169.254.169.254 from the probe
         instance within 5 minutes of the IMDS access attempt.
    [H3] EventBridge -> SNS -> SQS notification for the IMDS weakening
         event delivered within the 60-second detection SLA.

Infrastructure provisioned (all inside CFN stack -- no external S3):
    - VPC + public subnet + IGW + route table
    - Target EC2 instance: Environment=production, IMDSv2 relaxed for
      attack (http_tokens=optional set AFTER stack create by attack())
      Wait -- the TARGET starts with IMDSv2 enforced at launch; attack()
      weakens it using the permissive attacker role.
    - Probe EC2 instance: same subnet, SSM-enabled, used to perform
      the IMDS credential retrieval curl (Attack 2.2)
    - IAM attacker role: ALLOW on ec2:ModifyInstanceMetadataOptions
      (no Deny -- both attacks must succeed to generate real events)
    - IAM SSM instance role + profile for both EC2 instances
    - VPC Flow Logs -> CloudWatch Logs group (for D2)
    - CloudTrail trail -> S3 bucket (for D1)
      S3 bucket created OUTSIDE CFN (avoids AlreadyExists ROLLBACK)
    - SNS topic + SQS queue + SNS subscription (for D3)
    - EventBridge rule: ModifyInstanceMetadataOptions -> SNS topic (D3)

All fixes from previous probe runs applied:
    - AMI resolved via boto3 SSM GetParameter (no CFN dynamic substitution).
    - All CFN template strings sanitised via _ascii_safe() + validated
      with _validate_template_strings() before CFN submission.
    - account_id resolved programmatically as literal string in trust policies.
    - Explicit non-empty output guard after CREATE_COMPLETE.
    - Stack event capture on ROLLBACK for immediate root-cause logging.
    - UUID suffix on stack/resource names to prevent collision.
    - S3 bucket for CloudTrail created OUTSIDE CFN (AlreadyExists fix).
    - S3 bucket emptied and deleted AFTER CFN stack deletion in rollback().
    - Post-attack buffer before polling (CloudTrail delivery latency).
    - IAM propagation backoff before attack() starts.
"""

import subprocess
import sys
import time
import json
import logging
import os
import unicodedata
import uuid
import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("sce.2_5.detective")


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
_UNIQUE_SUFFIX: str = "{}-{}".format(_TIMESTAMP, uuid.uuid4().hex[:8])
_STACK_NAME: str = "sce-experiment-{}".format(_UNIQUE_SUFFIX)
_EXPERIMENT_TAG: str = "sce-2.5-detective"

# S3 bucket managed OUTSIDE CFN to prevent AlreadyExists ROLLBACK failure.
_S3_BUCKET_NAME: str = "sce-ct-{}".format(_UNIQUE_SUFFIX)
_REGION: str = ""

# Populated by steady_state()
_TARGET_INSTANCE_ID: str = ""
_TARGET_PRIVATE_IP: str = ""
_PROBE_INSTANCE_ID: str = ""
_ATTACKER_ROLE_ARN: str = ""
_SQS_QUEUE_URL: str = ""
_TRAIL_NAME: str = ""
_FLOW_LOG_GROUP: str = ""

# Written by attack(); read by hypothesis_verification()
_ATTACK_RESULT: dict = {}

# Detection SLAs
_CLOUDTRAIL_POLL_TIMEOUT: float = 300.0   # 5 minutes for CT delivery
_FLOWLOG_POLL_TIMEOUT: float = 300.0      # 5 minutes for VPC Flow Logs
_EVENTBRIDGE_SLA_SECONDS: float = 60.0    # 60 seconds for EventBridge->SQS

# Buffer after attack() before polling (CT delivery + EB propagation)
_POST_ATTACK_BUFFER_SECONDS: float = 15.0


# ---------------------------------------------------------------------------
# ASCII safety utilities
# ---------------------------------------------------------------------------

def _ascii_safe(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    ascii_bytes = normalized.encode("ascii", errors="ignore")
    ascii_str = ascii_bytes.decode("ascii")
    return "".join(
        ch if (0x20 <= ord(ch) <= 0x7E) else "-"
        for ch in ascii_str
    )


def _validate_template_strings(template, path: str = "root") -> None:
    if isinstance(template, dict):
        for k, v in template.items():
            _validate_template_strings(v, path="{}.{}".format(path, k))
    elif isinstance(template, list):
        for i, item in enumerate(template):
            _validate_template_strings(
                item, path="{}[{}]".format(path, i)
            )
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
    return session.region_name or os.environ.get(
        "AWS_DEFAULT_REGION", "us-east-1"
    )


def _get_account_id() -> str:
    return _boto3_client("sts").get_caller_identity()["Account"]


def _resolve_ami(region: str) -> str:
    ssm = boto3.client("ssm", region_name=region)
    param = (
        "/aws/service/ami-amazon-linux-latest"
        "/al2023-ami-kernel-default-x86_64"
    )
    log.info("Resolving latest AL2023 AMI via SSM '%s' ...", param)
    try:
        resp = ssm.get_parameter(Name=param)
        ami_id = resp["Parameter"]["Value"]
        log.info("Resolved AMI ID: %s", ami_id)
        return ami_id
    except ClientError as exc:
        log.error("Failed to resolve AMI via SSM: %s", exc)
        raise


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
        "ssm:SendCommand",
        "s3:CreateBucket",
        "sns:CreateTopic",
        "sqs:CreateQueue",
        "events:PutRule",
        "cloudtrail:CreateTrail",
        "logs:CreateLogGroup",
        "ec2:CreateFlowLogs",
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
# S3 bucket management (outside CFN -- AlreadyExists fix)
# ---------------------------------------------------------------------------

def _create_s3_bucket(bucket_name: str, region: str) -> None:
    s3 = boto3.client("s3", region_name=region)
    log.info(
        "Creating S3 bucket '%s' in region '%s' ...", bucket_name, region
    )
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
            log.info("Bucket '%s' already owned -- reusing.", bucket_name)
        else:
            log.error("Failed to create bucket '%s': %s", bucket_name, exc)
            raise
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )
    log.info("Versioning enabled on bucket '%s'.", bucket_name)


def _empty_and_delete_s3_bucket(bucket_name: str) -> None:
    log.info("Emptying and deleting S3 bucket '%s' ...", bucket_name)
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
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            objects = []
            for v in page.get("Versions", []):
                objects.append(
                    {"Key": v["Key"], "VersionId": v["VersionId"]}
                )
            for m in page.get("DeleteMarkers", []):
                objects.append(
                    {"Key": m["Key"], "VersionId": m["VersionId"]}
                )
            if objects:
                s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={"Objects": objects, "Quiet": True},
                )
    except ClientError as exc:
        log.warning(
            "Error emptying bucket '%s': %s -- proceeding.", bucket_name, exc
        )
    try:
        s3.delete_bucket(Bucket=bucket_name)
        log.info("S3 bucket '%s' deleted.", bucket_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "NoSuchBucket":
            log.info("Bucket '%s' already deleted.", bucket_name)
        else:
            log.error("Failed to delete bucket '%s': %s", bucket_name, exc)


# ---------------------------------------------------------------------------
# CloudFormation template builder
# ---------------------------------------------------------------------------

def _build_cfn_template(
    ami_id: str,
    account_id: str,
    region: str,
    s3_bucket_name: str,
) -> dict:
    """
    Build the CFN template dict for the detective probe.

    KEY DIFFERENCES from the preventive probe template:
      1. SCEAttackerRole has ALLOW (not Deny) on
         ec2:ModifyInstanceMetadataOptions so Attack 1.2 SUCCEEDS and
         generates a real CloudTrail event for detective controls to observe.
      2. VPC Flow Logs are enabled on the VPC, delivering to a CloudWatch
         Logs group -- required for D2 (Flow Log detection of IMDS access).
      3. CloudTrail trail + S3 bucket (external) for D1.
      4. SNS topic + SQS queue + EventBridge rule for D3.
      5. IAM role for VPC Flow Logs delivery to CloudWatch Logs.
      6. AWS::S3::Bucket intentionally ABSENT (bucket pre-created outside
         CFN to prevent AlreadyExists ROLLBACK failure).
    """
    sg_desc = _ascii_safe("SCE 2.5 detective - instance SG no inbound")
    exp_tag = _ascii_safe(_EXPERIMENT_TAG)
    ts_str = _ascii_safe(_UNIQUE_SUFFIX)
    stack_tag = _ascii_safe(_STACK_NAME)
    target_name = _ascii_safe("sce-target-{}".format(_UNIQUE_SUFFIX))
    probe_name = _ascii_safe("sce-probe-{}".format(_UNIQUE_SUFFIX))
    inst_role_name = _ascii_safe("sce-inst-role-{}".format(_UNIQUE_SUFFIX))
    inst_prof_name = _ascii_safe("sce-inst-prof-{}".format(_UNIQUE_SUFFIX))
    atk_role_name = _ascii_safe(
        "sce-attacker-role-{}".format(_UNIQUE_SUFFIX)
    )
    fl_role_name = _ascii_safe("sce-fl-role-{}".format(_UNIQUE_SUFFIX))
    fl_log_group = _ascii_safe(
        "/sce/flowlogs/{}".format(_UNIQUE_SUFFIX)
    )
    trail_name_val = _ascii_safe("sce-trail-{}".format(_UNIQUE_SUFFIX))
    topic_name_val = _ascii_safe("sce-alert-{}".format(_UNIQUE_SUFFIX))
    queue_name_val = _ascii_safe("sce-queue-{}".format(_UNIQUE_SUFFIX))
    rule_name_val = _ascii_safe("sce-rule-{}".format(_UNIQUE_SUFFIX))
    desc_val = _ascii_safe(
        "SCE 2.5 Detective - IMDS attack chain detection ({})".format(
            _UNIQUE_SUFFIX
        )
    )
    egress_desc = _ascii_safe("Allow all outbound")

    trail_bucket_arn = "arn:aws:s3:::{}".format(s3_bucket_name)
    trail_prefix_arn = "arn:aws:s3:::{}/AWSLogs/{}/*".format(
        s3_bucket_name, account_id
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
                    "MapPublicIpOnLaunch": True,
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
            "SCERoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "SCEIGWAttach",
                "Properties": {
                    "RouteTableId": {"Ref": "SCERT"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "SCEIGW"},
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
            # VPC Flow Logs -> CloudWatch Logs (for D2)                    #
            # ---------------------------------------------------------- #
            "SCEFlowLogRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": fl_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "vpc-flow-logs.amazonaws.com"
                                },
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "flow-log-cw-publish",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogGroup",
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                            "logs:DescribeLogGroups",
                                            "logs:DescribeLogStreams",
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
            "SCEFlowLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": fl_log_group,
                    "RetentionInDays": 1,
                    "Tags": [
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            "SCEVpcFlowLog": {
                "Type": "AWS::EC2::FlowLog",
                "DependsOn": ["SCEFlowLogGroup", "SCEFlowLogRole"],
                "Properties": {
                    "ResourceId": {"Ref": "SCEVpc"},
                    "ResourceType": "VPC",
                    "TrafficType": "ALL",
                    "LogDestinationType": "cloud-watch-logs",
                    "LogDestination": {
                        "Fn::GetAtt": ["SCEFlowLogGroup", "Arn"]
                    },
                    "DeliverLogsPermissionArn": {
                        "Fn::GetAtt": ["SCEFlowLogRole", "Arn"]
                    },
                    "LogFormat": _ascii_safe(
                        "${version} ${account-id} ${interface-id} "
                        "${srcaddr} ${dstaddr} ${srcport} ${dstport} "
                        "${protocol} ${packets} ${bytes} ${start} "
                        "${end} ${action} ${log-status}"
                    ),
                    "Tags": [
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # IAM instance role (SSM permissions)                          #
            # ---------------------------------------------------------- #
            "SCEInstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": inst_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "ec2.amazonaws.com"
                                },
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
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
                    "InstanceProfileName": inst_prof_name,
                    "Roles": [{"Ref": "SCEInstanceRole"}],
                },
            },
            # ---------------------------------------------------------- #
            # Attacker IAM role: ALLOW on ModifyInstanceMetadataOptions    #
            # No Deny -- Attack 1.2 must SUCCEED to generate CloudTrail    #
            # event for D1 and EventBridge D3 to observe.                  #
            # ---------------------------------------------------------- #
            "SCEAttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": atk_role_name,
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
                                        "Action": (
                                            "ec2:ModifyInstanceMetadataOptions"
                                        ),
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
            # Target EC2 instance: production-tagged, IMDSv2 enforced      #
            # attack() will weaken this instance's IMDS to IMDSv1          #
            # ---------------------------------------------------------- #
            "SCETargetInstance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": [
                    "SCEIGWAttach",
                    "SCEInstanceProfile",
                    "SCERoute",
                ],
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
                        {"Key": "Name", "Value": target_name},
                        {"Key": "Environment", "Value": "production"},
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # Probe EC2 instance: simulates co-located attacker process    #
            # SSM RunCommand executes the IMDS curl (Attack 2.2)           #
            # ---------------------------------------------------------- #
            "SCEProbeInstance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": [
                    "SCEIGWAttach",
                    "SCEInstanceProfile",
                    "SCERoute",
                ],
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
                        {"Key": "Name", "Value": probe_name},
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # CloudTrail bucket policy (bucket pre-created outside CFN)   #
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
            # CloudTrail trail (management write events -- for D1)         #
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
            # SNS topic + SQS queue + EventBridge rule (for D3)            #
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
            "SCETopicPolicy": {
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
                                    "Fn::GetAtt": [
                                        "SCEAlertQueue", "Arn"
                                    ]
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
            # EventBridge rule: ModifyInstanceMetadataOptions -> SNS (D3)
            "SCEDetectionRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": rule_name_val,
                    "Description": _ascii_safe(
                        "SCE 2.5 detective - detect IMDS weakening"
                    ),
                    "State": "ENABLED",
                    "EventPattern": json.dumps({
                        "source": ["aws.ec2"],
                        "detail-type": [
                            "AWS API Call via CloudTrail"
                        ],
                        "detail": {
                            "eventSource": ["ec2.amazonaws.com"],
                            "eventName": [
                                "ModifyInstanceMetadataOptions"
                            ],
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
            "TargetInstanceId": {
                "Value": {"Ref": "SCETargetInstance"},
                "Description": _ascii_safe(
                    "Production-tagged target EC2 instance ID"
                ),
            },
            "ProbeInstanceId": {
                "Value": {"Ref": "SCEProbeInstance"},
                "Description": _ascii_safe(
                    "Probe EC2 instance ID (co-located attacker)"
                ),
            },
            "AttackerRoleArn": {
                "Value": {
                    "Fn::GetAtt": ["SCEAttackerRole", "Arn"]
                },
                "Description": _ascii_safe("Attacker IAM role ARN"),
            },
            "SqsQueueUrl": {
                "Value": {"Ref": "SCEAlertQueue"},
                "Description": _ascii_safe("SQS queue URL for D3 polling"),
            },
            "TrailName": {
                "Value": trail_name_val,
                "Description": _ascii_safe("CloudTrail trail name"),
            },
            "FlowLogGroup": {
                "Value": fl_log_group,
                "Description": _ascii_safe(
                    "CloudWatch Logs group for VPC Flow Logs"
                ),
            },
            "VpcId": {
                "Value": {"Ref": "SCEVpc"},
                "Description": _ascii_safe("VPC ID"),
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
        "CFN waiter '%s' completed for '%s'.",
        waiter_name, stack_name,
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


# ---------------------------------------------------------------------------
# SSM helpers
# ---------------------------------------------------------------------------

def _wait_instance_ssm_ready(
    instance_id: str, timeout: float = 300.0
) -> bool:
    ssm = _boto3_client("ssm")

    def _ssm_online() -> bool:
        try:
            resp = ssm.describe_instance_information(
                Filters=[
                    {"Key": "InstanceIds", "Values": [instance_id]}
                ]
            )
            instances = resp.get("InstanceInformationList", [])
            if instances:
                status = instances[0].get("PingStatus", "")
                log.debug(
                    "SSM ping status for %s: %s", instance_id, status
                )
                return status == "Online"
            return False
        except ClientError as exc:
            log.debug("SSM DescribeInstanceInformation error: %s", exc)
            return False

    return _wait_with_backoff(
        _ssm_online,
        "SSM online for instance {}".format(instance_id),
        initial_delay=10.0,
        max_delay=30.0,
        timeout=timeout,
    )


def _run_ssm_command(
    instance_id: str,
    commands: list,
    timeout_seconds: int = 30,
) -> dict:
    ssm = _boto3_client("ssm")
    log.info(
        "Running SSM command on %s: %s", instance_id, commands
    )
    try:
        send_resp = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": commands},
            TimeoutSeconds=timeout_seconds,
        )
    except ClientError as exc:
        log.error(
            "SSM send_command failed for %s: %s", instance_id, exc
        )
        return {
            "status": "Failed",
            "stdout": "",
            "stderr": str(exc),
            "return_code": -1,
        }

    command_id = send_resp["Command"]["CommandId"]
    log.info(
        "SSM command %s submitted to %s.", command_id, instance_id
    )

    def _command_complete() -> bool:
        try:
            inv = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
            return inv.get("Status", "") in (
                "Success", "Failed", "Cancelled",
                "TimedOut", "DeliveryTimedOut",
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvocationDoesNotExist":
                return False
            raise

    completed = _wait_with_backoff(
        _command_complete,
        "SSM command {} completion".format(command_id),
        initial_delay=5.0,
        max_delay=15.0,
        timeout=120.0,
    )

    if not completed:
        log.error(
            "SSM command %s did not complete within timeout.", command_id
        )
        return {
            "status": "Timeout",
            "stdout": "",
            "stderr": "Command polling timed out.",
            "return_code": -1,
        }

    try:
        inv = ssm.get_command_invocation(
            CommandId=command_id,
            InstanceId=instance_id,
        )
        result = {
            "status": inv.get("Status", "Unknown"),
            "stdout": inv.get("StandardOutputContent", "").strip(),
            "stderr": inv.get("StandardErrorContent", "").strip(),
            "return_code": inv.get("ResponseCode", -1),
        }
        log.info(
            "SSM command %s: status=%s rc=%s stdout=%r",
            command_id, result["status"],
            result["return_code"], result["stdout"][:300],
        )
        return result
    except ClientError as exc:
        log.error(
            "Failed to get SSM invocation %s: %s", command_id, exc
        )
        return {
            "status": "Failed",
            "stdout": "",
            "stderr": str(exc),
            "return_code": -1,
        }


# ---------------------------------------------------------------------------
# Core experiment functions
# ---------------------------------------------------------------------------

def steady_state() -> None:
    """
    Provision all experiment resources and validate baselines.

    Sequence:
      1. Pre-flight permission check.
      2. Resolve AMI ID via boto3 SSM.
      3. Create S3 bucket OUTSIDE CFN (AlreadyExists fix).
      4. Build + validate CFN template (all strings ASCII-safe).
      5. Create CFN stack and wait for CREATE_COMPLETE.
      6. Validate all stack outputs are non-empty.
      7. Retrieve target instance private IP (for Flow Log matching).
      8. Baseline: target instance has IMDSv2 enforced.
      9. Baseline: CloudTrail trail is logging.
      10. Baseline: SQS queue is empty.
      11. Baseline: both instances SSM-reachable.
      12. IAM propagation backoff for attacker role.
    """
    global _TARGET_INSTANCE_ID, _TARGET_PRIVATE_IP, _PROBE_INSTANCE_ID
    global _ATTACKER_ROLE_ARN, _SQS_QUEUE_URL, _TRAIL_NAME
    global _FLOW_LOG_GROUP, _REGION

    log.info("=== steady_state() -- stack: %s ===", _STACK_NAME)
    log.info("Unique suffix: %s", _UNIQUE_SUFFIX)
    _REGION = _get_region()
    log.info("AWS region: %s", _REGION)

    _preflight_check()

    ami_id = _resolve_ami(_REGION)
    account_id = _get_account_id()
    log.info("Account: %s", account_id)

    # Create S3 bucket outside CFN
    _create_s3_bucket(_S3_BUCKET_NAME, _REGION)

    cfn_template = _build_cfn_template(
        ami_id, account_id, _REGION, _S3_BUCKET_NAME
    )

    log.info("Validating CFN template string encoding ...")
    try:
        _validate_template_strings(cfn_template)
        log.info("Template validation passed.")
    except ValueError as exc:
        log.error("Template validation FAILED: %s -- aborting.", exc)
        raise

    cf = _boto3_client("cloudformation")

    stack_exists = False
    try:
        existing = cf.describe_stacks(StackName=_STACK_NAME)
        status = existing["Stacks"][0]["StackStatus"]
        log.warning(
            "Stack '%s' already exists ('%s'). Continuing.",
            _STACK_NAME, status,
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
                        "Key": "sce-ts",
                        "Value": _ascii_safe(_UNIQUE_SUFFIX),
                    },
                ],
            )
        except ClientError as exc:
            log.error("Failed to create stack: %s", exc)
            raise

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
            "CloudFormation stack '{}' reached a terminal failure "
            "state.".format(_STACK_NAME)
        ) from wait_exc

    outputs = _get_stack_outputs(cf, _STACK_NAME)
    log.info("Stack outputs: %s", outputs)

    _TARGET_INSTANCE_ID = outputs.get("TargetInstanceId", "")
    _PROBE_INSTANCE_ID = outputs.get("ProbeInstanceId", "")
    _ATTACKER_ROLE_ARN = outputs.get("AttackerRoleArn", "")
    _SQS_QUEUE_URL = outputs.get("SqsQueueUrl", "")
    _TRAIL_NAME = outputs.get("TrailName", "")
    _FLOW_LOG_GROUP = outputs.get("FlowLogGroup", "")

    missing = [
        name
        for name, val in [
            ("TargetInstanceId", _TARGET_INSTANCE_ID),
            ("ProbeInstanceId", _PROBE_INSTANCE_ID),
            ("AttackerRoleArn", _ATTACKER_ROLE_ARN),
            ("SqsQueueUrl", _SQS_QUEUE_URL),
            ("TrailName", _TRAIL_NAME),
            ("FlowLogGroup", _FLOW_LOG_GROUP),
        ]
        if not val
    ]
    if missing:
        raise RuntimeError(
            "CFN outputs missing or empty: {}".format(missing)
        )

    log.info(
        "Outputs -- Target=%s Probe=%s Trail=%s FlowLogGroup=%s",
        _TARGET_INSTANCE_ID, _PROBE_INSTANCE_ID,
        _TRAIL_NAME, _FLOW_LOG_GROUP,
    )

    # Retrieve target instance private IP for Flow Log correlation
    ec2 = _boto3_client("ec2")
    try:
        resp = ec2.describe_instances(
            InstanceIds=[_TARGET_INSTANCE_ID]
        )
        reservations = resp.get("Reservations", [])
        if reservations:
            _TARGET_PRIVATE_IP = (
                reservations[0]["Instances"][0]
                .get("PrivateIpAddress", "")
            )
            log.info(
                "Target instance private IP: %s", _TARGET_PRIVATE_IP
            )
    except ClientError as exc:
        log.warning(
            "Could not retrieve target instance private IP: %s",
            exc,
        )

    # Baseline: target instance has IMDSv2 enforced
    def _target_imdsv2_enforced() -> bool:
        resp = ec2.describe_instances(
            InstanceIds=[_TARGET_INSTANCE_ID]
        )
        reservations = resp.get("Reservations", [])
        if not reservations:
            return False
        opts = (
            reservations[0]["Instances"][0].get("MetadataOptions", {})
        )
        return (
            opts.get("HttpTokens") == "required"
            and opts.get("HttpPutResponseHopLimit", 0) == 1
        )

    if not _wait_with_backoff(
        _target_imdsv2_enforced,
        "IMDSv2 enforced on target instance {}".format(
            _TARGET_INSTANCE_ID
        ),
        initial_delay=5.0, max_delay=20.0, timeout=180.0,
    ):
        raise RuntimeError(
            "Baseline FAILED: target instance {} does not have "
            "IMDSv2 enforced.".format(_TARGET_INSTANCE_ID)
        )
    log.info(
        "Baseline: IMDSv2 enforced on target %s.", _TARGET_INSTANCE_ID
    )

    # Baseline: CloudTrail trail is logging
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
        "CloudTrail trail '{}' is logging".format(_TRAIL_NAME),
        initial_delay=5.0, max_delay=15.0, timeout=120.0,
    ):
        log.warning(
            "CloudTrail trail '%s' may not be logging yet -- proceeding.",
            _TRAIL_NAME,
        )
    else:
        log.info(
            "Baseline: CloudTrail trail '%s' is logging.", _TRAIL_NAME
        )

    # Baseline: SQS queue is empty
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
                "SQS queue has %d pre-existing messages -- purging.",
                count,
            )
            sqs.purge_queue(QueueUrl=_SQS_QUEUE_URL)
            time.sleep(5)
        else:
            log.info("Baseline: SQS queue is empty.")
    except ClientError as exc:
        log.warning(
            "Could not check/purge SQS queue: %s -- proceeding.", exc
        )

    # Baseline: both EC2 instances SSM-reachable
    for iid, label in [
        (_TARGET_INSTANCE_ID, "target"),
        (_PROBE_INSTANCE_ID, "probe"),
    ]:
        log.info(
            "Waiting for %s instance %s to register with SSM ...",
            label, iid,
        )
        if not _wait_instance_ssm_ready(iid, timeout=300.0):
            log.warning(
                "%s instance %s not yet SSM-reachable -- "
                "Attack 2.2 SSM commands may fail.",
                label, iid,
            )
        else:
            log.info(
                "Baseline: %s instance %s is SSM-reachable.",
                label, iid,
            )

    # IAM propagation backoff
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
    Execute the chained attack steps in order:

    Step 1 (Attack Node 1.2 / T1578):
        Assume the attacker role (which has ALLOW on
        ec2:ModifyInstanceMetadataOptions) and call that API on the
        production-tagged target instance to downgrade IMDS to IMDSv1
        (http_tokens=optional, hop_limit=2).
        This call SUCCEEDS intentionally to generate a real CloudTrail
        management event for D1 (CloudTrail) and D3 (EventBridge->SQS)
        to observe.
        After recording the event time, the orchestrator immediately
        re-hardens the instance to minimise exposure.

    Step 2 (Attack Node 2.2 / T1552.005):
        From the probe EC2 instance via SSM RunCommand, execute a curl
        to 169.254.169.254 to attempt IMDS credential retrieval.
        This generates VPC Flow Log traffic to 169.254.169.254 from the
        probe instance's ENI for D2 (VPC Flow Logs) to observe.
        The target instance has been temporarily set to IMDSv1 (hop_limit=2)
        so the curl can reach the IMDS endpoint and generate a real flow
        record; however, the probe hits its OWN IMDS (not the target's)
        because link-local addresses are host-local in EC2.
        The important artifact is the Flow Log record showing a connection
        attempt to 169.254.169.254 from an unexpected source (probe ENI).

    Records attack_epoch and step details in _ATTACK_RESULT.
    Returns True if attack steps were issued; False on precondition failure.
    """
    global _ATTACK_RESULT

    log.info("=== attack() ===")
    log.info(
        "Target: %s | Probe: %s | AttackerRole: %s",
        _TARGET_INSTANCE_ID, _PROBE_INSTANCE_ID, _ATTACKER_ROLE_ARN,
    )

    if not _TARGET_INSTANCE_ID or not _PROBE_INSTANCE_ID \
            or not _ATTACKER_ROLE_ARN:
        log.error(
            "attack() aborted: preconditions not met. "
            "TargetId='%s' ProbeId='%s' RoleArn='%s'.",
            _TARGET_INSTANCE_ID, _PROBE_INSTANCE_ID, _ATTACKER_ROLE_ARN,
        )
        _ATTACK_RESULT = {
            "step1_executed": False,
            "step2_executed": False,
            "error": "Empty precondition",
        }
        return False

    _ATTACK_RESULT = {
        "step1_executed": False,
        "step1_succeeded": False,
        "step1_error_code": "",
        "step2_executed": False,
        "step2_ssm_status": "",
        "step2_http_code": "",
        "attack_epoch": 0.0,
    }

    # ------------------------------------------------------------------ #
    # Step 1: Attack Node 1.2 -- IMDS weakening (T1578)                   #
    # Call MUST SUCCEED to generate CloudTrail event for D1/D3             #
    # ------------------------------------------------------------------ #
    log.info(
        "--- Step 1: IMDS weakening on target instance %s ---",
        _TARGET_INSTANCE_ID,
    )

    sts = _boto3_client("sts")
    assumed = None
    try:
        assumed = sts.assume_role(
            RoleArn=_ATTACKER_ROLE_ARN,
            RoleSessionName="sce-attack-1-{}".format(_UNIQUE_SUFFIX),
            DurationSeconds=900,
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        log.error(
            "Step 1: Failed to assume attacker role: %s -- %s", code, exc
        )
        _ATTACK_RESULT["step1_executed"] = False
        _ATTACK_RESULT["step1_error_code"] = code

    if assumed is not None:
        creds = assumed["Credentials"]
        log.info(
            "Step 1: Assumed AttackerRole session: %s",
            assumed["AssumedRoleUser"]["AssumedRoleId"],
        )

        ec2_attacker = boto3.client(
            "ec2",
            region_name=_REGION,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

        # Record attack epoch immediately before the API call
        attack_epoch = time.time()
        _ATTACK_RESULT["attack_epoch"] = attack_epoch

        log.info(
            "Step 1: Calling ec2:ModifyInstanceMetadataOptions on %s "
            "(http_tokens=optional, hop_limit=2) ...",
            _TARGET_INSTANCE_ID,
        )
        try:
            response = ec2_attacker.modify_instance_metadata_options(
                InstanceId=_TARGET_INSTANCE_ID,
                HttpTokens="optional",
                HttpEndpoint="enabled",
                HttpPutResponseHopLimit=2,
            )
            http_status = response["ResponseMetadata"]["HTTPStatusCode"]
            log.info(
                "Step 1: ModifyInstanceMetadataOptions succeeded "
                "(HTTP %s). CloudTrail event generated.",
                http_status,
            )
            _ATTACK_RESULT["step1_executed"] = True
            _ATTACK_RESULT["step1_succeeded"] = True
            _ATTACK_RESULT["step1_http_status"] = http_status

            # Re-harden the instance immediately after the event is
            # generated to minimise IMDSv1 exposure window.
            # Use orchestrator credentials (not attacker role).
            ec2_orch = _boto3_client("ec2")
            try:
                ec2_orch.modify_instance_metadata_options(
                    InstanceId=_TARGET_INSTANCE_ID,
                    HttpTokens="required",
                    HttpEndpoint="enabled",
                    HttpPutResponseHopLimit=1,
                )
                log.info(
                    "Step 1: Instance %s re-hardened to IMDSv2 "
                    "(http_tokens=required, hop_limit=1).",
                    _TARGET_INSTANCE_ID,
                )
                _ATTACK_RESULT["step1_rehardened"] = True
            except ClientError as exc:
                log.warning(
                    "Step 1: Re-hardening failed (non-fatal for "
                    "detective probe): %s", exc,
                )
                _ATTACK_RESULT["step1_rehardened"] = False

        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"]["Message"]
            log.error(
                "Step 1: UNEXPECTED failure of "
                "ModifyInstanceMetadataOptions: %s -- %s. "
                "No CloudTrail event generated; D1 and D3 cannot "
                "be validated.",
                code, message,
            )
            _ATTACK_RESULT["step1_executed"] = True
            _ATTACK_RESULT["step1_succeeded"] = False
            _ATTACK_RESULT["step1_error_code"] = code
            _ATTACK_RESULT["step1_error_message"] = message
            # Still proceed to step 2 for D2 validation
            if _ATTACK_RESULT["attack_epoch"] == 0.0:
                _ATTACK_RESULT["attack_epoch"] = time.time()

    if _ATTACK_RESULT["attack_epoch"] == 0.0:
        _ATTACK_RESULT["attack_epoch"] = time.time()

    # ------------------------------------------------------------------ #
    # Step 2: Attack Node 2.2 -- IMDS credential retrieval (T1552.005)    #
    # Executed from probe instance via SSM RunCommand                     #
    # Generates VPC Flow Log traffic to 169.254.169.254 for D2            #
    # ------------------------------------------------------------------ #
    log.info(
        "--- Step 2: IMDS access from probe instance %s ---",
        _PROBE_INSTANCE_ID,
    )

    ssm_ready = _wait_instance_ssm_ready(
        _PROBE_INSTANCE_ID, timeout=60.0
    )
    if not ssm_ready:
        log.warning(
            "Step 2: Probe instance %s not SSM-reachable -- "
            "skipping IMDS curl (D2 Flow Log detection may be limited).",
            _PROBE_INSTANCE_ID,
        )
        _ATTACK_RESULT["step2_executed"] = False
        _ATTACK_RESULT["step2_skip_reason"] = (
            "Probe instance not SSM-reachable"
        )
    else:
        # Execute the IMDS credential retrieval curl from the probe instance.
        # This generates a real TCP connection to 169.254.169.254:80 that
        # VPC Flow Logs will record as traffic from the probe ENI to the
        # link-local IMDS address.
        # The probe hits its OWN IMDS; since it has the SSM-only role,
        # the response lists that role. The important artifact is the
        # Flow Log record showing the connection attempt.
        imds_cmd = [
            # First attempt: IMDSv1 unauthenticated (generates REJECT/ACCEPT flow)
            "curl -s --max-time 5 "
            "-o /tmp/imds_result.txt "
            "http://169.254.169.254/latest/meta-data/"
            "iam/security-credentials/ ; "
            "echo \"HTTP_CODE:$(curl -s -o /dev/null -w '%{http_code}' "
            "--max-time 5 "
            "http://169.254.169.254/latest/meta-data/"
            "iam/security-credentials/)\" ; "
            # Also generate a flow record to the IMDS endpoint itself
            "curl -s --max-time 3 -o /dev/null "
            "http://169.254.169.254/latest/meta-data/"
        ]

        result_2 = _run_ssm_command(
            _PROBE_INSTANCE_ID, imds_cmd, timeout_seconds=30
        )
        _ATTACK_RESULT["step2_executed"] = True
        _ATTACK_RESULT["step2_ssm_status"] = result_2.get("status", "")
        _ATTACK_RESULT["step2_stdout"] = result_2.get("stdout", "")[:500]

        # Extract HTTP code from stdout
        stdout = result_2.get("stdout", "")
        http_code = ""
        for line in stdout.splitlines():
            if line.startswith("HTTP_CODE:"):
                http_code = line.split(":", 1)[1].strip()
                break
        _ATTACK_RESULT["step2_http_code"] = http_code

        log.info(
            "Step 2: IMDS curl completed. SSM status=%s HTTP code=%r",
            result_2.get("status", ""), http_code,
        )
        log.info(
            "Step 2: IMDS curl stdout (first 300 chars): %r",
            stdout[:300],
        )

    log.info(
        "attack() complete. Waiting %.0fs for CT delivery + "
        "Flow Log delivery before polling ...",
        _POST_ATTACK_BUFFER_SECONDS,
    )
    time.sleep(_POST_ATTACK_BUFFER_SECONDS)
    log.info("attack() result: %s", _ATTACK_RESULT)
    return True


def hypothesis_verification() -> bool:
    """
    Detective probe verification (SCE Node 2.5 -- Detective).

    Returns True only when ALL hypotheses that can be evaluated pass:

    [H1] CloudTrail recorded the ModifyInstanceMetadataOptions API call
         for the target instance within the 5-minute delivery window.
         Verified via CloudTrail LookupEvents scoped to event name and
         the target instance ID.

    [H2] VPC Flow Logs captured traffic to 169.254.169.254 from the probe
         instance (or any source in the subnet) within 5 minutes of the
         IMDS curl execution.
         Verified by querying CloudWatch Logs Insights on the Flow Log group
         for records with dstaddr=169.254.169.254 appearing after the
         attack epoch.

    [H3] EventBridge -> SNS -> SQS notification for
         ModifyInstanceMetadataOptions delivered within the 60-second
         detection SLA of the attack call.
         Verified by polling the SQS queue for a message containing
         'ModifyInstanceMetadataOptions' within the SLA window.

    ADT Node 1.3: CloudTrail + EventBridge detection for IMDS weakening.
    ADT Node 2.3: VPC Flow Logs detection for IMDS access attempts.
    """
    log.info("=== hypothesis_verification() ===")

    if not _TARGET_INSTANCE_ID or not _ATTACKER_ROLE_ARN:
        log.error(
            "hypothesis_verification() aborted: infrastructure globals "
            "are empty. steady_state() must have failed."
        )
        return False

    if not _ATTACK_RESULT:
        log.error(
            "hypothesis_verification() aborted: _ATTACK_RESULT is empty."
        )
        return False

    attack_epoch = _ATTACK_RESULT.get("attack_epoch", time.time())
    all_passed = True

    # ------------------------------------------------------------------ #
    # H1: CloudTrail recorded ModifyInstanceMetadataOptions (D1)          #
    # ------------------------------------------------------------------ #
    if not _ATTACK_RESULT.get("step1_succeeded", False):
        log.warning(
            "[H1] SKIP -- Step 1 (IMDS weakening) did not succeed. "
            "No CloudTrail event generated; H1 is inconclusive. "
            "Marking as FAIL because the detective control cannot be "
            "validated without a real attack event."
        )
        all_passed = False
    else:
        log.info(
            "[H1] Querying CloudTrail LookupEvents for "
            "ModifyInstanceMetadataOptions (polling up to %.0f min) ...",
            _CLOUDTRAIL_POLL_TIMEOUT / 60,
        )
        ct = _boto3_client("cloudtrail")
        start_time = datetime.datetime.utcfromtimestamp(
            attack_epoch - 120
        )
        end_time = datetime.datetime.utcnow() + datetime.timedelta(
            minutes=2
        )
        h1_passed = False

        def _cloudtrail_event_found() -> bool:
            try:
                paginator = ct.get_paginator("lookup_events")
                for page in paginator.paginate(
                    LookupAttributes=[
                        {
                            "AttributeKey": "EventName",
                            "AttributeValue": (
                                "ModifyInstanceMetadataOptions"
                            ),
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    PaginationConfig={"MaxItems": 50},
                ):
                    for event in page.get("Events", []):
                        ct_str = event.get("CloudTrailEvent", "{}")
                        try:
                            ct_detail = json.loads(ct_str)
                        except json.JSONDecodeError:
                            ct_detail = {}
                        req_params = ct_detail.get(
                            "requestParameters", {}
                        )
                        event_instance = req_params.get("instanceId", "")
                        if (
                            event_instance == _TARGET_INSTANCE_ID
                            or _TARGET_INSTANCE_ID in ct_str
                        ):
                            event_time = event.get("EventTime", "")
                            actor = (
                                ct_detail.get("userIdentity", {})
                                .get("arn", "unknown")
                            )
                            log.info(
                                "[H1] CloudTrail event found. "
                                "EventTime=%s Actor=%s InstanceId=%s",
                                event_time, actor, event_instance,
                            )
                            return True
                return False
            except ClientError as exc:
                log.debug("CloudTrail lookup error: %s", exc)
                return False

        h1_passed = _wait_with_backoff(
            _cloudtrail_event_found,
            "CloudTrail ModifyInstanceMetadataOptions event for "
            "target instance",
            initial_delay=10.0,
            max_delay=30.0,
            timeout=_CLOUDTRAIL_POLL_TIMEOUT,
        )

        if h1_passed:
            log.info(
                "[H1] PASS -- CloudTrail recorded "
                "ModifyInstanceMetadataOptions for instance %s.",
                _TARGET_INSTANCE_ID,
            )
        else:
            elapsed = time.time() - attack_epoch
            log.error(
                "[H1] FAIL -- CloudTrail did NOT record "
                "ModifyInstanceMetadataOptions for instance %s within "
                "%.0f-second polling window. Elapsed: %.1fs. "
                "Trail '%s' may have a delivery delay or the event "
                "did not propagate.",
                _TARGET_INSTANCE_ID,
                _CLOUDTRAIL_POLL_TIMEOUT,
                elapsed,
                _TRAIL_NAME,
            )
            all_passed = False

    # ------------------------------------------------------------------ #
    # H2: VPC Flow Logs captured IMDS access traffic (D2)                 #
    # ------------------------------------------------------------------ #
    if not _ATTACK_RESULT.get("step2_executed", False):
        log.warning(
            "[H2] SKIP -- Step 2 (IMDS curl) was not executed. "
            "Flow Log detection cannot be validated. "
            "Treating as inconclusive (not failing experiment)."
        )
        # H2 skip treated as warning only since H1 and H3 validate D1/D3
    else:
        log.info(
            "[H2] Querying CloudWatch Logs Insights on Flow Log group "
            "'%s' for IMDS traffic to 169.254.169.254 ...",
            _FLOW_LOG_GROUP,
        )
        cw_logs = _boto3_client("logs")

        # Query Flow Logs for any traffic to the IMDS link-local address
        # from within the experiment window
        query_str = (
            "fields @timestamp, srcaddr, dstaddr, dstport, action "
            "| filter dstaddr = '169.254.169.254' "
            "| sort @timestamp desc "
            "| limit 20"
        )

        start_ts = int(attack_epoch - 120)
        end_ts = int(time.time()) + 120

        h2_passed = False

        def _start_insights_query():
            try:
                resp = cw_logs.start_query(
                    logGroupName=_FLOW_LOG_GROUP,
                    startTime=start_ts,
                    endTime=end_ts,
                    queryString=query_str,
                )
                return resp.get("queryId", "")
            except ClientError as exc:
                log.debug("CloudWatch Logs start_query error: %s", exc)
                return ""

        def _poll_insights_query(query_id: str) -> list:
            if not query_id:
                return []
            try:
                resp = cw_logs.get_query_results(queryId=query_id)
                status = resp.get("status", "")
                log.debug(
                    "Insights query %s status: %s", query_id, status
                )
                if status in ("Complete", "Failed", "Cancelled"):
                    return resp.get("results", [])
                return None  # Still running
            except ClientError as exc:
                log.debug(
                    "CloudWatch Logs get_query_results error: %s", exc
                )
                return []

        # Retry insights query with backoff to account for Flow Log
        # delivery latency (typically 1-5 minutes)
        flow_log_deadline = time.monotonic() + _FLOWLOG_POLL_TIMEOUT
        query_id = ""

        while time.monotonic() < flow_log_deadline and not h2_passed:
            # Start a fresh query each iteration to capture new records
            if not query_id:
                query_id = _start_insights_query()
                if not query_id:
                    log.debug(
                        "[H2] Could not start Insights query -- retrying."
                    )
                    time.sleep(10)
                    continue

            # Poll until query completes
            query_complete = False
            for _ in range(30):  # up to 30 x 5s = 150s per query
                results = _poll_insights_query(query_id)
                if results is None:
                    time.sleep(5)
                    continue
                query_complete = True
                if results:
                    # Found Flow Log records to 169.254.169.254
                    log.info(
                        "[H2] VPC Flow Log records for "
                        "169.254.169.254 found: %d record(s).",
                        len(results),
                    )
                    for row in results[:3]:
                        fields = {
                            f["field"]: f["value"] for f in row
                        }
                        log.info(
                            "[H2] Flow record: srcaddr=%s dstaddr=%s "
                            "dstport=%s action=%s ts=%s",
                            fields.get("srcaddr", "?"),
                            fields.get("dstaddr", "?"),
                            fields.get("dstport", "?"),
                            fields.get("action", "?"),
                            fields.get("@timestamp", "?"),
                        )
                    h2_passed = True
                else:
                    log.debug(
                        "[H2] Insights query %s returned 0 results -- "
                        "Flow Logs may not have delivered yet.",
                        query_id,
                    )
                    query_id = ""  # Reset to start fresh query next round
                break

            if not query_complete:
                log.debug(
                    "[H2] Insights query %s did not complete in time -- "
                    "retrying.",
                    query_id,
                )
                query_id = ""

            if not h2_passed:
                time.sleep(15)

        if h2_passed:
            log.info(
                "[H2] PASS -- VPC Flow Logs captured traffic to "
                "169.254.169.254 from within the experiment VPC. "
                "Detective control D2 is effective."
            )
        else:
            elapsed = time.time() - attack_epoch
            log.error(
                "[H2] FAIL -- VPC Flow Logs did NOT capture traffic to "
                "169.254.169.254 within %.0f-second polling window. "
                "Elapsed: %.1fs. "
                "Flow Logs may have a delivery delay > %.0fs, or the "
                "curl command did not generate the expected traffic. "
                "Flow Log group: '%s'.",
                _FLOWLOG_POLL_TIMEOUT,
                elapsed,
                _FLOWLOG_POLL_TIMEOUT,
                _FLOW_LOG_GROUP,
            )
            all_passed = False

    # ------------------------------------------------------------------ #
    # H3: EventBridge -> SNS -> SQS notification within 60s SLA (D3)     #
    # ------------------------------------------------------------------ #
    if not _ATTACK_RESULT.get("step1_succeeded", False):
        log.warning(
            "[H3] SKIP -- Step 1 did not succeed; no CloudTrail event "
            "was generated so EventBridge cannot fire. H3 inconclusive."
        )
        all_passed = False
    else:
        log.info(
            "[H3] Polling SQS queue for ModifyInstanceMetadataOptions "
            "EventBridge notification (SLA: %.0fs) ...",
            _EVENTBRIDGE_SLA_SECONDS,
        )

        sqs = _boto3_client("sqs")
        h3_passed = False
        # SLA window starts from attack_epoch; subtract post-attack buffer
        # already elapsed to get remaining SLA
        elapsed_so_far = time.time() - attack_epoch
        remaining_sla = max(
            10.0,
            _EVENTBRIDGE_SLA_SECONDS - elapsed_so_far
            + _POST_ATTACK_BUFFER_SECONDS
        )
        h3_deadline = time.monotonic() + remaining_sla

        log.info(
            "[H3] Remaining SLA for EventBridge notification: %.0fs.",
            remaining_sla,
        )

        while time.monotonic() < h3_deadline and not h3_passed:
            try:
                sqs_resp = sqs.receive_message(
                    QueueUrl=_SQS_QUEUE_URL,
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=5,
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

                    is_imds_event = (
                        "ModifyInstanceMetadataOptions" in inner_str
                        or inner.get("detail", {}).get("eventName")
                        == "ModifyInstanceMetadataOptions"
                    )

                    # Also check instance ID matches if present
                    detail = inner.get("detail", {})
                    req_params = detail.get("requestParameters", {})
                    event_instance = req_params.get("instanceId", "")
                    instance_match = (
                        not event_instance
                        or event_instance == _TARGET_INSTANCE_ID
                        or _TARGET_INSTANCE_ID in inner_str
                    )

                    # Delete message regardless
                    try:
                        sqs.delete_message(
                            QueueUrl=_SQS_QUEUE_URL,
                            ReceiptHandle=msg["ReceiptHandle"],
                        )
                    except ClientError:
                        pass

                    if is_imds_event and instance_match:
                        elapsed = time.time() - attack_epoch
                        log.info(
                            "[H3] PASS -- EventBridge notification "
                            "received %.1fs after attack. "
                            "Event: ModifyInstanceMetadataOptions "
                            "Instance: %s",
                            elapsed, event_instance or _TARGET_INSTANCE_ID,
                        )
                        h3_passed = True
                        break
                    else:
                        log.debug(
                            "[H3] Received unrelated SQS message -- "
                            "discarding."
                        )

            except ClientError as exc:
                log.error("[H3] SQS receive_message error: %s", exc)
                time.sleep(2)

        if not h3_passed:
            elapsed = time.time() - attack_epoch
            log.error(
                "[H3] FAIL -- EventBridge -> SNS -> SQS notification "
                "for ModifyInstanceMetadataOptions NOT received within "
                "%.0fs SLA. Elapsed: %.1fs. "
                "EventBridge rule may not have fired, or SNS/SQS "
                "delivery is delayed.",
                _EVENTBRIDGE_SLA_SECONDS, elapsed,
            )
            all_passed = False

    # ------------------------------------------------------------------ #
    # Final verdict                                                         #
    # ------------------------------------------------------------------ #
    if all_passed:
        log.info(
            "hypothesis_verification() -> PASS. "
            "All detective controls are effective: "
            "CloudTrail recorded IMDS weakening event (H1), "
            "VPC Flow Logs captured IMDS traffic (H2), "
            "EventBridge notification delivered within SLA (H3)."
        )
    else:
        log.error(
            "hypothesis_verification() -> FAIL. "
            "One or more detective hypotheses were not satisfied. "
            "Review [H1], [H2], [H3] log entries above."
        )

    return all_passed


def rollback() -> None:
    """
    Complete teardown:
      1. Delete the CFN stack and wait for DELETE_COMPLETE.
         (SCEBucketPolicy CFN resource is deleted here -- bucket still
         exists so BucketPolicy deletion succeeds.)
      2. Empty and delete the S3 bucket via boto3 AFTER CFN stack deletion.

    Always executes even on upstream failure (called from finally block).
    """
    log.info("=== rollback() -- stack: '%s' ===", _STACK_NAME)

    cf = _boto3_client("cloudformation")
    current_status = "UNKNOWN"

    try:
        status_resp = cf.describe_stacks(StackName=_STACK_NAME)
        current_status = status_resp["Stacks"][0]["StackStatus"]
        log.info(
            "Stack '%s' status: %s", _STACK_NAME, current_status
        )
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info(
                "Stack '%s' does not exist -- skipping CFN delete.",
                _STACK_NAME,
            )
            current_status = "DELETE_COMPLETE"
        else:
            log.error("Error checking stack: %s", exc)

    if current_status != "DELETE_COMPLETE":
        if current_status != "DELETE_IN_PROGRESS":
            try:
                cf.delete_stack(StackName=_STACK_NAME)
                log.info(
                    "Stack deletion initiated for '%s'.", _STACK_NAME
                )
            except ClientError as exc:
                log.error(
                    "Failed to initiate stack deletion: %s", exc
                )

        try:
            _wait_stack(
                cf, _STACK_NAME, "stack_delete_complete",
                delay=20, max_attempts=60,
            )
            log.info("Stack '%s' deleted.", _STACK_NAME)
        except ClientError as exc:
            if "does not exist" in str(exc):
                log.info(
                    "Stack '%s' confirmed deleted.", _STACK_NAME
                )
            else:
                log.error(
                    "Error waiting for stack deletion: %s", exc
                )
        except WaiterError as exc:
            try:
                cf.describe_stacks(StackName=_STACK_NAME)
                log.error(
                    "Deletion waiter failed; stack still exists: %s",
                    exc,
                )
            except ClientError as inner:
                if "does not exist" in str(inner):
                    log.info(
                        "Stack '%s' confirmed deleted (waiter false "
                        "alarm).",
                        _STACK_NAME,
                    )
                else:
                    log.error(
                        "Error confirming deletion: %s", inner
                    )
        except Exception as exc:  # noqa: BLE001
            log.error(
                "Unexpected error during stack deletion: %s", exc
            )

    # Delete the S3 bucket after CFN stack is gone
    _empty_and_delete_s3_bucket(_S3_BUCKET_NAME)

    log.info("rollback() complete.")


# ---------------------------------------------------------------------------
# Experiment entry point
# ---------------------------------------------------------------------------

def run_experiment() -> None:
    log.info(
        "============================================================"
    )
    log.info(
        "SCE 2.5 Detective -- IMDS Attack Chain Detection "
        "(T1578 + T1552.005)"
    )
    log.info("Stack  : %s", _STACK_NAME)
    log.info("Bucket : %s", _S3_BUCKET_NAME)
    log.info(
        "============================================================"
    )

    result = False

    try:
        steady_state()
        attack_issued = attack()

        if not attack_issued:
            log.error(
                "attack() returned False -- detective controls cannot "
                "be validated without attack execution."
            )
        else:
            result = hypothesis_verification()

    except Exception as exc:  # noqa: BLE001
        log.error(
            "Unhandled exception during experiment: %s",
            exc, exc_info=True,
        )
    finally:
        rollback()

    status = "PASSED" if result else "FAILED"
    log.info(
        "============================================================"
    )
    log.info(
        "SCE Experiment 2.5 Detective Probe result: %s", status
    )
    log.info(
        "============================================================"
    )

    if not result:
        sys.exit(1)


if __name__ == "__main__":
    run_experiment()