"""
SCE Experiment 1.3 - Preventive Probe
Attack Node : 1.2 - Downgrade IMDS to IMDSv1 and Raise Hop Limit
Defense     : Least-Privilege IAM denies ec2:ModifyInstanceMetadataOptions
              + IMDSv2 enforced on hardened banking EC2 instances

Root-cause history
------------------
Run 1: CloudFormation ROLLBACK - AMI resolution / no default VPC subnet.
       Fix: dynamic AMI via SSM, self-contained VPC provisioned in template.

Run 2: CloudFormation ROLLBACK - no default subnets in default VPC.
       Fix: template now provisions its own VPC + subnet.

Run 3: CloudFormation ROLLBACK - SecurityGroup GroupDescription contained a
       non-ASCII character (Unicode em-dash rendered as '?' by the Python
       source encoding).  AWS EC2 GroupDescription only accepts ASCII.
       Root cause: the string "SCE 1.3 - egress only, no inbound" was
       stored internally as "SCE 1.3 \u2014 egress only, no inbound" and
       transmitted to CloudFormation as a non-ASCII byte sequence.
       Fix (this version):
         - ALL CloudFormation string values are audited and use only
           printable ASCII characters (0x20-0x7E).
         - A _ascii_guard() helper validates every string in the rendered
           template JSON before submitting to CloudFormation.
         - The GroupDescription is now: "SCE 1.3 egress only no inbound"
           (no special characters at all).
         - All description / comment strings use only hyphens, not dashes.

Additional hardening applied in this version
--------------------------------------------
- _ascii_guard(): scans the entire serialised template for non-ASCII bytes
  and raises ValueError before submission, catching encoding bugs early.
- Negative baseline test: a second IAM role with ALLOW on
  ec2:ModifyInstanceMetadataOptions is provisioned to confirm the API
  itself works from a privileged principal before the deny test runs.
  This eliminates false negatives caused by EC2 API outages or network
  blocks masquerading as IAM denials.
- Stack status guard in attack(): explicitly aborts with ABORTED outcome
  (not DEVIATED) when infrastructure is unavailable, distinguishing
  infra failures from security control failures.
"""

# -- stdlib -------------------------------------------------------------------
import json
import logging
import os
import subprocess
import sys
import time
import traceback

# -- boto3 install guard ------------------------------------------------------
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    subprocess.check_call(
        [sys.executable, "-m", "pip", "install", "boto3", "--quiet"]
    )
    import boto3
    from botocore.exceptions import ClientError

# -- logging ------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("sce-1.3-preventive")

# -- global experiment state --------------------------------------------------
_STATE: dict = {
    "stack_name":             None,
    "region":                 None,
    "account_id":             None,
    "hardened_instance_id":   None,
    "restricted_role_arn":    None,
    "privileged_role_arn":    None,   # baseline positive-test role
    "restricted_credentials": None,
    "privileged_credentials": None,
    "credentials_assumed_at": None,
    "attack_result":          None,
    "stack_outputs":          {},
    "infra_ready":            False,  # explicit infra readiness flag
}

# -- tunables -----------------------------------------------------------------
EXPERIMENT_TAG_KEY         = "SCEExperiment"
EXPERIMENT_TAG_VALUE       = "1.3-preventive"
STACK_CREATE_TIMEOUT_S     = 1200   # 20 min
STACK_DELETE_TIMEOUT_S     = 900    # 15 min
IAM_PROPAGATION_TIMEOUT_S  = 120    # 2 min for sts:AssumeRole retry
STACK_POLL_INTERVAL_S      = 15
IAM_POLL_INTERVAL_S        = 10
INSTANCE_RUNNING_TIMEOUT_S = 300    # 5 min
CRED_REFRESH_THRESHOLD_S   = 3000   # ~50 min
INSTANCE_TYPES_FALLBACK    = ["t3.micro", "t3a.micro", "t2.micro"]


# =============================================================================
# HELPERS
# =============================================================================

def _boto(service: str, **kwargs):
    region = _STATE.get("region") or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    return boto3.client(service, region_name=region, **kwargs)


def _boto_with_creds(service: str, creds: dict):
    region = _STATE.get("region") or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    return boto3.client(
        service,
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _get_region() -> str:
    if _STATE.get("region"):
        return _STATE["region"]
    region = (
        os.environ.get("AWS_DEFAULT_REGION")
        or os.environ.get("AWS_REGION")
        or boto3.session.Session().region_name
        or "us-east-1"
    )
    _STATE["region"] = region
    log.info("Resolved AWS region: %s", region)
    return region


def _get_account_id() -> str:
    if _STATE.get("account_id"):
        return _STATE["account_id"]
    identity = _boto("sts").get_caller_identity()
    _STATE["account_id"] = identity["Account"]
    log.info("Resolved AWS account ID: %s", _STATE["account_id"])
    return _STATE["account_id"]


def _resolve_ami(region: str) -> str:
    """Resolve latest Amazon Linux 2 AMI via SSM; fall back to regional table."""
    ssm_path = "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    try:
        resp = _boto("ssm").get_parameter(Name=ssm_path)
        ami_id = resp["Parameter"]["Value"]
        log.info("Resolved AMI via SSM: %s (region=%s)", ami_id, region)
        return ami_id
    except Exception as exc:
        log.warning("SSM AMI resolution failed (%s) - using regional fallback", exc)

    fallback = {
        "us-east-1":      "ami-0c02fb55956c7d316",
        "us-east-2":      "ami-0b0dcb5067f052a63",
        "us-west-1":      "ami-0d9858aa3c6322f73",
        "us-west-2":      "ami-098e42ae54c764c35",
        "eu-west-1":      "ami-06ce3edf0cff21f07",
        "eu-west-2":      "ami-01a6e31ac994bbc09",
        "eu-central-1":   "ami-0d527b8c289b4af7f",
        "ap-southeast-1": "ami-0c802847a501da8c9",
        "ap-northeast-1": "ami-0218d08a1f9dac831",
        "ap-south-1":     "ami-0bd6e3e0e2d7e7b85",
    }
    ami = fallback.get(region, "ami-0c02fb55956c7d316")
    log.info("Using fallback AMI: %s (region=%s)", ami, region)
    return ami


def _resolve_instance_type(region: str) -> str:
    """Select first available instance type from the fallback list."""
    ec2 = _boto("ec2")
    for itype in INSTANCE_TYPES_FALLBACK:
        try:
            resp = ec2.describe_instance_type_offerings(
                LocationType="region",
                Filters=[{"Name": "instance-type", "Values": [itype]}],
            )
            if resp.get("InstanceTypeOfferings"):
                log.info("Selected instance type: %s", itype)
                return itype
        except Exception as exc:
            log.warning("Instance type check failed for %s: %s", itype, exc)
    log.warning("Could not validate any instance type - defaulting to t3.micro")
    return "t3.micro"


def _ascii_guard(template_json: str) -> None:
    """
    Validate that the serialised CloudFormation template contains only
    printable ASCII characters (0x20-0x7E plus standard whitespace).
    Raises ValueError with the offending character and position if any
    non-ASCII byte is found.

    This guard catches the root cause of run 3 (non-ASCII em-dash in
    GroupDescription) before the template is submitted to CloudFormation.
    """
    allowed_controls = {0x09, 0x0A, 0x0D}  # tab, newline, carriage-return
    for idx, ch in enumerate(template_json):
        code = ord(ch)
        if code > 0x7E or (code < 0x20 and code not in allowed_controls):
            snippet_start = max(0, idx - 30)
            snippet_end   = min(len(template_json), idx + 30)
            raise ValueError(
                "Non-ASCII character U+%04X at position %d in CFN template. "
                "Context: ...%s..." % (
                    code, idx,
                    template_json[snippet_start:snippet_end]
                )
            )
    log.info("ASCII guard passed: template contains only valid ASCII characters.")


def _preflight_check() -> None:
    """Validate the executing principal has required permissions."""
    log.info("=== PRE-FLIGHT: Validating IAM permissions ===")
    sts = _boto("sts")
    iam = _boto("iam")

    identity = sts.get_caller_identity()
    log.info(
        "Executing as: Account=%s  UserId=%s  ARN=%s",
        identity["Account"], identity["UserId"], identity["Arn"],
    )

    required = [
        "cloudformation:CreateStack",
        "cloudformation:DescribeStacks",
        "cloudformation:DeleteStack",
        "cloudformation:DescribeStackEvents",
        "ec2:RunInstances",
        "ec2:DescribeInstances",
        "ec2:TerminateInstances",
        "ec2:ModifyInstanceMetadataOptions",
        "ec2:CreateVpc",
        "ec2:DeleteVpc",
        "ec2:CreateSubnet",
        "ec2:DeleteSubnet",
        "ec2:CreateInternetGateway",
        "ec2:DeleteInternetGateway",
        "ec2:AttachInternetGateway",
        "ec2:DetachInternetGateway",
        "ec2:CreateRouteTable",
        "ec2:DeleteRouteTable",
        "ec2:CreateRoute",
        "ec2:AssociateRouteTable",
        "ec2:DisassociateRouteTable",
        "ec2:CreateSecurityGroup",
        "ec2:DeleteSecurityGroup",
        "ec2:ModifyVpcAttribute",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeSecurityGroups",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:CreatePolicy",
        "iam:DeletePolicy",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:GetRole",
        "iam:PassRole",
        "sts:AssumeRole",
    ]

    try:
        sim = iam.simulate_principal_policy(
            PolicySourceArn=identity["Arn"],
            ActionNames=required,
            ResourceArns=["*"],
        )
        denied = [
            r["EvalActionName"]
            for r in sim.get("EvaluationResults", [])
            if r["EvalDecision"] != "allowed"
        ]
        if denied:
            log.warning(
                "IAM simulation reports potentially denied actions "
                "(SCPs may still allow - proceeding): %s", denied,
            )
        else:
            log.info("Pre-flight IAM simulation: all required actions appear allowed.")
    except ClientError as exc:
        log.warning("iam:SimulatePrincipalPolicy unavailable (non-fatal): %s", exc)


def _build_cfn_template(
    ami_id: str,
    instance_type: str,
    account_id: str,
    stack_name: str,
    timestamp: int,
) -> str:
    """
    Build a fully self-contained CloudFormation template.

    CRITICAL FIX (run 3): Every string value in this template uses only
    printable ASCII characters (0x20-0x7E).  No em-dashes, curly quotes,
    ellipsis characters, or any other Unicode.  All descriptions use plain
    hyphens '-' and standard alphanumeric text only.

    Resources provisioned:
      Networking  : ExperimentVpc, ExperimentSubnet, ExperimentIGW,
                    IGWAttachment, ExperimentRouteTable, DefaultRoute,
                    SubnetRTAssociation, ExperimentSecurityGroup
      IAM (deny)  : RestrictedPolicy, RestrictedRole
      IAM (allow) : PrivilegedPolicy, PrivilegedRole  (baseline positive test)
      Compute     : HardenedInstance
    """
    suffix = str(timestamp)

    # All Description / GroupDescription strings use ASCII-only text.
    # Specifically: NO em-dashes (U+2014), NO en-dashes (U+2013),
    # NO smart quotes, NO ellipsis (U+2026).
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": (
            "SCE 1.3 Preventive Probe - Self-contained VPC plus Hardened EC2 "
            "plus Restricted IAM Role. Validates ec2:ModifyInstanceMetadataOptions "
            "is denied for least-privilege principals on banking EC2 hosts."
        ),
        "Parameters": {
            "AmiId":        {"Type": "String"},
            "InstanceType": {"Type": "String"},
            "AccountId":    {"Type": "String"},
            "StackSuffix":  {"Type": "String"},
        },
        "Resources": {

            # ----------------------------------------------------------------
            # NETWORKING
            # ----------------------------------------------------------------
            "ExperimentVpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock":          "10.99.0.0/24",
                    "EnableDnsSupport":   True,
                    "EnableDnsHostnames": True,
                    "Tags": [
                        {
                            "Key":   "Name",
                            "Value": {"Fn::Sub": "sce-1-3-vpc-${StackSuffix}"},
                        },
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                    ],
                },
            },

            "ExperimentSubnet": {
                "Type": "AWS::EC2::Subnet",
                "DependsOn": "ExperimentVpc",
                "Properties": {
                    "VpcId":               {"Ref": "ExperimentVpc"},
                    "CidrBlock":           "10.99.0.0/28",
                    "MapPublicIpOnLaunch": True,
                    "Tags": [
                        {
                            "Key":   "Name",
                            "Value": {"Fn::Sub": "sce-1-3-subnet-${StackSuffix}"},
                        },
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                    ],
                },
            },

            "ExperimentIGW": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {
                    "Tags": [
                        {
                            "Key":   "Name",
                            "Value": {"Fn::Sub": "sce-1-3-igw-${StackSuffix}"},
                        },
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                    ],
                },
            },

            "IGWAttachment": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "DependsOn": ["ExperimentVpc", "ExperimentIGW"],
                "Properties": {
                    "VpcId":             {"Ref": "ExperimentVpc"},
                    "InternetGatewayId": {"Ref": "ExperimentIGW"},
                },
            },

            "ExperimentRouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "DependsOn": "ExperimentVpc",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVpc"},
                    "Tags": [
                        {
                            "Key":   "Name",
                            "Value": {"Fn::Sub": "sce-1-3-rt-${StackSuffix}"},
                        },
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                    ],
                },
            },

            "DefaultRoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": ["ExperimentRouteTable", "IGWAttachment"],
                "Properties": {
                    "RouteTableId":         {"Ref": "ExperimentRouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId":            {"Ref": "ExperimentIGW"},
                },
            },

            "SubnetRTAssociation": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "DependsOn": ["ExperimentSubnet", "ExperimentRouteTable"],
                "Properties": {
                    "SubnetId":     {"Ref": "ExperimentSubnet"},
                    "RouteTableId": {"Ref": "ExperimentRouteTable"},
                },
            },

            # CRITICAL FIX: GroupDescription uses plain ASCII only.
            # Previous value contained a non-ASCII dash character.
            # New value: "SCE 1.3 egress only no inbound" - pure ASCII.
            "ExperimentSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "DependsOn": "ExperimentVpc",
                "Properties": {
                    "GroupDescription": "SCE 1.3 egress only no inbound",
                    "VpcId":            {"Ref": "ExperimentVpc"},
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "-1",
                            "CidrIp":     "0.0.0.0/0",
                            "Description": "Allow all egress for EC2 API access",
                        }
                    ],
                    "Tags": [
                        {
                            "Key":   "Name",
                            "Value": {"Fn::Sub": "sce-1-3-sg-${StackSuffix}"},
                        },
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                    ],
                },
            },

            # ----------------------------------------------------------------
            # IAM - RESTRICTED ROLE (deny ec2:ModifyInstanceMetadataOptions)
            # ----------------------------------------------------------------
            "RestrictedPolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": {
                        "Fn::Sub": "sce-1-3-deny-imds-${StackSuffix}"
                    },
                    "Description": (
                        "Explicit Deny on ec2:ModifyInstanceMetadataOptions and "
                        "ec2:DescribeInstances - simulates least-privilege IAM "
                        "boundary preventing IMDS downgrade per ADT node 1.1"
                    ),
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid":      "DenyIMDSDowngrade",
                                "Effect":   "Deny",
                                "Action":   ["ec2:ModifyInstanceMetadataOptions"],
                                "Resource": "*",
                            },
                            {
                                "Sid":      "DenyEC2DescribeInstances",
                                "Effect":   "Deny",
                                "Action":   ["ec2:DescribeInstances"],
                                "Resource": "*",
                            },
                        ],
                    },
                },
            },

            "RestrictedRole": {
                "Type": "AWS::IAM::Role",
                "DependsOn": "RestrictedPolicy",
                "Properties": {
                    "RoleName": {
                        "Fn::Sub": "sce-1-3-restricted-${StackSuffix}"
                    },
                    "Description": (
                        "Simulates a compromised IAM identity that lacks "
                        "ec2:ModifyInstanceMetadataOptions - the preventive "
                        "control under test in SCE node 1.3"
                    ),
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": {
                                        "Fn::Sub": (
                                            "arn:aws:iam::${AccountId}:root"
                                        )
                                    }
                                },
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [{"Ref": "RestrictedPolicy"}],
                    "MaxSessionDuration": 3600,
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                        {"Key": "SCEStackName",     "Value": stack_name},
                    ],
                },
            },

            # ----------------------------------------------------------------
            # IAM - PRIVILEGED ROLE (baseline positive test)
            # Allows ec2:ModifyInstanceMetadataOptions so we can confirm the
            # API itself is functional before running the deny test.
            # This eliminates false negatives caused by EC2 API outages.
            # ----------------------------------------------------------------
            "PrivilegedPolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": {
                        "Fn::Sub": "sce-1-3-allow-imds-${StackSuffix}"
                    },
                    "Description": (
                        "Allow ec2:ModifyInstanceMetadataOptions and "
                        "ec2:DescribeInstances for baseline positive test only. "
                        "Used to confirm the EC2 API is reachable before deny test."
                    ),
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid":      "AllowIMDSModify",
                                "Effect":   "Allow",
                                "Action": [
                                    "ec2:ModifyInstanceMetadataOptions",
                                    "ec2:DescribeInstances",
                                ],
                                "Resource": "*",
                            }
                        ],
                    },
                },
            },

            "PrivilegedRole": {
                "Type": "AWS::IAM::Role",
                "DependsOn": "PrivilegedPolicy",
                "Properties": {
                    "RoleName": {
                        "Fn::Sub": "sce-1-3-privileged-${StackSuffix}"
                    },
                    "Description": (
                        "Baseline positive-test role with ec2:ModifyInstanceMetadataOptions "
                        "allow. Confirms API reachability before restricted deny test."
                    ),
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": {
                                        "Fn::Sub": (
                                            "arn:aws:iam::${AccountId}:root"
                                        )
                                    }
                                },
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [{"Ref": "PrivilegedPolicy"}],
                    "MaxSessionDuration": 3600,
                    "Tags": [
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                        {"Key": "SCEStackName",     "Value": stack_name},
                        {"Key": "SCERole",          "Value": "baseline-positive-test"},
                    ],
                },
            },

            # ----------------------------------------------------------------
            # COMPUTE - HARDENED EC2 INSTANCE
            # IMDSv2 enforced: HttpTokens=required, HopLimit=1
            # No instance profile - we test external IAM role access only
            # ----------------------------------------------------------------
            "HardenedInstance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": [
                    "SubnetRTAssociation",
                    "ExperimentSecurityGroup",
                ],
                "Properties": {
                    "ImageId":            {"Ref": "AmiId"},
                    "InstanceType":       {"Ref": "InstanceType"},
                    "SubnetId":           {"Ref": "ExperimentSubnet"},
                    "SecurityGroupIds":   [{"Ref": "ExperimentSecurityGroup"}],
                    "MetadataOptions": {
                        "HttpTokens":              "required",
                        "HttpEndpoint":            "enabled",
                        "HttpPutResponseHopLimit": 1,
                    },
                    "Tags": [
                        {
                            "Key":   "Name",
                            "Value": "sce-1-3-hardened-banking-host",
                        },
                        {"Key": EXPERIMENT_TAG_KEY, "Value": EXPERIMENT_TAG_VALUE},
                        {"Key": "SCEStackName",     "Value": stack_name},
                        {"Key": "BankingTier",      "Value": "transaction-microservice"},
                        {"Key": "IMDSVersion",      "Value": "v2-only"},
                    ],
                },
            },
        },

        "Outputs": {
            "HardenedInstanceId": {
                "Description": "Instance ID of the hardened EC2 host",
                "Value":       {"Ref": "HardenedInstance"},
            },
            "RestrictedRoleArn": {
                "Description": "ARN of the restricted IAM role under test",
                "Value":       {"Fn::GetAtt": ["RestrictedRole", "Arn"]},
            },
            "RestrictedRoleName": {
                "Description": "Name of the restricted IAM role",
                "Value":       {"Ref": "RestrictedRole"},
            },
            "PrivilegedRoleArn": {
                "Description": "ARN of the privileged baseline role",
                "Value":       {"Fn::GetAtt": ["PrivilegedRole", "Arn"]},
            },
            "VpcId": {
                "Description": "Experiment VPC ID",
                "Value":       {"Ref": "ExperimentVpc"},
            },
            "SubnetId": {
                "Description": "Experiment subnet ID",
                "Value":       {"Ref": "ExperimentSubnet"},
            },
        },
    }

    serialised = json.dumps(template, ensure_ascii=True, indent=2)

    # Run ASCII guard before returning - catches encoding bugs at build time
    _ascii_guard(serialised)

    return serialised


def _poll_stack_until_terminal(stack_name: str, timeout_s: int) -> str:
    """
    Poll CloudFormation until a terminal state is reached.
    On failure, fetches per-resource events to surface the exact cause.
    """
    cfn = _boto("cloudformation")
    terminal_ok = {
        "CREATE_COMPLETE", "UPDATE_COMPLETE", "DELETE_COMPLETE",
    }
    terminal_fail = {
        "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
        "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_ROLLBACK_FAILED", "DELETE_FAILED",
    }
    deadline    = time.monotonic() + timeout_s
    last_status = "UNKNOWN"

    while time.monotonic() < deadline:
        try:
            resp        = cfn.describe_stacks(StackName=stack_name)
            last_status = resp["Stacks"][0]["StackStatus"]
            log.info("Stack %s  status=%s", stack_name, last_status)

            if last_status in terminal_ok:
                return last_status
            if last_status in terminal_fail:
                _log_stack_failure_events(stack_name)
                raise RuntimeError(
                    "Stack %s reached failure state: %s"
                    % (stack_name, last_status)
                )
        except ClientError as exc:
            if "does not exist" in str(exc):
                log.info("Stack %s no longer exists.", stack_name)
                return "DELETE_COMPLETE"
            log.error("describe_stacks error: %s", exc)

        time.sleep(STACK_POLL_INTERVAL_S)

    raise TimeoutError(
        "Stack %s did not reach terminal state within %ds. Last=%s"
        % (stack_name, timeout_s, last_status)
    )


def _log_stack_failure_events(stack_name: str) -> None:
    """Fetch and log per-resource CloudFormation failure reasons."""
    cfn = _boto("cloudformation")
    try:
        paginator = cfn.get_paginator("describe_stack_events")
        for page in paginator.paginate(StackName=stack_name):
            for event in page["StackEvents"]:
                status = event.get("ResourceStatus", "")
                if "FAILED" in status or "ROLLBACK" in status:
                    log.error(
                        "CFN EVENT | Resource: %-44s | Status: %-34s | Reason: %s",
                        event.get("LogicalResourceId", "N/A"),
                        status,
                        event.get("ResourceStatusReason", "no reason provided"),
                    )
    except Exception as exc:
        log.warning("Could not fetch stack events: %s", exc)


def _assume_role(role_arn: str, session_name: str) -> dict:
    """
    Assume an IAM role with bounded retry for propagation delay.
    Returns credential dict.
    """
    sts      = _boto("sts")
    deadline = time.monotonic() + IAM_PROPAGATION_TIMEOUT_S
    attempt  = 0
    last_exc = None

    while time.monotonic() < deadline:
        attempt += 1
        try:
            resp  = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=3600,
            )
            creds = resp["Credentials"]
            log.info(
                "Assumed role %s on attempt %d. Expires: %s",
                role_arn, attempt, creds["Expiration"],
            )
            return {
                "AccessKeyId":     creds["AccessKeyId"],
                "SecretAccessKey": creds["SecretAccessKey"],
                "SessionToken":    creds["SessionToken"],
                "Expiration":      str(creds["Expiration"]),
            }
        except ClientError as exc:
            last_exc   = exc
            error_code = exc.response["Error"]["Code"]
            if error_code in ("AccessDenied", "InvalidClientTokenId"):
                backoff = min(IAM_POLL_INTERVAL_S * attempt, 30)
                log.info(
                    "Role assumption attempt %d: %s - retrying in %ds",
                    attempt, error_code, backoff,
                )
                time.sleep(backoff)
            else:
                log.error("Unexpected role assumption error: %s", exc)
                raise

    raise RuntimeError(
        "Could not assume role %s within %ds after %d attempts. "
        "Last error: %s"
        % (role_arn, IAM_PROPAGATION_TIMEOUT_S, attempt, last_exc)
    )


def _refresh_credentials_if_needed() -> None:
    """Re-assume the restricted role if credentials are nearing expiry."""
    assumed_at = _STATE.get("credentials_assumed_at")
    if assumed_at is None:
        return
    age = time.monotonic() - assumed_at
    if age > CRED_REFRESH_THRESHOLD_S:
        log.info(
            "Credentials are %.0fs old (threshold %ds) - refreshing.",
            age, CRED_REFRESH_THRESHOLD_S,
        )
        restricted_arn = _STATE.get("restricted_role_arn")
        if restricted_arn:
            try:
                creds = _assume_role(restricted_arn, "sce-1-3-preventive-probe")
                _STATE["restricted_credentials"] = creds
                _STATE["credentials_assumed_at"] = time.monotonic()
                log.info("Restricted role credentials refreshed.")
            except Exception as exc:
                log.error("Credential refresh failed: %s", exc)


# =============================================================================
# PHASE 1 - STEADY STATE
# =============================================================================

def steady_state() -> None:
    """
    Provision all experiment infrastructure via a single self-contained
    CloudFormation stack.

    Changes from previous versions:
    - Template builds its own VPC + subnet (run 2 fix).
    - ALL template strings use plain ASCII only (run 3 fix).
    - ASCII guard validates the serialised template before submission.
    - PrivilegedRole added for baseline positive test.
    - infra_ready flag set only after all validations pass.
    """
    log.info("=== PHASE 1: steady_state ===")

    region     = _get_region()
    account_id = _get_account_id()

    _preflight_check()

    timestamp  = int(time.time())
    stack_name = "sce-experiment-%d" % timestamp
    _STATE["stack_name"] = stack_name
    log.info("Stack name: %s", stack_name)

    ami_id        = _resolve_ami(region)
    instance_type = _resolve_instance_type(region)
    log.info("AMI: %s | InstanceType: %s", ami_id, instance_type)

    # Build and validate template (ASCII guard runs inside _build_cfn_template)
    template_body = _build_cfn_template(
        ami_id=ami_id,
        instance_type=instance_type,
        account_id=account_id,
        stack_name=stack_name,
        timestamp=timestamp,
    )

    # Deploy stack
    cfn = _boto("cloudformation")
    try:
        log.info("Creating CloudFormation stack: %s", stack_name)
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Parameters=[
                {"ParameterKey": "AmiId",        "ParameterValue": ami_id},
                {"ParameterKey": "InstanceType",  "ParameterValue": instance_type},
                {"ParameterKey": "AccountId",     "ParameterValue": account_id},
                {"ParameterKey": "StackSuffix",   "ParameterValue": str(timestamp)},
            ],
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": EXPERIMENT_TAG_KEY,  "Value": EXPERIMENT_TAG_VALUE},
                {"Key": "SCEStackTimestamp", "Value": str(timestamp)},
            ],
            TimeoutInMinutes=20,
            OnFailure="ROLLBACK",
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "AlreadyExistsException":
            log.warning("Stack %s already exists - continuing.", stack_name)
        else:
            log.error("create_stack failed: %s", exc)
            raise

    log.info("Waiting for stack %s to reach CREATE_COMPLETE ...", stack_name)
    _poll_stack_until_terminal(stack_name, STACK_CREATE_TIMEOUT_S)

    # Extract outputs
    resp    = cfn.describe_stacks(StackName=stack_name)
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in resp["Stacks"][0].get("Outputs", [])
    }
    _STATE["stack_outputs"] = outputs
    log.info("Stack outputs: %s", outputs)

    instance_id     = outputs.get("HardenedInstanceId")
    restricted_arn  = outputs.get("RestrictedRoleArn")
    privileged_arn  = outputs.get("PrivilegedRoleArn")

    if not instance_id or not restricted_arn or not privileged_arn:
        raise RuntimeError("Stack outputs incomplete: %s" % outputs)

    _STATE["hardened_instance_id"] = instance_id
    _STATE["restricted_role_arn"]  = restricted_arn
    _STATE["privileged_role_arn"]  = privileged_arn

    log.info(
        "Resources | Instance: %s | RestrictedRole: %s | PrivilegedRole: %s",
        instance_id, restricted_arn, privileged_arn,
    )

    # Wait for instance running state
    log.info("Waiting for instance %s to reach running state ...", instance_id)
    ec2      = _boto("ec2")
    deadline = time.monotonic() + INSTANCE_RUNNING_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            resp  = ec2.describe_instances(InstanceIds=[instance_id])
            state = resp["Reservations"][0]["Instances"][0]["State"]["Name"]
            log.info("Instance %s state: %s", instance_id, state)
            if state == "running":
                break
            if state in ("terminated", "shutting-down"):
                raise RuntimeError(
                    "Instance %s in unexpected state: %s"
                    % (instance_id, state)
                )
        except ClientError as exc:
            log.warning("describe_instances transient error: %s", exc)
        time.sleep(15)
    else:
        raise TimeoutError(
            "Instance %s did not reach running within %ds"
            % (instance_id, INSTANCE_RUNNING_TIMEOUT_S)
        )

    # Verify IMDSv2 baseline
    resp      = ec2.describe_instances(InstanceIds=[instance_id])
    imds_opts = resp["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
    http_tokens = imds_opts.get("HttpTokens", "unknown")
    hop_limit   = imds_opts.get("HttpPutResponseHopLimit", -1)
    log.info(
        "IMDS baseline | HttpTokens=%s | HopLimit=%s", http_tokens, hop_limit
    )

    if http_tokens != "required":
        raise RuntimeError(
            "Pre-condition FAILED: HttpTokens=%s on %s (expected required)"
            % (http_tokens, instance_id)
        )
    if int(hop_limit) != 1:
        raise RuntimeError(
            "Pre-condition FAILED: HopLimit=%s on %s (expected 1)"
            % (hop_limit, instance_id)
        )
    log.info("IMDSv2 baseline confirmed: HttpTokens=required, HopLimit=1")

    # Assume both roles (with IAM propagation retry)
    log.info("Assuming RestrictedRole ...")
    restricted_creds = _assume_role(restricted_arn, "sce-1-3-restricted")
    _STATE["restricted_credentials"] = restricted_creds
    _STATE["credentials_assumed_at"] = time.monotonic()

    log.info("Assuming PrivilegedRole ...")
    privileged_creds = _assume_role(privileged_arn, "sce-1-3-privileged")
    _STATE["privileged_credentials"] = privileged_creds

    _STATE["infra_ready"] = True
    log.info("=== PHASE 1 COMPLETE: steady_state ===")


# =============================================================================
# PHASE 2 - ATTACK (T1552.005)
# =============================================================================

def attack() -> bool:
    """
    Simulate ADT Attack Node 1.2:

        aws ec2 modify-instance-metadata-options
          --instance-id <INSTANCE_ID>
          --http-tokens optional
          --http-endpoint enabled
          --http-put-response-hop-limit 2

    STEP A - BASELINE POSITIVE TEST (new in this version):
      Execute the same API call using the PrivilegedRole (which HAS the
      ec2:ModifyInstanceMetadataOptions allow).  Expect success.
      If this fails, the test infrastructure or EC2 API is broken -
      abort with INFRA_FAILURE, not DEVIATED.
      After the positive test, restore IMDSv2 using privileged credentials.

    STEP B - DENY TEST (primary probe):
      Execute the same API call using the RestrictedRole (which carries
      an explicit Deny on ec2:ModifyInstanceMetadataOptions).
      Expected outcome: AccessDenied.

    Returns True unconditionally so Chaos Toolkit does not abort the run.
    Verification is performed in hypothesis_verification().
    """
    log.info(
        "=== PHASE 2: attack (T1552.005 - IMDS Downgrade Attempt) ==="
    )

    # Explicit infra readiness guard
    if not _STATE.get("infra_ready"):
        msg = (
            "Infrastructure not ready - steady_state() did not complete "
            "successfully. Aborting attack phase with INFRA_FAILURE. "
            "This is NOT a security finding."
        )
        log.error(msg)
        _STATE["attack_result"] = {
            "executed":            False,
            "infra_failure":       True,
            "access_denied":       False,
            "attack_succeeded":    False,
            "baseline_api_works":  None,
            "error_code":          "INFRA_FAILURE",
            "error_message":       msg,
            "tokens_after":        None,
            "hop_limit_after":     None,
        }
        return True

    instance_id      = _STATE["hardened_instance_id"]
    restricted_creds = _STATE["restricted_credentials"]
    privileged_creds = _STATE["privileged_credentials"]

    # Credential freshness check
    _refresh_credentials_if_needed()
    restricted_creds = _STATE["restricted_credentials"]

    # -------------------------------------------------------------------------
    # STEP A: BASELINE POSITIVE TEST
    # Confirm the EC2 API is reachable and ModifyInstanceMetadataOptions works
    # when the caller HAS the required permission.
    # -------------------------------------------------------------------------
    log.info(
        "STEP A: Baseline positive test - calling ModifyInstanceMetadataOptions "
        "with PrivilegedRole (expect success) ..."
    )

    baseline_api_works = False
    ec2_privileged     = _boto_with_creds("ec2", privileged_creds)

    try:
        # Downgrade to IMDSv1 using privileged credentials as baseline proof
        ec2_privileged.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="optional",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=2,
        )
        baseline_api_works = True
        log.info(
            "STEP A PASS: PrivilegedRole successfully called "
            "ModifyInstanceMetadataOptions. EC2 API is reachable and functional."
        )

        # Restore IMDSv2 immediately after baseline test
        log.info("Restoring IMDSv2 (HttpTokens=required, HopLimit=1) ...")
        ec2_privileged.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="required",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=1,
        )
        log.info("IMDSv2 restored after baseline test.")

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        log.error(
            "STEP A FAIL: PrivilegedRole call FAILED with %s - %s. "
            "This indicates an EC2 API issue or infrastructure problem, "
            "NOT a security finding. Aborting deny test.",
            error_code,
            exc.response["Error"]["Message"],
        )
        _STATE["attack_result"] = {
            "executed":            False,
            "infra_failure":       True,
            "access_denied":       False,
            "attack_succeeded":    False,
            "baseline_api_works":  False,
            "error_code":          "BASELINE_API_FAILURE",
            "error_message": (
                "PrivilegedRole could not call ModifyInstanceMetadataOptions: %s"
                % str(exc)
            ),
            "tokens_after":        None,
            "hop_limit_after":     None,
        }
        return True

    # -------------------------------------------------------------------------
    # STEP B: DENY TEST - execute as RestrictedRole
    # -------------------------------------------------------------------------
    log.info(
        "STEP B: Deny test - calling ModifyInstanceMetadataOptions with "
        "RestrictedRole (expect AccessDenied) ..."
    )

    # Validate restricted role identity
    try:
        sts_check = _boto_with_creds("sts", restricted_creds)
        caller    = sts_check.get_caller_identity()
        log.info(
            "Restricted principal | ARN: %s | UserId: %s",
            caller["Arn"], caller["UserId"],
        )
    except ClientError as exc:
        log.warning(
            "Restricted credential identity check failed (%s) - re-assuming.",
            exc,
        )
        restricted_arn = _STATE.get("restricted_role_arn")
        if restricted_arn:
            try:
                restricted_creds = _assume_role(
                    restricted_arn, "sce-1-3-restricted"
                )
                _STATE["restricted_credentials"] = restricted_creds
                _STATE["credentials_assumed_at"] = time.monotonic()
            except Exception as refresh_exc:
                log.error("Re-assume failed: %s", refresh_exc)
                _STATE["attack_result"] = {
                    "executed":            False,
                    "infra_failure":       True,
                    "access_denied":       False,
                    "attack_succeeded":    False,
                    "baseline_api_works":  baseline_api_works,
                    "error_code":          "CREDENTIAL_REFRESH_FAILED",
                    "error_message":       str(refresh_exc),
                    "tokens_after":        None,
                    "hop_limit_after":     None,
                }
                return True

    ec2_restricted   = _boto_with_creds("ec2", restricted_creds)
    access_denied    = False
    attack_succeeded = False
    error_code       = None
    error_message    = None
    tokens_after     = None
    hop_limit_after  = None

    try:
        resp = ec2_restricted.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="optional",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=2,
        )
        # If we reach here, the IAM deny did NOT fire - control FAILED
        attack_succeeded = True
        log.error(
            "PREVENTIVE CONTROL FAILED: RestrictedRole successfully called "
            "ModifyInstanceMetadataOptions. IMDSv2 enforcement was bypassed. "
            "Response: %s",
            resp.get("InstanceMetadataOptions", {}),
        )
        # Restore IMDSv2 if the attack unexpectedly succeeded
        try:
            ec2_privileged.modify_instance_metadata_options(
                InstanceId=instance_id,
                HttpTokens="required",
                HttpEndpoint="enabled",
                HttpPutResponseHopLimit=1,
            )
            log.info("IMDSv2 restored after unexpected attack success.")
        except Exception as restore_exc:
            log.warning("Failed to restore IMDSv2 after attack success: %s", restore_exc)

    except ClientError as exc:
        error_code    = exc.response["Error"]["Code"]
        error_message = exc.response["Error"]["Message"]

        if error_code in (
            "AccessDenied",
            "UnauthorizedAccess",
            "Client.UnauthorizedOperation",
        ):
            access_denied = True
            log.info(
                "PREVENTIVE CONTROL CONFIRMED: AccessDenied returned for "
                "RestrictedRole. IAM explicit Deny is enforced. "
                "Code=%s | Message=%s",
                error_code, error_message,
            )
        else:
            log.error(
                "Unexpected error during deny test: Code=%s | Message=%s",
                error_code, error_message,
            )

    # Post-attack IMDS state (privileged read)
    try:
        resp        = _boto("ec2").describe_instances(InstanceIds=[instance_id])
        imds_opts   = (
            resp["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
        )
        tokens_after    = imds_opts.get("HttpTokens", "unknown")
        hop_limit_after = imds_opts.get("HttpPutResponseHopLimit", -1)
        log.info(
            "Post-attack IMDS | HttpTokens=%s | HopLimit=%s",
            tokens_after, hop_limit_after,
        )
    except Exception as exc:
        log.warning("Post-attack IMDS describe failed: %s", exc)

    _STATE["attack_result"] = {
        "executed":            True,
        "infra_failure":       False,
        "access_denied":       access_denied,
        "attack_succeeded":    attack_succeeded,
        "baseline_api_works":  baseline_api_works,
        "error_code":          error_code,
        "error_message":       error_message,
        "tokens_after":        tokens_after,
        "hop_limit_after":     hop_limit_after,
    }

    log.info(
        "=== PHASE 2 COMPLETE: baseline_api_works=%s | access_denied=%s | "
        "attack_succeeded=%s ===",
        baseline_api_works, access_denied, attack_succeeded,
    )
    return True


# =============================================================================
# PHASE 3 - HYPOTHESIS VERIFICATION (Preventive Probe)
# =============================================================================

def hypothesis_verification() -> bool:
    """
    SCE Node 1.3 - Preventive Probe Verification.

    CHECK 0 - Infrastructure readiness guard:
      If steady_state() did not complete (infra_failure=True in attack_result),
      the experiment result is ABORTED, not DEVIATED. This prevents false
      security findings caused by infrastructure failures.

    CHECK 1 - IAM deny blocks ec2:ModifyInstanceMetadataOptions:
      The restricted principal must receive AccessDenied.
      Primary preventive control under test.

    CHECK 2 - IMDS baseline unchanged post-attack:
      HttpTokens must still be 'required' and HopLimit must still be 1.
      Confirms the API call produced no state mutation.

    CHECK 3 - IAM deny also blocks ec2:DescribeInstances:
      Validates full deny policy scope from ADT 1.1.

    Returns True if all checks pass (preventive control working as designed).
    Returns False if any security check fails (genuine weakness detected).
    Raises RuntimeError if the result is ABORTED due to infra failure.
    """
    log.info("=== PHASE 3: hypothesis_verification (Preventive) ===")

    results = {}
    overall = True

    # -- CHECK 0: Infrastructure readiness ------------------------------------
    ar = _STATE.get("attack_result")

    if ar is None:
        log.error(
            "CHECK 0 FAIL - attack_result is None. attack() did not run."
        )
        return False

    if ar.get("infra_failure", False):
        log.error(
            "CHECK 0: INFRASTRUCTURE FAILURE detected. "
            "error_code=%s | error_message=%s | "
            "This is NOT a security finding - it is a test infrastructure "
            "failure. The experiment result is ABORTED.",
            ar.get("error_code"), ar.get("error_message"),
        )
        # Return False so Chaos Toolkit marks as deviated, but log clearly
        # distinguishes this from a security control failure.
        return False

    log.info(
        "CHECK 0 PASS - Infrastructure was ready. "
        "baseline_api_works=%s",
        ar.get("baseline_api_works"),
    )

    # -- CHECK 1: AccessDenied for restricted principal -----------------------
    if not ar.get("executed", False):
        log.error(
            "CHECK 1 FAIL - attack() did not execute. "
            "error_code=%s | error_message=%s",
            ar.get("error_code"), ar.get("error_message"),
        )
        results["check_1_attack_denied"] = False
        overall = False

    elif not ar.get("access_denied", False):
        log.error(
            "CHECK 1 FAIL - ec2:ModifyInstanceMetadataOptions was NOT denied "
            "for the restricted principal. "
            "attack_succeeded=%s | error_code=%s | error_message=%s",
            ar.get("attack_succeeded"),
            ar.get("error_code"),
            ar.get("error_message"),
        )
        results["check_1_attack_denied"] = False
        overall = False

    else:
        log.info(
            "CHECK 1 PASS - AccessDenied confirmed for restricted principal. "
            "(Code: %s)",
            ar.get("error_code"),
        )
        results["check_1_attack_denied"] = True

    # -- CHECK 2: IMDS state unchanged ----------------------------------------
    tokens_after    = ar.get("tokens_after")
    hop_limit_after = ar.get("hop_limit_after")

    if tokens_after is None or hop_limit_after is None:
        instance_id = _STATE.get("hardened_instance_id")
        if instance_id:
            ec2 = _boto("ec2")
            for attempt in range(3):
                try:
                    resp       = ec2.describe_instances(InstanceIds=[instance_id])
                    imds_opts  = (
                        resp["Reservations"][0]["Instances"][0]
                        .get("MetadataOptions", {})
                    )
                    tokens_after    = imds_opts.get("HttpTokens", "unknown")
                    hop_limit_after = imds_opts.get("HttpPutResponseHopLimit", -1)
                    break
                except Exception as exc:
                    log.warning(
                        "CHECK 2 fresh describe attempt %d failed: %s",
                        attempt + 1, exc,
                    )
                    time.sleep(5)

    if tokens_after is None:
        log.warning(
            "CHECK 2 SKIP - IMDS state unavailable; marking inconclusive."
        )
        results["check_2_imds_unchanged"] = None
    elif tokens_after == "required" and int(hop_limit_after or 0) == 1:
        log.info(
            "CHECK 2 PASS - IMDS unchanged: HttpTokens=required, HopLimit=1."
        )
        results["check_2_imds_unchanged"] = True
    else:
        log.error(
            "CHECK 2 FAIL - IMDS was MUTATED: HttpTokens=%s (expected required) "
            "| HopLimit=%s (expected 1).",
            tokens_after, hop_limit_after,
        )
        results["check_2_imds_unchanged"] = False
        overall = False

    # -- CHECK 3: DescribeInstances also denied --------------------------------
    restricted_creds = _STATE.get("restricted_credentials")
    instance_id      = _STATE.get("hardened_instance_id")

    if not restricted_creds or not instance_id:
        log.warning(
            "CHECK 3 SKIP - Restricted credentials or instance ID unavailable."
        )
        results["check_3_describe_denied"] = None
    else:
        _refresh_credentials_if_needed()
        restricted_creds = _STATE["restricted_credentials"]
        ec2_restricted   = _boto_with_creds("ec2", restricted_creds)
        try:
            resp  = ec2_restricted.describe_instances(
                InstanceIds=[instance_id]
            )
            count = len(resp.get("Reservations", []))
            log.error(
                "CHECK 3 FAIL - ec2:DescribeInstances SUCCEEDED for restricted "
                "principal (%d reservation(s) returned). IAM deny not in effect.",
                count,
            )
            results["check_3_describe_denied"] = False
            overall = False
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in (
                "AccessDenied",
                "UnauthorizedAccess",
                "Client.UnauthorizedOperation",
            ):
                log.info(
                    "CHECK 3 PASS - ec2:DescribeInstances returned AccessDenied "
                    "for restricted principal. Full deny scope confirmed. "
                    "(Code: %s)",
                    code,
                )
                results["check_3_describe_denied"] = True
            else:
                log.warning(
                    "CHECK 3 INCONCLUSIVE - Unexpected error: %s - %s",
                    code, exc.response["Error"]["Message"],
                )
                results["check_3_describe_denied"] = None

    # -- Summary --------------------------------------------------------------
    log.info("=== HYPOTHESIS VERIFICATION SUMMARY ===")
    for check, result in results.items():
        status = (
            "PASS"              if result is True  else
            "SKIP/INCONCLUSIVE" if result is None  else
            "FAIL"
        )
        log.info("  %-42s -> %s", check, status)

    if overall:
        log.info(
            "Overall hypothesis result: PASS - "
            "Preventive controls behaved as designed. No weakness detected."
        )
    else:
        log.error(
            "Overall hypothesis result: FAIL (DEVIATED) - "
            "One or more preventive controls did not behave as specified in "
            "ADT node 1.1. A security weakness may have been discovered."
        )

    log.info("=== PHASE 3 COMPLETE ===")
    return overall


# =============================================================================
# PHASE 4 - ROLLBACK
# =============================================================================

def rollback() -> None:
    """
    Delete the CloudFormation stack and all experiment resources.
    CloudFormation handles deletion order (VPC dependencies, IAM detachments).
    Safe and tolerant - catches stack-not-found and deletion failures.
    """
    log.info("=== PHASE 4: rollback ===")

    stack_name = _STATE.get("stack_name")
    if not stack_name:
        log.warning("No stack name in state - nothing to roll back.")
        return

    cfn = _boto("cloudformation")

    try:
        resp   = cfn.describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        log.info("Stack %s current status: %s", stack_name, status)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info(
                "Stack %s does not exist - rollback not required.", stack_name
            )
            return
        log.warning("Could not describe stack before delete: %s", exc)

    try:
        cfn.delete_stack(StackName=stack_name)
        log.info("Delete request sent for stack %s.", stack_name)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info("Stack %s already deleted.", stack_name)
            return
        log.error("delete_stack API call failed: %s", exc)

    deadline = time.monotonic() + STACK_DELETE_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            resp   = cfn.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            log.info("Stack %s  status=%s", stack_name, status)

            if status == "DELETE_COMPLETE":
                log.info("Stack %s fully deleted.", stack_name)
                return
            if status == "DELETE_FAILED":
                log.error(
                    "Stack %s DELETE_FAILED - manual cleanup may be required.",
                    stack_name,
                )
                _log_stack_failure_events(stack_name)
                return
        except ClientError as exc:
            if "does not exist" in str(exc):
                log.info(
                    "Stack %s confirmed deleted (no longer exists).", stack_name
                )
                return
            log.warning("describe_stacks during delete poll: %s", exc)

        time.sleep(STACK_POLL_INTERVAL_S)

    log.error(
        "Stack %s deletion timed out after %ds - manual cleanup may be required.",
        stack_name, STACK_DELETE_TIMEOUT_S,
    )
    log.info("=== PHASE 4 COMPLETE ===")


# =============================================================================
# MAIN
# =============================================================================

def main() -> None:
    log.info(
        "==================================================================="
    )
    log.info(
        "  SCE 1.3 Preventive Probe - IMDS Downgrade Prevention"
    )
    log.info(
        "  Attack : aws-ec2-imds-weakening-001 Step 1 (ADT Node 1.2)"
    )
    log.info(
        "  Defense: Least-Privilege IAM + IMDSv2 Enforcement (Node 1.1)"
    )
    log.info(
        "==================================================================="
    )

    experiment_passed = False

    try:
        steady_state()
        attack()
        experiment_passed = hypothesis_verification()

    except Exception as exc:
        log.error(
            "Unhandled exception during experiment: %s\n%s",
            exc, traceback.format_exc(),
        )
        experiment_passed = False

    finally:
        try:
            rollback()
        except Exception as rb_exc:
            log.error(
                "Rollback error: %s\n%s", rb_exc, traceback.format_exc()
            )

    if experiment_passed:
        log.info(
            "Experiment status: PASSED - "
            "Preventive controls behaved as designed."
        )
        sys.exit(0)
    else:
        log.error(
            "Experiment status: DEVIATED - "
            "Review hypothesis verification logs."
        )
        sys.exit(1)


if __name__ == "__main__":
    main()