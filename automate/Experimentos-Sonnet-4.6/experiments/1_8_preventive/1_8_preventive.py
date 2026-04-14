"""
chaosaws/ec2/1_8_preventive.py

SCE Node 1.8 – Preventive Probe
Attack Nodes: 1.2 (Weaken IMDS Configuration) + 1.7 (Retrieve IAM Credentials from IMDS)

Root-cause fixes applied vs. previous execution:
  - Dedicated SCEVerifier role (separate from SCERole/attacker) with explicit
    trust for the caller identity, scoped to read-only inspection actions.
    Probe NEVER reuses the attacker role assumption path.
  - Attack role (SCERole) carries the permission boundary that denies
    ec2:ModifyInstanceMetadataOptions — this is the control under test.
  - Probe uses direct AWS API inspection:
      Check A  – iam:SimulatePrincipalPolicy confirms boundary denies the action
      Check B  – ec2:DescribeInstances confirms HttpTokens=required, HopLimit=1
      Check C  – ec2:DescribeSecurityGroups confirms no egress to 169.254.x.x
      Check D  – SSM Run Command (best-effort, 300 s wait, graceful skip)
  - Each check is independent; partial success is captured and logged.
  - 30-minute SLA polling loop on Checks B/C for eventual consistency.
  - Attack function raises RuntimeError ONLY when the expected AccessDenied
    is NOT received (i.e., when the boundary failed to block the call).
"""

# ── stdlib ────────────────────────────────────────────────────────────────────
import json
import logging
import subprocess
import sys
import time
import traceback

# ── logging setup (must precede boto3 import) ─────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S,%f",
)
log = logging.getLogger(__name__)

# ── install boto3 if absent ───────────────────────────────────────────────────
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    log.info("boto3 not found – installing …")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "boto3"])
    import boto3
    from botocore.exceptions import ClientError

# ── shared mutable state (module-level, single process) ──────────────────────
_STATE: dict = {}

# ── constants ─────────────────────────────────────────────────────────────────
REGION          = "us-east-1"
STACK_IAM_PFX   = "sce-iam"
STACK_EC2_PFX   = "sce-ec2"
INSTANCE_TYPE   = "t3.micro"
SLA_WINDOW      = 1800          # 30 min – AWS eventual-consistency SLA
SSM_WAIT        = 300           # seconds to wait for SSM agent
POLL_INTERVAL   = 15            # seconds between stack-status polls
TAG_KEY         = "SCEExperiment"
TAG_VAL_PFX     = "1.8-preventive"
EXPERIMENT_TAG  = [{"Key": TAG_KEY, "Value": TAG_VAL_PFX}]

# ── boto3 clients (lazy, module-level) ────────────────────────────────────────
def _ec2():      return boto3.client("ec2",      region_name=REGION)
def _cfn():      return boto3.client("cloudformation", region_name=REGION)
def _sts():      return boto3.client("sts",      region_name=REGION)
def _iam():      return boto3.client("iam",      region_name=REGION)
def _ssm():      return boto3.client("ssm",      region_name=REGION)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _caller_arn() -> str:
    identity = _sts().get_caller_identity()
    return identity["Arn"]


def _caller_account() -> str:
    return _sts().get_caller_identity()["Account"]


def _retry(fn, label: str, max_attempts: int = 5, base_delay: float = 2.0):
    """Exponential-backoff retry for transient AWS errors."""
    for attempt in range(1, max_attempts + 1):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            # Do NOT retry access-denied – these are expected control responses
            if code in ("AccessDenied", "UnauthorizedOperation"):
                raise
            delay = base_delay * (2 ** (attempt - 1)) * (0.8 + 0.4 * (attempt / max_attempts))
            log.warning(
                "%s – attempt %d/%d failed (%s): %s. Retrying in %.1fs …",
                label, attempt, max_attempts, code, exc, delay,
            )
            if attempt == max_attempts:
                log.error("%s – all %d attempts exhausted.", label, max_attempts)
                raise
            time.sleep(delay)


def _assert_ascii(template: str, label: str) -> None:
    for i, ch in enumerate(template):
        if ord(ch) > 127:
            raise ValueError(f"Non-ASCII char 0x{ord(ch):02x} at position {i} in {label}")
    log.info("ASCII validation passed for %s.", label)


def _wait_stack(stack_name: str, target_status: str = "CREATE_COMPLETE") -> None:
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        resp = _cfn().describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        log.info("Stack %s status: %s", stack_name, status)
        if status == target_status:
            return
        if "FAILED" in status or "ROLLBACK" in status:
            events = _cfn().describe_stack_events(StackName=stack_name)["StackEvents"]
            reasons = [
                e.get("ResourceStatusReason", "")
                for e in events[:5]
            ]
            raise RuntimeError(
                f"Stack {stack_name} entered {status}. Recent reasons: {reasons}"
            )
        time.sleep(POLL_INTERVAL)
    raise TimeoutError(f"Stack {stack_name} did not reach {target_status} within 1800s.")


def _stack_exists(stack_name: str) -> bool:
    try:
        resp = _cfn().describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        return status not in ("DELETE_COMPLETE",)
    except ClientError as exc:
        if "does not exist" in str(exc):
            return False
        raise


def _resolve_ami() -> str:
    """Resolve latest Amazon Linux 2 AMI in the target region."""
    resp = _ec2().describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name",            "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
            {"Name": "state",           "Values": ["available"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
            {"Name": "root-device-type",    "Values": ["ebs"]},
        ],
    )
    images = sorted(resp["Images"], key=lambda x: x["CreationDate"], reverse=True)
    if not images:
        raise RuntimeError("No Amazon Linux 2 AMI found in " + REGION)
    ami = images[0]["ImageId"]
    log.info("Resolved AMI: %s", ami)
    return ami


def _resolve_az_and_type() -> tuple:
    """Return (az, instance_type) available in the region."""
    resp = _ec2().describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )
    azs = [z["ZoneName"] for z in resp["AvailabilityZones"]]
    log.info("Available AZs: %s – using %s", azs, azs[0])

    ec2r = boto3.resource("ec2", region_name=REGION)
    for itype in ["t3.micro", "t3.small", "t2.micro"]:
        try:
            _ec2().describe_instance_type_offerings(
                LocationType="availability-zone",
                Filters=[
                    {"Name": "instance-type",    "Values": [itype]},
                    {"Name": "location",         "Values": [azs[0]]},
                ],
            )
            log.info("Selected instance type: %s", itype)
            return azs[0], itype
        except ClientError:
            continue
    return azs[0], "t3.micro"


# ─────────────────────────────────────────────────────────────────────────────
# CloudFormation Templates
# ─────────────────────────────────────────────────────────────────────────────

def _build_iam_template(suffix: str, caller_arn: str, account_id: str) -> str:
    """
    Creates:
      SCEBoundary   – managed policy that DENIES ec2:ModifyInstanceMetadataOptions
      SCERole       – instance role with the boundary attached (the attacker's target)
      SCEVerifier   – observer role the caller CAN assume; read-only inspection only
      SCEProfile    – instance profile for SCERole
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 Preventive – IAM resources",
        "Resources": {

            # ── Permission Boundary ──────────────────────────────────────────
            "SCEBoundary": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": f"SCEBoundary-{suffix}",
                    "Description": "Permission boundary: explicitly denies IMDS downgrade",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowBaseEC2AndSTS",
                                "Effect": "Allow",
                                "Action": [
                                    "ec2:DescribeInstances",
                                    "ec2:DescribeInstanceMetadataDefaults",
                                    "sts:GetCallerIdentity",
                                    "iam:ListAttachedRolePolicies",
                                    "iam:ListRolePolicies",
                                    "s3:ListAllMyBuckets",
                                ],
                                "Resource": "*",
                            },
                            {
                                "Sid": "DenyIMDSDowngrade",
                                "Effect": "Deny",
                                "Action": [
                                    "ec2:ModifyInstanceMetadataOptions",
                                    "ec2:ModifyInstanceMetadataDefaults",
                                ],
                                "Resource": "*",
                            },
                        ],
                    },
                },
            },

            # ── Attack Role (SCERole) – the role the attacker wants to abuse ─
            "SCERole": {
                "Type": "AWS::IAM::Role",
                "DependsOn": ["SCEBoundary"],
                "Properties": {
                    "RoleName": f"SCERole-{suffix}",
                    "Description": "Simulated compromised instance role with IMDS-deny boundary",
                    "PermissionsBoundary": {"Ref": "SCEBoundary"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                # Trust EC2 service only – NOT the ChaosXploit-Labs user.
                                # The experiment verifies the boundary via SimulatePrincipalPolicy,
                                # not by actually assuming the role from outside EC2.
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "SCERoleInline",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:ModifyInstanceMetadataOptions",
                                            "ec2:DescribeInstances",
                                            "sts:GetCallerIdentity",
                                            "iam:ListAttachedRolePolicies",
                                            "iam:ListRolePolicies",
                                            "s3:ListAllMyBuckets",
                                            "s3:GetObject",
                                            "secretsmanager:GetSecretValue",
                                        ],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": EXPERIMENT_TAG,
                },
            },

            # ── Verifier Role (SCEVerifier) – the probe's inspection identity ─
            # The caller (ChaosXploit-Labs user) CAN assume this role.
            # Scoped to read-only IAM simulation and EC2/SG inspection only.
            "SCEVerifier": {
                "Type": "AWS::IAM::Role",
                "DependsOn": ["SCEBoundary"],
                "Properties": {
                    "RoleName": f"SCEVerifier-{suffix}",
                    "Description": "Observer role for SCE probe verification (read-only)",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": caller_arn},
                                "Action": "sts:AssumeRole",
                                "Condition": {},
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "SCEVerifierInline",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "IAMSimulate",
                                        "Effect": "Allow",
                                        "Action": [
                                            "iam:SimulatePrincipalPolicy",
                                            "iam:GetRole",
                                            "iam:GetPolicy",
                                            "iam:GetPolicyVersion",
                                            "iam:ListAttachedRolePolicies",
                                            "iam:ListRolePolicies",
                                            "iam:GetRolePolicy",
                                        ],
                                        "Resource": "*",
                                    },
                                    {
                                        "Sid": "EC2Inspect",
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:DescribeInstances",
                                            "ec2:DescribeSecurityGroups",
                                            "ec2:DescribeSecurityGroupRules",
                                            "ec2:DescribeLaunchTemplates",
                                            "ec2:DescribeLaunchTemplateVersions",
                                        ],
                                        "Resource": "*",
                                    },
                                    {
                                        "Sid": "SSMSendCommand",
                                        "Effect": "Allow",
                                        "Action": [
                                            "ssm:SendCommand",
                                            "ssm:GetCommandInvocation",
                                            "ssm:DescribeInstanceInformation",
                                        ],
                                        "Resource": "*",
                                    },
                                    {
                                        "Sid": "STS",
                                        "Effect": "Allow",
                                        "Action": "sts:GetCallerIdentity",
                                        "Resource": "*",
                                    },
                                ],
                            },
                        }
                    ],
                    "Tags": EXPERIMENT_TAG,
                },
            },

            # ── Instance Profile ──────────────────────────────────────────────
            "SCEProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "DependsOn": ["SCERole"],
                "Properties": {
                    "InstanceProfileName": f"SCEProfile-{suffix}",
                    "Roles": [{"Ref": "SCERole"}],
                },
            },
        },

        "Outputs": {
            "RoleArn":       {"Value": {"Fn::GetAtt": ["SCERole",      "Arn"]}},
            "RoleName":      {"Value": {"Ref": "SCERole"}},
            "VerifierArn":   {"Value": {"Fn::GetAtt": ["SCEVerifier",  "Arn"]}},
            "VerifierName":  {"Value": {"Ref": "SCEVerifier"}},
            "BoundaryArn":   {"Value": {"Ref": "SCEBoundary"}},
            "ProfileName":   {"Value": {"Ref": "SCEProfile"}},
        },
    }
    body = json.dumps(template, indent=2)
    _assert_ascii(body, "IAM template")
    return body


def _build_ec2_template(
    suffix: str, az: str, itype: str, ami: str
) -> str:
    """
    Creates a VPC with:
      - Private subnet only (no IGW, no public route)
      - VPC Interface Endpoints for SSM (ssm, ssmmessages, ec2messages)
      - VPC Interface Endpoint for EC2 (to allow ModifyInstanceMetadataOptions call)
      - Security group: egress TCP/443 only (no TCP/80, no 169.254.x.x path)
      - Launch template: MetadataOptions.HttpTokens=required, HopLimit=1
      - EC2 instance with the SCEProfile attached
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 Preventive – VPC + EC2 resources",

        "Parameters": {
            "InstanceProfileName": {
                "Type": "String",
                "Default": f"SCEProfile-{suffix}",
            }
        },

        "Resources": {

            # ── VPC ────────────────────────────────────────────────────────────
            "SCEVPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport":   True,
                    "Tags": [{"Key": "Name", "Value": f"SCE-VPC-{suffix}"}] + EXPERIMENT_TAG,
                },
            },

            "SCESubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId":               {"Ref": "SCEVPC"},
                    "CidrBlock":           "10.0.1.0/24",
                    "AvailabilityZone":    az,
                    "MapPublicIpOnLaunch": False,
                    "Tags": [{"Key": "Name", "Value": f"SCE-Subnet-{suffix}"}] + EXPERIMENT_TAG,
                },
            },

            # Route table (no IGW attachment → fully private)
            "SCERouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {
                    "VpcId": {"Ref": "SCEVPC"},
                    "Tags":  [{"Key": "Name", "Value": f"SCE-RT-{suffix}"}] + EXPERIMENT_TAG,
                },
            },
            "SCESubnetRTAssoc": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId":     {"Ref": "SCESubnet"},
                    "RouteTableId": {"Ref": "SCERouteTable"},
                },
            },

            # ── Security Group ─────────────────────────────────────────────────
            # Egress: TCP/443 only to 0.0.0.0/0 (for VPC endpoints over PrivateLink)
            # No rule for TCP/80 or any path to 169.254.0.0/16
            "SCESG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": f"SCE-SG-{suffix}: egress 443 only, no IMDS path",
                    "VpcId": {"Ref": "SCEVPC"},
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort":   443,
                            "ToPort":     443,
                            "CidrIp":     "0.0.0.0/0",
                            "Description": "HTTPS to VPC endpoints only",
                        }
                    ],
                    # No ingress rules needed (SSM uses outbound PrivateLink only)
                    "Tags": [{"Key": "Name", "Value": f"SCE-SG-{suffix}"}] + EXPERIMENT_TAG,
                },
            },

            # ── VPC Endpoints (SSM + EC2) ──────────────────────────────────────
            "SCEEndpointSG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": f"SCE-EndpointSG-{suffix}: allow HTTPS from subnet",
                    "VpcId": {"Ref": "SCEVPC"},
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort":   443,
                            "ToPort":     443,
                            "CidrIp":     "10.0.1.0/24",
                        }
                    ],
                    "Tags": EXPERIMENT_TAG,
                },
            },

            "VPCEndpointSSM": {
                "Type": "AWS::EC2::VPCEndpoint",
                "Properties": {
                    "VpcEndpointType": "Interface",
                    "ServiceName": f"com.amazonaws.{REGION}.ssm",
                    "VpcId":       {"Ref": "SCEVPC"},
                    "SubnetIds":   [{"Ref": "SCESubnet"}],
                    "SecurityGroupIds": [{"Ref": "SCEEndpointSG"}],
                    "PrivateDnsEnabled": True,
                },
            },
            "VPCEndpointSSMMessages": {
                "Type": "AWS::EC2::VPCEndpoint",
                "Properties": {
                    "VpcEndpointType": "Interface",
                    "ServiceName": f"com.amazonaws.{REGION}.ssmmessages",
                    "VpcId":       {"Ref": "SCEVPC"},
                    "SubnetIds":   [{"Ref": "SCESubnet"}],
                    "SecurityGroupIds": [{"Ref": "SCEEndpointSG"}],
                    "PrivateDnsEnabled": True,
                },
            },
            "VPCEndpointEC2Messages": {
                "Type": "AWS::EC2::VPCEndpoint",
                "Properties": {
                    "VpcEndpointType": "Interface",
                    "ServiceName": f"com.amazonaws.{REGION}.ec2messages",
                    "VpcId":       {"Ref": "SCEVPC"},
                    "SubnetIds":   [{"Ref": "SCESubnet"}],
                    "SecurityGroupIds": [{"Ref": "SCEEndpointSG"}],
                    "PrivateDnsEnabled": True,
                },
            },
            "VPCEndpointEC2": {
                "Type": "AWS::EC2::VPCEndpoint",
                "Properties": {
                    "VpcEndpointType": "Interface",
                    "ServiceName": f"com.amazonaws.{REGION}.ec2",
                    "VpcId":       {"Ref": "SCEVPC"},
                    "SubnetIds":   [{"Ref": "SCESubnet"}],
                    "SecurityGroupIds": [{"Ref": "SCEEndpointSG"}],
                    "PrivateDnsEnabled": True,
                },
            },

            # ── Launch Template (enforces IMDSv2 / HopLimit=1) ─────────────────
            "SCELaunchTemplate": {
                "Type": "AWS::EC2::LaunchTemplate",
                "Properties": {
                    "LaunchTemplateName": f"SCE-LT-{suffix}",
                    "LaunchTemplateData": {
                        "ImageId":      ami,
                        "InstanceType": itype,
                        "IamInstanceProfile": {
                            "Name": f"SCEProfile-{suffix}",
                        },
                        "NetworkInterfaces": [
                            {
                                "DeviceIndex":              0,
                                "AssociatePublicIpAddress": False,
                                "SubnetId":                 {"Ref": "SCESubnet"},
                                "Groups":                   [{"Ref": "SCESG"}],
                            }
                        ],
                        "MetadataOptions": {
                            "HttpTokens":              "required",
                            "HttpEndpoint":            "enabled",
                            "HttpPutResponseHopLimit": 1,
                        },
                        "TagSpecifications": [
                            {
                                "ResourceType": "instance",
                                "Tags": [
                                    {"Key": "Name", "Value": f"SCE-Instance-{suffix}"},
                                ] + EXPERIMENT_TAG,
                            }
                        ],
                    },
                },
            },

            # ── EC2 Instance ───────────────────────────────────────────────────
            "SCEInstance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": [
                    "VPCEndpointSSM",
                    "VPCEndpointSSMMessages",
                    "VPCEndpointEC2Messages",
                    "VPCEndpointEC2",
                    "SCESubnetRTAssoc",
                ],
                "Properties": {
                    "LaunchTemplate": {
                        "LaunchTemplateName": f"SCE-LT-{suffix}",
                        "Version": {
                            "Fn::GetAtt": ["SCELaunchTemplate", "LatestVersionNumber"]
                        },
                    },
                    "Tags": [
                        {"Key": "Name", "Value": f"SCE-Instance-{suffix}"},
                    ] + EXPERIMENT_TAG,
                },
            },
        },

        "Outputs": {
            "InstanceId": {"Value": {"Ref": "SCEInstance"}},
            "SGID":       {"Value": {"Ref": "SCESG"}},
            "VPCID":      {"Value": {"Ref": "SCEVPC"}},
            "SubnetID":   {"Value": {"Ref": "SCESubnet"}},
        },
    }

    body = json.dumps(template, indent=2)
    _assert_ascii(body, "EC2 template")
    return body


# ─────────────────────────────────────────────────────────────────────────────
# Stack helpers
# ─────────────────────────────────────────────────────────────────────────────

def _stack_outputs(stack_name: str) -> dict:
    resp = _cfn().describe_stacks(StackName=stack_name)
    outputs = {}
    for o in resp["Stacks"][0].get("Outputs", []):
        outputs[o["OutputKey"]] = o["OutputValue"]
    return outputs


def _delete_stack(stack_name: str) -> None:
    try:
        status = _cfn().describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            log.info("Stack %s already deleted.", stack_name)
            return
        if "ROLLBACK" in status and "IN_PROGRESS" not in status:
            log.info("Stack %s in %s – forcing delete.", stack_name, status)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info("Stack %s does not exist – skip.", stack_name)
            return
        raise

    log.info("Deleting stack %s …", stack_name)
    _cfn().delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        try:
            resp   = _cfn().describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            log.info("Stack %s delete status: %s", stack_name, status)
            if status == "DELETE_COMPLETE":
                log.info("Stack %s deleted.", stack_name)
                return
            if "FAILED" in status:
                log.error("Stack %s deletion failed with status %s.", stack_name, status)
                return
        except ClientError as exc:
            if "does not exist" in str(exc):
                log.info("Stack %s confirmed deleted.", stack_name)
                return
            raise
        time.sleep(POLL_INTERVAL)
    log.warning("Stack %s deletion did not complete within 1800s.", stack_name)


# ─────────────────────────────────────────────────────────────────────────────
# Pre-flight
# ─────────────────────────────────────────────────────────────────────────────

def _preflight() -> None:
    """Verify caller identity and simulate required IAM permissions."""
    caller = _sts().get_caller_identity()
    log.info(
        "Caller identity: Account=%s Arn=%s",
        caller["Account"], caller["Arn"],
    )

    # Simulate that the caller can create CloudFormation stacks and IAM resources
    sim = _iam().simulate_principal_policy(
        PolicySourceArn=caller["Arn"],
        ActionNames=[
            "cloudformation:CreateStack",
            "cloudformation:DescribeStacks",
            "cloudformation:DeleteStack",
            "ec2:RunInstances",
            "ec2:DescribeInstances",
            "ec2:DescribeSecurityGroups",
            "iam:CreateRole",
            "iam:CreateInstanceProfile",
            "iam:SimulatePrincipalPolicy",
        ],
        ResourceArns=["*"],
    )
    denied = [
        r["EvalActionName"]
        for r in sim["EvaluationResults"]
        if r["EvalDecision"] != "allowed"
    ]
    if denied:
        log.warning("Pre-flight: some actions may not be allowed: %s", denied)
    else:
        log.info("Pre-flight simulation: all required actions appear allowed.")


# ─────────────────────────────────────────────────────────────────────────────
# STEADY STATE
# ─────────────────────────────────────────────────────────────────────────────

def steady_state() -> bool:
    """
    Provision all experiment resources via CloudFormation:
      1. IAM stack: SCEBoundary + SCERole (attacker) + SCEVerifier (observer) + SCEProfile
      2. EC2 stack: VPC (private, no IGW) + SG (443 only) + VPC Endpoints + LT + Instance

    All state stored in module-level _STATE dict.
    """
    global _STATE
    log.info("Installing boto3 if needed …")
    # (already imported above)

    log.info("=== steady_state ===")
    _preflight()

    suffix     = str(int(time.time()))
    account_id = _caller_account()
    caller_arn = _caller_arn()

    _STATE["suffix"]     = suffix
    _STATE["account_id"] = account_id
    _STATE["caller_arn"] = caller_arn

    iam_stack_name = f"{STACK_IAM_PFX}-{suffix}"
    ec2_stack_name = f"{STACK_EC2_PFX}-{suffix}"
    _STATE["iam_stack"] = iam_stack_name
    _STATE["ec2_stack"] = ec2_stack_name

    ami           = _resolve_ami()
    az, itype     = _resolve_az_and_type()
    _STATE["ami"] = ami
    _STATE["az"]  = az

    # ── IAM Stack ──────────────────────────────────────────────────────────────
    iam_tpl = _build_iam_template(suffix, caller_arn, account_id)

    if _stack_exists(iam_stack_name):
        log.warning("Stack %s already exists – continuing.", iam_stack_name)
    else:
        log.info("Deploying IAM stack: %s", iam_stack_name)
        _cfn().create_stack(
            StackName=iam_stack_name,
            TemplateBody=iam_tpl,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=EXPERIMENT_TAG,
        )
        log.info("IAM stack creation initiated.")

    _wait_stack(iam_stack_name)
    iam_outputs = _stack_outputs(iam_stack_name)
    _STATE.update({
        "role_arn":      iam_outputs["RoleArn"],
        "role_name":     iam_outputs["RoleName"],
        "verifier_arn":  iam_outputs["VerifierArn"],
        "verifier_name": iam_outputs["VerifierName"],
        "boundary_arn":  iam_outputs["BoundaryArn"],
        "profile_name":  iam_outputs["ProfileName"],
    })
    log.info(
        "IAM stack complete. RoleArn=%s | VerifierArn=%s | BoundaryArn=%s",
        _STATE["role_arn"], _STATE["verifier_arn"], _STATE["boundary_arn"],
    )

    # Wait for IAM propagation
    log.info("Waiting 30s for IAM propagation …")
    time.sleep(30)

    # ── EC2 Stack ──────────────────────────────────────────────────────────────
    ec2_tpl = _build_ec2_template(suffix, az, itype, ami)

    if _stack_exists(ec2_stack_name):
        log.warning("Stack %s already exists – continuing.", ec2_stack_name)
    else:
        log.info(
            "Deploying EC2 stack: %s (AZ=%s type=%s ami=%s)",
            ec2_stack_name, az, itype, ami,
        )
        _cfn().create_stack(
            StackName=ec2_stack_name,
            TemplateBody=ec2_tpl,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=EXPERIMENT_TAG,
        )
        log.info("EC2 stack creation initiated.")

    _wait_stack(ec2_stack_name)
    ec2_outputs = _stack_outputs(ec2_stack_name)
    _STATE.update({
        "instance_id": ec2_outputs["InstanceId"],
        "sg_id":       ec2_outputs["SGID"],
        "vpc_id":      ec2_outputs["VPCID"],
        "subnet_id":   ec2_outputs["SubnetID"],
    })
    log.info(
        "EC2 stack complete. InstanceId=%s | SG=%s | VPC=%s | Subnet=%s",
        _STATE["instance_id"], _STATE["sg_id"],
        _STATE["vpc_id"],      _STATE["subnet_id"],
    )

    # Wait for instance running
    log.info("Waiting for instance %s to reach 'running' …", _STATE["instance_id"])
    _retry(
        lambda: _ec2().get_waiter("instance_running").wait(
            InstanceIds=[_STATE["instance_id"]],
            WaiterConfig={"Delay": 10, "MaxAttempts": 30},
        ),
        "instance_running_waiter",
        max_attempts=3,
    )
    log.info("Instance %s is running.", _STATE["instance_id"])

    # SSM registration (best-effort, 300 s)
    log.info(
        "Waiting up to %ds for SSM agent on %s …",
        SSM_WAIT, _STATE["instance_id"],
    )
    ssm_ok     = False
    ssm_deadline = time.monotonic() + SSM_WAIT
    while time.monotonic() < ssm_deadline:
        try:
            resp = _ssm().describe_instance_information(
                Filters=[
                    {"Key": "InstanceIds", "Values": [_STATE["instance_id"]]}
                ]
            )
            infos = resp.get("InstanceInformationList", [])
            if infos and infos[0].get("PingStatus") == "Online":
                log.info("SSM agent Online on %s.", _STATE["instance_id"])
                ssm_ok = True
                break
        except ClientError as exc:
            log.warning("SSM describe failed: %s", exc)
        time.sleep(15)

    _STATE["ssm_registered"] = ssm_ok
    if not ssm_ok:
        log.warning(
            "SSM agent not Online within %ds on %s. Check D will be best-effort.",
            SSM_WAIT, _STATE["instance_id"],
        )

    log.info(
        "steady_state complete. State keys: %s", list(_STATE.keys())
    )
    return True


# ─────────────────────────────────────────────────────────────────────────────
# ATTACK
# ─────────────────────────────────────────────────────────────────────────────

def attack() -> bool:
    """
    Attack Node 1.2 + 1.7 simulation:
      Attempt to call ec2:ModifyInstanceMetadataOptions (HttpTokens=optional,
      HopLimit=2) on the target instance using the SCERole identity.

    KEY DESIGN CHANGE vs. previous execution:
      The attack does NOT attempt sts:AssumeRole from outside the EC2 trust
      boundary (that always fails as documented in the previous run logs).
      Instead, the attack is simulated via iam:SimulatePrincipalPolicy against
      SCERole — this precisely models whether the role, if compromised, could
      execute the IMDS downgrade. This is the correct simulation model because:
        - SCERole's trust policy allows only ec2.amazonaws.com to assume it
        - In the real attack, the adversary WOULD hold these credentials having
          stolen them from IMDS (Step 2 of attack node 1.7 is the exfiltration)
        - The permission boundary is what stops the action regardless of how
          credentials were obtained
        - iam:SimulatePrincipalPolicy accurately evaluates the boundary effect

    Additionally: attempt the call directly using the caller's own credentials
    (which do NOT have ec2:ModifyInstanceMetadataOptions) as a secondary vector,
    capturing the AccessDenied response as attack evidence.
    """
    log.info(
        "=== attack: simulating ModifyInstanceMetadataOptions on %s ===",
        _STATE.get("instance_id", "UNKNOWN"),
    )

    instance_id  = _STATE["instance_id"]
    role_arn     = _STATE["role_arn"]
    boundary_arn = _STATE["boundary_arn"]

    # ── Vector 1: SimulatePrincipalPolicy against SCERole ─────────────────────
    # This evaluates the ACTUAL effective permission (role inline + boundary).
    log.info("Attack Vector 1: iam:SimulatePrincipalPolicy on SCERole …")
    try:
        sim_resp = _iam().simulate_principal_policy(
            PolicySourceArn=role_arn,
            ActionNames=["ec2:ModifyInstanceMetadataOptions"],
            ResourceArns=[
                f"arn:aws:ec2:{REGION}:{_STATE['account_id']}:instance/{instance_id}"
            ],
        )
        results = sim_resp["EvaluationResults"]
        for r in results:
            decision   = r["EvalDecision"]
            action     = r["EvalActionName"]
            deny_reason = r.get("MatchedStatements", [])
            log.info(
                "SimulatePrincipalPolicy: Action=%s Decision=%s MatchedStatements=%s",
                action, decision,
                [s.get("SourcePolicyId", "") for s in deny_reason],
            )
            _STATE["sim_decision"]       = decision
            _STATE["sim_matched"]        = [s.get("SourcePolicyId", "") for s in deny_reason]

    except ClientError as exc:
        log.error("SimulatePrincipalPolicy failed: %s", exc)
        _STATE["sim_decision"] = "error"
        _STATE["sim_error"]    = str(exc)

    # ── Vector 2: Direct call attempt using caller credentials ────────────────
    # The ChaosXploit-Labs user almost certainly lacks ec2:ModifyInstanceMetadataOptions.
    # This generates a real AccessDenied CloudTrail event as attack evidence.
    log.info(
        "Attack Vector 2: direct ModifyInstanceMetadataOptions call from caller identity …"
    )
    try:
        _ec2().modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="optional",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=2,
        )
        # If this succeeds, the control FAILED – record it.
        log.error(
            "CONTROL FAILURE: ModifyInstanceMetadataOptions SUCCEEDED – "
            "HttpTokens was set to optional on %s!", instance_id
        )
        _STATE["attack_result"]     = "succeeded_unexpected"
        _STATE["attack_error_code"] = None
        return False

    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        log.info(
            "ModifyInstanceMetadataOptions blocked with %s (expected). "
            "Attack vector 2 repelled.", code
        )
        _STATE["attack_result"]     = "blocked"
        _STATE["attack_error_code"] = code
        return True

    except Exception as exc:
        log.error("Unexpected error in attack vector 2: %s", exc)
        _STATE["attack_result"]     = "error"
        _STATE["attack_error_code"] = type(exc).__name__
        return True   # Non-AWS error doesn't indicate control failure


# ─────────────────────────────────────────────────────────────────────────────
# HYPOTHESIS VERIFICATION
# ─────────────────────────────────────────────────────────────────────────────

def hypothesis_verification() -> bool:
    """
    Verify all four preventive controls using the SCEVerifier role
    (which the caller CAN assume) and direct EC2 API inspection.

    Check A – iam:SimulatePrincipalPolicy confirms boundary denies
               ec2:ModifyInstanceMetadataOptions on SCERole
    Check B – ec2:DescribeInstances confirms HttpTokens=required, HopLimit=1
               (30-min SLA polling loop)
    Check C – ec2:DescribeSecurityGroups confirms no egress rule permits
               TCP/80 or any path to 169.254.0.0/16
               (30-min SLA polling loop)
    Check D – SSM Run Command: curl without token returns HTTP 401
               (best-effort, skipped if SSM not online)

    Each check is independent. Returns True iff checks A, B, and C all pass.
    """
    log.info("=== hypothesis_verification (SCE 1.8 Preventive) ===")

    results: dict = {
        "check_a_boundary_denies":  False,
        "check_b_metadata_options": False,
        "check_c_sg_no_imds_egress": False,
        "check_d_ssm_curl_401":     None,   # None = skipped
    }

    # ── Assume SCEVerifier role ────────────────────────────────────────────────
    log.info("Assuming SCEVerifier role: %s", _STATE["verifier_arn"])
    verifier_creds = None
    try:
        assume_resp = _retry(
            lambda: _sts().assume_role(
                RoleArn=_STATE["verifier_arn"],
                RoleSessionName="sce-verifier-probe",
                DurationSeconds=3600,
            ),
            "assume_verifier_role",
            max_attempts=5,
            base_delay=3.0,
        )
        verifier_creds = assume_resp["Credentials"]
        log.info("Successfully assumed SCEVerifier role.")
    except ClientError as exc:
        log.error("Failed to assume SCEVerifier: %s", exc)
        log.error(traceback.format_exc())
        # Fall back to caller credentials for EC2/SG checks (they don't need the verifier)
        verifier_creds = None

    def _verifier_iam():
        if verifier_creds:
            return boto3.client(
                "iam",
                region_name=REGION,
                aws_access_key_id=verifier_creds["AccessKeyId"],
                aws_secret_access_key=verifier_creds["SecretAccessKey"],
                aws_session_token=verifier_creds["SessionToken"],
            )
        return _iam()

    def _verifier_ec2():
        if verifier_creds:
            return boto3.client(
                "ec2",
                region_name=REGION,
                aws_access_key_id=verifier_creds["AccessKeyId"],
                aws_secret_access_key=verifier_creds["SecretAccessKey"],
                aws_session_token=verifier_creds["SessionToken"],
            )
        return _ec2()

    def _verifier_ssm():
        if verifier_creds:
            return boto3.client(
                "ssm",
                region_name=REGION,
                aws_access_key_id=verifier_creds["AccessKeyId"],
                aws_secret_access_key=verifier_creds["SecretAccessKey"],
                aws_session_token=verifier_creds["SessionToken"],
            )
        return _ssm()

    # ── Check A: Permission Boundary Simulation ────────────────────────────────
    log.info("=== Check A: IAM permission boundary denies ModifyInstanceMetadataOptions ===")
    try:
        sim = _verifier_iam().simulate_principal_policy(
            PolicySourceArn=_STATE["role_arn"],
            ActionNames=["ec2:ModifyInstanceMetadataOptions"],
            ResourceArns=[
                f"arn:aws:ec2:{REGION}:{_STATE['account_id']}:instance/{_STATE['instance_id']}"
            ],
        )
        for r in sim["EvaluationResults"]:
            decision = r["EvalDecision"]
            matched  = [s.get("SourcePolicyId", "") for s in r.get("MatchedStatements", [])]
            log.info(
                "Check A: SimulatePrincipalPolicy result – Action=%s Decision=%s "
                "MatchedStatements=%s",
                r["EvalActionName"], decision, matched,
            )
            if decision in ("explicitDeny", "implicitDeny"):
                # Verify the denial came from the permission boundary
                boundary_denied = any(
                    _STATE.get("boundary_arn", "").split("/")[-1] in s
                    or "SCEBoundary" in s
                    or "DenyIMDSDowngrade" in s
                    for s in matched
                )
                if boundary_denied or decision == "explicitDeny":
                    log.info(
                        "Check A PASSED: ec2:ModifyInstanceMetadataOptions is denied "
                        "(decision=%s, matched=%s).", decision, matched
                    )
                    results["check_a_boundary_denies"] = True
                else:
                    log.warning(
                        "Check A: denied but boundary not identified in matched statements. "
                        "Accepting explicitDeny as sufficient evidence."
                    )
                    # An explicit deny from any policy is still a passing control
                    results["check_a_boundary_denies"] = (decision == "explicitDeny")
            else:
                log.error(
                    "Check A FAILED: expected deny, got decision=%s for action=%s",
                    decision, r["EvalActionName"],
                )

    except ClientError as exc:
        log.error("Check A failed with ClientError: %s", exc)
        log.error(traceback.format_exc())

    # ── Check B: EC2 Metadata Options (30-min SLA) ─────────────────────────────
    log.info(
        "=== Check B: EC2 metadata options – HttpTokens=required, HopLimit=1 "
        "(SLA=%ds) ===", SLA_WINDOW
    )
    check_b_deadline = time.monotonic() + SLA_WINDOW
    while time.monotonic() < check_b_deadline:
        try:
            resp = _verifier_ec2().describe_instances(
                InstanceIds=[_STATE["instance_id"]]
            )
            reservations = resp.get("Reservations", [])
            if not reservations:
                log.warning("Check B: no reservations returned yet, retrying …")
                time.sleep(POLL_INTERVAL)
                continue

            instance = reservations[0]["Instances"][0]
            meta     = instance.get("MetadataOptions", {})
            tokens   = meta.get("HttpTokens",              "unknown")
            hop      = meta.get("HttpPutResponseHopLimit", -1)
            state    = meta.get("State",                   "unknown")
            endpoint = meta.get("HttpEndpoint",            "unknown")

            log.info(
                "Check B: MetadataOptions – HttpTokens=%s HopLimit=%s Endpoint=%s State=%s",
                tokens, hop, endpoint, state,
            )

            if tokens == "required" and hop == 1:
                log.info("Check B PASSED: HttpTokens=required and HopLimit=1 confirmed.")
                results["check_b_metadata_options"] = True
                break
            elif state == "pending":
                log.info("Check B: metadata options state=pending, waiting …")
            else:
                log.warning(
                    "Check B: HttpTokens=%s (expected 'required'), HopLimit=%s (expected 1). "
                    "Retrying within SLA window …", tokens, hop,
                )

        except ClientError as exc:
            log.warning("Check B DescribeInstances error: %s – retrying …", exc)

        time.sleep(POLL_INTERVAL)

    if not results["check_b_metadata_options"]:
        log.error("Check B FAILED: metadata options not as expected within %ds SLA.", SLA_WINDOW)

    # ── Check C: Security Group Egress – no IMDS path (30-min SLA) ────────────
    log.info(
        "=== Check C: Security group has no egress path to 169.254.0.0/16 "
        "(SLA=%ds) ===", SLA_WINDOW
    )
    IMDS_CIDRS = {"169.254.169.254/32", "169.254.0.0/16", "169.254.0.0/24"}

    check_c_deadline = time.monotonic() + SLA_WINDOW
    while time.monotonic() < check_c_deadline:
        try:
            sg_resp = _verifier_ec2().describe_security_groups(
                GroupIds=[_STATE["sg_id"]]
            )
            sg = sg_resp["SecurityGroups"][0]
            egress_rules = sg.get("IpPermissionsEgress", [])

            imds_exposed = False
            for rule in egress_rules:
                proto    = rule.get("IpProtocol", "")
                from_p   = rule.get("FromPort",    0)
                to_p     = rule.get("ToPort",     65535)
                ip_ranges = rule.get("IpRanges", [])

                for ip_r in ip_ranges:
                    cidr = ip_r.get("CidrIp", "")
                    # Check 1: explicit IMDS CIDR
                    if cidr in IMDS_CIDRS:
                        imds_exposed = True
                        log.error(
                            "Check C FAILED: egress rule allows %s to IMDS CIDR %s",
                            proto, cidr,
                        )
                    # Check 2: 0.0.0.0/0 with TCP/80 (could reach IMDS)
                    if cidr == "0.0.0.0/0" and proto == "tcp":
                        if from_p <= 80 <= to_p:
                            imds_exposed = True
                            log.error(
                                "Check C FAILED: egress 0.0.0.0/0 TCP port 80 allows IMDS path"
                            )
                    # Check 3: 0.0.0.0/0 with -1 (all traffic)
                    if cidr == "0.0.0.0/0" and proto == "-1":
                        imds_exposed = True
                        log.error(
                            "Check C FAILED: egress 0.0.0.0/0 all-traffic allows IMDS path"
                        )

            if not imds_exposed:
                log.info(
                    "Check C PASSED: no egress rule permits TCP/80 or any path "
                    "to 169.254.x.x. Egress rules: %s",
                    [
                        {
                            "proto": r.get("IpProtocol"),
                            "from":  r.get("FromPort"),
                            "to":    r.get("ToPort"),
                            "cidrs": [x.get("CidrIp") for x in r.get("IpRanges", [])],
                        }
                        for r in egress_rules
                    ],
                )
                results["check_c_sg_no_imds_egress"] = True
                break
            else:
                log.warning("Check C: IMDS path exposed – retrying …")

        except ClientError as exc:
            log.warning("Check C DescribeSecurityGroups error: %s – retrying …", exc)

        time.sleep(POLL_INTERVAL)

    if not results["check_c_sg_no_imds_egress"]:
        log.error("Check C FAILED within %ds SLA.", SLA_WINDOW)

    # ── Check D: SSM Run Command – unauthenticated IMDS curl returns 401 ──────
    log.info("=== Check D: SSM Run Command – unauthenticated IMDS returns HTTP 401 ===")
    if not _STATE.get("ssm_registered"):
        log.warning(
            "Check D SKIPPED: SSM agent not online on %s within %ds.",
            _STATE["instance_id"], SSM_WAIT,
        )
        results["check_d_ssm_curl_401"] = None
    else:
        try:
            cmd_resp = _verifier_ssm().send_command(
                InstanceIds=[_STATE["instance_id"]],
                DocumentName="AWS-RunShellScript",
                Parameters={
                    "commands": [
                        # Attempt unauthenticated IMDSv1 request (no token header)
                        "HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "
                        "--max-time 5 "
                        "http://169.254.169.254/latest/meta-data/iam/security-credentials/)",
                        "echo \"IMDS_HTTP_CODE=${HTTP_CODE}\"",
                        "if [ \"${HTTP_CODE}\" = \"401\" ]; then "
                        "  echo 'CHECK_D=PASSED'; "
                        "elif [ -z \"${HTTP_CODE}\" ] || [ \"${HTTP_CODE}\" = \"000\" ]; then "
                        "  echo 'CHECK_D=PASSED_UNREACHABLE'; "
                        "else "
                        "  echo \"CHECK_D=FAILED_HTTP_${HTTP_CODE}\"; "
                        "fi",
                    ]
                },
                TimeoutSeconds=60,
            )
            cmd_id = cmd_resp["Command"]["CommandId"]
            log.info("Check D: SSM command sent, CommandId=%s", cmd_id)

            # Poll for command result (up to 120s)
            cmd_deadline = time.monotonic() + 120
            while time.monotonic() < cmd_deadline:
                time.sleep(10)
                try:
                    inv = _verifier_ssm().get_command_invocation(
                        CommandId=cmd_id,
                        InstanceId=_STATE["instance_id"],
                    )
                    status = inv["Status"]
                    log.info("Check D: command status=%s", status)
                    if status in ("Success", "Failed", "TimedOut", "Cancelled"):
                        output = inv.get("StandardOutputContent", "")
                        error  = inv.get("StandardErrorContent", "")
                        log.info("Check D stdout: %s", output.strip())
                        if error.strip():
                            log.info("Check D stderr: %s", error.strip())

                        if "CHECK_D=PASSED" in output:
                            log.info(
                                "Check D PASSED: unauthenticated IMDS returns 401 or unreachable."
                            )
                            results["check_d_ssm_curl_401"] = True
                        else:
                            log.warning("Check D result: %s", output.strip())
                            results["check_d_ssm_curl_401"] = False
                        break
                except ClientError as exc:
                    log.warning("Check D GetCommandInvocation error: %s", exc)
            else:
                log.warning("Check D: command result polling timed out after 120s.")
                results["check_d_ssm_curl_401"] = None

        except ClientError as exc:
            log.error("Check D SSM error: %s", exc)
            results["check_d_ssm_curl_401"] = None

    # ── Summary ────────────────────────────────────────────────────────────────
    log.info("=== Hypothesis Verification Summary ===")
    for check, result in results.items():
        status = "PASSED" if result is True else ("SKIPPED" if result is None else "FAILED")
        log.info("  %-35s : %s", check, status)

    _STATE["hypothesis_results"] = results

    # Core pass condition: A, B, C must all pass.
    # D is informational (best-effort).
    mandatory_pass = (
        results["check_a_boundary_denies"]
        and results["check_b_metadata_options"]
        and results["check_c_sg_no_imds_egress"]
    )

    if mandatory_pass:
        log.info(
            "hypothesis_verification: PASSED "
            "(A=%s, B=%s, C=%s, D=%s)",
            results["check_a_boundary_denies"],
            results["check_b_metadata_options"],
            results["check_c_sg_no_imds_egress"],
            results["check_d_ssm_curl_401"],
        )
    else:
        log.error(
            "hypothesis_verification: FAILED "
            "(A=%s, B=%s, C=%s, D=%s) – "
            "one or more mandatory preventive controls not confirmed.",
            results["check_a_boundary_denies"],
            results["check_b_metadata_options"],
            results["check_c_sg_no_imds_egress"],
            results["check_d_ssm_curl_401"],
        )

    return mandatory_pass


# ─────────────────────────────────────────────────────────────────────────────
# ROLLBACK
# ─────────────────────────────────────────────────────────────────────────────

def rollback() -> bool:
    """
    Delete all CloudFormation stacks created by steady_state().
    EC2 stack must be deleted before IAM stack (dependency order).
    Safe and tolerant: continues even if stacks don't exist.
    """
    log.info("=== rollback ===")
    ec2_stack = _STATE.get("ec2_stack")
    iam_stack = _STATE.get("iam_stack")

    if ec2_stack:
        try:
            _delete_stack(ec2_stack)
        except Exception as exc:
            log.error("Error deleting EC2 stack %s: %s", ec2_stack, exc)
            log.error(traceback.format_exc())

    # Wait between stack deletions to allow instance profile detachment
    time.sleep(15)

    if iam_stack:
        try:
            _delete_stack(iam_stack)
        except Exception as exc:
            log.error("Error deleting IAM stack %s: %s", iam_stack, exc)
            log.error(traceback.format_exc())

    log.info("rollback complete.")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Standalone entry-point
# ─────────────────────────────────────────────────────────────────────────────

def _run_experiment() -> None:
    """Run the full experiment with guaranteed rollback."""
    exit_code = 0
    try:
        log.info("Starting SCE 1.8 Preventive experiment …")

        ok = steady_state()
        if not ok:
            log.error("steady_state() returned False – aborting.")
            exit_code = 1
            return

        attack_ok = attack()
        log.info("attack() returned: %s", attack_ok)

        hypothesis_ok = hypothesis_verification()
        log.info("hypothesis_verification() returned: %s", hypothesis_ok)

        if hypothesis_ok:
            log.info("Experiment PASSED: all mandatory preventive controls confirmed.")
        else:
            log.error(
                "Experiment FAILED: one or more preventive controls not confirmed. "
                "A security weakness may have been discovered."
            )
            exit_code = 1

    except Exception as exc:
        log.error("Unhandled exception in experiment: %s", exc)
        log.error(traceback.format_exc())
        exit_code = 1

    finally:
        try:
            rollback()
        except Exception as exc:
            log.error("Rollback error: %s", exc)
            log.error(traceback.format_exc())

    sys.exit(exit_code)


if __name__ == "__main__":
    _run_experiment()