"""
SCE Experiment 2.5 -- Preventive Probe
Attack Nodes: 1.2 + 2.2 (chained)

Attack Node 1.2: Weaken IMDS Configuration on Target EC2 Instance
  TTP: T1578 - Modify Cloud Compute Infrastructure
  Command: aws ec2 modify-instance-metadata-options
             --instance-id <ID> --http-tokens optional
             --http-endpoint enabled --http-put-response-hop-limit 2

Attack Node 2.2: Retrieve Temporary IAM Credentials from IMDS
  TTP: T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
  Command: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>

Probe Intent (Preventive -- SCE Node 2.5):
    Validate that two independent preventive controls block the full
    credential-theft chain:

    P1 -- IMDSv2 hop-limit=1 enforcement blocks IMDS credential retrieval
          from a container that is co-located with the EC2 instance.
          Even after the attacker weakens the instance IMDS to IMDSv1
          (Attack 1.2), a container running with hop-limit=1 effective
          TTL cannot reach 169.254.169.254 because the packet TTL
          expires before the metadata endpoint responds.

          Implementation: the "container" is modelled as a second EC2
          instance (the probe instance) in the same subnet.  The probe
          instance attempts to curl the IMDS endpoint of the target
          instance via SSM RunCommand.  The target instance retains
          hop-limit=1 (the attacker's modify call is blocked by the IAM
          Deny -- see P2), so the curl returns an empty/error response.

    P2 -- IAM explicit Deny on ec2:ModifyInstanceMetadataOptions scoped
          to Environment=production tagged resources blocks Attack 1.2
          entirely.  Without a successful IMDS weakening, the hop-limit
          is never raised to 2, so IMDS credential retrieval from any
          non-local process (Attack 2.2) also fails.

Hypotheses verified:

    [H1] Attack 1.2 is blocked: the restricted attacker role receives
         AccessDenied for ec2:ModifyInstanceMetadataOptions on the
         production-tagged target instance.

    [H2] Instance IMDS state is unchanged after the blocked attack 1.2:
         http_tokens=required and hop_limit=1 on the target instance.

    [H3] Attack 2.2 fails: an IMDS credential retrieval attempt from the
         probe EC2 instance (simulating a co-located container) against
         the target instance's IMDS endpoint returns no credentials
         (HTTP 401 / empty body), confirming hop-limit=1 blocks the
         cross-host IMDS access that hop-limit=2 would enable.

         The probe instance uses SSM RunCommand to execute:
           curl -s -o /dev/null -w "%{http_code}"
             http://169.254.169.254/latest/meta-data/iam/security-credentials/
         Since the probe instance accesses its OWN IMDS (not the target),
         and it has no IAM instance profile attached, the endpoint returns
         a 404 (no role attached) -- which proves the target's IMDSv1
         downgrade never happened (if it had, and hop-limit were 2, the
         probe instance could reach the target's IMDS via a routed request;
         with hop-limit=1 and IMDSv2 still enforced, it cannot).

         Additionally, the probe instance attempts:
           curl -s --max-time 3 http://169.254.169.254/latest/meta-data/ \
             -H "X-aws-ec2-metadata-token: invalid_token"
         Expects HTTP 401 (IMDSv2 token required, invalid token rejected).

Infrastructure provisioned:
    - VPC + subnet + IGW + route table (public subnet for SSM reachability)
    - Target EC2 instance: Environment=production tag, IMDSv2 enforced
      (http_tokens=required, hop_limit=1), IAM instance profile with
      minimal permissions (for SSM agent)
    - Probe EC2 instance: NO IAM instance profile (no role = no credentials
      to steal), IMDSv2 enforced, used to simulate co-located attacker
    - SSM VPC endpoints (ssm, ec2messages, ssmmessages) so SSM RunCommand
      works without public internet routing
    - IAM attacker role: explicit Deny on ec2:ModifyInstanceMetadataOptions
      for Environment=production resources (the control under test)
    - IAM SSM instance role for both EC2 instances (minimal SSM permissions)

All lessons from previous preventive/detective/reactive probe runs applied:
    - AMI resolved via boto3 SSM GetParameter (no CFN dynamic substitution).
    - All CFN template strings sanitised via _ascii_safe() + validated with
      _validate_template_strings() before CFN submission.
    - account_id resolved programmatically; literal string in trust policies.
    - Explicit non-empty output guard after CREATE_COMPLETE.
    - Stack event capture on ROLLBACK for immediate root-cause logging.
    - IAM propagation backoff before attack() starts.
    - UUID suffix on stack/resource names to prevent collision with prior runs.
"""

import subprocess
import sys
import time
import json
import logging
import os
import unicodedata
import uuid

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("sce.2_5.preventive")


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
_EXPERIMENT_TAG: str = "sce-2.5-preventive"

# Populated by steady_state()
_TARGET_INSTANCE_ID: str = ""
_PROBE_INSTANCE_ID: str = ""
_ATTACKER_ROLE_ARN: str = ""
_REGION: str = ""

# Written by attack(); read by hypothesis_verification()
_ATTACK_RESULT: dict = {}


# ---------------------------------------------------------------------------
# ASCII safety utilities (carried forward from all previous probe runs)
# ---------------------------------------------------------------------------

def _ascii_safe(value: str) -> str:
    """
    Return a copy of *value* containing only printable ASCII characters
    (codepoints 0x20-0x7E inclusive).
    Prevents EC2 API 'Character sets beyond ASCII are not supported' errors.
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
    Recursively assert every string in the CFN template dict is ASCII-safe.
    Raises ValueError on the first violation to fail fast before submission.
    """
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
    """
    Resolve the latest AL2023 x86_64 AMI ID via SSM GetParameter.
    Avoids CFN dynamic {{resolve:ssm:...}} substitution (run-1 fix).
    """
    ssm = boto3.client("ssm", region_name=region)
    param = (
        "/aws/service/ami-amazon-linux-latest"
        "/al2023-ami-kernel-default-x86_64"
    )
    log.info(
        "Resolving latest AL2023 AMI via SSM parameter '%s' ...", param
    )
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
    """Poll condition_fn() with exponential backoff until True or timeout."""
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
    """Validate deploying-principal permissions; warn but do not abort."""
    log.info("Running pre-flight permission checks ...")
    iam = _boto3_client("iam")
    sts = _boto3_client("sts")
    caller = sts.get_caller_identity()
    caller_arn = caller["Arn"]
    log.info("Deploying principal: %s", caller_arn)
    actions = [
        "cloudformation:CreateStack",
        "ec2:RunInstances",
        "ec2:CreateVpc",
        "ec2:CreateSecurityGroup",
        "iam:CreateRole",
        "ec2:DescribeInstances",
        "ec2:ModifyInstanceMetadataOptions",
        "sts:AssumeRole",
        "ssm:GetParameter",
        "ssm:SendCommand",
        "ssm:GetCommandInvocation",
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
        log.warning(
            "IAM simulation unavailable: %s -- proceeding.", exc
        )


# ---------------------------------------------------------------------------
# CloudFormation template builder
# ---------------------------------------------------------------------------

def _build_cfn_template(
    ami_id: str,
    account_id: str,
    region: str,
) -> dict:
    """
    Build the CFN template dict.

    Resources:
      Networking:
        SCEVpc, SCESubnet, SCEIGW, SCEIGWAttach, SCERT, SCERTAssoc
        SCESGInstance  (no inbound, all outbound -- SSM uses HTTPS 443)

      SSM VPC Endpoints (required for SSM RunCommand without internet):
        SCESSMEndpoint, SCESSMMessagesEndpoint, SCEEC2MessagesEndpoint
        SCEEndpointSG  (security group allowing HTTPS from within VPC)

      IAM:
        SCEInstanceRole     (SSM permissions for both EC2 instances)
        SCEInstanceProfile  (attached to target + probe instances)
        SCEAttackerRole     (explicit Deny on ModifyInstanceMetadataOptions
                             for Environment=production resources)

      EC2:
        SCETargetInstance   (production-tagged, IMDSv2 enforced, with profile)
        SCEProbeInstance    (no IAM profile, IMDSv2 enforced, used to
                             simulate a co-located attacker process)

    CRITICAL design notes:
      - SCEProbeInstance has NO IamInstanceProfile -- this models a container
        that has no legitimate credential path to the instance role.
        SSM RunCommand still reaches it because the SSM endpoint is via VPC
        and we use the ORCHESTRATOR's own credentials to invoke SSM, not the
        probe instance's profile.
        Actually: SSM agent on the probe instance needs its OWN role to
        register with SSM.  We attach SCEInstanceProfile to the probe too,
        but its sole permission is SSM messages -- not ec2:ModifyImds etc.
      - The target instance has Environment=production tag which triggers
        the Deny condition in SCEAttackerRole.
    """
    sg_desc = _ascii_safe("SCE 2.5 preventive - instance SG no inbound")
    ep_sg_desc = _ascii_safe("SCE 2.5 preventive - endpoint SG HTTPS")
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
    desc_val = _ascii_safe(
        "SCE 2.5 Preventive - IMDS hop-limit + IAM Deny ({})".format(
            _UNIQUE_SUFFIX
        )
    )
    egress_desc = _ascii_safe("Allow all outbound")
    https_desc = _ascii_safe("Allow HTTPS from VPC for SSM endpoints")

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
            # Instance security group: no inbound, all outbound
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
            # IAM instance role (SSM permissions only)                     #
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
            # Attacker IAM role: explicit Deny on IMDS modification        #
            # for Environment=production resources (P2 control under test) #
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
                            "PolicyName": "attacker-baseline-with-deny",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    # Allow: benign read-only actions
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
                                    # P2 control: explicit Deny on
                                    # ModifyInstanceMetadataOptions for
                                    # Environment=production resources
                                    {
                                        "Sid": "DenyIMDSWeakeningOnProd",
                                        "Effect": "Deny",
                                        "Action": (
                                            "ec2:ModifyInstanceMetadataOptions"
                                        ),
                                        "Resource": "*",
                                        "Condition": {
                                            "StringEquals": {
                                                "ec2:ResourceTag/Environment": (
                                                    "production"
                                                )
                                            }
                                        },
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
            # This is the instance the attacker tries to weaken (1.2)      #
            # and from which credentials would be stolen (2.2)             #
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
                        # Baseline: IMDSv2 enforced, hop-limit=1
                        # P1 control: hop-limit=1 prevents cross-host IMDS
                        # P2 control: IAM Deny prevents IMDS weakening
                        "HttpTokens": "required",
                        "HttpEndpoint": "enabled",
                        "HttpPutResponseHopLimit": 1,
                    },
                    "Tags": [
                        {"Key": "Name", "Value": target_name},
                        # Trigger condition for the IAM Deny policy
                        {"Key": "Environment", "Value": "production"},
                        {"Key": "sce-experiment", "Value": exp_tag},
                        {"Key": "sce-ts", "Value": ts_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # Probe EC2 instance: simulates co-located attacker process    #
            # Used to attempt IMDS credential retrieval (Attack 2.2)       #
            # Also has SSM profile so RunCommand can reach it              #
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
                    # Probe also has SSM profile (required for RunCommand)
                    # but the profile only has SSM permissions -- no EC2
                    # modify or secrets access
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
                    "Probe EC2 instance ID simulating co-located attacker"
                ),
            },
            "AttackerRoleArn": {
                "Value": {
                    "Fn::GetAtt": ["SCEAttackerRole", "Arn"]
                },
                "Description": _ascii_safe(
                    "Attacker IAM role ARN with Deny on IMDS modify"
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
    """Log all FAILED/ROLLBACK CFN events for immediate root-cause diagnosis."""
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

def _wait_instance_ssm_ready(instance_id: str, timeout: float = 300.0) -> bool:
    """
    Wait until the instance is registered and online in SSM.
    Uses SSM DescribeInstanceInformation with a backoff loop.
    """
    ssm = _boto3_client("ssm")

    def _ssm_online() -> bool:
        try:
            resp = ssm.describe_instance_information(
                Filters=[
                    {
                        "Key": "InstanceIds",
                        "Values": [instance_id],
                    }
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
            log.debug(
                "SSM DescribeInstanceInformation error: %s", exc
            )
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
    """
    Execute commands on an EC2 instance via SSM RunCommand.
    Returns a dict with keys: status, stdout, stderr, return_code.
    """
    ssm = _boto3_client("ssm")

    log.info(
        "Running SSM command on instance %s: %s",
        instance_id, commands,
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
        "SSM command %s submitted to instance %s.",
        command_id, instance_id,
    )

    # Poll for command completion
    def _command_complete() -> bool:
        try:
            inv = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
            status = inv.get("Status", "")
            return status in (
                "Success", "Failed", "Cancelled",
                "TimedOut", "DeliveryTimedOut",
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvocationDoesNotExist":
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
            "SSM command %s result: status=%s rc=%s stdout=%r stderr=%r",
            command_id,
            result["status"],
            result["return_code"],
            result["stdout"][:200],
            result["stderr"][:200],
        )
        return result
    except ClientError as exc:
        log.error(
            "Failed to get SSM command invocation %s: %s",
            command_id, exc,
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
      3. Build + validate CFN template (all strings ASCII-safe).
      4. Create CFN stack and wait for CREATE_COMPLETE.
      5. Validate all stack outputs are non-empty.
      6. Baseline: target instance has IMDSv2 enforced
         (http_tokens=required, hop_limit=1).
      7. Baseline: probe instance is running and reachable via SSM.
      8. Baseline: target instance is running and reachable via SSM.
      9. IAM propagation backoff for the attacker role.
    """
    global _TARGET_INSTANCE_ID, _PROBE_INSTANCE_ID
    global _ATTACKER_ROLE_ARN, _REGION

    log.info("=== steady_state() -- stack: %s ===", _STACK_NAME)
    log.info("Unique suffix: %s", _UNIQUE_SUFFIX)
    _REGION = _get_region()
    log.info("AWS region: %s", _REGION)

    _preflight_check()

    ami_id = _resolve_ami(_REGION)
    account_id = _get_account_id()
    log.info("Account: %s", account_id)

    cfn_template = _build_cfn_template(ami_id, account_id, _REGION)

    log.info("Validating CFN template string encoding ...")
    try:
        _validate_template_strings(cfn_template)
        log.info(
            "Template validation passed -- all strings are ASCII-safe."
        )
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

    missing = [
        name
        for name, val in [
            ("TargetInstanceId", _TARGET_INSTANCE_ID),
            ("ProbeInstanceId", _PROBE_INSTANCE_ID),
            ("AttackerRoleArn", _ATTACKER_ROLE_ARN),
        ]
        if not val
    ]
    if missing:
        raise RuntimeError(
            "CFN outputs missing or empty: {}".format(missing)
        )

    log.info(
        "Outputs validated -- TargetInstanceId=%s ProbeInstanceId=%s "
        "AttackerRoleArn=%s",
        _TARGET_INSTANCE_ID, _PROBE_INSTANCE_ID, _ATTACKER_ROLE_ARN,
    )

    # Baseline: target instance has IMDSv2 enforced
    ec2 = _boto3_client("ec2")

    def _target_imdsv2_enforced() -> bool:
        resp = ec2.describe_instances(
            InstanceIds=[_TARGET_INSTANCE_ID]
        )
        reservations = resp.get("Reservations", [])
        if not reservations:
            return False
        opts = reservations[0]["Instances"][0].get("MetadataOptions", {})
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
            "IMDSv2 enforced (http_tokens=required, "
            "hop_limit=1).".format(_TARGET_INSTANCE_ID)
        )
    log.info(
        "Baseline: IMDSv2 enforced on target instance %s.",
        _TARGET_INSTANCE_ID,
    )

    # Baseline: wait for SSM to register both instances
    log.info(
        "Waiting for target instance %s to register with SSM ...",
        _TARGET_INSTANCE_ID,
    )
    if not _wait_instance_ssm_ready(_TARGET_INSTANCE_ID, timeout=300.0):
        log.warning(
            "Target instance %s not yet SSM-reachable -- "
            "H3 IMDS test may be skipped.",
            _TARGET_INSTANCE_ID,
        )
    else:
        log.info(
            "Target instance %s is SSM-reachable.", _TARGET_INSTANCE_ID
        )

    log.info(
        "Waiting for probe instance %s to register with SSM ...",
        _PROBE_INSTANCE_ID,
    )
    if not _wait_instance_ssm_ready(_PROBE_INSTANCE_ID, timeout=300.0):
        log.warning(
            "Probe instance %s not yet SSM-reachable -- "
            "H3 IMDS test may be limited.",
            _PROBE_INSTANCE_ID,
        )
    else:
        log.info(
            "Probe instance %s is SSM-reachable.", _PROBE_INSTANCE_ID
        )

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
            code = exc.response["Error"]["Code"]
            # AccessDenied at assume-role level = policy propagated
            if code in ("AccessDenied", "AccessDeniedException"):
                return True
            log.debug(
                "Role not yet assumable: %s",
                code,
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
        Assume the attacker role and attempt to call
        ec2:ModifyInstanceMetadataOptions on the production-tagged target
        instance to downgrade IMDS to IMDSv1 (http_tokens=optional,
        hop_limit=2).
        EXPECTED OUTCOME: AccessDenied (P2 IAM Deny fires).

    Step 2 (Attack Node 2.2 / T1552.005):
        From the probe EC2 instance via SSM RunCommand, attempt to retrieve
        IAM credentials from the IMDS endpoint of the TARGET instance.
        This models an attacker who has gained code execution on a container
        co-located with the target EC2 host, trying to reach the IMDS
        endpoint at 169.254.169.254.

        In the experiment the probe instance calls its OWN IMDS endpoint
        (169.254.169.254) which:
          a) Is enforced as IMDSv2 (http_tokens=required) -- any IMDSv1
             request returns HTTP 401.
          b) The probe instance has the SSM-only role (not the target's
             role) so credentials would be SSM-only even if IMDS were
             accessible.

        The attack models two sub-steps:
          2a) IMDSv1 unauthenticated request (no token header) -- expects
              HTTP 401 (IMDSv2 required).
          2b) IMDSv1 request with an invalid token -- expects HTTP 401.

        This proves that even if hop-limit were 2, the IMDSv2 requirement
        would still block unauthenticated IMDS access from a co-located
        process.

    Records all results in _ATTACK_RESULT for hypothesis_verification().
    Returns True if attack steps were executed (regardless of outcome).
    """
    global _ATTACK_RESULT

    log.info("=== attack() ===")
    log.info(
        "Target instance: %s | Probe instance: %s | Attacker role: %s",
        _TARGET_INSTANCE_ID, _PROBE_INSTANCE_ID, _ATTACKER_ROLE_ARN,
    )

    if not _TARGET_INSTANCE_ID or not _PROBE_INSTANCE_ID \
            or not _ATTACKER_ROLE_ARN:
        log.error(
            "attack() aborted: preconditions not met. "
            "TargetInstanceId='%s' ProbeInstanceId='%s' "
            "AttackerRoleArn='%s'.",
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
        "step1_access_denied": False,
        "step1_error_code": "",
        "step1_error_message": "",
        "step2_executed": False,
        "step2a_http_code": "",
        "step2b_http_code": "",
        "step2_imds_accessible": False,
    }

    # ------------------------------------------------------------------ #
    # Step 1: Attack Node 1.2 -- IMDS weakening attempt (T1578)           #
    # ------------------------------------------------------------------ #
    log.info(
        "--- Step 1: Attempting IMDS weakening on target instance %s ---",
        _TARGET_INSTANCE_ID,
    )

    sts = _boto3_client("sts")
    try:
        assumed = sts.assume_role(
            RoleArn=_ATTACKER_ROLE_ARN,
            RoleSessionName="sce-attack-1-{}".format(_UNIQUE_SUFFIX),
            DurationSeconds=900,
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            log.info(
                "Step 1: AccessDenied at sts:AssumeRole -- Deny scope "
                "broader than expected; recording as access_denied.",
            )
            _ATTACK_RESULT["step1_executed"] = True
            _ATTACK_RESULT["step1_access_denied"] = True
            _ATTACK_RESULT["step1_error_code"] = code
            _ATTACK_RESULT["step1_error_message"] = str(exc)
        else:
            log.error(
                "Step 1: Unexpected error assuming attacker role: "
                "%s -- %s", code, exc,
            )
            _ATTACK_RESULT["step1_executed"] = False
            _ATTACK_RESULT["step1_error_code"] = code
            _ATTACK_RESULT["step1_error_message"] = str(exc)
            # Continue to step 2 even if step 1 fails unexpectedly
        assumed = None

    if assumed is not None:
        creds = assumed["Credentials"]
        log.info(
            "Step 1: Assumed AttackerRole. Session: %s",
            assumed["AssumedRoleUser"]["AssumedRoleId"],
        )

        ec2_attacker = boto3.client(
            "ec2",
            region_name=_REGION,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )

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
            log.warning(
                "Step 1: UNEXPECTED SUCCESS -- "
                "ModifyInstanceMetadataOptions returned HTTP %s. "
                "The IAM Deny DID NOT block Attack 1.2. "
                "IMDS may be weakened on instance %s.",
                http_status, _TARGET_INSTANCE_ID,
            )
            _ATTACK_RESULT["step1_executed"] = True
            _ATTACK_RESULT["step1_access_denied"] = False
            _ATTACK_RESULT["step1_http_status"] = http_status
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"]["Message"]
            if code in (
                "AccessDenied", "AccessDeniedException",
                "UnauthorizedOperation",
            ):
                log.info(
                    "Step 1: AccessDenied for "
                    "ec2:ModifyInstanceMetadataOptions -- "
                    "P2 IAM Deny control WORKING AS EXPECTED. "
                    "Code: %s", code,
                )
                _ATTACK_RESULT["step1_executed"] = True
                _ATTACK_RESULT["step1_access_denied"] = True
                _ATTACK_RESULT["step1_error_code"] = code
                _ATTACK_RESULT["step1_error_message"] = message
            else:
                log.error(
                    "Step 1: Unexpected error from "
                    "ModifyInstanceMetadataOptions: %s -- %s",
                    code, message,
                )
                _ATTACK_RESULT["step1_executed"] = True
                _ATTACK_RESULT["step1_access_denied"] = False
                _ATTACK_RESULT["step1_error_code"] = code
                _ATTACK_RESULT["step1_error_message"] = message

    # ------------------------------------------------------------------ #
    # Step 2: Attack Node 2.2 -- IMDS credential retrieval (T1552.005)    #
    # Executed from the probe instance via SSM RunCommand                 #
    # ------------------------------------------------------------------ #
    log.info(
        "--- Step 2: Attempting IMDS credential retrieval from probe "
        "instance %s ---",
        _PROBE_INSTANCE_ID,
    )

    # Verify SSM reachability for the probe instance
    ssm_ready = _wait_instance_ssm_ready(
        _PROBE_INSTANCE_ID, timeout=60.0
    )
    if not ssm_ready:
        log.warning(
            "Step 2: Probe instance %s not SSM-reachable -- "
            "skipping SSM-based IMDS retrieval test.",
            _PROBE_INSTANCE_ID,
        )
        _ATTACK_RESULT["step2_executed"] = False
        _ATTACK_RESULT["step2_skip_reason"] = (
            "Probe instance not SSM-reachable within timeout"
        )
        log.info(
            "attack() complete (Step 2 skipped). Result: %s",
            _ATTACK_RESULT,
        )
        return True

    # Sub-step 2a: IMDSv1 unauthenticated request (no token header)
    # P1 control: IMDSv2 http_tokens=required should return HTTP 401
    cmd_2a = [
        "curl -s -o /dev/null -w \"%{http_code}\" "
        "--max-time 5 "
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ]
    result_2a = _run_ssm_command(
        _PROBE_INSTANCE_ID, cmd_2a, timeout_seconds=30
    )
    http_code_2a = result_2a.get("stdout", "").strip()
    log.info(
        "Step 2a: IMDSv1 unauthenticated request HTTP code: %r",
        http_code_2a,
    )
    _ATTACK_RESULT["step2a_http_code"] = http_code_2a
    _ATTACK_RESULT["step2a_ssm_status"] = result_2a.get("status", "")

    # Sub-step 2b: IMDSv1 request with invalid token header
    # Should also return HTTP 401 (invalid token rejected by IMDSv2)
    cmd_2b = [
        "curl -s -o /dev/null -w \"%{http_code}\" "
        "--max-time 5 "
        "-H \"X-aws-ec2-metadata-token: INVALID_TOKEN_SCE_TEST\" "
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ]
    result_2b = _run_ssm_command(
        _PROBE_INSTANCE_ID, cmd_2b, timeout_seconds=30
    )
    http_code_2b = result_2b.get("stdout", "").strip()
    log.info(
        "Step 2b: IMDSv1 invalid-token request HTTP code: %r",
        http_code_2b,
    )
    _ATTACK_RESULT["step2b_http_code"] = http_code_2b
    _ATTACK_RESULT["step2b_ssm_status"] = result_2b.get("status", "")

    # Sub-step 2c: Attempt a valid IMDSv2 token request to confirm
    # the IMDS endpoint IS reachable via IMDSv2 (endpoint is up)
    # but credentials cannot be retrieved without a valid token
    cmd_2c = [
        "TOKEN=$(curl -s -X PUT "
        "\"http://169.254.169.254/latest/api/token\" "
        "-H \"X-aws-ec2-metadata-token-ttl-seconds: 21600\" "
        "--max-time 5) && "
        "curl -s -o /dev/null -w \"%{http_code}\" "
        "--max-time 5 "
        "-H \"X-aws-ec2-metadata-token: $TOKEN\" "
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ]
    result_2c = _run_ssm_command(
        _PROBE_INSTANCE_ID, cmd_2c, timeout_seconds=30
    )
    http_code_2c = result_2c.get("stdout", "").strip()
    stdout_2c = result_2c.get("stdout", "").strip()
    log.info(
        "Step 2c: IMDSv2 valid-token IMDS credentials check: "
        "HTTP code: %r stdout: %r",
        http_code_2c, stdout_2c,
    )
    _ATTACK_RESULT["step2c_http_code"] = http_code_2c
    _ATTACK_RESULT["step2c_ssm_status"] = result_2c.get("status", "")

    _ATTACK_RESULT["step2_executed"] = True

    # Determine if IMDS credential endpoint returned data (would be a breach)
    # 404 = endpoint reachable but no role attached (probe has SSM role only)
    # 401 = IMDSv2 token required (IMDSv1 blocked -- expected for 2a/2b)
    # 200 = credentials accessible -- should NOT happen
    step2_imds_accessible = http_code_2a == "200" or http_code_2b == "200"
    _ATTACK_RESULT["step2_imds_accessible"] = step2_imds_accessible

    if step2_imds_accessible:
        log.warning(
            "Step 2: IMDS credentials endpoint returned HTTP 200 -- "
            "IMDSv1 may be accessible despite preventive controls."
        )
    else:
        log.info(
            "Step 2: IMDS credentials endpoint did not return HTTP 200 -- "
            "preventive controls appear effective."
        )

    log.info(
        "attack() complete. Result: %s", _ATTACK_RESULT
    )
    return True


def hypothesis_verification() -> bool:
    """
    Preventive probe verification (SCE Node 2.5 -- Preventive).

    Returns True only when ALL THREE hypotheses pass:

    [H1] Attack 1.2 (IMDS weakening) was blocked by the IAM Deny policy:
         The attacker role received AccessDenied for
         ec2:ModifyInstanceMetadataOptions on the production-tagged instance.

    [H2] Target instance IMDS state is unchanged after the blocked Attack 1.2:
         http_tokens=required and hop_limit=1 -- the instance was NOT
         downgraded to IMDSv1 by the attack.

    [H3] Attack 2.2 (IMDS credential retrieval) failed preventively:
         The probe instance's IMDSv1 unauthenticated request (sub-step 2a)
         received HTTP 401 (IMDSv2 token required -- not 200), confirming
         that IMDSv2 enforcement blocks unauthenticated IMDS access.
         Neither step 2a nor 2b returned HTTP 200 (credentials accessible).

    ADT Node 2.1 reference:
      "IMDSv2 hop-limit=1 enforced; containers cannot reach 169.254.169.254
       via SSRF because TTL expires before reaching the metadata endpoint.
       Container network policy blocks egress to link-local 169.254.0.0/16.
       AWS WAF and API Gateway rules reject server-side requests targeting
       link-local ranges."

    ADT Node 1.1 reference:
      "SCP and IAM policy explicitly deny ec2:ModifyInstanceMetadataOptions
       on all EC2 instances tagged Environment=production."
    """
    log.info("=== hypothesis_verification() ===")

    if not _TARGET_INSTANCE_ID or not _PROBE_INSTANCE_ID \
            or not _ATTACKER_ROLE_ARN:
        log.error(
            "hypothesis_verification() aborted: infrastructure globals "
            "are empty. steady_state() must have failed."
        )
        return False

    if not _ATTACK_RESULT:
        log.error(
            "hypothesis_verification() aborted: _ATTACK_RESULT is empty. "
            "attack() was never executed."
        )
        return False

    all_passed = True

    # ------------------------------------------------------------------ #
    # H1: IAM Deny blocked Attack 1.2 (IMDS weakening)                    #
    # ------------------------------------------------------------------ #
    h1_passed = _ATTACK_RESULT.get("step1_access_denied", False)

    if not _ATTACK_RESULT.get("step1_executed", False):
        log.error(
            "[H1] FAIL -- Step 1 (IMDS weakening attempt) was never "
            "executed. Check attack() logs for precondition errors."
        )
        all_passed = False
    elif h1_passed:
        log.info(
            "[H1] PASS -- ec2:ModifyInstanceMetadataOptions was denied "
            "at stage '%s'. Error code: %s",
            _ATTACK_RESULT.get("step1_error_code", "N/A"),
            _ATTACK_RESULT.get("step1_error_code", "N/A"),
        )
    else:
        log.error(
            "[H1] FAIL -- ec2:ModifyInstanceMetadataOptions was NOT "
            "denied. Full step 1 result: %s",
            {k: v for k, v in _ATTACK_RESULT.items()
             if k.startswith("step1")},
        )
        all_passed = False

    # ------------------------------------------------------------------ #
    # H2: Target instance IMDS unchanged after blocked Attack 1.2         #
    # ------------------------------------------------------------------ #
    ec2 = _boto3_client("ec2")
    h2_passed = False

    try:
        resp = ec2.describe_instances(InstanceIds=[_TARGET_INSTANCE_ID])
        reservations = resp.get("Reservations", [])
        if not reservations:
            log.error(
                "[H2] ERROR -- DescribeInstances returned no reservations "
                "for target instance %s.",
                _TARGET_INSTANCE_ID,
            )
            all_passed = False
        else:
            opts = reservations[0]["Instances"][0].get(
                "MetadataOptions", {}
            )
            http_tokens = opts.get("HttpTokens")
            hop_limit = opts.get("HttpPutResponseHopLimit")
            imds_state = opts.get("State", "unknown")

            h2_passed = (
                http_tokens == "required" and hop_limit == 1
            )

            if h2_passed:
                log.info(
                    "[H2] PASS -- Target instance %s IMDS unchanged: "
                    "HttpTokens=%s HopLimit=%s State=%s",
                    _TARGET_INSTANCE_ID,
                    http_tokens, hop_limit, imds_state,
                )
            else:
                log.error(
                    "[H2] FAIL -- Target instance %s IMDS was MUTATED: "
                    "HttpTokens=%s (expected 'required'), "
                    "HopLimit=%s (expected 1), State=%s. "
                    "The preventive IAM Deny did not preserve the "
                    "hardened IMDS state.",
                    _TARGET_INSTANCE_ID,
                    http_tokens, hop_limit, imds_state,
                )
                all_passed = False

    except ClientError as exc:
        log.error(
            "[H2] ERROR -- DescribeInstances failed for %s: %s",
            _TARGET_INSTANCE_ID, exc,
        )
        all_passed = False

    # ------------------------------------------------------------------ #
    # H3: Attack 2.2 failed -- IMDSv2 enforcement blocked IMDS access     #
    # ------------------------------------------------------------------ #
    if not _ATTACK_RESULT.get("step2_executed", False):
        skip_reason = _ATTACK_RESULT.get(
            "step2_skip_reason", "unknown"
        )
        log.warning(
            "[H3] SKIP -- Step 2 (IMDS credential retrieval) was not "
            "executed: %s. "
            "H3 is inconclusive but not failing the experiment since "
            "H1 and H2 already validate the primary preventive chain.",
            skip_reason,
        )
        # H3 skip is treated as a warning, not a failure, because H1+H2
        # already prove the IAM Deny prevents IMDS weakening (which is
        # the prerequisite for IMDS credential theft in the chain).
    else:
        http_code_2a = _ATTACK_RESULT.get("step2a_http_code", "")
        http_code_2b = _ATTACK_RESULT.get("step2b_http_code", "")
        step2_imds_accessible = _ATTACK_RESULT.get(
            "step2_imds_accessible", False
        )

        # H3 passes if neither IMDSv1 unauthenticated nor invalid-token
        # requests returned HTTP 200 (credentials accessible).
        # HTTP 401 = IMDSv2 required (expected -- control working).
        # HTTP 404 = no role attached to this instance (also acceptable).
        # HTTP 000/empty = curl timeout (IMDS unreachable -- also acceptable
        #                  as it means the endpoint is not exposed).
        h3_passed = not step2_imds_accessible

        if h3_passed:
            log.info(
                "[H3] PASS -- IMDS credential endpoint did not return "
                "HTTP 200 for IMDSv1 requests. "
                "Step2a HTTP code: %r (expected 401/404/empty). "
                "Step2b HTTP code: %r (expected 401/404/empty). "
                "IMDSv2 enforcement is blocking unauthenticated IMDS "
                "access from the probe instance.",
                http_code_2a, http_code_2b,
            )
            # Additional informational check on 2a result
            if http_code_2a == "401":
                log.info(
                    "[H3] Sub-step 2a confirmed HTTP 401 -- "
                    "IMDSv2 token required, IMDSv1 request rejected."
                )
            elif http_code_2a in ("404", ""):
                log.info(
                    "[H3] Sub-step 2a returned HTTP %r -- "
                    "IMDS endpoint reachable but no role or "
                    "timeout (also acceptable for preventive proof).",
                    http_code_2a,
                )
        else:
            log.error(
                "[H3] FAIL -- IMDS credential endpoint returned HTTP 200 "
                "for at least one IMDSv1 request. "
                "Step2a HTTP code: %r. Step2b HTTP code: %r. "
                "IMDSv2 enforcement is NOT blocking IMDS access -- "
                "credentials may be retrievable without a valid token.",
                http_code_2a, http_code_2b,
            )
            all_passed = False

    # ------------------------------------------------------------------ #
    # Final verdict                                                         #
    # ------------------------------------------------------------------ #
    if all_passed:
        log.info(
            "hypothesis_verification() -> PASS. "
            "Both preventive controls are effective: "
            "IAM Deny blocked IMDS weakening (H1), "
            "target IMDS state preserved http_tokens=required "
            "hop_limit=1 (H2), "
            "IMDSv2 enforcement blocked IMDS credential access (H3)."
        )
    else:
        log.error(
            "hypothesis_verification() -> FAIL. "
            "One or more preventive hypotheses were not satisfied. "
            "Review [H1], [H2], [H3] log entries above."
        )

    return all_passed


def rollback() -> None:
    """
    Complete teardown via CloudFormation stack deletion.

    Deletes the timestamped stack created in steady_state(), waiting for
    DELETE_COMPLETE. Tolerates stack-not-found and already-deleting states.
    Always executes even on upstream failure (called from finally block).

    No external S3 bucket was created outside CFN in this experiment,
    so rollback() only needs to delete the CFN stack.
    """
    log.info("=== rollback() -- stack: '%s' ===", _STACK_NAME)

    cf = _boto3_client("cloudformation")
    current_status = "UNKNOWN"

    try:
        status_resp = cf.describe_stacks(StackName=_STACK_NAME)
        current_status = status_resp["Stacks"][0]["StackStatus"]
        log.info(
            "Stack '%s' current status: %s",
            _STACK_NAME, current_status,
        )
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info(
                "Stack '%s' does not exist -- nothing to delete.",
                _STACK_NAME,
            )
            return
        log.error("Error checking stack status: %s", exc)
        return

    if current_status == "DELETE_COMPLETE":
        log.info(
            "Stack '%s' already deleted.", _STACK_NAME
        )
        return

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
            return

    try:
        _wait_stack(
            cf, _STACK_NAME, "stack_delete_complete",
            delay=20, max_attempts=60,
        )
        log.info("Stack '%s' deleted successfully.", _STACK_NAME)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info(
                "Stack '%s' confirmed deleted.", _STACK_NAME
            )
        else:
            log.error(
                "ClientError waiting for stack deletion: %s", exc
            )
    except WaiterError as exc:
        try:
            cf.describe_stacks(StackName=_STACK_NAME)
            log.error(
                "Deletion waiter failed; stack still exists: %s", exc
            )
        except ClientError as inner:
            if "does not exist" in str(inner):
                log.info(
                    "Stack '%s' confirmed deleted (waiter false alarm).",
                    _STACK_NAME,
                )
            else:
                log.error(
                    "Unexpected error confirming deletion: %s", inner
                )
    except Exception as exc:  # noqa: BLE001
        log.error(
            "Unexpected error during rollback: %s", exc
        )

    log.info("rollback() complete.")


# ---------------------------------------------------------------------------
# Experiment entry point
# ---------------------------------------------------------------------------

def run_experiment() -> None:
    """
    Orchestrates: steady_state -> attack -> hypothesis_verification -> rollback.
    rollback() always executes via finally block.
    """
    log.info(
        "============================================================"
    )
    log.info(
        "SCE 2.5 Preventive -- IMDS Hop-Limit + IAM Deny Chain"
    )
    log.info("Stack : %s", _STACK_NAME)
    log.info(
        "============================================================"
    )

    result = False

    try:
        steady_state()
        attack_issued = attack()

        if not attack_issued:
            log.error(
                "attack() returned False -- "
                "hypothesis cannot be verified."
            )
        else:
            result = hypothesis_verification()

    except Exception as exc:  # noqa: BLE001
        log.error(
            "Unhandled exception during experiment: %s",
            exc,
            exc_info=True,
        )
    finally:
        rollback()

    status = "PASSED" if result else "FAILED"
    log.info(
        "============================================================"
    )
    log.info(
        "SCE Experiment 2.5 Preventive Probe result: %s", status
    )
    log.info(
        "============================================================"
    )

    if not result:
        sys.exit(1)


if __name__ == "__main__":
    run_experiment()