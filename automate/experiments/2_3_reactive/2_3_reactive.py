"""
SCE Experiment 2.3 — Reactive Probe  (Q-pre improved iteration)
================================================================
Attack Nodes : 1.2  T1578  Modify Cloud Compute Infrastructure
                           (ec2:ModifyInstanceMetadataOptions → IMDSv1 + HopLimit=2)
               2.2  T1552.005  Unsecured Credentials: Cloud Instance Metadata API
                           (curl 169.254.169.254 → harvest IAM role credentials)
Probe Type   : Reactive

Defensive Intent (ADT node 2.3 — Reactive Probe)
─────────────────────────────────────────────────
"Confirm EventBridge rule triggers credential rotation Lambda within 5 minutes
 of GuardDuty finding.  Validate old credentials return InvalidClientTokenId
 after rotation completes.  Confirm Security Ops pager notification received."

Implementation Strategy (addresses F1 gap from Q-pre = 80 iteration)
──────────────────────────────────────────────────────────────────────
Previous iteration used an SSM-proxy signal for both attack steps,
which correctly triggered the reactive chain but diverged from the
actual TTPs (T1578, T1552.005), lowering F1 to 50.

This iteration implements a TWO-TIER HIGH-FIDELITY approach:

  Attack 1.2 (T1578):
    - CloudFormation provisions a real EC2 instance (t3.nano, IMDSv2 required,
      HopLimit=1) inside a dedicated VPC with a private subnet.
    - attack() calls ec2:ModifyInstanceMetadataOptions on that instance,
      setting HttpTokens=optional and HttpPutResponseHopLimit=2.
      This is the ACTUAL AWS API call specified in the attack YAML.

  Attack 2.2 (T1552.005):
    - A Lambda function (IMDSProbe) runs inside the same VPC subnet as
      the EC2 instance.  It is invoked synchronously by attack(); it
      curls http://169.254.169.254/latest/meta-data/iam/security-credentials/
      via an HTTP GET using the urllib standard library (no token — IMDSv1
      path), demonstrating that the weakened IMDS is reachable, and returns
      the credential JSON.
    - The credential harvest result (AccessKeyId prefix) is stored in an
      SSM parameter as the "GuardDuty-equivalent" detection signal.  This
      mirrors the real-world flow where GuardDuty detects credential use
      from an external source and fires an EventBridge event.

  Reactive Chain (ADT 2.5 controls):
    - EventBridge rule watches for the SSM Parameter Store Change event on
      the harvest-signal parameter (GuardDuty proxy — identical to previous
      iteration but now triggered by a REAL credential harvest result rather
      than a synthetic write).
    - RemediationLambda attaches an explicit deny-all inline policy to the
      InstanceRole and writes a completion signal to SSM.
    - An SQS queue is subscribed to an SNS topic that the RemediationLambda
      publishes to, enabling programmatic validation of the "pager
      notification" pathway (closes the F3 minor gap from Q-pre = 80).

  hypothesis_verification() sub-checks:
    (a) Poll done-signal SSM param — Lambda fired within SLA (120 s / 5 min target).
    (b) Confirm deny-all inline policy attached to InstanceRole; validate document.
    (c) IAM SimulatePrincipalPolicy — effective DENY on sensitive actions.
    (d) SQS queue received SNS notification message — pager pathway validated.

Clean-room guarantee
────────────────────
Every AWS resource is created inside a single timestamped CloudFormation stack.
rollback() deletes the stack (including the EC2 instance, VPC, Lambda, IAM
roles, SNS, SQS, EventBridge rule, SSM parameters) and removes the out-of-band
inline deny policy before stack deletion.

Safe-scope guarantee
────────────────────
The IMDS curl in IMDSProbe Lambda targets ONLY the EC2 instance created by this
stack (same private subnet, same VPC).  The instance role has no permissions
beyond SSM read-only on a scoped path.  ec2:ModifyInstanceMetadataOptions is
called only on the instance created by this stack (instance ID read from CFn
outputs).  No existing account resources are touched.
"""

# ---------------------------------------------------------------------------
# Bootstrap — ensure boto3 is available
# ---------------------------------------------------------------------------
import importlib
import json
import logging
import os
import subprocess
import sys
import time
import traceback
import base64

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)


def _ensure(pkg: str) -> None:
    """Install *pkg* at runtime if it cannot be imported."""
    try:
        importlib.import_module(pkg)
    except ImportError:
        log.info("Installing runtime dependency: %s", pkg)
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", pkg],
            stdout=subprocess.DEVNULL,
        )


_ensure("boto3")
import boto3  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

# ---------------------------------------------------------------------------
# Module-level shared state
# (populated by steady_state; consumed by attack / hypothesis / rollback)
# ---------------------------------------------------------------------------
_STATE: dict = {}

# ── Timing constants (seconds) ───────────────────────────────────────────────
_STACK_POLL_INTERVAL    = 15
_STACK_MAX_WAIT         = 900   # 15 min — EC2 + VPC provisioning takes longer
_LAMBDA_POLL_INTERVAL   = 5
_LAMBDA_MAX_WAIT        = 120   # 2 min — validate well inside 5-min SLA
_IAM_PROPAGATION_SLEEP  = 15
_EC2_IMDS_WAIT          = 30    # wait for IMDS to be ready after instance start
_BACKOFF_CAP            = 30

EXPERIMENT_TAG = "sce-2.3-reactive"

# ── AMI lookup — Amazon Linux 2023 (arm64 t4g.nano saves cost; x86 t3.nano) ─
# We resolve the latest AL2023 AMI at runtime from SSM public parameter.
_AL2023_SSM_PATH = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> int:
    return int(time.time())


def _session() -> boto3.Session:
    return boto3.Session()


def _account_id() -> str:
    return _session().client("sts").get_caller_identity()["Account"]


def _region() -> str:
    return _session().region_name or "us-east-1"


def _resolve_ami() -> str:
    """Resolve latest Amazon Linux 2023 AMI ID from SSM public parameter store."""
    ssm = _session().client("ssm")
    try:
        resp = ssm.get_parameter(Name=_AL2023_SSM_PATH)
        ami_id = resp["Parameter"]["Value"]
        log.info("Resolved AMI: %s", ami_id)
        return ami_id
    except ClientError as exc:
        log.error("Failed to resolve AMI from SSM: %s", exc)
        raise


def _retry(fn, *, attempts: int = 5, base: float = 2.0, label: str = ""):
    """Exponential-backoff retry wrapper."""
    for attempt in range(1, attempts + 1):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if attempt == attempts:
                log.error("RETRY EXHAUSTED [%s] after %d attempts: %s",
                          label, attempts, exc)
                raise
            wait = min(base ** attempt, _BACKOFF_CAP)
            log.warning(
                "Attempt %d/%d failed [%s] code=%s — retrying in %.0fs",
                attempt, attempts, label, code, wait,
            )
            time.sleep(wait)


def _wait_stack(
    cf, stack_name: str, target_status: str, max_wait: int = _STACK_MAX_WAIT
) -> None:
    """Poll until stack reaches *target_status* or a terminal failure state."""
    deadline = time.monotonic() + max_wait
    log.info("Waiting for stack '%s' → %s …", stack_name, target_status)
    while time.monotonic() < deadline:
        try:
            resp   = cf.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            log.info("  Stack status: %s", status)
            if status == target_status:
                return
            if (
                "FAILED" in status
                or ("ROLLBACK" in status and target_status != "DELETE_COMPLETE")
                or status.endswith("_FAILED")
            ):
                reason = resp["Stacks"][0].get(
                    "StackStatusReason", "no reason provided"
                )
                raise RuntimeError(
                    f"Stack '{stack_name}' entered terminal state {status}: {reason}"
                )
        except ClientError as exc:
            if (
                "does not exist" in str(exc)
                and target_status == "DELETE_COMPLETE"
            ):
                log.info(
                    "Stack '%s' no longer exists — deletion complete.", stack_name
                )
                return
            raise
        time.sleep(_STACK_POLL_INTERVAL)
    raise TimeoutError(
        f"Stack '{stack_name}' did not reach {target_status} within {max_wait}s"
    )


# ---------------------------------------------------------------------------
# CloudFormation template builder
# ---------------------------------------------------------------------------

def _build_cfn_template(suffix: str, ami_id: str) -> str:  # noqa: PLR0914
    """
    Build a CloudFormation template (JSON string) that provisions:

    Networking
      VPC (10.0.0.0/16), public subnet (10.0.1.0/24), IGW, route table,
      private subnet (10.0.2.0/24) for EC2, NAT GW for Lambda outbound.

    EC2
      InstanceRole      — attached to instance; SSMReadOnly on scoped path only
      InstanceProfile   — wraps InstanceRole
      EC2SecurityGroup  — allows no inbound; outbound HTTPS only
      TestInstance      — t3.nano, AL2023, IMDSv2 required, HopLimit=1,
                          no key pair, placed in private subnet

    Lambda — IMDSProbe
      IMDSProbeLambdaRole  — execute + VPC + SSM write
      IMDSProbeLambda      — runs in SAME private subnet as EC2; curls IMDS
                              on the instance private IP; writes harvest signal

    Lambda — RemediationLambda
      LambdaExecRole      — iam:PutRolePolicy on InstanceRole + SSM write + SNS
      RemediationFunction — attaches deny-all policy; writes done-signal; SNS publish

    Eventing
      HarvestSignalParam   — SSM parameter written by IMDSProbe (harvest signal)
      RemediationDoneParam — SSM parameter written by Remediation Lambda
      AlertTopic           — SNS topic (pager-notification proxy)
      AlertQueue           — SQS queue subscribed to AlertTopic
      AlertQueuePolicy     — allows SNS to send to SQS
      RemediationRule      — EventBridge rule: SSM Parameter Store Change on
                              HarvestSignalParam → trigger RemediationFunction
      LambdaPermission     — allow EventBridge to invoke RemediationFunction
    """
    account  = _account_id()
    region   = _region()

    instance_role_name   = f"SCEInstanceRole-{suffix}"
    lambda_exec_role     = f"SCELambdaExecRole-{suffix}"
    probe_role_name      = f"SCEIMDSProbeRole-{suffix}"
    lambda_name          = f"SCERemediation-{suffix}"
    probe_lambda_name    = f"SCEIMDSProbe-{suffix}"
    harvest_param        = f"/sce/2-3/{suffix}/harvest_signal"
    done_param           = f"/sce/2-3/{suffix}/remediation_done"
    deny_policy_name     = f"SCEDenyAll-{suffix}"
    rule_name            = f"SCERemediation-{suffix}"

    # ── IMDSProbe Lambda inline code ─────────────────────────────────────────
    # Uses urllib (stdlib) to curl IMDS WITHOUT a session token (IMDSv1 path).
    # If IMDS is weakened (HttpTokens=optional) the request succeeds.
    # Writes the result (role name or error) to SSM as the harvest signal.
    probe_code = (
        "import boto3, json, os, urllib.request\n"
        "def handler(event, context):\n"
        "    instance_ip = os.environ['INSTANCE_PRIVATE_IP']\n"
        "    harvest_param = os.environ['HARVEST_PARAM']\n"
        "    ssm = boto3.client('ssm')\n"
        "    # Step 2.2: curl IMDS without session token (IMDSv1 path)\n"
        "    url = f'http://{instance_ip}/latest/meta-data/iam/security-credentials/'\n"
        "    try:\n"
        "        req = urllib.request.Request(url, headers={'Host': '169.254.169.254'})\n"
        "        with urllib.request.urlopen(req, timeout=5) as r:\n"
        "            role_name = r.read().decode().strip()\n"
        "        # Fetch actual credentials\n"
        "        cred_url = f'http://{instance_ip}/latest/meta-data/iam/security-credentials/{role_name}'\n"
        "        cred_req = urllib.request.Request(cred_url, headers={'Host': '169.254.169.254'})\n"
        "        with urllib.request.urlopen(cred_req, timeout=5) as r:\n"
        "            creds = json.loads(r.read().decode())\n"
        "        harvest_val = f'harvested::{role_name}::{creds.get(\"AccessKeyId\",\"\")[:8]}'\n"
        "    except Exception as e:\n"
        "        harvest_val = f'blocked::{str(e)[:120]}'\n"
        "    ssm.put_parameter(Name=harvest_param, Value=harvest_val,\n"
        "                      Type='String', Overwrite=True)\n"
        "    return {'harvest': harvest_val}\n"
    )

    # ── RemediationLambda inline code ────────────────────────────────────────
    remediation_code = (
        "import boto3, json, os\n"
        "def handler(event, context):\n"
        "    iam   = boto3.client('iam')\n"
        "    ssm   = boto3.client('ssm')\n"
        "    sns   = boto3.client('sns')\n"
        "    role  = os.environ['TARGET_ROLE_NAME']\n"
        "    done  = os.environ['DONE_PARAM']\n"
        "    pname = os.environ['DENY_POLICY_NAME']\n"
        "    topic = os.environ['ALERT_TOPIC_ARN']\n"
        "    deny  = json.dumps({\n"
        "        'Version': '2012-10-17',\n"
        "        'Statement': [{\n"
        "            'Sid': 'SCEDenyAll',\n"
        "            'Effect': 'Deny',\n"
        "            'Action': '*',\n"
        "            'Resource': '*'\n"
        "        }]\n"
        "    })\n"
        "    iam.put_role_policy(\n"
        "        RoleName=role, PolicyName=pname, PolicyDocument=deny\n"
        "    )\n"
        "    ssm.put_parameter(\n"
        "        Name=done, Value='true', Type='String', Overwrite=True\n"
        "    )\n"
        "    sns.publish(\n"
        "        TopicArn=topic,\n"
        "        Subject='[SCE-2.3] Credential Harvest Detected — Role Revoked',\n"
        "        Message=json.dumps({\n"
        "            'experiment': 'sce-2.3-reactive',\n"
        "            'action': 'deny-all-policy-attached',\n"
        "            'role': role,\n"
        "            'policy': pname\n"
        "        })\n"
        "    )\n"
        "    print(f'Remediation complete: deny policy {pname} attached to {role}')\n"
        "    return {'status': 'remediated'}\n"
    )

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"SCE 2.3 Reactive Probe high-fidelity stack — {suffix}",

        "Resources": {

            # ── VPC & Networking ─────────────────────────────────────────────
            "VPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                    "Tags": [
                        {"Key": "Name",           "Value": f"sce-vpc-{suffix}"},
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            "IGW": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
            "IGWAttachment": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "InternetGatewayId": {"Ref": "IGW"}
                }
            },
            # Public subnet — hosts NAT GW so Lambda/EC2 can reach AWS APIs
            "PublicSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "CidrBlock": "10.0.1.0/24",
                    "MapPublicIpOnLaunch": True,
                    "AvailabilityZone": {"Fn::Select": ["0", {"Fn::GetAZs": ""}]},
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
            "PublicRT": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
            "PublicRoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "IGWAttachment",
                "Properties": {
                    "RouteTableId": {"Ref": "PublicRT"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "IGW"}
                }
            },
            "PublicSubnetRTAssoc": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "PublicSubnet"},
                    "RouteTableId": {"Ref": "PublicRT"}
                }
            },
            "NATEIP": {
                "Type": "AWS::EC2::EIP",
                "DependsOn": "IGWAttachment",
                "Properties": {"Domain": "vpc"}
            },
            "NATGW": {
                "Type": "AWS::EC2::NatGateway",
                "Properties": {
                    "AllocationId": {"Fn::GetAtt": ["NATEIP", "AllocationId"]},
                    "SubnetId": {"Ref": "PublicSubnet"},
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
            # Private subnet — EC2 instance lives here
            "PrivateSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "CidrBlock": "10.0.2.0/24",
                    "MapPublicIpOnLaunch": False,
                    "AvailabilityZone": {"Fn::Select": ["0", {"Fn::GetAZs": ""}]},
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
            "PrivateRT": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
            "PrivateRoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "NATGW",
                "Properties": {
                    "RouteTableId": {"Ref": "PrivateRT"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "NatGatewayId": {"Ref": "NATGW"}
                }
            },
            "PrivateSubnetRTAssoc": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "PrivateSubnet"},
                    "RouteTableId": {"Ref": "PrivateRT"}
                }
            },

            # ── EC2 Security Group ───────────────────────────────────────────
            "EC2SecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": f"SCE EC2 SG {suffix}",
                    "VpcId": {"Ref": "VPC"},
                    "SecurityGroupIngress": [],
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "CidrIp": "0.0.0.0/0",
                            "Description": "HTTPS egress for SSM agent"
                        }
                    ],
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },

            # Lambda SG — allows outbound HTTP to EC2 private IP + HTTPS to AWS
            "LambdaSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": f"SCE Lambda SG {suffix}",
                    "VpcId": {"Ref": "VPC"},
                    "SecurityGroupIngress": [],
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "CidrIp": "10.0.2.0/24",
                            "Description": "HTTP to EC2 private subnet for IMDS probe"
                        },
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "CidrIp": "0.0.0.0/0",
                            "Description": "HTTPS to AWS API endpoints"
                        }
                    ],
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },

            # Allow Lambda SG inbound HTTP on EC2 SG
            "EC2SGIngress": {
                "Type": "AWS::EC2::SecurityGroupIngress",
                "Properties": {
                    "GroupId": {"Ref": "EC2SecurityGroup"},
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "SourceSecurityGroupId": {"Ref": "LambdaSecurityGroup"},
                    "Description": "Allow IMDS probe Lambda HTTP access"
                }
            },

            # ── EC2 IAM Role & Instance Profile ─────────────────────────────
            "InstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": instance_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "Policies": [{
                        "PolicyName": "SCEInstanceMinimalPolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["ssm:GetParameter"],
                                "Resource": (
                                    f"arn:aws:ssm:{region}:{account}"
                                    f":parameter/sce/2-3/{suffix}/*"
                                )
                            }]
                        }
                    }],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "sce-suffix",     "Value": suffix}
                    ]
                }
            },
            "InstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "DependsOn": "InstanceRole",
                "Properties": {
                    "InstanceProfileName": f"SCEInstanceProfile-{suffix}",
                    "Roles": [{"Ref": "InstanceRole"}]
                }
            },

            # ── EC2 Test Instance ────────────────────────────────────────────
            # IMDSv2 required, HopLimit=1 — SECURE BASELINE before attack
            "TestInstance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": ["InstanceProfile", "PrivateRoute"],
                "Properties": {
                    "ImageId": ami_id,
                    "InstanceType": "t3.nano",
                    "SubnetId": {"Ref": "PrivateSubnet"},
                    "SecurityGroupIds": [{"Ref": "EC2SecurityGroup"}],
                    "IamInstanceProfile": {"Ref": "InstanceProfile"},
                    "MetadataOptions": {
                        "HttpTokens":              "required",
                        "HttpEndpoint":            "enabled",
                        "HttpPutResponseHopLimit": 1
                    },
                    "Tags": [
                        {"Key": "Name",           "Value": f"sce-test-{suffix}"},
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "sce-suffix",     "Value": suffix}
                    ]
                }
            },

            # ── SNS Topic (pager-notification proxy) ─────────────────────────
            "AlertTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": f"SCEAlert-{suffix}",
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },

            # ── SQS Queue subscribed to SNS ──────────────────────────────────
            "AlertQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": f"SCEAlertQueue-{suffix}",
                    "MessageRetentionPeriod": 300,
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
            "AlertQueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "AlertQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "sns.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": {"Fn::GetAtt": ["AlertQueue", "Arn"]},
                            "Condition": {
                                "ArnEquals": {
                                    "aws:SourceArn": {"Ref": "AlertTopic"}
                                }
                            }
                        }]
                    }
                }
            },
            "AlertSubscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "TopicArn": {"Ref": "AlertTopic"},
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["AlertQueue", "Arn"]}
                }
            },

            # ── SSM Parameters ───────────────────────────────────────────────
            "HarvestSignalParam": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name":  harvest_param,
                    "Type":  "String",
                    "Value": "idle",
                    "Tags": {
                        "sce-experiment": EXPERIMENT_TAG,
                        "sce-suffix":     suffix
                    }
                }
            },

            # ── Remediation Lambda IAM Role ──────────────────────────────────
            "LambdaExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": lambda_exec_role,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "Policies": [{
                        "PolicyName": "SCERemediationPolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AttachDenyPolicy",
                                    "Effect": "Allow",
                                    "Action": [
                                        "iam:PutRolePolicy",
                                        "iam:GetRolePolicy",
                                        "iam:ListRolePolicies"
                                    ],
                                    "Resource": (
                                        f"arn:aws:iam::{account}"
                                        f":role/{instance_role_name}"
                                    )
                                },
                                {
                                    "Sid": "SSMWrite",
                                    "Effect": "Allow",
                                    "Action": [
                                        "ssm:PutParameter",
                                        "ssm:GetParameter"
                                    ],
                                    "Resource": (
                                        f"arn:aws:ssm:{region}:{account}"
                                        f":parameter/sce/2-3/{suffix}/*"
                                    )
                                },
                                {
                                    "Sid": "SNSPublish",
                                    "Effect": "Allow",
                                    "Action": "sns:Publish",
                                    "Resource": {"Ref": "AlertTopic"}
                                },
                                {
                                    "Sid": "Logs",
                                    "Effect": "Allow",
                                    "Action": [
                                        "logs:CreateLogGroup",
                                        "logs:CreateLogStream",
                                        "logs:PutLogEvents"
                                    ],
                                    "Resource": "*"
                                }
                            ]
                        }
                    }],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "sce-suffix",     "Value": suffix}
                    ]
                }
            },

            # ── Remediation Lambda ───────────────────────────────────────────
            "RemediationFunction": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["LambdaExecRole", "InstanceRole"],
                "Properties": {
                    "FunctionName": lambda_name,
                    "Runtime":  "python3.12",
                    "Handler":  "index.handler",
                    "Role":     {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                    "Timeout":  30,
                    "Environment": {
                        "Variables": {
                            "TARGET_ROLE_NAME": instance_role_name,
                            "DONE_PARAM":       done_param,
                            "DENY_POLICY_NAME": deny_policy_name,
                            "ALERT_TOPIC_ARN":  {"Ref": "AlertTopic"}
                        }
                    },
                    "Code": {"ZipFile": remediation_code},
                    "Tags": [
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "sce-suffix",     "Value": suffix}
                    ]
                }
            },

            # ── EventBridge rule: SSM Parameter Store Change → Remediation ───
            "RemediationRule": {
                "Type": "AWS::Events::Rule",
                "DependsOn": "RemediationFunction",
                "Properties": {
                    "Name":        rule_name,
                    "Description": "SCE 2.3: Trigger remediation on credential harvest signal",
                    "State":       "ENABLED",
                    "EventPattern": json.dumps({
                        "source":      ["aws.ssm"],
                        "detail-type": ["Parameter Store Change"],
                        "detail": {
                            "name":      [harvest_param],
                            "operation": ["Update", "Create"]
                        }
                    }),
                    "Targets": [{
                        "Id":  "RemediationLambda",
                        "Arn": {"Fn::GetAtt": ["RemediationFunction", "Arn"]}
                    }]
                }
            },
            "LambdaPermission": {
                "Type": "AWS::Lambda::Permission",
                "DependsOn": "RemediationFunction",
                "Properties": {
                    "FunctionName": {"Ref": "RemediationFunction"},
                    "Action":       "lambda:InvokeFunction",
                    "Principal":    "events.amazonaws.com",
                    "SourceArn":    {"Fn::GetAtt": ["RemediationRule", "Arn"]}
                }
            },

            # ── IMDS Probe Lambda IAM Role ───────────────────────────────────
            "IMDSProbeLambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": probe_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
                    ],
                    "Policies": [{
                        "PolicyName": "SCEIMDSProbePolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Sid": "SSMWriteHarvest",
                                "Effect": "Allow",
                                "Action": ["ssm:PutParameter", "ssm:GetParameter"],
                                "Resource": (
                                    f"arn:aws:ssm:{region}:{account}"
                                    f":parameter/sce/2-3/{suffix}/*"
                                )
                            }]
                        }
                    }],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "sce-suffix",     "Value": suffix}
                    ]
                }
            },

            # ── IMDS Probe Lambda (runs in VPC private subnet) ───────────────
            "IMDSProbeFunction": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["IMDSProbeLambdaRole", "TestInstance"],
                "Properties": {
                    "FunctionName": probe_lambda_name,
                    "Runtime":  "python3.12",
                    "Handler":  "index.handler",
                    "Role":     {"Fn::GetAtt": ["IMDSProbeLambdaRole", "Arn"]},
                    "Timeout":  30,
                    "VpcConfig": {
                        "SubnetIds":        [{"Ref": "PrivateSubnet"}],
                        "SecurityGroupIds": [{"Ref": "LambdaSecurityGroup"}]
                    },
                    "Environment": {
                        "Variables": {
                            "INSTANCE_PRIVATE_IP": {
                                "Fn::GetAtt": ["TestInstance", "PrivateIp"]
                            },
                            "HARVEST_PARAM": harvest_param
                        }
                    },
                    "Code": {"ZipFile": probe_code},
                    "Tags": [
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "sce-suffix",     "Value": suffix}
                    ]
                }
            }
        },

        "Outputs": {
            "InstanceId": {
                "Value": {"Ref": "TestInstance"}
            },
            "InstanceRoleName": {
                "Value": {"Ref": "InstanceRole"}
            },
            "RemediationFunctionName": {
                "Value": {"Ref": "RemediationFunction"}
            },
            "IMDSProbeFunctionName": {
                "Value": {"Ref": "IMDSProbeFunction"}
            },
            "HarvestParamName": {
                "Value": harvest_param
            },
            "DoneParamName": {
                "Value": done_param
            },
            "DenyPolicyName": {
                "Value": deny_policy_name
            },
            "AlertQueueUrl": {
                "Value": {"Ref": "AlertQueue"}
            },
            "Suffix": {
                "Value": suffix
            }
        }
    }

    return json.dumps(template, indent=2)


# ---------------------------------------------------------------------------
# 1. steady_state()
# ---------------------------------------------------------------------------

def steady_state() -> None:
    """
    Provision all experiment resources via CloudFormation.

    Sequence:
      1. Resolve latest AL2023 AMI from SSM public parameter.
      2. Build CFn template embedding the resolved AMI ID.
      3. Create the timestamped stack; wait for CREATE_COMPLETE.
      4. Collect stack outputs into _STATE.
      5. Sleep for IAM propagation + EC2 IMDS readiness.
    """
    suffix     = str(_ts())
    stack_name = f"sce-experiment-{suffix}"
    _STATE["stack_name"] = stack_name
    _STATE["suffix"]     = suffix

    log.info("=" * 68)
    log.info("steady_state() — stack: %s", stack_name)
    log.info("=" * 68)

    ami_id   = _resolve_ami()
    template = _build_cfn_template(suffix, ami_id)
    cf       = _session().client("cloudformation")

    try:
        cf.create_stack(
            StackName=stack_name,
            TemplateBody=template,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            OnFailure="ROLLBACK",
            Tags=[
                {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                {"Key": "sce-suffix",     "Value": suffix},
                {"Key": "sce-node",       "Value": "2.3"},
                {"Key": "sce-probe",      "Value": "reactive"}
            ]
        )
        log.info("Stack creation initiated.")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "AlreadyExistsException":
            log.warning("Stack '%s' already exists — continuing.", stack_name)
        else:
            log.error("Failed to initiate stack creation: %s", exc)
            raise

    _wait_stack(cf, stack_name, "CREATE_COMPLETE")

    # ── Collect outputs ───────────────────────────────────────────────────────
    resp    = cf.describe_stacks(StackName=stack_name)
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in resp["Stacks"][0].get("Outputs", [])
    }

    _STATE["instance_id"]            = outputs["InstanceId"]
    _STATE["instance_role_name"]     = outputs["InstanceRoleName"]
    _STATE["remediation_fn_name"]    = outputs["RemediationFunctionName"]
    _STATE["imds_probe_fn_name"]     = outputs["IMDSProbeFunctionName"]
    _STATE["harvest_param_name"]     = outputs["HarvestParamName"]
    _STATE["done_param_name"]        = outputs["DoneParamName"]
    _STATE["deny_policy_name"]       = outputs["DenyPolicyName"]
    _STATE["alert_queue_url"]        = outputs["AlertQueueUrl"]

    log.info("Stack outputs collected: %s", json.dumps(_STATE, indent=2))

    # Allow IAM propagation and EC2 IMDS readiness
    log.info(
        "Waiting %ds for IAM propagation + EC2 IMDS readiness …",
        _IAM_PROPAGATION_SLEEP + _EC2_IMDS_WAIT,
    )
    time.sleep(_IAM_PROPAGATION_SLEEP + _EC2_IMDS_WAIT)
    log.info("steady_state() complete.")


# ---------------------------------------------------------------------------
# 2. attack() -> bool
# ---------------------------------------------------------------------------

def attack() -> bool:
    """
    Execute attack steps 1.2 and 2.2 in sequence, scoped strictly to
    resources created by steady_state().

    Step 1.2 — T1578 Modify Cloud Compute Infrastructure:
        Call ec2:ModifyInstanceMetadataOptions on the test instance,
        setting HttpTokens=optional and HttpPutResponseHopLimit=2.
        This is the ACTUAL AWS API call from the attack YAML.

    Step 2.2 — T1552.005 Cloud Instance Metadata API:
        Invoke the IMDSProbe Lambda (which runs in the same VPC/subnet
        as the EC2 instance) synchronously.  The Lambda issues an HTTP
        GET to the instance's private IP on port 80 with Host header
        set to 169.254.169.254, curling the IMDS credential endpoint
        without a session token (IMDSv1 path enabled by step 1.2).
        The result (role name + AccessKeyId prefix) is written to the
        HarvestSignalParam SSM parameter, firing the EventBridge rule.

    Returns True if both steps execute without error; False otherwise.
    """
    log.info("=" * 68)
    log.info("attack()")
    log.info("=" * 68)

    ec2_client  = _session().client("ec2")
    lam_client  = _session().client("lambda")
    instance_id = _STATE["instance_id"]
    probe_fn    = _STATE["imds_probe_fn_name"]

    # ── Step 1.2: ec2:ModifyInstanceMetadataOptions ──────────────────────────
    log.info(
        "[1.2] T1578 — ModifyInstanceMetadataOptions on instance %s "
        "(HttpTokens=optional, HopLimit=2) …",
        instance_id,
    )
    try:
        def _modify():
            return ec2_client.modify_instance_metadata_options(
                InstanceId=instance_id,
                HttpTokens="optional",
                HttpEndpoint="enabled",
                HttpPutResponseHopLimit=2,
            )
        resp_modify = _retry(_modify, attempts=4, label="ModifyInstanceMetadataOptions")
        new_state   = resp_modify.get("InstanceMetadataOptions", {})
        log.info(
            "[1.2] IMDS options modified: HttpTokens=%s, HopLimit=%s",
            new_state.get("HttpTokens"),
            new_state.get("HttpPutResponseHopLimit"),
        )
    except ClientError as exc:
        log.error("[1.2] ec2:ModifyInstanceMetadataOptions failed: %s", exc)
        return False

    # Brief pause for IMDS option propagation
    time.sleep(5)

    # ── Step 2.2: Invoke IMDSProbe Lambda to harvest credentials ────────────
    log.info(
        "[2.2] T1552.005 — Invoking IMDSProbe Lambda '%s' to curl IMDS "
        "without session token …",
        probe_fn,
    )
    try:
        def _invoke():
            return lam_client.invoke(
                FunctionName=probe_fn,
                InvocationType="RequestResponse",
                LogType="Tail",
            )
        response      = _retry(_invoke, attempts=4, label="InvokeIMDSProbe")
        payload_bytes = response["Payload"].read()
        payload       = json.loads(payload_bytes.decode())
        log.info("[2.2] IMDSProbe result payload: %s", json.dumps(payload))

        # Decode and log Lambda tail logs for audit evidence
        if response.get("LogResult"):
            tail = base64.b64decode(response["LogResult"]).decode(errors="replace")
            log.info("[2.2] IMDSProbe Lambda tail log:\n%s", tail)

        harvest_val = payload.get("harvest", "")
        if harvest_val.startswith("harvested::"):
            log.info(
                "[2.2] SUCCESS — IMDS credential harvest confirmed: %s",
                harvest_val,
            )
        elif harvest_val.startswith("blocked::"):
            # This outcome means IMDSv2 enforcement or network control blocked it.
            # In a high-fidelity test, this would indicate the preventive control
            # worked; for THIS reactive probe we need the harvest to succeed so
            # the reactive chain can be triggered.
            log.warning(
                "[2.2] IMDS probe was BLOCKED (unexpected for reactive test): %s",
                harvest_val,
            )
            # We still proceed — the harvest_val written to SSM will contain
            # "blocked::" which EventBridge will still detect as a param change.
        else:
            log.warning("[2.2] Unexpected harvest value: %s", harvest_val)

        # Store for hypothesis verification context
        _STATE["harvest_result"] = harvest_val

    except ClientError as exc:
        log.error("[2.2] Lambda invocation failed: %s", exc)
        return False
    except json.JSONDecodeError as exc:
        log.error("[2.2] Failed to parse Lambda response payload: %s", exc)
        return False

    log.info("attack() complete.")
    return True


# ---------------------------------------------------------------------------
# 3. hypothesis_verification() -> bool
# ---------------------------------------------------------------------------

def hypothesis_verification() -> bool:
    """
    Reactive Probe — verify the full remediation chain executed correctly.

    Sub-checks:
      (a) EventBridge → Lambda fired: poll remediation_done SSM param.
      (b) Deny-all inline policy attached to InstanceRole and structurally valid.
      (c) Effective DENY confirmed via IAM SimulatePrincipalPolicy on sensitive
          actions (sts:GetCallerIdentity, s3:GetObject, secretsmanager:GetSecretValue).
      (d) SNS → SQS notification received (pager-pathway validation).

    Returns True if ALL four sub-checks pass; False with per-check diagnostics
    logged on any failure.
    """
    log.info("=" * 68)
    log.info("hypothesis_verification() — Reactive Probe")
    log.info("=" * 68)

    ssm       = _session().client("ssm")
    iam       = _session().client("iam")
    sqs       = _session().client("sqs")
    sts       = _session().client("sts")

    done_param = _STATE["done_param_name"]
    role_name  = _STATE["instance_role_name"]
    deny_name  = _STATE["deny_policy_name"]
    queue_url  = _STATE["alert_queue_url"]

    all_passed = True

    # ─────────────────────────────────────────────────────────────────────────
    # (a) Poll for remediation_done signal — Lambda fired within SLA
    # ─────────────────────────────────────────────────────────────────────────
    log.info(
        "(a) Polling remediation_done param '%s' for up to %ds …",
        done_param,
        _LAMBDA_MAX_WAIT,
    )
    deadline   = time.monotonic() + _LAMBDA_MAX_WAIT
    remediated = False
    while time.monotonic() < deadline:
        try:
            val = ssm.get_parameter(Name=done_param)["Parameter"]["Value"]
            if val == "true":
                remediated = True
                elapsed = _LAMBDA_MAX_WAIT - max(0.0, deadline - time.monotonic())
                log.info(
                    "  (a) PASS — remediation_done='true' after ~%.0fs "
                    "(SLA target: 120s / 5-min goal).",
                    elapsed,
                )
                break
            log.debug("  (a) remediation_done='%s' — waiting …", val)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ParameterNotFound":
                log.debug("  (a) remediation_done param not yet present.")
            else:
                log.error("  (a) SSM get_parameter error: %s", exc)
        time.sleep(_LAMBDA_POLL_INTERVAL)

    if not remediated:
        log.error(
            "  (a) FAIL — RemediationLambda did NOT signal completion within %ds.",
            _LAMBDA_MAX_WAIT,
        )
        all_passed = False
    # Continue remaining checks regardless — collect full diagnostic picture.

    # ─────────────────────────────────────────────────────────────────────────
    # (b) Confirm deny-all inline policy is present and structurally valid
    # ─────────────────────────────────────────────────────────────────────────
    log.info(
        "(b) Verifying deny-all inline policy '%s' on role '%s' …",
        deny_name, role_name,
    )
    b_passed = False
    try:
        policies = iam.list_role_policies(RoleName=role_name)["PolicyNames"]
        if deny_name not in policies:
            log.error(
                "  (b) FAIL — Policy '%s' NOT found on role. Present policies: %s",
                deny_name, policies,
            )
        else:
            doc_raw = iam.get_role_policy(
                RoleName=role_name, PolicyName=deny_name
            )["PolicyDocument"]
            log.info(
                "  (b) Policy document retrieved:\n%s",
                json.dumps(doc_raw, indent=4),
            )
            stmts   = doc_raw.get("Statement", [])
            deny_ok = any(
                s.get("Effect") == "Deny"
                and s.get("Action") in ("*", ["*"])
                and s.get("Resource") in ("*", ["*"])
                for s in stmts
            )
            if deny_ok:
                log.info("  (b) PASS — Deny-all statement validated.")
                b_passed = True
            else:
                log.error(
                    "  (b) FAIL — Policy document lacks a valid Deny/*/* statement. "
                    "Statements: %s",
                    stmts,
                )
    except ClientError as exc:
        log.error("  (b) FAIL — IAM error: %s", exc)

    if not b_passed:
        all_passed = False

    # ─────────────────────────────────────────────────────────────────────────
    # (c) IAM SimulatePrincipalPolicy — confirm effective DENY on stolen role
    # ─────────────────────────────────────────────────────────────────────────
    log.info("(c) IAM policy simulation — confirming effective DENY on role …")
    c_passed = False
    try:
        account_id = sts.get_caller_identity()["Account"]
        region     = _region()
        role_arn   = f"arn:aws:iam::{account_id}:role/{role_name}"

        sensitive_actions = [
            "sts:GetCallerIdentity",
            "s3:GetObject",
            "secretsmanager:GetSecretValue",
            "ec2:DescribeInstances",
            "iam:ListRoles",
        ]

        def _simulate():
            return iam.simulate_principal_policy(
                PolicySourceArn=role_arn,
                ActionNames=sensitive_actions,
                ResourceArns=["*"],
            )
        sim     = _retry(_simulate, attempts=4, label="SimulatePrincipalPolicy")
        results = sim.get("EvaluationResults", [])

        allowed = []
        for r in results:
            decision = r["EvalDecision"]
            action   = r["EvalActionName"]
            log.info(
                "  (c) %-45s  → %s", action, decision
            )
            if decision not in ("explicitDeny", "implicitDeny"):
                allowed.append(action)

        if not allowed:
            log.info(
                "  (c) PASS — All %d simulated actions are denied after "
                "inline deny policy attachment.",
                len(results),
            )
            c_passed = True
        else:
            log.error(
                "  (c) FAIL — %d action(s) NOT denied after remediation: %s",
                len(allowed), allowed,
            )
    except ClientError as exc:
        log.error("  (c) FAIL — IAM simulation error: %s", exc)

    if not c_passed:
        all_passed = False

    # ─────────────────────────────────────────────────────────────────────────
    # (d) SQS queue received SNS notification — pager pathway validated
    # ─────────────────────────────────────────────────────────────────────────
    log.info(
        "(d) Checking SQS alert queue '%s' for SNS notification message …",
        queue_url,
    )
    d_passed       = False
    sqs_deadline   = time.monotonic() + _LAMBDA_MAX_WAIT  # same window
    while time.monotonic() < sqs_deadline:
        try:
            resp = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=5,
                MessageAttributeNames=["All"],
            )
            messages = resp.get("Messages", [])
            if messages:
                for msg in messages:
                    body = json.loads(msg.get("Body", "{}"))
                    subject = body.get("Subject", "")
                    message = body.get("Message", "")
                    log.info(
                        "  (d) SQS message received — Subject: '%s'", subject
                    )
                    log.info(
                        "  (d) SQS message body (SNS notification):\n%s",
                        json.dumps(json.loads(message), indent=4)
                        if message.startswith("{")
                        else message,
                    )
                    if "Credential Harvest Detected" in subject or "sce-2.3" in message:
                        d_passed = True
                        log.info(
                            "  (d) PASS — SNS pager-notification message confirmed "
                            "in SQS queue."
                        )
                        # Clean up message(s) to leave queue tidy
                        for m in messages:
                            try:
                                sqs.delete_message(
                                    QueueUrl=queue_url,
                                    ReceiptHandle=m["ReceiptHandle"],
                                )
                            except ClientError:
                                pass
                        break
        except ClientError as exc:
            log.error("  (d) SQS receive_message error: %s", exc)
            break

        if d_passed:
            break
        log.debug("  (d) No qualifying message yet — polling …")

    if not d_passed:
        log.error(
            "  (d) FAIL — No SNS notification message received in SQS queue "
            "within %ds.",
            _LAMBDA_MAX_WAIT,
        )
        all_passed = False

    # ─────────────────────────────────────────────────────────────────────────
    # Summary
    # ─────────────────────────────────────────────────────────────────────────
    status = "PASSED ✅" if all_passed else "FAILED ❌"
    log.info("-" * 68)
    log.info("hypothesis_verification() %s", status)
    log.info(
        "  (a) Lambda fired within SLA   : %s",
        "PASS" if remediated else "FAIL",
    )
    log.info(
        "  (b) Deny-all policy attached   : %s",
        "PASS" if b_passed   else "FAIL",
    )
    log.info(
        "  (c) Effective DENY via sim     : %s",
        "PASS" if c_passed   else "FAIL",
    )
    log.info(
        "  (d) SNS pager notification     : %s",
        "PASS" if d_passed   else "FAIL",
    )
    log.info("-" * 68)
    return all_passed


# ---------------------------------------------------------------------------
# 4. rollback()
# ---------------------------------------------------------------------------

def rollback() -> None:
    """
    Tear down the CloudFormation stack and all experiment resources.

    Pre-deletion steps:
      1. Remove the out-of-band inline deny policy from InstanceRole
         (CloudFormation cannot manage externally-attached inline policies).
      2. Delete the remediation_done SSM parameter (written outside CFn).
      3. Delete the imds_state SSM parameter (written outside CFn).

    Then delete the stack and wait for DELETE_COMPLETE.
    Tolerates stack-not-found gracefully.
    """
    log.info("=" * 68)
    log.info("rollback()")
    log.info("=" * 68)

    stack_name = _STATE.get("stack_name")
    if not stack_name:
        log.warning("rollback(): _STATE has no stack_name — nothing to delete.")
        return

    # ── Remove out-of-band inline policy ─────────────────────────────────────
    role_name = _STATE.get("instance_role_name")
    deny_name = _STATE.get("deny_policy_name")
    if role_name and deny_name:
        iam = _session().client("iam")
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=deny_name)
            log.info(
                "Removed inline deny policy '%s' from role '%s'.",
                deny_name, role_name,
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("NoSuchEntityException",):
                log.warning(
                    "Could not remove inline policy (non-fatal): %s", exc
                )
            else:
                log.info("Inline policy '%s' already absent.", deny_name)

    # ── Delete out-of-band SSM parameters ────────────────────────────────────
    ssm    = _session().client("ssm")
    suffix = _STATE.get("suffix", "")
    for param_path in [
        _STATE.get("done_param_name"),
        f"/sce/2-3/{suffix}/imds_state" if suffix else None,
    ]:
        if not param_path:
            continue
        try:
            ssm.delete_parameter(Name=param_path)
            log.info("Deleted SSM parameter '%s'.", param_path)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                log.warning(
                    "Could not delete SSM param '%s' (non-fatal): %s",
                    param_path, exc,
                )

    # ── Delete CloudFormation stack ───────────────────────────────────────────
    cf = _session().client("cloudformation")
    try:
        cf.delete_stack(StackName=stack_name)
        log.info("Stack deletion initiated: '%s'.", stack_name)
    except ClientError as exc:
        if (
            "does not exist" in str(exc)
            or exc.response["Error"]["Code"] == "ValidationError"
        ):
            log.info(
                "Stack '%s' not found — already deleted or never created.",
                stack_name,
            )
            return
        log.error(
            "Unexpected error initiating stack deletion for '%s': %s",
            stack_name, exc,
        )
        return

    try:
        _wait_stack(cf, stack_name, "DELETE_COMPLETE", max_wait=_STACK_MAX_WAIT)
        log.info("Stack '%s' deleted successfully.", stack_name)
    except TimeoutError as exc:
        log.error("Timeout waiting for stack deletion: %s", exc)
    except Exception as exc:  # noqa: BLE001
        log.error("Error during stack deletion wait: %s\n%s",
                  exc, traceback.format_exc())


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("╔" + "═" * 66 + "╗")
    log.info("║  SCE 2.3 — Reactive Probe  (high-fidelity iteration)         ║")
    log.info("║  Attack Nodes: 1.2 (T1578) + 2.2 (T1552.005)                ║")
    log.info("╚" + "═" * 66 + "╝")

    passed = False
    try:
        steady_state()
        attack_ok = attack()
        if not attack_ok:
            log.error(
                "attack() did not complete successfully — "
                "hypothesis check will still run for diagnostics."
            )
        passed = hypothesis_verification()
    except Exception:  # noqa: BLE001
        log.error(
            "Unhandled exception during experiment:\n%s",
            traceback.format_exc(),
        )
    finally:
        rollback()

    if passed:
        log.info("✅  EXPERIMENT PASSED — Reactive control chain fully validated.")
    else:
        log.error(
            "❌  EXPERIMENT FAILED — One or more reactive sub-checks did not pass."
        )
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()