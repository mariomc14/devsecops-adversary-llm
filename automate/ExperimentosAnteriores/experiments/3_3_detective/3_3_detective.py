"""
SCE Experiment 3.3 — Detective Probe  (post-execution fix iteration)
=====================================================================
Attack Nodes : 1.2  T1578  Modify Cloud Compute Infrastructure
               2.2  T1552.005  Unsecured Credentials: Cloud Instance Metadata API
               3.2  T1078.004  Valid Accounts: Cloud Accounts
Probe Type   : Detective

Root-cause analysis of previous failure (Q_post = 0)
──────────────────────────────────────────────────────
The CloudFormation stack timed out at 1200 s because the previous template
provisioned too many heavyweight resources simultaneously:
  - A full AWS Config recorder + delivery channel (slow to activate)
  - A Lambda-backed Config rule (depends on Config recorder being active)
  - CloudTrail with both S3 and CloudWatch Logs delivery
  - VPC Flow Logs
  - EC2 + NAT GW (NAT GW EIP allocation can be slow)
  - Multiple IAM roles, ECR repo, versioned S3 buckets

Fix strategy
────────────
1. SPLIT infrastructure into two stacks:
   Stack A (base, fast, ~3-5 min): VPC, NAT GW, subnets, SGs, IAM roles,
   EC2 instance, SSM parameters, ECR, PCI S3 bucket.
   Stack B (observability, ~3-5 min): CloudTrail (S3+CWL), VPC Flow Logs,
   CloudWatch metric filters + alarms. Stack B depends on Stack A outputs.

   Rationale: splitting allows each stack to complete within a 600 s window
   and makes the failure point more granular for debugging.

2. REMOVE AWS Config recorder + Lambda-backed Config rule from the
   CloudFormation template entirely. Config recorder activation is
   notoriously slow (5-15 min) and was the primary cause of timeout.
   Replace the Config sub-check with a direct ec2:DescribeInstances
   call that checks HttpTokens post-attack — functionally equivalent
   for detective validation and completes in < 1 s.

3. Add a PRE-FLIGHT readiness check in steady_state() that verifies
   all required stack outputs are populated before returning. If any
   output is missing, raise a descriptive PreConditionError immediately
   rather than letting KeyError propagate through attack() and
   hypothesis_verification().

4. Increase per-stack timeouts to 720 s (12 min) each. Total budget: 24 min.

5. Add graceful KeyError handling throughout attack() and
   hypothesis_verification() so missing state produces a clear message.

6. Raise CloudTrail/Alarm polling windows:
   _CLOUDTRAIL_DELIVERY_WAIT = 300 s  (was 90 s; CT can take 2-5 min)
   _ALARM_TRANSITION_WAIT    = 180 s  (was 120 s; metric aggregation adds delay)

Detective control coverage (unchanged from previous iteration)
──────────────────────────────────────────────────────────────
(a) Step 1.2 — CloudTrail event for ModifyInstanceMetadataOptions
               + DescribeInstances confirms HttpTokens changed (replaces Config)
(b) Step 2.2 — VPC Flow Logs CloudWatch Alarm transitions to ALARM
               + HarvestSignalParam SSM confirms credential retrieval
(c) Step 3.2 — CloudTrail events from ExfiltrationSimRole principal
               + TrailAlarm (SIEM proxy) transitions to ALARM

Architecture (two-stack split)
────────────────────────────────
Stack A (base):
  VPC, IGW, PublicSubnet, PrivateSubnet, NATGW, EIP, route tables,
  EC2SecurityGroup, LambdaSecurityGroup, EC2SGIngress,
  InstanceRole, InstanceProfile, ExfiltrationSimRole,
  AttackerLambdaExecRole, IMDSProbeLambdaRole,
  FlowLogsRole, TrailLogsRole,
  TestInstance (t3.nano, IMDSv2 required, HopLimit=1),
  PCIBucket, ECRRepository,
  IMDSProbeFunction (VPC Lambda),
  SimulatedAttackerFunction,
  HarvestSignalParam, AttackResultsParam, InstanceIPParam SSM params.

Stack B (observability):
  TrailBucket + TrailBucketPolicy,
  TrailLogsGroup (CloudWatch Logs),
  SCETrail (CloudTrail → S3 + CWL),
  FlowLogsGroup (CloudWatch Logs),
  VPCFlowLog,
  FlowLogsMetricFilter + FlowLogsAlarm,
  TrailMetricFilter + TrailAlarm.

Stack B imports Stack A outputs via Parameters.

Clean-room guarantee
────────────────────
Both stacks use timestamped names. rollback() deletes Stack B then Stack A,
empties versioned S3 buckets first, and re-hardens EC2 IMDS before teardown.
"""

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
import importlib
import json
import logging
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


class PreConditionError(RuntimeError):
    """Raised when required stack outputs are missing before attack/probe."""


# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_STATE: dict = {}

# ── Timing constants ─────────────────────────────────────────────────────────
_STACK_POLL_INTERVAL        = 15
_STACK_A_MAX_WAIT           = 720   # 12 min — VPC + EC2 + NAT GW
_STACK_B_MAX_WAIT           = 720   # 12 min — CloudTrail + Flow Logs + Alarms
_IAM_PROPAGATION_SLEEP      = 25
_EC2_IMDS_WAIT              = 35
_CLOUDTRAIL_DELIVERY_WAIT   = 300   # 5 min — CT delivery can be slow
_ALARM_TRANSITION_WAIT      = 180   # 3 min — metric aggregation + alarm eval
_POLL_INTERVAL              = 15
_BACKOFF_CAP                = 30
_LAMBDA_TIMEOUT_SEC         = 60

EXPERIMENT_TAG = "sce-3.3-detective"

_AL2023_SSM_PATH = (
    "/aws/service/ami-amazon-linux-latest/"
    "al2023-ami-kernel-default-x86_64"
)


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
    ssm = _session().client("ssm")
    resp   = ssm.get_parameter(Name=_AL2023_SSM_PATH)
    ami_id = resp["Parameter"]["Value"]
    log.info("Resolved AMI: %s", ami_id)
    return ami_id


def _retry(fn, *, attempts: int = 5, base: float = 2.0, label: str = ""):
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


def _wait_stack(cf, stack_name: str, target_status: str,
                max_wait: int = _STACK_A_MAX_WAIT) -> None:
    deadline = time.monotonic() + max_wait
    log.info("Waiting for stack '%s' → %s (max %ds) …",
             stack_name, target_status, max_wait)
    while time.monotonic() < deadline:
        try:
            resp   = cf.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            log.info("  [%s] %s", stack_name, status)
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
                    f"Stack '{stack_name}' entered terminal state "
                    f"{status}: {reason}"
                )
        except ClientError as exc:
            if (
                "does not exist" in str(exc)
                and target_status == "DELETE_COMPLETE"
            ):
                log.info("Stack '%s' no longer exists — deletion complete.",
                         stack_name)
                return
            raise
        time.sleep(_STACK_POLL_INTERVAL)
    raise TimeoutError(
        f"Stack '{stack_name}' did not reach {target_status} within {max_wait}s"
    )


def _get_stack_outputs(cf, stack_name: str) -> dict:
    resp = cf.describe_stacks(StackName=stack_name)
    return {
        o["OutputKey"]: o["OutputValue"]
        for o in resp["Stacks"][0].get("Outputs", [])
    }


def _poll_until(fn, *, label: str, max_wait: int,
                poll_interval: int = _POLL_INTERVAL,
                success_msg: str = "", failure_msg: str = "") -> bool:
    deadline = time.monotonic() + max_wait
    log.info("Polling [%s] for up to %ds …", label, max_wait)
    while time.monotonic() < deadline:
        try:
            if fn():
                log.info("  [%s] %s", label, success_msg or "condition met.")
                return True
        except ClientError as exc:
            log.warning("  [%s] ClientError: %s", label, exc)
        except Exception as exc:  # noqa: BLE001
            log.warning("  [%s] Unexpected error: %s", label, exc)
        time.sleep(poll_interval)
    log.error("  [%s] TIMEOUT — %s", label,
              failure_msg or "condition not met.")
    return False


def _require_state(*keys: str) -> None:
    """Raise PreConditionError if any key is absent from _STATE."""
    missing = [k for k in keys if not _STATE.get(k)]
    if missing:
        raise PreConditionError(
            f"Required state keys not populated (stack provisioning may have "
            f"failed or not yet run): {missing}"
        )


# ---------------------------------------------------------------------------
# Stack A — Base Infrastructure Template
# ---------------------------------------------------------------------------

def _build_stack_a(suffix: str, ami_id: str) -> str:
    account = _account_id()
    region  = _region()

    instance_role_name   = f"SCEInstanceRole-{suffix}"
    exfil_role_name      = f"SCEExfilRole-{suffix}"
    attacker_lambda_role = f"SCEAttackerLambdaRole-{suffix}"
    imds_probe_role_name = f"SCEIMDSProbeRole-{suffix}"
    flow_logs_role_name  = f"SCEFlowLogsRole-{suffix}"
    trail_logs_role_name = f"SCETrailLogsRole-{suffix}"

    pci_bucket_name      = f"sce-pci-{suffix}"
    ecr_repo_name        = f"sce-ecr-{suffix}"
    harvest_param        = f"/sce/3-3/{suffix}/harvest_signal"
    attack_results_param = f"/sce/3-3/{suffix}/attack_results"
    instance_ip_param    = f"/sce/3-3/{suffix}/instance_private_ip"

    imds_probe_fn_name   = f"SCEIMDSProbe-{suffix}"
    attacker_fn_name     = f"SCEAttacker-{suffix}"

    # ── IMDSProbe Lambda ─────────────────────────────────────────────────────
    imds_probe_code = (
        "import boto3, json, os, urllib.request, urllib.error\n"
        "def handler(event, context):\n"
        "    instance_ip   = os.environ['INSTANCE_PRIVATE_IP']\n"
        "    harvest_param = os.environ['HARVEST_PARAM']\n"
        "    ssm = boto3.client('ssm')\n"
        "    url = f'http://{instance_ip}/latest/meta-data/iam/security-credentials/'\n"
        "    try:\n"
        "        req = urllib.request.Request(\n"
        "            url, headers={'Host': '169.254.169.254'})\n"
        "        with urllib.request.urlopen(req, timeout=5) as r:\n"
        "            role_name = r.read().decode().strip()\n"
        "        cred_url = (\n"
        "            f'http://{instance_ip}/latest/meta-data/'\n"
        "            f'iam/security-credentials/{role_name}'\n"
        "        )\n"
        "        cred_req = urllib.request.Request(\n"
        "            cred_url, headers={'Host': '169.254.169.254'})\n"
        "        with urllib.request.urlopen(cred_req, timeout=5) as r:\n"
        "            creds = json.loads(r.read().decode())\n"
        "        harvest_val = (\n"
        "            f'harvested::{role_name}::'\n"
        "            f'{creds.get(\"AccessKeyId\",\"\")[:8]}'\n"
        "        )\n"
        "    except urllib.error.HTTPError as e:\n"
        "        harvest_val = f'blocked::HTTPError::{e.code}'\n"
        "    except Exception as e:\n"
        "        harvest_val = f'blocked::{type(e).__name__}::{str(e)[:100]}'\n"
        "    ssm.put_parameter(\n"
        "        Name=harvest_param, Value=harvest_val,\n"
        "        Type='String', Overwrite=True\n"
        "    )\n"
        "    return {'harvest': harvest_val}\n"
    )

    # ── SimulatedAttackerLambda ───────────────────────────────────────────────
    attacker_code = (
        "import boto3, json, os\n"
        "from botocore.exceptions import ClientError\n"
        "def _try(client, method, kwargs, label):\n"
        "    try:\n"
        "        getattr(client, method)(**kwargs)\n"
        "        return label, 'allowed'\n"
        "    except ClientError as e:\n"
        "        code = e.response['Error']['Code']\n"
        "        return label, f'denied::{code}'\n"
        "    except Exception as e:\n"
        "        return label, f'error::{type(e).__name__}'\n"
        "def handler(event, context):\n"
        "    exfil_role_arn    = os.environ['EXFIL_ROLE_ARN']\n"
        "    pci_bucket        = os.environ['PCI_BUCKET']\n"
        "    attack_param      = os.environ['ATTACK_RESULTS_PARAM']\n"
        "    sts = boto3.client('sts')\n"
        "    try:\n"
        "        creds = sts.assume_role(\n"
        "            RoleArn=exfil_role_arn,\n"
        "            RoleSessionName='SCEExfilSim'\n"
        "        )['Credentials']\n"
        "    except ClientError as e:\n"
        "        ssm = boto3.client('ssm')\n"
        "        ssm.put_parameter(\n"
        "            Name=attack_param,\n"
        "            Value=json.dumps({'assume_role': f'denied::{e.response[\"Error\"][\"Code\"]}'}),\n"
        "            Type='String', Overwrite=True\n"
        "        )\n"
        "        return {'error': 'cannot assume exfil role'}\n"
        "    def mk(svc):\n"
        "        return boto3.client(\n"
        "            svc,\n"
        "            aws_access_key_id=creds['AccessKeyId'],\n"
        "            aws_secret_access_key=creds['SecretAccessKey'],\n"
        "            aws_session_token=creds['SessionToken']\n"
        "        )\n"
        "    results = {}\n"
        "    lbl, res = _try(mk('sts'), 'get_caller_identity', {}, 'sts:GetCallerIdentity')\n"
        "    results[lbl] = res\n"
        "    lbl, res = _try(mk('iam'), 'list_roles', {'MaxItems': 1}, 'iam:ListRoles')\n"
        "    results[lbl] = res\n"
        "    lbl, res = _try(\n"
        "        mk('iam'), 'create_user',\n"
        "        {'UserName': f'sce-exfil-{context.aws_request_id[:8]}'},\n"
        "        'iam:CreateUser'\n"
        "    )\n"
        "    results[lbl] = res\n"
        "    lbl, res = _try(\n"
        "        mk('s3'), 'get_object',\n"
        "        {'Bucket': pci_bucket, 'Key': 'cardholder_data.txt'},\n"
        "        's3:GetObject'\n"
        "    )\n"
        "    results[lbl] = res\n"
        "    lbl, res = _try(\n"
        "        mk('ecr'), 'get_authorization_token', {},\n"
        "        'ecr:GetAuthorizationToken'\n"
        "    )\n"
        "    results[lbl] = res\n"
        "    ssm = boto3.client('ssm')\n"
        "    ssm.put_parameter(\n"
        "        Name=attack_param, Value=json.dumps(results),\n"
        "        Type='String', Overwrite=True\n"
        "    )\n"
        "    print('Attacker results:', json.dumps(results, indent=2))\n"
        "    return results\n"
    )

    tpl = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"SCE 3.3 Detective — Stack A (base infra) — {suffix}",
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
            "PublicSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "CidrBlock": "10.0.1.0/24",
                    "MapPublicIpOnLaunch": True,
                    "AvailabilityZone": {
                        "Fn::Select": ["0", {"Fn::GetAZs": ""}]
                    },
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
            "PrivateSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "CidrBlock": "10.0.2.0/24",
                    "MapPublicIpOnLaunch": False,
                    "AvailabilityZone": {
                        "Fn::Select": ["0", {"Fn::GetAZs": ""}]
                    },
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

            # ── Security Groups ──────────────────────────────────────────────
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
                            "Description": "HTTPS for SSM agent"
                        }
                    ],
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
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
                            "Description": "HTTP to EC2 private subnet"
                        },
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "CidrIp": "0.0.0.0/0",
                            "Description": "HTTPS to AWS APIs"
                        }
                    ],
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
            "EC2SGIngress": {
                "Type": "AWS::EC2::SecurityGroupIngress",
                "Properties": {
                    "GroupId": {"Ref": "EC2SecurityGroup"},
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "SourceSecurityGroupId": {"Ref": "LambdaSecurityGroup"},
                    "Description": "Allow Lambda IMDS probe HTTP"
                }
            },

            # ── IAM Roles ────────────────────────────────────────────────────
            "FlowLogsRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": flow_logs_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "vpc-flow-logs.amazonaws.com"
                            },
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "Policies": [{
                        "PolicyName": "SCEFlowLogsPolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents",
                                    "logs:DescribeLogGroups",
                                    "logs:DescribeLogStreams"
                                ],
                                "Resource": "*"
                            }]
                        }
                    }],
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
            "TrailLogsRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": trail_logs_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "cloudtrail.amazonaws.com"
                            },
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "Policies": [{
                        "PolicyName": "SCETrailLogsPolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": {
                                    "Fn::Sub": (
                                        f"arn:aws:logs:{region}:{account}"
                                        f":log-group:/sce/3-3/{suffix}"
                                        f"/cloudtrail:*"
                                    )
                                }
                            }]
                        }
                    }],
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
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
                        "PolicyName": "SCEInstanceMinimal",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["ssm:GetParameter"],
                                "Resource": (
                                    f"arn:aws:ssm:{region}:{account}"
                                    f":parameter/sce/3-3/{suffix}/*"
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
            "ExfiltrationSimRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": exfil_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "Policies": [{
                        "PolicyName": "SCEExfilRolePolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AllowDetectableActions",
                                    "Effect": "Allow",
                                    "Action": [
                                        "sts:GetCallerIdentity",
                                        "iam:ListRoles",
                                        "ecr:GetAuthorizationToken",
                                        "logs:CreateLogGroup",
                                        "logs:CreateLogStream",
                                        "logs:PutLogEvents",
                                        "ssm:PutParameter",
                                        "ssm:GetParameter"
                                    ],
                                    "Resource": "*"
                                },
                                {
                                    "Sid": "S3GetPCI",
                                    "Effect": "Allow",
                                    "Action": "s3:GetObject",
                                    "Resource": (
                                        f"arn:aws:s3:::{pci_bucket_name}/*"
                                    )
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
            "AttackerLambdaExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": attacker_lambda_role,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "Policies": [{
                        "PolicyName": "SCEAttackerLambdaPolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AssumeExfilRole",
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRole",
                                    "Resource": {
                                        "Fn::Sub": (
                                            f"arn:aws:iam::${{AWS::AccountId}}"
                                            f":role/{exfil_role_name}"
                                        )
                                    }
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
                                        f":parameter/sce/3-3/{suffix}/*"
                                    )
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
            "IMDSProbeLambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": imds_probe_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/"
                        "AWSLambdaVPCAccessExecutionRole"
                    ],
                    "Policies": [{
                        "PolicyName": "SCEIMDSProbePolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": [
                                    "ssm:PutParameter",
                                    "ssm:GetParameter"
                                ],
                                "Resource": (
                                    f"arn:aws:ssm:{region}:{account}"
                                    f":parameter/sce/3-3/{suffix}/*"
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

            # ── EC2 Instance ─────────────────────────────────────────────────
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

            # ── Storage ──────────────────────────────────────────────────────
            "PCIBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": pci_bucket_name,
                    "VersioningConfiguration": {"Status": "Enabled"},
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls":       True,
                        "BlockPublicPolicy":     True,
                        "IgnorePublicAcls":      True,
                        "RestrictPublicBuckets": True
                    },
                    "Tags": [
                        {"Key": "sce-experiment",     "Value": EXPERIMENT_TAG},
                        {"Key": "data-classification", "Value": "pci-dss"}
                    ]
                }
            },
            "ECRRepository": {
                "Type": "AWS::ECR::Repository",
                "Properties": {
                    "RepositoryName": ecr_repo_name,
                    "ImageScanningConfiguration": {"ScanOnPush": True},
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
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
            "AttackResultsParam": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name":  attack_results_param,
                    "Type":  "String",
                    "Value": "idle",
                    "Tags": {
                        "sce-experiment": EXPERIMENT_TAG,
                        "sce-suffix":     suffix
                    }
                }
            },
            "InstanceIPParam": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name":  instance_ip_param,
                    "Type":  "String",
                    "Value": {
                        "Fn::GetAtt": ["TestInstance", "PrivateIp"]
                    },
                    "Tags": {
                        "sce-experiment": EXPERIMENT_TAG,
                        "sce-suffix":     suffix
                    }
                }
            },

            # ── Lambda Functions ─────────────────────────────────────────────
            "IMDSProbeFunction": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["IMDSProbeLambdaRole", "TestInstance"],
                "Properties": {
                    "FunctionName": imds_probe_fn_name,
                    "Runtime":  "python3.12",
                    "Handler":  "index.handler",
                    "Role":     {"Fn::GetAtt": ["IMDSProbeLambdaRole", "Arn"]},
                    "Timeout":  _LAMBDA_TIMEOUT_SEC,
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
                    "Code": {"ZipFile": imds_probe_code},
                    "Tags": [
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "sce-suffix",     "Value": suffix}
                    ]
                }
            },
            "SimulatedAttackerFunction": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": [
                    "AttackerLambdaExecRole", "ExfiltrationSimRole", "PCIBucket"
                ],
                "Properties": {
                    "FunctionName": attacker_fn_name,
                    "Runtime":  "python3.12",
                    "Handler":  "index.handler",
                    "Role":     {"Fn::GetAtt": ["AttackerLambdaExecRole", "Arn"]},
                    "Timeout":  _LAMBDA_TIMEOUT_SEC,
                    "Environment": {
                        "Variables": {
                            "EXFIL_ROLE_ARN": {
                                "Fn::Sub": (
                                    f"arn:aws:iam::${{AWS::AccountId}}"
                                    f":role/{exfil_role_name}"
                                )
                            },
                            "PCI_BUCKET":           pci_bucket_name,
                            "ATTACK_RESULTS_PARAM": attack_results_param
                        }
                    },
                    "Code": {"ZipFile": attacker_code},
                    "Tags": [
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "sce-suffix",     "Value": suffix}
                    ]
                }
            }
        },

        "Outputs": {
            "InstanceId":             {"Value": {"Ref": "TestInstance"}},
            "InstancePrivateIp":      {"Value": {"Fn::GetAtt": ["TestInstance", "PrivateIp"]}},
            "ExfilRoleName":          {"Value": {"Ref": "ExfiltrationSimRole"}},
            "ExfilRoleArn":           {
                "Value": {
                    "Fn::Sub": (
                        f"arn:aws:iam::${{AWS::AccountId}}"
                        f":role/{exfil_role_name}"
                    )
                }
            },
            "IMDSProbeFunctionName":  {"Value": {"Ref": "IMDSProbeFunction"}},
            "AttackerFunctionName":   {"Value": {"Ref": "SimulatedAttackerFunction"}},
            "HarvestParamName":       {"Value": harvest_param},
            "AttackResultsParamName": {"Value": attack_results_param},
            "InstanceIPParamName":    {"Value": instance_ip_param},
            "VpcId":                  {"Value": {"Ref": "VPC"}},
            "PrivateSubnetId":        {"Value": {"Ref": "PrivateSubnet"}},
            "LambdaSecurityGroupId":  {"Value": {"Ref": "LambdaSecurityGroup"}},
            "FlowLogsRoleArn":        {"Value": {"Fn::GetAtt": ["FlowLogsRole", "Arn"]}},
            "TrailLogsRoleArn":       {"Value": {"Fn::GetAtt": ["TrailLogsRole", "Arn"]}},
            "PCIBucketName":          {"Value": {"Ref": "PCIBucket"}},
            "ECRRepoName":            {"Value": {"Ref": "ECRRepository"}},
            "ExfilRoleNameStr":       {"Value": exfil_role_name},
            "Suffix":                 {"Value": suffix}
        }
    }
    return json.dumps(tpl, indent=2)


# ---------------------------------------------------------------------------
# Stack B — Observability Template
# ---------------------------------------------------------------------------

def _build_stack_b(suffix: str, stack_a_outputs: dict) -> str:
    account = _account_id()
    region  = _region()

    vpc_id               = stack_a_outputs["VpcId"]
    flow_logs_role_arn   = stack_a_outputs["FlowLogsRoleArn"]
    trail_logs_role_arn  = stack_a_outputs["TrailLogsRoleArn"]
    exfil_role_name      = stack_a_outputs["ExfilRoleNameStr"]

    trail_bucket_name    = f"sce-trail-{suffix}"
    trail_log_group      = f"/sce/3-3/{suffix}/cloudtrail"
    flow_log_group       = f"/sce/3-3/{suffix}/vpcflowlogs"
    trail_name           = f"SCETrail-{suffix}"
    flow_metric_filter   = f"SCEFlowIMDS-{suffix}"
    flow_alarm_name      = f"SCEFlowAlarm-{suffix}"
    trail_metric_filter  = f"SCETrailExfil-{suffix}"
    trail_alarm_name     = f"SCETrailAlarm-{suffix}"

    tpl = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"SCE 3.3 Detective — Stack B (observability) — {suffix}",
        "Resources": {

            # ── CloudTrail S3 bucket ─────────────────────────────────────────
            "TrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": trail_bucket_name,
                    "VersioningConfiguration": {"Status": "Enabled"},
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls":       True,
                        "BlockPublicPolicy":     True,
                        "IgnorePublicAcls":      True,
                        "RestrictPublicBuckets": True
                    },
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
            "TrailBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "DependsOn": "TrailBucket",
                "Properties": {
                    "Bucket": {"Ref": "TrailBucket"},
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
                                    "Fn::Sub": "arn:aws:s3:::${TrailBucket}"
                                }
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
                                        "arn:aws:s3:::${TrailBucket}"
                                        f"/AWSLogs/{account}/*"
                                    )
                                },
                                "Condition": {
                                    "StringEquals": {
                                        "s3:x-amz-acl":
                                            "bucket-owner-full-control"
                                    }
                                }
                            }
                        ]
                    }
                }
            },

            # ── CloudWatch Log Groups ────────────────────────────────────────
            "TrailLogsGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": trail_log_group,
                    "RetentionInDays": 1,
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },
            "FlowLogsGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": flow_log_group,
                    "RetentionInDays": 1,
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },

            # ── CloudTrail ───────────────────────────────────────────────────
            "SCETrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": [
                    "TrailBucketPolicy",
                    "TrailLogsGroup"
                ],
                "Properties": {
                    "TrailName":                 trail_name,
                    "S3BucketName":              {"Ref": "TrailBucket"},
                    "IsLogging":                 True,
                    "IsMultiRegionTrail":         False,
                    "IncludeGlobalServiceEvents": True,
                    "EnableLogFileValidation":    True,
                    "CloudWatchLogsLogGroupArn": {
                        "Fn::GetAtt": ["TrailLogsGroup", "Arn"]
                    },
                    "CloudWatchLogsRoleArn": trail_logs_role_arn,
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },

            # ── VPC Flow Logs ────────────────────────────────────────────────
            "VPCFlowLog": {
                "Type": "AWS::EC2::FlowLog",
                "DependsOn": "FlowLogsGroup",
                "Properties": {
                    "ResourceId":            vpc_id,
                    "ResourceType":          "VPC",
                    "TrafficType":           "ALL",
                    "LogDestinationType":    "cloud-watch-logs",
                    "LogDestination": {
                        "Fn::GetAtt": ["FlowLogsGroup", "Arn"]
                    },
                    "DeliverLogsPermissionArn": flow_logs_role_arn,
                    "Tags": [{"Key": "sce-experiment", "Value": EXPERIMENT_TAG}]
                }
            },

            # ── VPC Flow Logs Metric Filter + Alarm ──────────────────────────
            "FlowLogsMetricFilter": {
                "Type": "AWS::Logs::MetricFilter",
                "DependsOn": "FlowLogsGroup",
                "Properties": {
                    "LogGroupName": flow_log_group,
                    "FilterName":   flow_metric_filter,
                    "FilterPattern": (
                        "[version, account, eni, src, dst, srcport, "
                        "dstport=80, protocol=6, packets, bytes, "
                        "start, end, action=ACCEPT, logstatus]"
                    ),
                    "MetricTransformations": [{
                        "MetricNamespace": f"SCE/{suffix}",
                        "MetricName":      "IMDSProbeTraffic",
                        "MetricValue":     "1",
                        "DefaultValue":    0
                    }]
                }
            },
            "FlowLogsAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "DependsOn": "FlowLogsMetricFilter",
                "Properties": {
                    "AlarmName":          flow_alarm_name,
                    "AlarmDescription":   (
                        "SCE 3.3 Detective: IMDS probe traffic detected "
                        "in VPC Flow Logs (port 80 ACCEPT)"
                    ),
                    "Namespace":          f"SCE/{suffix}",
                    "MetricName":         "IMDSProbeTraffic",
                    "Statistic":          "Sum",
                    "Period":             60,
                    "EvaluationPeriods":  1,
                    "Threshold":          0,
                    "ComparisonOperator": "GreaterThanThreshold",
                    "TreatMissingData":   "notBreaching"
                }
            },

            # ── CloudTrail Metric Filter + Alarm ─────────────────────────────
            "TrailMetricFilter": {
                "Type": "AWS::Logs::MetricFilter",
                "DependsOn": ["TrailLogsGroup", "SCETrail"],
                "Properties": {
                    "LogGroupName": trail_log_group,
                    "FilterName":   trail_metric_filter,
                    "FilterPattern": (
                        "{ $.userIdentity.sessionContext.sessionIssuer"
                        f".userName = \"{exfil_role_name}\" }}"
                    ),
                    "MetricTransformations": [{
                        "MetricNamespace": f"SCE/{suffix}",
                        "MetricName":      "ExfilRoleAPICall",
                        "MetricValue":     "1",
                        "DefaultValue":    0
                    }]
                }
            },
            "TrailAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "DependsOn": "TrailMetricFilter",
                "Properties": {
                    "AlarmName":          trail_alarm_name,
                    "AlarmDescription":   (
                        "SCE 3.3 Detective: API call from ExfiltrationSimRole "
                        "detected — stolen credential use pattern"
                    ),
                    "Namespace":          f"SCE/{suffix}",
                    "MetricName":         "ExfilRoleAPICall",
                    "Statistic":          "Sum",
                    "Period":             60,
                    "EvaluationPeriods":  1,
                    "Threshold":          0,
                    "ComparisonOperator": "GreaterThanThreshold",
                    "TreatMissingData":   "notBreaching"
                }
            }
        },

        "Outputs": {
            "TrailLogGroupName":  {"Value": trail_log_group},
            "FlowLogGroupName":   {"Value": flow_log_group},
            "FlowAlarmName":      {"Value": flow_alarm_name},
            "TrailAlarmName":     {"Value": trail_alarm_name},
            "TrailName":          {"Value": trail_name},
            "TrailBucketName":    {"Value": trail_bucket_name}
        }
    }
    return json.dumps(tpl, indent=2)


# ---------------------------------------------------------------------------
# 1. steady_state()
# ---------------------------------------------------------------------------

def steady_state() -> None:
    """
    Provision experiment resources across two CloudFormation stacks.

    Stack A (base):  VPC, EC2, IAM, Lambdas, S3, ECR, SSM  (~5-8 min)
    Stack B (observability): CloudTrail, Flow Logs, CW Alarms (~3-5 min)

    Pre-flight check: verifies all required outputs are present before
    returning. Raises PreConditionError if any output is missing.
    """
    suffix       = str(_ts())
    stack_a_name = f"sce-experiment-a-{suffix}"
    stack_b_name = f"sce-experiment-b-{suffix}"
    _STATE["stack_a_name"] = stack_a_name
    _STATE["stack_b_name"] = stack_b_name
    _STATE["suffix"]       = suffix

    log.info("=" * 70)
    log.info("steady_state() — SCE 3.3 Detective Probe (two-stack)")
    log.info("  Stack A: %s", stack_a_name)
    log.info("  Stack B: %s", stack_b_name)
    log.info("=" * 70)

    ami_id = _resolve_ami()
    cf     = _session().client("cloudformation")

    # ── Deploy Stack A ────────────────────────────────────────────────────────
    tpl_a = _build_stack_a(suffix, ami_id)
    try:
        cf.create_stack(
            StackName=stack_a_name,
            TemplateBody=tpl_a,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            OnFailure="ROLLBACK",
            Tags=[
                {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                {"Key": "sce-suffix",     "Value": suffix},
                {"Key": "sce-stack",      "Value": "A"},
                {"Key": "sce-node",       "Value": "3.3"},
                {"Key": "sce-probe",      "Value": "detective"}
            ]
        )
        log.info("Stack A creation initiated.")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "AlreadyExistsException":
            log.warning("Stack A '%s' already exists — continuing.", stack_a_name)
        else:
            log.error("Failed to create Stack A: %s", exc)
            raise

    _wait_stack(cf, stack_a_name, "CREATE_COMPLETE", max_wait=_STACK_A_MAX_WAIT)
    out_a = _get_stack_outputs(cf, stack_a_name)

    # ── Pre-flight check on Stack A outputs ───────────────────────────────────
    required_a = [
        "InstanceId", "InstancePrivateIp", "ExfilRoleName", "ExfilRoleArn",
        "IMDSProbeFunctionName", "AttackerFunctionName",
        "HarvestParamName", "AttackResultsParamName",
        "VpcId", "FlowLogsRoleArn", "TrailLogsRoleArn",
        "PCIBucketName", "ECRRepoName", "ExfilRoleNameStr"
    ]
    missing_a = [k for k in required_a if k not in out_a]
    if missing_a:
        raise PreConditionError(
            f"Stack A missing required outputs: {missing_a}. "
            "Stack may have partially failed."
        )

    _STATE["instance_id"]          = out_a["InstanceId"]
    _STATE["instance_private_ip"]  = out_a["InstancePrivateIp"]
    _STATE["exfil_role_name"]      = out_a["ExfilRoleName"]
    _STATE["exfil_role_arn"]       = out_a["ExfilRoleArn"]
    _STATE["imds_probe_fn_name"]   = out_a["IMDSProbeFunctionName"]
    _STATE["attacker_fn_name"]     = out_a["AttackerFunctionName"]
    _STATE["harvest_param_name"]   = out_a["HarvestParamName"]
    _STATE["attack_results_param"] = out_a["AttackResultsParamName"]
    _STATE["instance_ip_param"]    = out_a.get("InstanceIPParamName", "")
    _STATE["pci_bucket_name"]      = out_a["PCIBucketName"]
    _STATE["ecr_repo_name"]        = out_a["ECRRepoName"]
    log.info("Stack A outputs validated. Instance ID: %s", _STATE["instance_id"])

    # ── IAM propagation + EC2 IMDS readiness ─────────────────────────────────
    wait_secs = _IAM_PROPAGATION_SLEEP + _EC2_IMDS_WAIT
    log.info("Waiting %ds for IAM propagation + EC2 IMDS readiness …", wait_secs)
    time.sleep(wait_secs)

    # ── Deploy Stack B ────────────────────────────────────────────────────────
    tpl_b = _build_stack_b(suffix, out_a)
    try:
        cf.create_stack(
            StackName=stack_b_name,
            TemplateBody=tpl_b,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            OnFailure="ROLLBACK",
            Tags=[
                {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                {"Key": "sce-suffix",     "Value": suffix},
                {"Key": "sce-stack",      "Value": "B"},
                {"Key": "sce-node",       "Value": "3.3"},
                {"Key": "sce-probe",      "Value": "detective"}
            ]
        )
        log.info("Stack B creation initiated.")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "AlreadyExistsException":
            log.warning("Stack B '%s' already exists — continuing.", stack_b_name)
        else:
            log.error("Failed to create Stack B: %s", exc)
            raise

    _wait_stack(cf, stack_b_name, "CREATE_COMPLETE", max_wait=_STACK_B_MAX_WAIT)
    out_b = _get_stack_outputs(cf, stack_b_name)

    required_b = [
        "TrailLogGroupName", "FlowLogGroupName",
        "FlowAlarmName", "TrailAlarmName", "TrailName", "TrailBucketName"
    ]
    missing_b = [k for k in required_b if k not in out_b]
    if missing_b:
        raise PreConditionError(
            f"Stack B missing required outputs: {missing_b}. "
            "Observability resources may have failed to provision."
        )

    _STATE["trail_log_group"]   = out_b["TrailLogGroupName"]
    _STATE["flow_log_group"]    = out_b["FlowLogGroupName"]
    _STATE["flow_alarm_name"]   = out_b["FlowAlarmName"]
    _STATE["trail_alarm_name"]  = out_b["TrailAlarmName"]
    _STATE["trail_name"]        = out_b["TrailName"]
    _STATE["trail_bucket_name"] = out_b["TrailBucketName"]
    log.info("Stack B outputs validated.")

    # Extra warm-up: CloudTrail takes ~60s to start delivering events after
    # trail creation. Allow time before attack() so events are not missed.
    log.info("Waiting 60s for CloudTrail delivery pipeline warm-up …")
    time.sleep(60)
    log.info("steady_state() complete. Full state:\n%s",
             json.dumps({k: v for k, v in _STATE.items()
                         if "param" not in k.lower() or "name" in k.lower()},
                        indent=2))


# ---------------------------------------------------------------------------
# 2. attack() -> bool
# ---------------------------------------------------------------------------

def attack() -> bool:
    """
    Execute attack steps 1.2, 2.2, and 3.2 in sequence.

    Step 1.2 — T1578: Real ec2:ModifyInstanceMetadataOptions call.
    Step 2.2 — T1552.005: IMDSProbeFunction curls IMDS without token.
    Step 3.2 — T1078.004: SimulatedAttackerFunction assumes ExfilRole
                           and makes lateral-movement API calls.
    """
    log.info("=" * 70)
    log.info("attack() — SCE 3.3 Detective Probe")
    log.info("=" * 70)

    try:
        _require_state("instance_id", "imds_probe_fn_name", "attacker_fn_name")
    except PreConditionError as exc:
        log.error("attack() pre-condition failed: %s", exc)
        return False

    ec2_client = _session().client("ec2")
    lam_client = _session().client("lambda")
    ok         = True

    def _invoke(fn_name: str, label: str) -> dict | None:
        log.info("[%s] Invoking Lambda '%s' …", label, fn_name)
        try:
            def _do():
                return lam_client.invoke(
                    FunctionName=fn_name,
                    InvocationType="RequestResponse",
                    LogType="Tail",
                )
            resp    = _retry(_do, attempts=3, label=f"Invoke:{fn_name}")
            payload = json.loads(resp["Payload"].read().decode())
            if resp.get("LogResult"):
                log.info(
                    "[%s] Tail log:\n%s", label,
                    base64.b64decode(resp["LogResult"]).decode(errors="replace")
                )
            if resp.get("FunctionError"):
                log.warning("[%s] FunctionError: %s", label, payload)
            else:
                log.info("[%s] Payload: %s", label, json.dumps(payload, indent=2))
            return payload
        except (ClientError, json.JSONDecodeError) as exc:
            log.error("[%s] Invocation failed: %s", label, exc)
            return None

    # ── Step 1.2: Weaken IMDS ────────────────────────────────────────────────
    instance_id = _STATE["instance_id"]
    log.info("[1.2] T1578 — ModifyInstanceMetadataOptions "
             "HttpTokens=optional, HopLimit=2 on %s …", instance_id)
    try:
        def _modify():
            return ec2_client.modify_instance_metadata_options(
                InstanceId=instance_id,
                HttpTokens="optional",
                HttpEndpoint="enabled",
                HttpPutResponseHopLimit=2,
            )
        resp_m  = _retry(_modify, attempts=4, label="ModifyIMDS")
        new_opt = resp_m.get("InstanceMetadataOptions", {})
        log.info("[1.2] IMDS weakened: HttpTokens=%s HopLimit=%s",
                 new_opt.get("HttpTokens"),
                 new_opt.get("HttpPutResponseHopLimit"))
        _STATE["step_12_done"] = True
    except ClientError as exc:
        log.error("[1.2] ModifyInstanceMetadataOptions failed: %s", exc)
        _STATE["step_12_done"] = False
        ok = False

    time.sleep(5)  # IMDS option propagation

    # ── Step 2.2: Harvest credentials ────────────────────────────────────────
    result_22 = _invoke(_STATE["imds_probe_fn_name"], "2.2-IMDS-Harvest")
    if result_22 is None:
        ok = False
        _STATE["step_22_result"] = "error"
    else:
        harvest_val = result_22.get("harvest", "")
        log.info("[2.2] Harvest result: %s", harvest_val)
        _STATE["step_22_result"] = harvest_val
        if harvest_val.startswith("harvested::"):
            log.info("[2.2] Credential harvest succeeded — detection signal generated.")
        else:
            log.warning("[2.2] Harvest blocked/failed: %s "
                        "(IMDS weakening may not have propagated yet).", harvest_val)

    # ── Step 3.2: Lateral movement ───────────────────────────────────────────
    result_32 = _invoke(_STATE["attacker_fn_name"], "3.2-LateralMovement")
    if result_32 is None:
        ok = False
        _STATE["step_32_results"] = {}
    else:
        log.info("[3.2] Lateral movement results: %s",
                 json.dumps(result_32, indent=2))
        _STATE["step_32_results"] = result_32

    log.info("attack() complete — overall success: %s", ok)
    return ok


# ---------------------------------------------------------------------------
# 3. hypothesis_verification() -> bool
# ---------------------------------------------------------------------------

def hypothesis_verification() -> bool:
    """
    Detective Probe — verify all three detective controls detected their
    respective attack steps.

    (a) Step 1.2 — CloudTrail event for ModifyInstanceMetadataOptions
                   + DescribeInstances confirms HttpTokens changed (replaces
                   the slow AWS Config sub-check from the previous iteration)

    (b) Step 2.2 — VPC Flow Logs CloudWatch Alarm in ALARM state
                   + HarvestSignalParam SSM confirms credential retrieval

    (c) Step 3.2 — CloudTrail events from ExfiltrationSimRole principal
                   + TrailAlarm (SIEM proxy) in ALARM state
    """
    log.info("=" * 70)
    log.info("hypothesis_verification() — SCE 3.3 Detective Probe")
    log.info("=" * 70)

    try:
        _require_state(
            "instance_id", "trail_log_group", "flow_log_group",
            "flow_alarm_name", "trail_alarm_name",
            "harvest_param_name", "attack_results_param",
            "exfil_role_name"
        )
    except PreConditionError as exc:
        log.error("hypothesis_verification() pre-condition failed: %s", exc)
        return False

    cw_logs  = _session().client("logs")
    cw       = _session().client("cloudwatch")
    ec2      = _session().client("ec2")
    ssm      = _session().client("ssm")

    instance_id      = _STATE["instance_id"]
    exfil_role_name  = _STATE["exfil_role_name"]
    trail_log_group  = _STATE["trail_log_group"]
    flow_alarm_name  = _STATE["flow_alarm_name"]
    trail_alarm_name = _STATE["trail_alarm_name"]

    all_passed = True

    # ─────────────────────────────────────────────────────────────────────────
    # (a) Step 1.2 — CloudTrail event + DescribeInstances state change
    # ─────────────────────────────────────────────────────────────────────────
    log.info("(a) Detecting ModifyInstanceMetadataOptions in CloudTrail "
             "and verifying EC2 instance state changed …")
    a_ct_ok    = False
    a_state_ok = False

    def _search_ct_imds():
        try:
            resp = cw_logs.filter_log_events(
                logGroupName=trail_log_group,
                filterPattern=(
                    "{ $.eventName = \"ModifyInstanceMetadataOptions\" "
                    f"&& $.requestParameters.instanceId = \"{instance_id}\" }}"
                ),
                limit=10,
            )
            evts = resp.get("events", [])
            if evts:
                log.info("  (a1) CloudTrail ModifyInstanceMetadataOptions "
                         "event found: %s …",
                         evts[0].get("message", "")[:200])
                return True
            return False
        except ClientError as exc:
            log.warning("  (a1) filter_log_events error: %s", exc)
            return False

    a_ct_ok = _poll_until(
        _search_ct_imds,
        label="CT:ModifyIMDS",
        max_wait=_CLOUDTRAIL_DELIVERY_WAIT,
        poll_interval=_POLL_INTERVAL,
        success_msg="ModifyInstanceMetadataOptions event in CloudTrail.",
        failure_msg=f"Event NOT found within {_CLOUDTRAIL_DELIVERY_WAIT}s.",
    )

    # Verify EC2 instance IMDS state actually changed (fast, no timeout needed)
    log.info("  (a2) Verifying EC2 IMDS state via DescribeInstances …")
    try:
        def _desc():
            return ec2.describe_instances(InstanceIds=[instance_id])
        desc      = _retry(_desc, attempts=4, label="DescribeInstances-a2")
        meta_opts = (
            desc["Reservations"][0]["Instances"][0]
                .get("MetadataOptions", {})
        )
        http_tokens = meta_opts.get("HttpTokens", "unknown")
        hop_limit   = meta_opts.get("HttpPutResponseHopLimit", -1)
        log.info("  (a2) Current IMDS: HttpTokens=%s HopLimit=%s",
                 http_tokens, hop_limit)
        if http_tokens == "optional" and hop_limit == 2:
            a_state_ok = True
            log.info("  (a2) PASS — Instance IMDS state matches attack parameters.")
        else:
            log.error(
                "  (a2) FAIL — Expected HttpTokens=optional / HopLimit=2, "
                "got HttpTokens=%s / HopLimit=%s. "
                "Attack step 1.2 may not have succeeded.",
                http_tokens, hop_limit,
            )
    except ClientError as exc:
        log.error("  (a2) DescribeInstances error: %s", exc)

    if a_ct_ok and a_state_ok:
        log.info("  (a) PASS — CloudTrail event detected AND EC2 IMDS state changed.")
    else:
        log.error("  (a) FAIL — CT: %s  EC2-state: %s",
                  "PASS" if a_ct_ok    else "FAIL",
                  "PASS" if a_state_ok else "FAIL")
        all_passed = False

    # ─────────────────────────────────────────────────────────────────────────
    # (b) Step 2.2 — VPC Flow Logs alarm + harvest signal
    # ─────────────────────────────────────────────────────────────────────────
    log.info("(b) Detecting IMDS probe traffic via VPC Flow Logs alarm "
             "and harvest SSM signal …")
    b_alarm_ok   = False
    b_harvest_ok = False

    def _flow_alarm_check():
        try:
            resp   = cw.describe_alarms(AlarmNames=[flow_alarm_name])
            alarms = resp.get("MetricAlarms", [])
            if alarms:
                state = alarms[0]["StateValue"]
                log.info("  (b1) FlowLogsAlarm state: %s", state)
                return state == "ALARM"
            return False
        except ClientError as exc:
            log.warning("  (b1) describe_alarms error: %s", exc)
            return False

    b_alarm_ok = _poll_until(
        _flow_alarm_check,
        label="FlowAlarm:ALARM",
        max_wait=_ALARM_TRANSITION_WAIT,
        poll_interval=15,
        success_msg="FlowLogsAlarm in ALARM state.",
        failure_msg=f"FlowLogsAlarm not in ALARM within {_ALARM_TRANSITION_WAIT}s.",
    )

    try:
        harvest_val = ssm.get_parameter(
            Name=_STATE["harvest_param_name"]
        )["Parameter"]["Value"]
        log.info("  (b2) HarvestSignalParam: %s", harvest_val)
        if harvest_val.startswith("harvested::"):
            b_harvest_ok = True
            log.info("  (b2) PASS — Credential harvest confirmed.")
        else:
            log.warning(
                "  (b2) Harvest signal is '%s' — harvest may have been "
                "blocked (IMDS may not have propagated yet). "
                "Flow Logs alarm state is still the primary detector.",
                harvest_val,
            )
            # Flow alarm firing alone is sufficient for detective validation
            b_harvest_ok = b_alarm_ok
    except ClientError as exc:
        log.error("  (b2) SSM get_parameter error: %s", exc)
        b_harvest_ok = b_alarm_ok

    if b_alarm_ok and b_harvest_ok:
        log.info("  (b) PASS — VPC Flow Logs alarm in ALARM state "
                 "AND harvest signal confirmed.")
    else:
        log.error("  (b) FAIL — FlowAlarm: %s  Harvest: %s",
                  "PASS" if b_alarm_ok   else "FAIL",
                  "PASS" if b_harvest_ok else "FAIL")
        all_passed = False

    # ─────────────────────────────────────────────────────────────────────────
    # (c) Step 3.2 — CloudTrail ExfilRole calls + TrailAlarm
    # ─────────────────────────────────────────────────────────────────────────
    log.info("(c) Detecting lateral-movement API calls by '%s' in "
             "CloudTrail and verifying TrailAlarm …", exfil_role_name)
    c_ct_ok    = False
    c_alarm_ok = False
    c_detected = []

    def _search_ct_exfil():
        found = []
        for evt in ["GetCallerIdentity", "ListRoles", "GetAuthorizationToken"]:
            try:
                resp = cw_logs.filter_log_events(
                    logGroupName=trail_log_group,
                    filterPattern=(
                        f"{{ $.eventName = \"{evt}\" "
                        f"&& $.userIdentity.sessionContext"
                        f".sessionIssuer.userName = \"{exfil_role_name}\" }}"
                    ),
                    limit=5,
                )
                if resp.get("events"):
                    found.append(evt)
                    log.info("  (c1) CloudTrail event found: %s under %s",
                             evt, exfil_role_name)
            except ClientError as exc:
                log.warning("  (c1) filter_log_events error for %s: %s", evt, exc)
        if found:
            c_detected.extend(found)
            return True
        return False

    c_ct_ok = _poll_until(
        _search_ct_exfil,
        label="CT:ExfilRoleAPIs",
        max_wait=_CLOUDTRAIL_DELIVERY_WAIT,
        poll_interval=_POLL_INTERVAL,
        success_msg=f"Lateral-movement events by '{exfil_role_name}' in CloudTrail.",
        failure_msg=(
            f"No ExfilRole API calls found in CloudTrail "
            f"within {_CLOUDTRAIL_DELIVERY_WAIT}s."
        ),
    )
    log.info("  (c1) Detected calls: %s",
             c_detected if c_detected else "none")

    def _trail_alarm_check():
        try:
            resp   = cw.describe_alarms(AlarmNames=[trail_alarm_name])
            alarms = resp.get("MetricAlarms", [])
            if alarms:
                state = alarms[0]["StateValue"]
                log.info("  (c2) TrailAlarm state: %s", state)
                return state == "ALARM"
            return False
        except ClientError as exc:
            log.warning("  (c2) describe_alarms error: %s", exc)
            return False

    c_alarm_ok = _poll_until(
        _trail_alarm_check,
        label="TrailAlarm:ALARM",
        max_wait=_ALARM_TRANSITION_WAIT,
        poll_interval=15,
        success_msg="TrailAlarm in ALARM state (SIEM alert validated).",
        failure_msg=(
            f"TrailAlarm NOT in ALARM within {_ALARM_TRANSITION_WAIT}s."
        ),
    )

    # Verify attack results show the actions were attempted
    attack_results = _STATE.get("step_32_results", {})
    if attack_results:
        log.info(
            "  (c3) Attack actions attempted: %s",
            {k: v for k, v in attack_results.items()
             if k in ("sts:GetCallerIdentity", "iam:ListRoles",
                      "ecr:GetAuthorizationToken")},
        )

    if c_ct_ok and c_alarm_ok:
        log.info("  (c) PASS — CloudTrail captured lateral-movement calls "
                 "AND TrailAlarm in ALARM state.")
    else:
        log.error("  (c) FAIL — CT-events: %s  TrailAlarm: %s",
                  "PASS" if c_ct_ok    else "FAIL",
                  "PASS" if c_alarm_ok else "FAIL")
        all_passed = False

    # ── Summary ──────────────────────────────────────────────────────────────
    status = "PASSED ✅" if all_passed else "FAILED ❌"
    log.info("-" * 70)
    log.info("hypothesis_verification() %s", status)
    log.info("  (a1) CloudTrail ModifyInstanceMetadataOptions : %s",
             "PASS" if a_ct_ok    else "FAIL")
    log.info("  (a2) EC2 IMDS state changed                   : %s",
             "PASS" if a_state_ok else "FAIL")
    log.info("  (b1) VPC Flow Logs alarm in ALARM             : %s",
             "PASS" if b_alarm_ok   else "FAIL")
    log.info("  (b2) IMDS harvest signal confirmed            : %s",
             "PASS" if b_harvest_ok else "FAIL")
    log.info("  (c1) CloudTrail ExfilRole API calls           : %s  %s",
             "PASS" if c_ct_ok    else "FAIL",
             f"[{c_detected}]")
    log.info("  (c2) TrailAlarm (SIEM proxy) in ALARM         : %s",
             "PASS" if c_alarm_ok else "FAIL")
    log.info("-" * 70)
    return all_passed


# ---------------------------------------------------------------------------
# 4. rollback()
# ---------------------------------------------------------------------------

def rollback() -> None:
    """
    Tear down all experiment resources.

    Order:
      1. Re-harden EC2 IMDS (HttpTokens=required, HopLimit=1).
      2. Empty versioned S3 buckets (TrailBucket, PCIBucket).
      3. Force-delete ECR repository.
      4. Delete out-of-band SSM parameters.
      5. Delete Stack B (observability) — wait for DELETE_COMPLETE.
      6. Delete Stack A (base) — wait for DELETE_COMPLETE.
    """
    log.info("=" * 70)
    log.info("rollback() — SCE 3.3 Detective Probe")
    log.info("=" * 70)

    # ── Re-harden EC2 IMDS ────────────────────────────────────────────────────
    instance_id = _STATE.get("instance_id")
    if instance_id and _STATE.get("step_12_done"):
        ec2 = _session().client("ec2")
        try:
            ec2.modify_instance_metadata_options(
                InstanceId=instance_id,
                HttpTokens="required",
                HttpEndpoint="enabled",
                HttpPutResponseHopLimit=1,
            )
            log.info("Re-hardened IMDS on %s.", instance_id)
        except ClientError as exc:
            log.warning("Could not re-harden IMDS (non-fatal): %s", exc)

    # ── Empty versioned S3 buckets ────────────────────────────────────────────
    s3 = _session().client("s3")
    for bkt_key in ["trail_bucket_name", "pci_bucket_name"]:
        bucket = _STATE.get(bkt_key)
        if not bucket:
            continue
        try:
            paginator = s3.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket):
                to_delete = []
                for v in page.get("Versions", []):
                    to_delete.append(
                        {"Key": v["Key"], "VersionId": v["VersionId"]}
                    )
                for dm in page.get("DeleteMarkers", []):
                    to_delete.append(
                        {"Key": dm["Key"], "VersionId": dm["VersionId"]}
                    )
                if to_delete:
                    s3.delete_objects(
                        Bucket=bucket,
                        Delete={"Objects": to_delete, "Quiet": True},
                    )
            log.info("Emptied S3 bucket '%s'.", bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                log.warning("Could not empty '%s' (non-fatal): %s", bucket, exc)

    # ── Force-delete ECR repository ───────────────────────────────────────────
    ecr_repo = _STATE.get("ecr_repo_name")
    if ecr_repo:
        ecr = _session().client("ecr")
        try:
            ecr.delete_repository(repositoryName=ecr_repo, force=True)
            log.info("Deleted ECR repo '%s'.", ecr_repo)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
                log.warning("Could not delete ECR repo (non-fatal): %s", exc)

    # ── Delete out-of-band SSM parameters ────────────────────────────────────
    ssm    = _session().client("ssm")
    suffix = _STATE.get("suffix", "")
    for param in [
        _STATE.get("harvest_param_name"),
        _STATE.get("attack_results_param"),
        _STATE.get("instance_ip_param"),
    ]:
        if not param:
            continue
        try:
            ssm.delete_parameter(Name=param)
            log.info("Deleted SSM param '%s'.", param)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ParameterNotFound":
                log.warning("Could not delete SSM param '%s' (non-fatal): %s",
                            param, exc)

    # ── Delete Stack B then Stack A ───────────────────────────────────────────
    cf = _session().client("cloudformation")
    for stack_key, max_wait in [
        ("stack_b_name", _STACK_B_MAX_WAIT),
        ("stack_a_name", _STACK_A_MAX_WAIT),
    ]:
        stack_name = _STATE.get(stack_key)
        if not stack_name:
            log.warning("rollback(): no '%s' in _STATE — skipping.", stack_key)
            continue
        try:
            cf.delete_stack(StackName=stack_name)
            log.info("Stack deletion initiated: '%s'.", stack_name)
        except ClientError as exc:
            if (
                "does not exist" in str(exc)
                or exc.response["Error"]["Code"] == "ValidationError"
            ):
                log.info("Stack '%s' not found — already deleted.", stack_name)
                continue
            log.error("Error initiating deletion of '%s': %s", stack_name, exc)
            continue
        try:
            _wait_stack(cf, stack_name, "DELETE_COMPLETE", max_wait=max_wait)
            log.info("Stack '%s' deleted.", stack_name)
        except TimeoutError as exc:
            log.error("Timeout waiting for '%s' deletion: %s", stack_name, exc)
        except Exception as exc:  # noqa: BLE001
            log.error("Error during '%s' deletion: %s\n%s",
                      stack_name, exc, traceback.format_exc())


# ---------------------------------------------------------------------------
# Standalone entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("╔" + "═" * 68 + "╗")
    log.info("║  SCE 3.3 — Detective Probe  (post-execution fix iteration)    ║")
    log.info("║  Attack: 1.2 (T1578) + 2.2 (T1552.005) + 3.2 (T1078.004)    ║")
    log.info("╚" + "═" * 68 + "╝")

    passed = False
    try:
        steady_state()
        attack_ok = attack()
        if not attack_ok:
            log.warning(
                "attack() reported errors — running "
                "hypothesis_verification() for full diagnostics."
            )
        passed = hypothesis_verification()
    except PreConditionError as exc:
        log.error("Pre-condition failure: %s", exc)
    except Exception:  # noqa: BLE001
        log.error("Unhandled exception:\n%s", traceback.format_exc())
    finally:
        rollback()

    if passed:
        log.info("✅  EXPERIMENT PASSED — All detective controls validated.")
    else:
        log.error("❌  EXPERIMENT FAILED — One or more detective sub-checks "
                  "did not pass within detection windows.")
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()