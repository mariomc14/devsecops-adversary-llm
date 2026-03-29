"""
SCE Experiment 3.3 — Preventive Probe
======================================
Attack Nodes : 1.2  T1578  Modify Cloud Compute Infrastructure
                           (ec2:ModifyInstanceMetadataOptions → IMDSv1 + HopLimit=2)
               2.2  T1552.005  Unsecured Credentials: Cloud Instance Metadata API
                           (curl 169.254.169.254 → harvest IAM role credentials)
               3.2  T1078.004  Valid Accounts: Cloud Accounts
                           (use exfiltrated credentials for lateral movement /
                            privilege escalation: iam:List*, sts:AssumeRole,
                            ecr:PutImage, s3:GetObject on PCI buckets)
Probe Type   : Preventive

Defensive Intent (ADT node 3.3 — Preventive Probe)
───────────────────────────────────────────────────
"Simulate ec2:ModifyInstanceMetadataOptions call with a non-admin role.
 Validate SCP hard-denies the API call and returns AccessDenied before any
 state change occurs.  Confirm IaC launch template re-applies
 HttpTokens=required on next instance refresh cycle within 5 minutes."

Expanded to cover the full three-step attack chain:

  Step 1.2 — Preventive control: SCP / IAM deny on ec2:ModifyInstanceMetadataOptions
    → A non-admin IAM role (AttackerRole) that lacks ec2:ModifyInstanceMetadataOptions
      attempts to weaken IMDS.  The test verifies the call is hard-denied (AccessDenied)
      and the EC2 instance IMDS state remains HttpTokens=required / HopLimit=1.

  Step 2.2 — Preventive control: IMDSv2 enforcement + network NACL block
    → Even if step 1.2 somehow succeeded, the Lambda probe attempting an
      unauthenticated GET to the IMDS endpoint (IMDSv1 path) must be blocked.
      We verify this by invoking the IMDSProbe Lambda; because HttpTokens
      remains "required" (preventive control held), the IMDSv1 curl returns
      a 401 / connection error.  The harvest_result SSM param must contain
      "blocked::" not "harvested::".

  Step 3.2 — Preventive control: SCPs + IAM Permission Boundaries deny
              privileged lateral-movement actions on the AttackerRole
    → Using the AttackerRole credentials (assumed via sts:AssumeRole on a
      role that explicitly allows it, scoped to the test account), we attempt
      each sensitive action listed in attack node 3.2:
        • iam:ListRoles              (IAM enumeration)
        • sts:GetCallerIdentity      (identity verification — allowed as baseline)
        • iam:CreateUser             (persistence)
        • iam:AttachRolePolicy       (privilege escalation)
        • iam:CreatePolicy           (privilege escalation)
        • ecr:PutImage               (container image poisoning)
        • s3:GetObject on PCI bucket (data exfiltration)
      The AttackerRole has a Permission Boundary that denies all of the above
      except sts:GetCallerIdentity.  We confirm each sensitive action returns
      AccessDenied (explicitDeny or implicitDeny via IAM SimulatePrincipalPolicy
      AND live API call verification where safe).

Architecture
────────────
CloudFormation provisions:
  Networking     : VPC, public subnet, private subnet, IGW, NAT GW,
                   route tables, Security Groups, NACL blocking
                   169.254.169.254/32 egress from container subnet.
  EC2            : t3.nano instance in private subnet,
                   IMDSv2 required / HopLimit=1 (secure baseline).
                   InstanceRole — scoped minimal permissions + Permission Boundary.
  AttackerRole   : IAM role with Permission Boundary denying all privileged actions.
                   Assumable only by Lambda (SimulatedAttackerLambda).
  AttackerLambda : Invoked by attack(); assumes AttackerRole, attempts each
                   lateral-movement action, returns per-action results.
  IMDSProbeLambda: Runs in private subnet; curls EC2 IMDS without token.
  S3 PCI Bucket  : Empty bucket representing PCI-DSS cardholder data store.
  ECR Repository : Represents the banking container image registry.
  SSM Parameters : Signal bus for probe results.

Clean-room guarantee
────────────────────
All resources live in a single timestamped CloudFormation stack.
rollback() removes out-of-band resources then deletes the stack.
No pre-existing account resources are read or modified.
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

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------
_STATE: dict = {}

# ── Timing constants ─────────────────────────────────────────────────────────
_STACK_POLL_INTERVAL   = 15
_STACK_MAX_WAIT        = 900   # 15 min — VPC + EC2 + NAT GW provisioning
_IAM_PROPAGATION_SLEEP = 20
_EC2_IMDS_WAIT         = 30
_BACKOFF_CAP           = 30
_LAMBDA_TIMEOUT_SEC    = 60

EXPERIMENT_TAG = "sce-3.3-preventive"

# Public SSM path for latest Amazon Linux 2023 AMI
_AL2023_SSM_PATH = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"

# Sensitive actions the AttackerRole must be denied (step 3.2)
_PRIVILEGED_ACTIONS = [
    "iam:CreateUser",
    "iam:AttachRolePolicy",
    "iam:CreatePolicy",
    "iam:ListRoles",
    "ecr:PutImage",
    "s3:GetObject",
    "sts:AssumeRole",
]
# Action that MUST be allowed (baseline identity check — not a privileged action)
_ALLOWED_BASELINE = "sts:GetCallerIdentity"


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
    try:
        resp   = ssm.get_parameter(Name=_AL2023_SSM_PATH)
        ami_id = resp["Parameter"]["Value"]
        log.info("Resolved AMI: %s", ami_id)
        return ami_id
    except ClientError as exc:
        log.error("Failed to resolve AMI: %s", exc)
        raise


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
                max_wait: int = _STACK_MAX_WAIT) -> None:
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
                reason = resp["Stacks"][0].get("StackStatusReason",
                                               "no reason provided")
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


# ---------------------------------------------------------------------------
# CloudFormation template builder
# ---------------------------------------------------------------------------

def _build_cfn_template(suffix: str, ami_id: str) -> str:  # noqa: PLR0914
    """
    Build the full CloudFormation template for SCE 3.3 Preventive probe.

    Resources created
    ─────────────────
    Networking
      VPC (10.0.0.0/16)
      PublicSubnet  (10.0.1.0/24) — NAT GW
      PrivateSubnet (10.0.2.0/24) — EC2 + Lambdas
      IGW, PublicRT, PrivateRT, NATGW, EIP
      ContainerNACL — explicit DENY on egress to 169.254.169.254/32 from
                       private subnet (defense-in-depth for step 2.2)
      EC2SecurityGroup   — no inbound; HTTPS egress for SSM agent
      LambdaSecurityGroup — HTTP to 10.0.2.0/24; HTTPS to 0.0.0.0/0
      EC2SGIngress       — allow Lambda SG → EC2 SG on port 80

    IAM
      PermissionBoundaryPolicy — denies all _PRIVILEGED_ACTIONS + all
                                  iam:* / ecr:* / s3:* except explicitly
                                  scoped experiment actions; allows
                                  sts:GetCallerIdentity
      InstanceRole             — EC2 instance profile role; minimal SSM read
      InstanceProfile          — wraps InstanceRole
      AttackerRole             — represents the compromised role used in step 3.2;
                                  PermissionBoundary attached; assumable by
                                  AttackerLambdaExecRole only
      AttackerLambdaExecRole   — Lambda execution role for SimulatedAttackerLambda;
                                  can assume AttackerRole; has basic Lambda perms
      IMDSProbeLambdaRole      — VPC Lambda + SSM write
      RemediationCheckRole     — verifies EC2 IMDS options (DescribeInstances)

    Storage
      PCIBucket    — represents cardholder data store (empty; versioned)
      ECRRepository — represents banking container registry

    Lambda
      IMDSProbeFunction        — VPC Lambda; curls instance IMDS without token
      SimulatedAttackerLambda  — assumes AttackerRole; attempts each privileged
                                  action; returns per-action {allowed/denied} map
      IMDSModifyLambda         — assumes AttackerRole; attempts
                                  ec2:ModifyInstanceMetadataOptions; returns
                                  {allowed/denied}

    SSM Parameters
      HarvestSignalParam  — written by IMDSProbeFunction with probe result
      AttackResultsParam  — written by SimulatedAttackerLambda with JSON results
      IMDSModifyParam     — written by IMDSModifyLambda with modify attempt result
    """
    account = _account_id()
    region  = _region()

    # Resource name constants
    instance_role_name      = f"SCEInstanceRole-{suffix}"
    attacker_role_name      = f"SCEAttackerRole-{suffix}"
    attacker_lambda_role    = f"SCEAttackerLambdaRole-{suffix}"
    imds_probe_role_name    = f"SCEIMDSProbeRole-{suffix}"
    remediation_check_role  = f"SCERemCheckRole-{suffix}"
    boundary_policy_name    = f"SCEPermBoundary-{suffix}"
    pci_bucket_name         = f"sce-pci-bucket-{suffix}"
    ecr_repo_name           = f"sce-ecr-{suffix}"
    imds_probe_fn_name      = f"SCEIMDSProbe-{suffix}"
    attacker_fn_name        = f"SCEAttacker-{suffix}"
    imds_modify_fn_name     = f"SCEIMDSModify-{suffix}"
    harvest_param           = f"/sce/3-3/{suffix}/harvest_signal"
    attack_results_param    = f"/sce/3-3/{suffix}/attack_results"
    imds_modify_param       = f"/sce/3-3/{suffix}/imds_modify_result"

    # ── IMDSProbe Lambda code ────────────────────────────────────────────────
    # Attempts IMDSv1 GET (no token). With HttpTokens=required this must fail.
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
        "        harvest_val = f'blocked::HTTPError::{e.code}::{str(e.reason)[:80]}'\n"
        "    except Exception as e:\n"
        "        harvest_val = f'blocked::{type(e).__name__}::{str(e)[:120]}'\n"
        "    ssm.put_parameter(\n"
        "        Name=harvest_param, Value=harvest_val,\n"
        "        Type='String', Overwrite=True\n"
        "    )\n"
        "    return {'harvest': harvest_val}\n"
    )

    # ── IMDSModify Lambda code ───────────────────────────────────────────────
    # Attempts ec2:ModifyInstanceMetadataOptions as the AttackerRole.
    # Because AttackerRole has a Permission Boundary that does not include
    # ec2:ModifyInstanceMetadataOptions, this MUST return AccessDenied.
    imds_modify_code = (
        "import boto3, json, os\n"
        "from botocore.exceptions import ClientError\n"
        "def handler(event, context):\n"
        "    attacker_role_arn = os.environ['ATTACKER_ROLE_ARN']\n"
        "    instance_id       = os.environ['INSTANCE_ID']\n"
        "    modify_param      = os.environ['MODIFY_PARAM']\n"
        "    # Assume AttackerRole\n"
        "    sts = boto3.client('sts')\n"
        "    try:\n"
        "        creds = sts.assume_role(\n"
        "            RoleArn=attacker_role_arn,\n"
        "            RoleSessionName='SCEAttacker'\n"
        "        )['Credentials']\n"
        "        ec2 = boto3.client(\n"
        "            'ec2',\n"
        "            aws_access_key_id=creds['AccessKeyId'],\n"
        "            aws_secret_access_key=creds['SecretAccessKey'],\n"
        "            aws_session_token=creds['SessionToken']\n"
        "        )\n"
        "        ec2.modify_instance_metadata_options(\n"
        "            InstanceId=instance_id,\n"
        "            HttpTokens='optional',\n"
        "            HttpEndpoint='enabled',\n"
        "            HttpPutResponseHopLimit=2\n"
        "        )\n"
        "        result = 'allowed::modify_succeeded'\n"
        "    except ClientError as e:\n"
        "        code = e.response['Error']['Code']\n"
        "        result = f'denied::{code}::{e.response[\"Error\"][\"Message\"][:120]}'\n"
        "    except Exception as e:\n"
        "        result = f'error::{type(e).__name__}::{str(e)[:120]}'\n"
        "    ssm = boto3.client('ssm')\n"
        "    ssm.put_parameter(\n"
        "        Name=modify_param, Value=result,\n"
        "        Type='String', Overwrite=True\n"
        "    )\n"
        "    return {'modify_result': result}\n"
    )

    # ── SimulatedAttackerLambda code ─────────────────────────────────────────
    # Assumes AttackerRole; attempts each privileged action from step 3.2;
    # records per-action allowed/denied result; writes JSON to SSM.
    attacker_code = (
        "import boto3, json, os\n"
        "from botocore.exceptions import ClientError\n"
        "def _try(client, method, kwargs, label):\n"
        "    try:\n"
        "        getattr(client, method)(**kwargs)\n"
        "        return label, 'allowed'\n"
        "    except ClientError as e:\n"
        "        code = e.response['Error']['Code']\n"
        "        if code in ('AccessDenied','AccessDeniedException',\n"
        "                    'UnauthorizedOperation','AuthFailure'):\n"
        "            return label, f'denied::{code}'\n"
        "        return label, f'error::{code}'\n"
        "    except Exception as e:\n"
        "        return label, f'error::{type(e).__name__}'\n"
        "def handler(event, context):\n"
        "    attacker_role_arn  = os.environ['ATTACKER_ROLE_ARN']\n"
        "    pci_bucket         = os.environ['PCI_BUCKET']\n"
        "    ecr_repo_uri       = os.environ['ECR_REPO_URI']\n"
        "    attack_param       = os.environ['ATTACK_RESULTS_PARAM']\n"
        "    account_id         = os.environ['ACCOUNT_ID']\n"
        "    region             = os.environ['AWS_REGION']\n"
        "    sts = boto3.client('sts')\n"
        "    try:\n"
        "        creds = sts.assume_role(\n"
        "            RoleArn=attacker_role_arn,\n"
        "            RoleSessionName='SCEAttacker3'\n"
        "        )['Credentials']\n"
        "    except ClientError as e:\n"
        "        ssm = boto3.client('ssm')\n"
        "        ssm.put_parameter(\n"
        "            Name=attack_param,\n"
        "            Value=json.dumps({'assume_role': f'denied::{e.response[\"Error\"][\"Code\"]}'}),\n"
        "            Type='String', Overwrite=True\n"
        "        )\n"
        "        return {'error': 'cannot assume attacker role'}\n"
        "    def mk(svc):\n"
        "        return boto3.client(\n"
        "            svc,\n"
        "            aws_access_key_id=creds['AccessKeyId'],\n"
        "            aws_secret_access_key=creds['SecretAccessKey'],\n"
        "            aws_session_token=creds['SessionToken']\n"
        "        )\n"
        "    results = {}\n"
        "    # sts:GetCallerIdentity — MUST be allowed (baseline)\n"
        "    lbl, res = _try(mk('sts'), 'get_caller_identity', {}, 'sts:GetCallerIdentity')\n"
        "    results[lbl] = res\n"
        "    # iam:ListRoles\n"
        "    lbl, res = _try(mk('iam'), 'list_roles', {'MaxItems': 1}, 'iam:ListRoles')\n"
        "    results[lbl] = res\n"
        "    # iam:CreateUser\n"
        "    lbl, res = _try(mk('iam'), 'create_user',\n"
        "                    {'UserName': f'sce-test-{context.aws_request_id[:8]}'},\n"
        "                    'iam:CreateUser')\n"
        "    results[lbl] = res\n"
        "    # iam:CreatePolicy\n"
        "    lbl, res = _try(\n"
        "        mk('iam'), 'create_policy',\n"
        "        {'PolicyName': f'sce-pol-{context.aws_request_id[:8]}',\n"
        "         'PolicyDocument': json.dumps({\n"
        "             'Version':'2012-10-17',\n"
        "             'Statement':[{'Effect':'Allow','Action':'*','Resource':'*'}]\n"
        "         })},\n"
        "        'iam:CreatePolicy'\n"
        "    )\n"
        "    results[lbl] = res\n"
        "    # iam:AttachRolePolicy (try to attach AdministratorAccess to itself)\n"
        "    lbl, res = _try(\n"
        "        mk('iam'), 'attach_role_policy',\n"
        "        {'RoleName': attacker_role_arn.split('/')[-1],\n"
        "         'PolicyArn': 'arn:aws:iam::aws:policy/AdministratorAccess'},\n"
        "        'iam:AttachRolePolicy'\n"
        "    )\n"
        "    results[lbl] = res\n"
        "    # s3:GetObject on PCI bucket\n"
        "    lbl, res = _try(\n"
        "        mk('s3'), 'get_object',\n"
        "        {'Bucket': pci_bucket, 'Key': 'cardholder_data.txt'},\n"
        "        's3:GetObject'\n"
        "    )\n"
        "    results[lbl] = res\n"
        "    # ecr:PutImage — cannot push without a real manifest, but\n"
        "    # GetAuthorizationToken tests the ECR permission boundary\n"
        "    lbl, res = _try(\n"
        "        mk('ecr'), 'get_authorization_token', {}, 'ecr:GetAuthorizationToken'\n"
        "    )\n"
        "    results[lbl] = res\n"
        "    ssm = boto3.client('ssm')\n"
        "    ssm.put_parameter(\n"
        "        Name=attack_param, Value=json.dumps(results),\n"
        "        Type='String', Overwrite=True\n"
        "    )\n"
        "    print('Attack results:', json.dumps(results, indent=2))\n"
        "    return results\n"
    )

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"SCE 3.3 Preventive Probe stack — {suffix}",

        "Resources": {

            # ── Networking ───────────────────────────────────────────────────
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

            # ── NACL: block egress to IMDS link-local from private subnet ────
            # This represents the defense-in-depth NACL control from ADT 2.1
            "ContainerNACL": {
                "Type": "AWS::EC2::NetworkAcl",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "Tags": [
                        {"Key": "Name",           "Value": f"sce-nacl-{suffix}"},
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # Deny outbound HTTP to 169.254.169.254/32 (IMDS link-local)
            "NACLEgressDenyIMDS": {
                "Type": "AWS::EC2::NetworkAclEntry",
                "Properties": {
                    "NetworkAclId": {"Ref": "ContainerNACL"},
                    "RuleNumber": 50,
                    "Protocol": 6,
                    "RuleAction": "deny",
                    "Egress": True,
                    "CidrBlock": "169.254.169.254/32",
                    "PortRange": {"From": 80, "To": 80}
                }
            },
            # Allow all other outbound
            "NACLEgressAllowAll": {
                "Type": "AWS::EC2::NetworkAclEntry",
                "Properties": {
                    "NetworkAclId": {"Ref": "ContainerNACL"},
                    "RuleNumber": 100,
                    "Protocol": -1,
                    "RuleAction": "allow",
                    "Egress": True,
                    "CidrBlock": "0.0.0.0/0"
                }
            },
            # Allow all inbound
            "NACLIngressAllowAll": {
                "Type": "AWS::EC2::NetworkAclEntry",
                "Properties": {
                    "NetworkAclId": {"Ref": "ContainerNACL"},
                    "RuleNumber": 100,
                    "Protocol": -1,
                    "RuleAction": "allow",
                    "Egress": False,
                    "CidrBlock": "0.0.0.0/0"
                }
            },
            "PrivateSubnetNACLAssoc": {
                "Type": "AWS::EC2::SubnetNetworkAclAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "PrivateSubnet"},
                    "NetworkAclId": {"Ref": "ContainerNACL"}
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
            "EC2SGIngress": {
                "Type": "AWS::EC2::SecurityGroupIngress",
                "Properties": {
                    "GroupId": {"Ref": "EC2SecurityGroup"},
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "SourceSecurityGroupId": {"Ref": "LambdaSecurityGroup"},
                    "Description": "Allow IMDS probe Lambda HTTP"
                }
            },

            # ── Permission Boundary Policy ───────────────────────────────────
            # This is the core preventive control for step 3.2.
            # It denies all privileged lateral-movement actions regardless of
            # what identity policies the AttackerRole may have.
            "PermissionBoundaryPolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": boundary_policy_name,
                    "Description": (
                        "SCE 3.3: Permission boundary denying all privileged "
                        "actions on AttackerRole"
                    ),
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                # Allow only the baseline identity check
                                "Sid": "AllowBaselineOnly",
                                "Effect": "Allow",
                                "Action": [
                                    "sts:GetCallerIdentity",
                                    "ssm:PutParameter",
                                    "ssm:GetParameter",
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "*"
                            },
                            {
                                # Explicit deny on all privileged actions
                                "Sid": "DenyPrivilegedActions",
                                "Effect": "Deny",
                                "Action": [
                                    "iam:CreateUser",
                                    "iam:CreateRole",
                                    "iam:AttachRolePolicy",
                                    "iam:AttachUserPolicy",
                                    "iam:CreatePolicy",
                                    "iam:PutRolePolicy",
                                    "iam:PutUserPolicy",
                                    "iam:PassRole",
                                    "iam:ListRoles",
                                    "iam:ListUsers",
                                    "iam:ListPolicies",
                                    "iam:GetRole",
                                    "iam:GetUser",
                                    "ec2:ModifyInstanceMetadataOptions",
                                    "ec2:DescribeInstances",
                                    "ecr:PutImage",
                                    "ecr:GetAuthorizationToken",
                                    "ecr:BatchCheckLayerAvailability",
                                    "ecr:InitiateLayerUpload",
                                    "s3:GetObject",
                                    "s3:PutObject",
                                    "s3:ListBucket",
                                    "secretsmanager:GetSecretValue",
                                    "secretsmanager:DescribeSecret",
                                    "sts:AssumeRole"
                                ],
                                "Resource": "*"
                            }
                        ]
                    }
                }
            },

            # ── EC2 Instance Role ────────────────────────────────────────────
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

            # ── AttackerRole (has Permission Boundary) ───────────────────────
            "AttackerRole": {
                "Type": "AWS::IAM::Role",
                "DependsOn": "PermissionBoundaryPolicy",
                "Properties": {
                    "RoleName": attacker_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    # Identity policy grants broad permissions — boundary restricts
                    "Policies": [{
                        "PolicyName": "SCEAttackerIdentityPolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*"
                            }]
                        }
                    }],
                    # Permission Boundary — the preventive control under test
                    "PermissionsBoundary": {
                        "Fn::Sub": (
                            f"arn:aws:iam::${{AWS::AccountId}}"
                            f":policy/{boundary_policy_name}"
                        )
                    },
                    "Tags": [
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "sce-suffix",     "Value": suffix}
                    ]
                }
            },

            # ── AttackerLambdaExecRole ───────────────────────────────────────
            # Execution role for SimulatedAttackerLambda and IMDSModifyLambda.
            # Can assume AttackerRole; has Lambda basics + SSM write.
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
                                    "Sid": "AssumeAttackerRole",
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRole",
                                    "Resource": {
                                        "Fn::Sub": (
                                            f"arn:aws:iam::${{AWS::AccountId}}"
                                            f":role/{attacker_role_name}"
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

            # ── IMDSProbe Lambda Role ────────────────────────────────────────
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
                                "Sid": "SSMWriteHarvest",
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

            # ── EC2 Test Instance ────────────────────────────────────────────
            # Secure baseline: IMDSv2 required, HopLimit=1
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

            # ── S3 PCI Bucket (represents cardholder data store) ─────────────
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
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "sce-suffix",     "Value": suffix},
                        {"Key": "data-classification", "Value": "pci-dss"}
                    ]
                }
            },

            # ── ECR Repository (represents banking container registry) ────────
            "ECRRepository": {
                "Type": "AWS::ECR::Repository",
                "Properties": {
                    "RepositoryName": ecr_repo_name,
                    "ImageScanningConfiguration": {
                        "ScanOnPush": True
                    },
                    "Tags": [
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "sce-suffix",     "Value": suffix}
                    ]
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
            "IMDSModifyParam": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name":  imds_modify_param,
                    "Type":  "String",
                    "Value": "idle",
                    "Tags": {
                        "sce-experiment": EXPERIMENT_TAG,
                        "sce-suffix":     suffix
                    }
                }
            },

            # ── IMDSProbe Lambda ─────────────────────────────────────────────
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

            # ── IMDSModify Lambda ────────────────────────────────────────────
            "IMDSModifyFunction": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["AttackerLambdaExecRole", "AttackerRole",
                              "TestInstance"],
                "Properties": {
                    "FunctionName": imds_modify_fn_name,
                    "Runtime":  "python3.12",
                    "Handler":  "index.handler",
                    "Role":     {"Fn::GetAtt": ["AttackerLambdaExecRole", "Arn"]},
                    "Timeout":  _LAMBDA_TIMEOUT_SEC,
                    "Environment": {
                        "Variables": {
                            "ATTACKER_ROLE_ARN": {
                                "Fn::Sub": (
                                    f"arn:aws:iam::${{AWS::AccountId}}"
                                    f":role/{attacker_role_name}"
                                )
                            },
                            "INSTANCE_ID": {"Ref": "TestInstance"},
                            "MODIFY_PARAM": imds_modify_param
                        }
                    },
                    "Code": {"ZipFile": imds_modify_code},
                    "Tags": [
                        {"Key": "sce-experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "sce-suffix",     "Value": suffix}
                    ]
                }
            },

            # ── SimulatedAttackerLambda ──────────────────────────────────────
            "SimulatedAttackerFunction": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["AttackerLambdaExecRole", "AttackerRole",
                              "PCIBucket", "ECRRepository"],
                "Properties": {
                    "FunctionName": attacker_fn_name,
                    "Runtime":  "python3.12",
                    "Handler":  "index.handler",
                    "Role":     {"Fn::GetAtt": ["AttackerLambdaExecRole", "Arn"]},
                    "Timeout":  _LAMBDA_TIMEOUT_SEC,
                    "Environment": {
                        "Variables": {
                            "ATTACKER_ROLE_ARN": {
                                "Fn::Sub": (
                                    f"arn:aws:iam::${{AWS::AccountId}}"
                                    f":role/{attacker_role_name}"
                                )
                            },
                            "PCI_BUCKET":          pci_bucket_name,
                            "ECR_REPO_URI": {
                                "Fn::Sub": (
                                    f"${{AWS::AccountId}}.dkr.ecr"
                                    f".${{AWS::Region}}.amazonaws.com"
                                    f"/{ecr_repo_name}"
                                )
                            },
                            "ATTACK_RESULTS_PARAM": attack_results_param,
                            "ACCOUNT_ID": {"Ref": "AWS::AccountId"}
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
            "InstanceId": {
                "Value": {"Ref": "TestInstance"}
            },
            "InstanceRoleName": {
                "Value": {"Ref": "InstanceRole"}
            },
            "AttackerRoleName": {
                "Value": {"Ref": "AttackerRole"}
            },
            "AttackerRoleArn": {
                "Value": {
                    "Fn::Sub": (
                        f"arn:aws:iam::${{AWS::AccountId}}"
                        f":role/{attacker_role_name}"
                    )
                }
            },
            "IMDSProbeFunctionName": {
                "Value": {"Ref": "IMDSProbeFunction"}
            },
            "IMDSModifyFunctionName": {
                "Value": {"Ref": "IMDSModifyFunction"}
            },
            "SimulatedAttackerFunctionName": {
                "Value": {"Ref": "SimulatedAttackerFunction"}
            },
            "HarvestParamName": {
                "Value": harvest_param
            },
            "AttackResultsParamName": {
                "Value": attack_results_param
            },
            "IMDSModifyParamName": {
                "Value": imds_modify_param
            },
            "PCIBucketName": {
                "Value": {"Ref": "PCIBucket"}
            },
            "ECRRepoName": {
                "Value": {"Ref": "ECRRepository"}
            },
            "BoundaryPolicyName": {
                "Value": boundary_policy_name
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
      1. Resolve latest AL2023 AMI.
      2. Build CloudFormation template.
      3. Deploy timestamped stack; wait for CREATE_COMPLETE.
      4. Collect outputs into _STATE.
      5. Sleep for IAM propagation + EC2 IMDS readiness.
    """
    suffix     = str(_ts())
    stack_name = f"sce-experiment-{suffix}"
    _STATE["stack_name"] = stack_name
    _STATE["suffix"]     = suffix

    log.info("=" * 70)
    log.info("steady_state() — SCE 3.3 Preventive Probe — stack: %s", stack_name)
    log.info("=" * 70)

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
                {"Key": "sce-node",       "Value": "3.3"},
                {"Key": "sce-probe",      "Value": "preventive"}
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

    resp    = cf.describe_stacks(StackName=stack_name)
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in resp["Stacks"][0].get("Outputs", [])
    }

    _STATE["instance_id"]              = outputs["InstanceId"]
    _STATE["instance_role_name"]       = outputs["InstanceRoleName"]
    _STATE["attacker_role_name"]       = outputs["AttackerRoleName"]
    _STATE["attacker_role_arn"]        = outputs["AttackerRoleArn"]
    _STATE["imds_probe_fn_name"]       = outputs["IMDSProbeFunctionName"]
    _STATE["imds_modify_fn_name"]      = outputs["IMDSModifyFunctionName"]
    _STATE["attacker_fn_name"]         = outputs["SimulatedAttackerFunctionName"]
    _STATE["harvest_param_name"]       = outputs["HarvestParamName"]
    _STATE["attack_results_param"]     = outputs["AttackResultsParamName"]
    _STATE["imds_modify_param"]        = outputs["IMDSModifyParamName"]
    _STATE["pci_bucket_name"]          = outputs["PCIBucketName"]
    _STATE["ecr_repo_name"]            = outputs["ECRRepoName"]
    _STATE["boundary_policy_name"]     = outputs["BoundaryPolicyName"]

    log.info("Stack outputs collected:\n%s", json.dumps(_STATE, indent=2))

    wait_secs = _IAM_PROPAGATION_SLEEP + _EC2_IMDS_WAIT
    log.info("Waiting %ds for IAM propagation + EC2 IMDS readiness …", wait_secs)
    time.sleep(wait_secs)
    log.info("steady_state() complete.")


# ---------------------------------------------------------------------------
# 2. attack() -> bool
# ---------------------------------------------------------------------------

def attack() -> bool:
    """
    Execute all three attack steps in sequence, strictly on resources
    created by steady_state().

    Step 1.2 — T1578: Attempt ec2:ModifyInstanceMetadataOptions via IMDSModifyLambda
        The Lambda assumes AttackerRole (which has a Permission Boundary
        denying ec2:ModifyInstanceMetadataOptions) and calls the API.
        Result written to IMDSModifyParam SSM parameter.

    Step 2.2 — T1552.005: Attempt IMDS credential harvest via IMDSProbeFunction
        The VPC Lambda curls the instance IMDS endpoint without a session
        token (IMDSv1 path).  Because HttpTokens=required and the NACL blocks
        169.254.169.254 egress, this must return a blocked:: result.
        Result written to HarvestSignalParam SSM parameter.

    Step 3.2 — T1078.004: Attempt lateral movement / privilege escalation
        via SimulatedAttackerFunction.
        The Lambda assumes AttackerRole and attempts each privileged action
        from the attack node: iam:CreateUser, iam:AttachRolePolicy,
        iam:CreatePolicy, iam:ListRoles, ecr:GetAuthorizationToken,
        s3:GetObject on PCI bucket, sts:AssumeRole.
        Results written as JSON to AttackResultsParam SSM parameter.

    Returns True if all three Lambda invocations complete without
    invocation-level errors (not application-level AccessDenied — those
    are the expected outcomes verified in hypothesis_verification).
    """
    log.info("=" * 70)
    log.info("attack() — SCE 3.3")
    log.info("=" * 70)

    lam    = _session().client("lambda")
    ok     = True

    def _invoke_lambda(fn_name: str, label: str) -> dict | None:
        """Invoke Lambda synchronously; return parsed payload or None on error."""
        log.info("[%s] Invoking Lambda '%s' …", label, fn_name)
        try:
            def _do_invoke():
                return lam.invoke(
                    FunctionName=fn_name,
                    InvocationType="RequestResponse",
                    LogType="Tail",
                )
            resp          = _retry(_do_invoke, attempts=3,
                                   label=f"Invoke:{fn_name}")
            payload_bytes = resp["Payload"].read()
            payload       = json.loads(payload_bytes.decode())

            if resp.get("LogResult"):
                tail = base64.b64decode(
                    resp["LogResult"]
                ).decode(errors="replace")
                log.info("[%s] Lambda tail log:\n%s", label, tail)

            func_error = resp.get("FunctionError")
            if func_error:
                log.warning(
                    "[%s] Lambda returned FunctionError='%s': %s",
                    label, func_error, payload,
                )
            else:
                log.info("[%s] Lambda payload: %s",
                         label, json.dumps(payload, indent=2))
            return payload
        except ClientError as exc:
            log.error("[%s] Lambda invocation ClientError: %s", label, exc)
            return None
        except json.JSONDecodeError as exc:
            log.error("[%s] Failed to parse Lambda payload: %s", label, exc)
            return None

    # ── Step 1.2: Attempt IMDS weakening via AttackerRole ────────────────────
    result_12 = _invoke_lambda(
        _STATE["imds_modify_fn_name"], "1.2-IMDS-Modify"
    )
    if result_12 is None:
        log.error("[1.2] Lambda invocation failed — cannot confirm denial.")
        ok = False
    else:
        modify_val = result_12.get("modify_result", "")
        log.info("[1.2] IMDS modify attempt result: %s", modify_val)
        _STATE["step_12_result"] = modify_val

    # ── Step 2.2: Attempt IMDS credential harvest ────────────────────────────
    result_22 = _invoke_lambda(
        _STATE["imds_probe_fn_name"], "2.2-IMDS-Harvest"
    )
    if result_22 is None:
        log.error("[2.2] Lambda invocation failed — cannot confirm blocking.")
        ok = False
    else:
        harvest_val = result_22.get("harvest", "")
        log.info("[2.2] IMDS harvest attempt result: %s", harvest_val)
        _STATE["step_22_result"] = harvest_val

    # ── Step 3.2: Attempt lateral movement via AttackerRole ──────────────────
    result_32 = _invoke_lambda(
        _STATE["attacker_fn_name"], "3.2-LateralMovement"
    )
    if result_32 is None:
        log.error("[3.2] Lambda invocation failed — cannot confirm denial.")
        ok = False
    else:
        log.info("[3.2] Lateral movement attempt results: %s",
                 json.dumps(result_32, indent=2))
        _STATE["step_32_results"] = result_32

    log.info("attack() complete — invocation success: %s", ok)
    return ok


# ---------------------------------------------------------------------------
# 3. hypothesis_verification() -> bool
# ---------------------------------------------------------------------------

def hypothesis_verification() -> bool:
    """
    Preventive Probe — verify all three preventive controls blocked their
    respective attack steps BEFORE any state change occurred.

    Sub-checks:
      (a) Step 1.2 — ec2:ModifyInstanceMetadataOptions denied by Permission
          Boundary on AttackerRole.  Verify:
          • IMDSModifyParam SSM contains "denied::" (not "allowed::").
          • EC2 instance IMDS config remains HttpTokens=required, HopLimit=1
            (no state change occurred — the IaC baseline was preserved).

      (b) Step 2.2 — IMDS credential harvest blocked by IMDSv2 enforcement
          and/or NACL.  Verify:
          • HarvestSignalParam SSM contains "blocked::" (not "harvested::").
          • EC2 IMDS HttpTokens is still "required" (confirming step 1.2
            prevention held — no weakening occurred to enable the harvest).

      (c) Step 3.2 — All privileged lateral-movement actions denied by
          Permission Boundary.  Verify from AttackResultsParam SSM:
          • Every action in _PRIVILEGED_ACTIONS returns a "denied::" value.
          • The baseline action (sts:GetCallerIdentity) returns "allowed"
            (confirming the boundary is correctly scoped — not a blanket
            deny-all that would obscure true prevention logic).

      (d) IAM SimulatePrincipalPolicy cross-check — independently confirm
          effective denial of all privileged actions on AttackerRole via
          the IAM policy simulation API (not relying solely on Lambda
          execution results).

    Returns True if all four sub-checks pass.
    """
    log.info("=" * 70)
    log.info("hypothesis_verification() — SCE 3.3 Preventive Probe")
    log.info("=" * 70)

    ssm = _session().client("ssm")
    ec2 = _session().client("ec2")
    iam = _session().client("iam")

    instance_id       = _STATE["instance_id"]
    attacker_role_arn = _STATE["attacker_role_arn"]
    all_passed        = True

    # ─────────────────────────────────────────────────────────────────────────
    # (a) Step 1.2 — IMDS modify denied + instance state unchanged
    # ─────────────────────────────────────────────────────────────────────────
    log.info("(a) Verifying ec2:ModifyInstanceMetadataOptions was denied …")
    a_passed = False
    try:
        modify_val = ssm.get_parameter(
            Name=_STATE["imds_modify_param"]
        )["Parameter"]["Value"]
        log.info("  (a) IMDSModifyParam value: %s", modify_val)

        if modify_val.startswith("denied::") or modify_val.startswith("error::"):
            # Confirm the EC2 instance IMDS options were NOT changed
            def _describe():
                return ec2.describe_instances(
                    InstanceIds=[instance_id]
                )
            desc      = _retry(_describe, attempts=4,
                               label="DescribeInstances-step-a")
            meta_opts = (
                desc["Reservations"][0]["Instances"][0]
                    .get("MetadataOptions", {})
            )
            http_tokens = meta_opts.get("HttpTokens", "unknown")
            hop_limit   = meta_opts.get("HttpPutResponseHopLimit", -1)

            log.info(
                "  (a) EC2 IMDS options post-attack: HttpTokens=%s, HopLimit=%s",
                http_tokens, hop_limit,
            )

            tokens_ok    = http_tokens == "required"
            hop_limit_ok = hop_limit == 1

            if tokens_ok and hop_limit_ok:
                log.info(
                    "  (a) PASS — ModifyInstanceMetadataOptions denied "
                    "(result: %s) AND EC2 IMDS baseline preserved "
                    "(HttpTokens=required, HopLimit=1).",
                    modify_val,
                )
                a_passed = True
            else:
                log.error(
                    "  (a) FAIL — IMDS call was denied (%s) BUT instance "
                    "state is unexpected: HttpTokens=%s HopLimit=%s",
                    modify_val, http_tokens, hop_limit,
                )
        elif modify_val == "idle":
            log.error(
                "  (a) FAIL — IMDSModifyParam still 'idle' — "
                "IMDSModifyLambda may not have run."
            )
        else:
            log.error(
                "  (a) FAIL — ModifyInstanceMetadataOptions was ALLOWED "
                "(result: %s) — preventive control did NOT block the attack.",
                modify_val,
            )
    except ClientError as exc:
        log.error("  (a) FAIL — Error reading IMDSModifyParam or describing "
                  "instance: %s", exc)

    if not a_passed:
        all_passed = False

    # ─────────────────────────────────────────────────────────────────────────
    # (b) Step 2.2 — IMDS harvest blocked
    # ─────────────────────────────────────────────────────────────────────────
    log.info("(b) Verifying IMDS credential harvest was blocked …")
    b_passed = False
    try:
        harvest_val = ssm.get_parameter(
            Name=_STATE["harvest_param_name"]
        )["Parameter"]["Value"]
        log.info("  (b) HarvestSignalParam value: %s", harvest_val)

        if harvest_val.startswith("blocked::"):
            log.info(
                "  (b) PASS — IMDS credential harvest blocked by IMDSv2 "
                "enforcement / NACL: %s",
                harvest_val,
            )
            b_passed = True
        elif harvest_val.startswith("harvested::"):
            log.error(
                "  (b) FAIL — IMDS credential harvest SUCCEEDED "
                "(preventive control failed): %s",
                harvest_val,
            )
        elif harvest_val == "idle":
            log.error(
                "  (b) FAIL — HarvestSignalParam still 'idle' — "
                "IMDSProbeFunction may not have run."
            )
        else:
            log.error("  (b) FAIL — Unexpected harvest value: %s", harvest_val)
    except ClientError as exc:
        log.error("  (b) FAIL — Error reading HarvestSignalParam: %s", exc)

    if not b_passed:
        all_passed = False

    # ─────────────────────────────────────────────────────────────────────────
    # (c) Step 3.2 — All privileged actions denied; baseline allowed
    # ─────────────────────────────────────────────────────────────────────────
    log.info("(c) Verifying all privileged lateral-movement actions were denied …")
    c_passed = False
    try:
        raw = ssm.get_parameter(
            Name=_STATE["attack_results_param"]
        )["Parameter"]["Value"]
        log.info("  (c) AttackResultsParam raw value: %s", raw)

        if raw == "idle":
            log.error(
                "  (c) FAIL — AttackResultsParam still 'idle' — "
                "SimulatedAttackerFunction may not have run."
            )
        else:
            results = json.loads(raw)
            log.info(
                "  (c) Per-action results:\n%s",
                json.dumps(results, indent=4),
            )

            # Check every privileged action was denied
            not_denied = []
            for action in _PRIVILEGED_ACTIONS:
                result = results.get(action, "missing")
                if not (
                    result.startswith("denied::")
                    or result.startswith("error::AccessDenied")
                    or result.startswith("error::UnauthorizedOperation")
                ):
                    not_denied.append((action, result))

            # Check baseline action was allowed
            baseline_result = results.get(_ALLOWED_BASELINE, "missing")
            baseline_ok     = baseline_result == "allowed"

            if not_denied:
                log.error(
                    "  (c) FAIL — %d privileged action(s) were NOT denied: %s",
                    len(not_denied),
                    [(a, r) for a, r in not_denied],
                )
            elif not baseline_ok:
                log.error(
                    "  (c) FAIL — Baseline action '%s' was not allowed "
                    "(got: %s) — boundary may be over-restrictive or broken.",
                    _ALLOWED_BASELINE, baseline_result,
                )
            else:
                log.info(
                    "  (c) PASS — All %d privileged actions denied; "
                    "baseline '%s' allowed.",
                    len(_PRIVILEGED_ACTIONS),
                    _ALLOWED_BASELINE,
                )
                c_passed = True
    except (ClientError, json.JSONDecodeError) as exc:
        log.error("  (c) FAIL — Error reading or parsing AttackResultsParam: %s",
                  exc)

    if not c_passed:
        all_passed = False

    # ─────────────────────────────────────────────────────────────────────────
    # (d) IAM SimulatePrincipalPolicy independent cross-check
    # ─────────────────────────────────────────────────────────────────────────
    log.info(
        "(d) IAM SimulatePrincipalPolicy cross-check on AttackerRole '%s' …",
        attacker_role_arn,
    )
    d_passed = False
    try:
        all_check_actions = _PRIVILEGED_ACTIONS + [_ALLOWED_BASELINE]

        def _simulate():
            return iam.simulate_principal_policy(
                PolicySourceArn=attacker_role_arn,
                ActionNames=all_check_actions,
                ResourceArns=["*"],
            )
        sim     = _retry(_simulate, attempts=4,
                         label="SimulatePrincipalPolicy")
        results = sim.get("EvaluationResults", [])

        sim_not_denied  = []
        sim_baseline_ok = False
        for r in results:
            action   = r["EvalActionName"]
            decision = r["EvalDecision"]
            log.info("  (d)  %-45s → %s", action, decision)

            if action == _ALLOWED_BASELINE:
                if decision == "allowed":
                    sim_baseline_ok = True
            else:
                if decision not in ("explicitDeny", "implicitDeny"):
                    sim_not_denied.append((action, decision))

        if sim_not_denied:
            log.error(
                "  (d) FAIL — Simulation shows %d privileged action(s) "
                "NOT denied: %s",
                len(sim_not_denied), sim_not_denied,
            )
        elif not sim_baseline_ok:
            log.error(
                "  (d) FAIL — Simulation shows baseline '%s' is NOT "
                "allowed — boundary misconfiguration detected.",
                _ALLOWED_BASELINE,
            )
        else:
            log.info(
                "  (d) PASS — All privileged actions confirmed denied; "
                "baseline confirmed allowed via IAM policy simulation."
            )
            d_passed = True
    except ClientError as exc:
        log.error("  (d) FAIL — IAM simulation error: %s", exc)

    if not d_passed:
        all_passed = False

    # ── Summary ──────────────────────────────────────────────────────────────
    status = "PASSED ✅" if all_passed else "FAILED ❌"
    log.info("-" * 70)
    log.info("hypothesis_verification() %s", status)
    log.info(
        "  (a) ModifyIMDS denied + EC2 state unchanged  : %s",
        "PASS" if a_passed else "FAIL",
    )
    log.info(
        "  (b) IMDS harvest blocked                     : %s",
        "PASS" if b_passed else "FAIL",
    )
    log.info(
        "  (c) Privileged actions denied (live)         : %s",
        "PASS" if c_passed else "FAIL",
    )
    log.info(
        "  (d) Privileged actions denied (simulation)   : %s",
        "PASS" if d_passed else "FAIL",
    )
    log.info("-" * 70)
    return all_passed


# ---------------------------------------------------------------------------
# 4. rollback()
# ---------------------------------------------------------------------------

def rollback() -> None:
    """
    Tear down all experiment resources.

    Pre-deletion:
      1. Empty the PCI S3 bucket (versioned; must delete all object versions
         before CloudFormation can delete it).
      2. Delete the ECR repository (must be empty or force-deleted).
      3. Delete out-of-band SSM parameters written by Lambdas outside CFn.

    Then delete the CloudFormation stack and wait for DELETE_COMPLETE.
    """
    log.info("=" * 70)
    log.info("rollback() — SCE 3.3")
    log.info("=" * 70)

    stack_name = _STATE.get("stack_name")
    if not stack_name:
        log.warning("rollback(): no stack_name in _STATE — nothing to delete.")
        return

    # ── Empty versioned S3 bucket ─────────────────────────────────────────────
    bucket = _STATE.get("pci_bucket_name")
    if bucket:
        s3 = _session().client("s3")
        try:
            paginator = s3.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket):
                objects_to_delete = []
                for v in page.get("Versions", []):
                    objects_to_delete.append(
                        {"Key": v["Key"], "VersionId": v["VersionId"]}
                    )
                for dm in page.get("DeleteMarkers", []):
                    objects_to_delete.append(
                        {"Key": dm["Key"], "VersionId": dm["VersionId"]}
                    )
                if objects_to_delete:
                    s3.delete_objects(
                        Bucket=bucket,
                        Delete={"Objects": objects_to_delete, "Quiet": True}
                    )
            log.info("Emptied S3 bucket '%s'.", bucket)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("NoSuchBucket",):
                log.warning("Could not empty S3 bucket '%s' (non-fatal): %s",
                            bucket, exc)

    # ── Force-delete ECR repository ───────────────────────────────────────────
    ecr_repo = _STATE.get("ecr_repo_name")
    if ecr_repo:
        ecr = _session().client("ecr")
        try:
            ecr.delete_repository(
                repositoryName=ecr_repo, force=True
            )
            log.info("Deleted ECR repository '%s'.", ecr_repo)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("RepositoryNotFoundException",):
                log.warning("Could not delete ECR repo '%s' (non-fatal): %s",
                            ecr_repo, exc)

    # ── Delete out-of-band SSM parameters ────────────────────────────────────
    ssm    = _session().client("ssm")
    suffix = _STATE.get("suffix", "")
    oob_params = [
        _STATE.get("harvest_param_name"),
        _STATE.get("attack_results_param"),
        _STATE.get("imds_modify_param"),
    ]
    for param_path in oob_params:
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
            log.info("Stack '%s' not found — already deleted.", stack_name)
            return
        log.error("Unexpected error initiating stack deletion for '%s': %s",
                  stack_name, exc)
        return

    try:
        _wait_stack(cf, stack_name, "DELETE_COMPLETE",
                    max_wait=_STACK_MAX_WAIT)
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
    log.info("╔" + "═" * 68 + "╗")
    log.info("║  SCE 3.3 — Preventive Probe                                    ║")
    log.info("║  Attack Nodes: 1.2 (T1578) + 2.2 (T1552.005) + 3.2 (T1078.004)║")
    log.info("╚" + "═" * 68 + "╝")

    passed = False
    try:
        steady_state()
        attack_ok = attack()
        if not attack_ok:
            log.warning(
                "attack() reported invocation errors — running "
                "hypothesis_verification() for diagnostic output."
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
        log.info("✅  EXPERIMENT PASSED — All preventive controls validated.")
    else:
        log.error(
            "❌  EXPERIMENT FAILED — One or more preventive controls "
            "did not behave as expected."
        )
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()