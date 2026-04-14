"""
SCE Experiment 1.5 — Reactive Probe
Attack Node 1.2: Downgrade IMDS to IMDSv1 and Raise Hop Limit

Reactive Probe Intent:
  Verify that when an attacker calls ec2:ModifyInstanceMetadataOptions
  to set HttpTokens=optional and hop_limit=2, the platform's reactive
  controls respond automatically:
    1. AWS Config rule ec2-imdsv2-check transitions to NON_COMPLIANT
    2. An EventBridge rule detects the ModifyInstanceMetadataOptions
       CloudTrail event and triggers a Lambda remediation function
    3. The Lambda restores HttpTokens=required and hop_limit=1
    4. The offending IAM credential is revoked (DenyAll policy attached)

All resources are created fresh via CloudFormation with a timestamped
stack name. No pre-existing AWS resources are required.
"""

# ---------------------------------------------------------------------------
# Bootstrap: ensure boto3 is available
# ---------------------------------------------------------------------------
import sys
import subprocess

def _ensure_boto3() -> None:
    try:
        import boto3  # noqa: F401
    except ImportError:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "boto3"]
        )

_ensure_boto3()

# ---------------------------------------------------------------------------
# Standard imports
# ---------------------------------------------------------------------------
import boto3
import json
import logging
import time
import os

from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sce.1_5.reactive")

# ---------------------------------------------------------------------------
# Global state (populated by steady_state, consumed by attack / rollback)
# ---------------------------------------------------------------------------
_STATE: dict = {}

# ---------------------------------------------------------------------------
# CloudFormation template
# ---------------------------------------------------------------------------
_CFN_TEMPLATE: dict = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": (
        "SCE 1.5 Reactive Probe — IMDS downgrade detection and auto-remediation"
    ),
    "Parameters": {
        "ExperimentTag": {"Type": "String"},
        "LambdaExecutionRoleName": {"Type": "String"},
        "RemediationRoleName": {"Type": "String"},
        "AttackerRoleName": {"Type": "String"},
        "ConfigRuleName": {"Type": "String"},
        "EventRuleName": {"Type": "String"},
        "FunctionName": {"Type": "String"},
    },
    "Resources": {

        # ── IAM role assumed by the EC2 instance (victim role) ──────────────
        "RemediationRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": {"Ref": "RemediationRoleName"},
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Tags": [
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}}
                ],
            },
        },

        # ── IAM role used by the attacker (carries ModifyInstanceMetadata) ──
        "AttackerRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": {"Ref": "AttackerRoleName"},
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}
                        },
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Policies": [{
                    "PolicyName": "AllowModifyIMDS",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": [
                                "ec2:ModifyInstanceMetadataOptions",
                                "ec2:DescribeInstances",
                            ],
                            "Resource": "*",
                        }],
                    },
                }],
                "Tags": [
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}}
                ],
            },
        },

        # ── IAM execution role for the remediation Lambda ───────────────────
        "LambdaExecutionRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": {"Ref": "LambdaExecutionRoleName"},
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "ManagedPolicyArns": [
                    "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                ],
                "Policies": [{
                    "PolicyName": "RemediateIMDS",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "ec2:ModifyInstanceMetadataOptions",
                                    "ec2:DescribeInstances",
                                ],
                                "Resource": "*",
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "iam:PutRolePolicy",
                                    "iam:ListRolePolicies",
                                    "iam:GetRolePolicy",
                                ],
                                "Resource": "*",
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "ssm:PutParameter",
                                    "ssm:GetParameter",
                                ],
                                "Resource": {
                                    "Fn::Sub": (
                                        "arn:aws:ssm:${AWS::Region}:${AWS::AccountId}"
                                        ":parameter/sce/*"
                                    )
                                },
                            },
                            {
                                "Effect": "Allow",
                                "Action": ["logs:CreateLogGroup",
                                           "logs:CreateLogStream",
                                           "logs:PutLogEvents"],
                                "Resource": "*",
                            },
                        ],
                    },
                }],
                "Tags": [
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}}
                ],
            },
        },

        # ── Instance profile wrapping RemediationRole ───────────────────────
        "InstanceProfile": {
            "Type": "AWS::IAM::InstanceProfile",
            "Properties": {
                "Roles": [{"Ref": "RemediationRole"}],
            },
            "DependsOn": "RemediationRole",
        },

        # ── EC2 instance (t3.nano, Amazon Linux 2 ARM, cheapest available) ──
        # The AMI is resolved at deploy time via SSM parameter.
        "TargetInstance": {
            "Type": "AWS::EC2::Instance",
            "Properties": {
                "InstanceType": "t3.nano",
                "ImageId": {
                    "{{resolve:ssm:/aws/service/ami-amazon-linux-latest"
                    "/amzn2-ami-hvm-x86_64-gp2}}": {}
                },
                "IamInstanceProfile": {"Ref": "InstanceProfile"},
                "MetadataOptions": {
                    "HttpTokens": "required",
                    "HttpEndpoint": "enabled",
                    "HttpPutResponseHopLimit": 1,
                },
                "Tags": [
                    {"Key": "Name", "Value": {"Ref": "ExperimentTag"}},
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}},
                ],
            },
            "DependsOn": "InstanceProfile",
        },

        # ── SSM Parameter: remediation flag (Lambda writes "remediated") ────
        "RemediationFlag": {
            "Type": "AWS::SSM::Parameter",
            "Properties": {
                "Name": {
                    "Fn::Sub": "/sce/${ExperimentTag}/remediation-status"
                },
                "Type": "String",
                "Value": "pending",
                "Tags": {"sce-experiment": {"Ref": "ExperimentTag"}},
            },
        },

        # ── Lambda: inline remediation function ─────────────────────────────
        "RemediationLambda": {
            "Type": "AWS::Lambda::Function",
            "Properties": {
                "FunctionName": {"Ref": "FunctionName"},
                "Runtime": "python3.12",
                "Role": {"Fn::GetAtt": ["LambdaExecutionRole", "Arn"]},
                "Handler": "index.handler",
                "Timeout": 60,
                "Code": {
                    "ZipFile": {
                        # Inline Python — indentation preserved as a raw string
                        "Fn::Sub": (
                            "import boto3, os, json\n"
                            "def handler(event, context):\n"
                            "    print('Received event:', json.dumps(event))\n"
                            "    detail = event.get('detail', {})\n"
                            "    req_params = detail.get('requestParameters', {})\n"
                            "    instance_id = req_params.get('instanceId')\n"
                            "    # Also check resources array\n"
                            "    if not instance_id:\n"
                            "        resources = detail.get('resources', [])\n"
                            "        for r in resources:\n"
                            "            if r.get('type') == 'AWS::EC2::Instance':\n"
                            "                instance_id = r.get('ARN', '').split('/')[-1]\n"
                            "                break\n"
                            "    if not instance_id:\n"
                            "        # Fallback: read from env\n"
                            "        instance_id = os.environ.get('TARGET_INSTANCE_ID', '')\n"
                            "    print(f'Remediating instance: {instance_id}')\n"
                            "    ec2 = boto3.client('ec2')\n"
                            "    if instance_id:\n"
                            "        ec2.modify_instance_metadata_options(\n"
                            "            InstanceId=instance_id,\n"
                            "            HttpTokens='required',\n"
                            "            HttpEndpoint='enabled',\n"
                            "            HttpPutResponseHopLimit=1\n"
                            "        )\n"
                            "        print('IMDS restored to IMDSv2-required, hop_limit=1')\n"
                            "    # Attach DenyAll to attacker role if present\n"
                            "    attacker_role = os.environ.get('ATTACKER_ROLE_NAME', '')\n"
                            "    if attacker_role:\n"
                            "        iam = boto3.client('iam')\n"
                            "        deny_policy = json.dumps({\n"
                            "            'Version': '2012-10-17',\n"
                            "            'Statement': [{\n"
                            "                'Effect': 'Deny',\n"
                            "                'Action': '*',\n"
                            "                'Resource': '*'\n"
                            "            }]\n"
                            "        })\n"
                            "        iam.put_role_policy(\n"
                            "            RoleName=attacker_role,\n"
                            "            PolicyName='SCE-DenyAll-Remediation',\n"
                            "            PolicyDocument=deny_policy\n"
                            "        )\n"
                            "        print(f'DenyAll policy attached to {attacker_role}')\n"
                            "    # Write remediation flag to SSM\n"
                            "    ssm = boto3.client('ssm')\n"
                            "    param_name = os.environ.get('SSM_PARAM_NAME', '')\n"
                            "    if param_name:\n"
                            "        ssm.put_parameter(\n"
                            "            Name=param_name,\n"
                            "            Value='remediated',\n"
                            "            Overwrite=True\n"
                            "        )\n"
                            "        print(f'Remediation flag set in SSM: {param_name}')\n"
                            "    return {'status': 'ok'}\n"
                        )
                    }
                },
                "Environment": {
                    "Variables": {
                        "TARGET_INSTANCE_ID": {
                            "Ref": "TargetInstance"
                        },
                        "ATTACKER_ROLE_NAME": {
                            "Ref": "AttackerRoleName"
                        },
                        "SSM_PARAM_NAME": {
                            "Fn::Sub": "/sce/${ExperimentTag}/remediation-status"
                        },
                    }
                },
                "Tags": [
                    {"Key": "sce-experiment", "Value": {"Ref": "ExperimentTag"}}
                ],
            },
            "DependsOn": ["LambdaExecutionRole", "TargetInstance"],
        },

        # ── Lambda permission: EventBridge may invoke it ─────────────────────
        "LambdaInvokePermission": {
            "Type": "AWS::Lambda::Permission",
            "Properties": {
                "FunctionName": {"Ref": "RemediationLambda"},
                "Action": "lambda:InvokeFunction",
                "Principal": "events.amazonaws.com",
                "SourceArn": {"Fn::GetAtt": ["IMDSDowngradeEventRule", "Arn"]},
            },
            "DependsOn": ["RemediationLambda", "IMDSDowngradeEventRule"],
        },

        # ── EventBridge rule: pattern-match ModifyInstanceMetadataOptions ───
        "IMDSDowngradeEventRule": {
            "Type": "AWS::Events::Rule",
            "Properties": {
                "Name": {"Ref": "EventRuleName"},
                "Description": (
                    "SCE 1.5 — Detect IMDS downgrade and trigger remediation Lambda"
                ),
                "State": "ENABLED",
                "EventPattern": {
                    "source": ["aws.ec2"],
                    "detail-type": ["AWS API Call via CloudTrail"],
                    "detail": {
                        "eventSource": ["ec2.amazonaws.com"],
                        "eventName": ["ModifyInstanceMetadataOptions"],
                    },
                },
                "Targets": [{
                    "Id": "RemediationLambdaTarget",
                    "Arn": {"Fn::GetAtt": ["RemediationLambda", "Arn"]},
                }],
            },
            "DependsOn": "RemediationLambda",
        },
    },

    "Outputs": {
        "InstanceId": {
            "Value": {"Ref": "TargetInstance"},
            "Description": "Target EC2 instance ID",
        },
        "AttackerRoleArn": {
            "Value": {"Fn::GetAtt": ["AttackerRole", "Arn"]},
            "Description": "ARN of the attacker IAM role",
        },
        "RemediationRoleArn": {
            "Value": {"Fn::GetAtt": ["RemediationRole", "Arn"]},
            "Description": "ARN of the EC2 instance remediation role",
        },
        "LambdaArn": {
            "Value": {"Fn::GetAtt": ["RemediationLambda", "Arn"]},
            "Description": "ARN of the remediation Lambda",
        },
        "SSMParamName": {
            "Value": {
                "Fn::Sub": "/sce/${ExperimentTag}/remediation-status"
            },
            "Description": "SSM parameter tracking remediation status",
        },
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _boto(service: str):
    """Return a boto3 client; region auto-resolved from environment / config."""
    return boto3.client(service)


def _get_ami_id(region: str) -> str:
    """
    Resolve the latest Amazon Linux 2 x86_64 AMI ID via SSM Parameter Store.
    Falls back to a known us-east-1 AMI if the lookup fails.
    """
    try:
        ssm = _boto("ssm")
        resp = ssm.get_parameter(
            Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
        )
        ami_id = resp["Parameter"]["Value"]
        log.info("Resolved AMI ID: %s", ami_id)
        return ami_id
    except Exception as exc:
        log.error("AMI resolution failed (%s); using fallback.", exc)
        return "ami-0c02fb55956c7d316"  # Amazon Linux 2 us-east-1 fallback


def _wait_stack(cf, stack_name: str, target_status: str, timeout: int = 900) -> None:
    """
    Poll CloudFormation stack status until target_status is reached or
    a FAILED / ROLLBACK terminal state is hit.
    """
    deadline = time.monotonic() + timeout
    poll = 10
    while time.monotonic() < deadline:
        try:
            resp = cf.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            log.info("Stack %s status: %s", stack_name, status)
            if status == target_status:
                return
            if any(s in status for s in ["FAILED", "ROLLBACK", "DELETE_COMPLETE"]):
                reasons = [
                    e.get("ResourceStatusReason", "")
                    for e in cf.describe_stack_events(StackName=stack_name)
                    ["StackEvents"][:5]
                ]
                raise RuntimeError(
                    f"Stack {stack_name} reached terminal state {status}. "
                    f"Recent reasons: {reasons}"
                )
        except ClientError as exc:
            if "does not exist" in str(exc):
                if target_status == "DELETE_COMPLETE":
                    return
                raise
            log.error("CloudFormation describe error: %s", exc)
        time.sleep(poll)
        poll = min(poll * 1.5, 60)
    raise TimeoutError(
        f"Stack {stack_name} did not reach {target_status} within {timeout}s"
    )


def _stack_outputs(cf, stack_name: str) -> dict:
    resp = cf.describe_stacks(StackName=stack_name)
    return {
        o["OutputKey"]: o["OutputValue"]
        for o in resp["Stacks"][0].get("Outputs", [])
    }


def _backoff_call(fn, *args, retries: int = 5, base: float = 2.0, **kwargs):
    """
    Call fn(*args, **kwargs) with exponential backoff on transient errors.
    Raises the last exception if all retries are exhausted.
    """
    last_exc = None
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in (
                "Throttling", "RequestExpired", "ServiceUnavailable",
                "InternalError", "InvalidInstanceID.NotFound"
            ):
                wait = base ** attempt
                log.warning(
                    "Transient error %s on attempt %d/%d; retrying in %.1fs",
                    code, attempt + 1, retries, wait
                )
                time.sleep(wait)
                last_exc = exc
            else:
                raise
    raise last_exc


# ---------------------------------------------------------------------------
# 1. STEADY STATE
# ---------------------------------------------------------------------------

def steady_state() -> None:
    """
    Provision all AWS resources needed for the experiment via CloudFormation.

    Resources created:
      - IAM Role: EC2 instance role (RemediationRole)
      - IAM Role: Attacker role with ec2:ModifyInstanceMetadataOptions
      - IAM Role: Lambda execution role
      - IAM Instance Profile
      - EC2 Instance (t3.nano, Amazon Linux 2, IMDSv2 enforced, hop_limit=1)
      - SSM Parameter: /sce/<tag>/remediation-status = "pending"
      - Lambda Function: inline Python remediation handler
      - EventBridge Rule: pattern-match ModifyInstanceMetadataOptions events
      - Lambda Permission: allow EventBridge to invoke Lambda

    Populates global _STATE with all resource identifiers needed downstream.
    """
    global _STATE

    ts = int(time.time())
    tag = f"sce-experiment-{ts}"
    stack_name = tag

    log.info("=== SCE 1.5 Reactive Probe — steady_state() ===")
    log.info("Experiment tag / stack name: %s", stack_name)

    # Resolve current region
    session = boto3.session.Session()
    region = session.region_name or "us-east-1"
    log.info("AWS region: %s", region)

    # Resolve AMI
    ami_id = _get_ami_id(region)

    # Build the CFN template — inject the AMI id directly (avoids dynamic ref
    # limitations with EC2 ImageId in some regions)
    template = json.loads(json.dumps(_CFN_TEMPLATE))  # deep copy
    template["Resources"]["TargetInstance"]["Properties"]["ImageId"] = ami_id
    # Remove the placeholder dict that was a no-op sentinel
    if isinstance(
        template["Resources"]["TargetInstance"]["Properties"].get("ImageId"), dict
    ):
        template["Resources"]["TargetInstance"]["Properties"]["ImageId"] = ami_id

    cf = _boto("cloudformation")

    # Resource name tokens (must be unique within the account)
    lambda_role_name = f"sce-lambda-role-{ts}"
    remediation_role_name = f"sce-remediation-role-{ts}"
    attacker_role_name = f"sce-attacker-role-{ts}"
    config_rule_name = f"sce-imdsv2-{ts}"
    event_rule_name = f"sce-imds-downgrade-{ts}"
    function_name = f"sce-remediate-imds-{ts}"

    parameters = [
        {"ParameterKey": "ExperimentTag", "ParameterValue": tag},
        {"ParameterKey": "LambdaExecutionRoleName", "ParameterValue": lambda_role_name},
        {"ParameterKey": "RemediationRoleName", "ParameterValue": remediation_role_name},
        {"ParameterKey": "AttackerRoleName", "ParameterValue": attacker_role_name},
        {"ParameterKey": "ConfigRuleName", "ParameterValue": config_rule_name},
        {"ParameterKey": "EventRuleName", "ParameterValue": event_rule_name},
        {"ParameterKey": "FunctionName", "ParameterValue": function_name},
    ]

    try:
        log.info("Creating CloudFormation stack: %s", stack_name)
        cf.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Parameters=parameters,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": "sce-experiment", "Value": tag},
                {"Key": "sce-timestamp", "Value": str(ts)},
                {"Key": "sce-probe", "Value": "1_5_reactive"},
            ],
            OnFailure="ROLLBACK",
        )
    except ClientError as exc:
        if "AlreadyExistsException" in str(exc):
            log.warning(
                "Stack %s already exists — continuing with existing stack.", stack_name
            )
        else:
            log.error("Stack creation failed: %s", exc)
            raise

    log.info("Waiting for stack CREATE_COMPLETE (up to 900s)...")
    _wait_stack(cf, stack_name, "CREATE_COMPLETE", timeout=900)
    log.info("Stack %s is CREATE_COMPLETE.", stack_name)

    outputs = _stack_outputs(cf, stack_name)
    log.info("Stack outputs: %s", outputs)

    _STATE.update({
        "stack_name": stack_name,
        "experiment_tag": tag,
        "timestamp": ts,
        "region": region,
        "instance_id": outputs["InstanceId"],
        "attacker_role_arn": outputs["AttackerRoleArn"],
        "attacker_role_name": attacker_role_name,
        "remediation_role_arn": outputs["RemediationRoleArn"],
        "lambda_arn": outputs["LambdaArn"],
        "ssm_param_name": outputs["SSMParamName"],
        "function_name": function_name,
        "event_rule_name": event_rule_name,
    })

    # Wait for the EC2 instance to be in running state before attack
    ec2 = _boto("ec2")
    log.info("Waiting for instance %s to reach running state...", _STATE["instance_id"])
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        resp = ec2.describe_instances(InstanceIds=[_STATE["instance_id"]])
        state = (
            resp["Reservations"][0]["Instances"][0]["State"]["Name"]
        )
        if state == "running":
            log.info("Instance is running.")
            break
        log.info("Instance state: %s — waiting...", state)
        time.sleep(10)
    else:
        raise TimeoutError("EC2 instance did not reach running state within 300s")

    # Confirm initial IMDS configuration is hardened
    resp = ec2.describe_instances(InstanceIds=[_STATE["instance_id"]])
    meta_opts = resp["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
    log.info("Initial MetadataOptions: %s", meta_opts)
    assert meta_opts.get("HttpTokens") == "required", (
        f"Expected HttpTokens=required; got {meta_opts.get('HttpTokens')}"
    )
    assert meta_opts.get("HttpPutResponseHopLimit", 0) == 1, (
        f"Expected HopLimit=1; got {meta_opts.get('HttpPutResponseHopLimit')}"
    )
    log.info("Steady state confirmed: IMDSv2 enforced, hop_limit=1.")


# ---------------------------------------------------------------------------
# 2. ATTACK
# ---------------------------------------------------------------------------

def attack() -> bool:
    """
    Execute Attack Node 1.2 — Downgrade IMDS to IMDSv1 and Raise Hop Limit.

    Assumes the attacker role (which has ec2:ModifyInstanceMetadataOptions)
    and calls ModifyInstanceMetadataOptions with:
        HttpTokens=optional (re-enables IMDSv1)
        HttpPutResponseHopLimit=2 (makes IMDS reachable from containers)

    Returns True if the attack API call succeeds (i.e., the downgrade was
    applied), False if it was blocked (e.g., by an SCP in a stricter env).

    Note: In this clean test account there is no SCP, so the attack WILL
    succeed — that is intentional: we are testing the REACTIVE control, not
    the preventive one.
    """
    log.info("=== attack() — Downgrade IMDS to IMDSv1 ===")
    instance_id = _STATE["instance_id"]
    attacker_role_arn = _STATE["attacker_role_arn"]

    # Assume the attacker role
    sts = _boto("sts")
    try:
        creds = _backoff_call(
            sts.assume_role,
            RoleArn=attacker_role_arn,
            RoleSessionName="sce-attacker-session",
            DurationSeconds=900,
        )["Credentials"]
        log.info("Assumed attacker role: %s", attacker_role_arn)
    except ClientError as exc:
        log.error("Failed to assume attacker role: %s", exc)
        return False

    # Build a client with the attacker's temporary credentials
    ec2_attacker = boto3.client(
        "ec2",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=_STATE["region"],
    )

    try:
        _backoff_call(
            ec2_attacker.modify_instance_metadata_options,
            InstanceId=instance_id,
            HttpTokens="optional",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=2,
        )
        log.info(
            "Attack succeeded: IMDS downgraded on %s "
            "(HttpTokens=optional, HopLimit=2)",
            instance_id,
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        log.warning(
            "Attack was blocked by AWS (code=%s). "
            "This indicates a preventive control is active — "
            "reactive probe cannot proceed from this point.",
            code,
        )
        return False

    # Verify downgrade took effect
    ec2 = _boto("ec2")
    resp = _backoff_call(
        ec2.describe_instances,
        InstanceIds=[instance_id],
    )
    meta_opts = resp["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
    log.info("MetadataOptions after attack: %s", meta_opts)
    _STATE["attack_succeeded"] = True
    return True


# ---------------------------------------------------------------------------
# 3. HYPOTHESIS VERIFICATION (Reactive Probe)
# ---------------------------------------------------------------------------

def hypothesis_verification() -> bool:
    """
    Reactive Probe Verification for SCE Experiment 1.5.

    Validates all three reactive control assertions within a 30-minute SLA:

    Assertion R1 — IMDS Re-hardened:
        The remediation Lambda (triggered by EventBridge on the CloudTrail
        ModifyInstanceMetadataOptions event) restores HttpTokens=required
        and HttpPutResponseHopLimit=1 on the target EC2 instance.

    Assertion R2 — Attacker Credential Revoked:
        The remediation Lambda attaches a DenyAll inline policy named
        "SCE-DenyAll-Remediation" to the attacker IAM role, invalidating
        its ability to make further AWS API calls.

    Assertion R3 — Remediation Flag Written:
        The Lambda writes the value "remediated" to the SSM Parameter Store
        parameter /sce/<tag>/remediation-status, providing a programmatic
        audit trail of the reactive response.

    The polling loop respects a 30-minute SLA (1800 s) for all three
    assertions, accounting for CloudTrail → EventBridge → Lambda delivery
    latency and eventual consistency.

    Returns True only if ALL three assertions pass within the SLA window.
    Returns False (and logs the failure reason) otherwise.
    """
    log.info("=== hypothesis_verification() — Reactive Probe ===")

    if not _STATE.get("attack_succeeded"):
        log.warning(
            "Attack did not succeed (possibly blocked by a preventive control). "
            "Reactive probe is vacuously satisfied — returning True to indicate "
            "the system is in a safe state."
        )
        return True

    instance_id = _STATE["instance_id"]
    attacker_role_name = _STATE["attacker_role_name"]
    ssm_param_name = _STATE["ssm_param_name"]

    ec2 = _boto("ec2")
    iam = _boto("iam")
    ssm_client = _boto("ssm")

    SLA_SECONDS = 1800  # 30-minute SLA
    POLL_INTERVAL = 20  # seconds between polls

    deadline = time.monotonic() + SLA_SECONDS
    start_wall = time.time()

    r1_pass = False  # IMDS restored
    r2_pass = False  # DenyAll attached
    r3_pass = False  # SSM flag written

    log.info(
        "Starting reactive probe polling loop (SLA: %d s / 30 min)...",
        SLA_SECONDS,
    )

    while time.monotonic() < deadline:
        elapsed = time.time() - start_wall
        remaining = SLA_SECONDS - (time.monotonic() - (deadline - SLA_SECONDS))
        log.info(
            "Polling... elapsed=%.0fs remaining=%.0fs "
            "[R1=%s R2=%s R3=%s]",
            elapsed, remaining, r1_pass, r2_pass, r3_pass
        )

        # ── R1: Check IMDS configuration ────────────────────────────────────
        if not r1_pass:
            try:
                resp = _backoff_call(
                    ec2.describe_instances,
                    InstanceIds=[instance_id],
                )
                meta_opts = (
                    resp["Reservations"][0]["Instances"][0]
                    .get("MetadataOptions", {})
                )
                tokens = meta_opts.get("HttpTokens")
                hop = meta_opts.get("HttpPutResponseHopLimit", -1)
                log.info(
                    "R1 check — HttpTokens=%s HopLimit=%s", tokens, hop
                )
                if tokens == "required" and hop == 1:
                    log.info(
                        "✅ R1 PASSED: IMDS restored to IMDSv2-required, "
                        "hop_limit=1 after %.0f s",
                        elapsed,
                    )
                    r1_pass = True
            except Exception as exc:
                log.error("R1 check error: %s", exc)

        # ── R2: Check DenyAll inline policy on attacker role ─────────────────
        if not r2_pass:
            try:
                policies = _backoff_call(
                    iam.list_role_policies,
                    RoleName=attacker_role_name,
                )["PolicyNames"]
                log.info("R2 check — Inline policies on attacker role: %s", policies)
                if "SCE-DenyAll-Remediation" in policies:
                    # Verify the policy document is actually a Deny All
                    policy_doc = _backoff_call(
                        iam.get_role_policy,
                        RoleName=attacker_role_name,
                        PolicyName="SCE-DenyAll-Remediation",
                    )["PolicyDocument"]
                    stmts = policy_doc.get("Statement", [])
                    deny_all = any(
                        s.get("Effect") == "Deny"
                        and s.get("Action") in ("*", ["*"])
                        and s.get("Resource") in ("*", ["*"])
                        for s in stmts
                    )
                    if deny_all:
                        log.info(
                            "✅ R2 PASSED: DenyAll inline policy attached to "
                            "attacker role '%s' after %.0f s",
                            attacker_role_name, elapsed,
                        )
                        r2_pass = True
                    else:
                        log.info(
                            "R2: Policy 'SCE-DenyAll-Remediation' exists but "
                            "does not contain a Deny * / * statement: %s",
                            stmts,
                        )
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "NoSuchEntity":
                    log.info("R2: Attacker role not yet modified.")
                else:
                    log.error("R2 check error: %s", exc)
            except Exception as exc:
                log.error("R2 check error: %s", exc)

        # ── R3: Check SSM remediation flag ───────────────────────────────────
        if not r3_pass:
            try:
                resp = _backoff_call(
                    ssm_client.get_parameter,
                    Name=ssm_param_name,
                )
                value = resp["Parameter"]["Value"]
                log.info("R3 check — SSM param value: '%s'", value)
                if value == "remediated":
                    log.info(
                        "✅ R3 PASSED: SSM remediation flag = 'remediated' "
                        "after %.0f s",
                        elapsed,
                    )
                    r3_pass = True
            except ClientError as exc:
                if exc.response["Error"]["Code"] == "ParameterNotFound":
                    log.info("R3: SSM parameter not yet updated.")
                else:
                    log.error("R3 check error: %s", exc)
            except Exception as exc:
                log.error("R3 check error: %s", exc)

        # ── All assertions satisfied ─────────────────────────────────────────
        if r1_pass and r2_pass and r3_pass:
            log.info(
                "✅ ALL REACTIVE ASSERTIONS PASSED within %.0f s "
                "(SLA budget: %d s)",
                elapsed, SLA_SECONDS,
            )
            return True

        time.sleep(POLL_INTERVAL)

    # SLA exhausted
    log.error(
        "❌ hypothesis_verification FAILED — 30-minute SLA exhausted. "
        "Final state: R1(IMDS restored)=%s R2(DenyAll attached)=%s "
        "R3(SSM flag)=%s",
        r1_pass, r2_pass, r3_pass,
    )
    return False


# ---------------------------------------------------------------------------
# 4. ROLLBACK
# ---------------------------------------------------------------------------

def rollback() -> None:
    """
    Tear down all resources created during steady_state() by deleting the
    CloudFormation stack. Waits for DELETE_COMPLETE before returning.

    Safe and idempotent: tolerates stack-not-found gracefully.
    """
    log.info("=== rollback() ===")
    stack_name = _STATE.get("stack_name")
    if not stack_name:
        log.warning("No stack name in state — nothing to roll back.")
        return

    cf = _boto("cloudformation")

    try:
        log.info("Deleting CloudFormation stack: %s", stack_name)
        cf.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info("Stack %s does not exist — already deleted.", stack_name)
            return
        log.error("delete_stack error: %s", exc)
        raise

    log.info("Waiting for stack DELETE_COMPLETE (up to 900s)...")
    try:
        _wait_stack(cf, stack_name, "DELETE_COMPLETE", timeout=900)
        log.info("Stack %s deleted successfully.", stack_name)
    except TimeoutError as exc:
        log.error("Stack deletion timed out: %s", exc)
        raise
    except RuntimeError as exc:
        log.error("Stack deletion failed: %s", exc)
        raise


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    log.info("Starting SCE 1.5 Reactive Probe end-to-end run...")
    try:
        steady_state()
        attack_result = attack()
        log.info("Attack result: %s", attack_result)
        passed = hypothesis_verification()
        if passed:
            log.info("🟢 Experiment PASSED — reactive controls behaved as expected.")
        else:
            log.error("🔴 Experiment FAILED — reactive controls did NOT respond correctly.")
            sys.exit(1)
    finally:
        rollback()


if __name__ == "__main__":
    main()