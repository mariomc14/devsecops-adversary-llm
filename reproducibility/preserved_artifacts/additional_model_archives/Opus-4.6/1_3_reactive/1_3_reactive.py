"""
SCE Experiment 1.3 - Reactive Probe
Attack Node 1.2: Enumerate Target EC2 Instance & IMDS Configuration
TTP: T1580 - Cloud Infrastructure Discovery

Validates that reactive controls automatically respond to unauthorized
ec2:DescribeInstances reconnaissance attempts by:
  1. Detecting the event via CloudTrail → CloudWatch Logs → Metric Filter
  2. Triggering an EventBridge rule that invokes a Lambda function
  3. Lambda applies an inline deny-all IAM policy to the attacker role,
     revoking effective permissions for the compromised principal
  4. Verifying that subsequent API calls from the attacker role are denied

Defense Node 1.5: Credential Revocation & SOC Alert
Classification: Reactive
"""

import json
import logging
import os
import sys
import time
import hashlib

try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Global experiment state
# ──────────────────────────────────────────────
_state = {
    "timestamp": None,
    "stack_name": None,
    "role_arn": None,
    "role_name": None,
    "external_id": None,
    "account_id": None,
    "region": None,
    "lambda_function_name": None,
    "trail_name": None,
    "log_group_name": None,
    "bucket_name": None,
    "eventbridge_rule_name": None,
    "attack_executed": False,
    "attack_time_utc": None,
    "attack_principal_arn": None,
    "deny_policy_name": None,
}

STACK_CREATION_TIMEOUT = 1200
STACK_DELETION_TIMEOUT = 600
IAM_PROPAGATION_WAIT = 25
POLL_INTERVAL = 15
SLA_TIMEOUT = 1800


def _get_caller_identity():
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    session = boto3.session.Session()
    return identity["Account"], session.region_name or "us-east-1"


def _lambda_code(attacker_role_name: str, deny_policy_name: str) -> str:
    """
    Inline Python code for the reactive Lambda function.
    When invoked by EventBridge (triggered by CloudTrail DescribeInstances
    from the attacker role), it attaches an inline deny-all policy to the
    attacker role, effectively revoking all permissions.
    """
    code = f'''
import json
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ATTACKER_ROLE_NAME = "{attacker_role_name}"
DENY_POLICY_NAME = "{deny_policy_name}"

def handler(event, context):
    logger.info("Reactive Lambda triggered")
    logger.info("Event: %s", json.dumps(event, default=str))

    detail = event.get("detail", {{}})
    event_name = detail.get("eventName", "")
    user_identity = detail.get("userIdentity", {{}})
    principal_arn = user_identity.get("arn", "")
    session_context = user_identity.get("sessionContext", {{}})
    session_issuer = session_context.get("sessionIssuer", {{}})
    issuer_arn = session_issuer.get("arn", "")

    logger.info("EventName: %s, Principal: %s, Issuer: %s",
                event_name, principal_arn, issuer_arn)

    # Only react if the event is from our attacker role
    if ATTACKER_ROLE_NAME not in principal_arn and ATTACKER_ROLE_NAME not in issuer_arn:
        logger.info("Event not from attacker role, skipping")
        return {{"action": "skipped", "reason": "not_attacker_role"}}

    iam = boto3.client("iam")

    deny_policy = {{
        "Version": "2012-10-17",
        "Statement": [
            {{
                "Sid": "DenyAllAfterCompromise",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }}
        ]
    }}

    try:
        iam.put_role_policy(
            RoleName=ATTACKER_ROLE_NAME,
            PolicyName=DENY_POLICY_NAME,
            PolicyDocument=json.dumps(deny_policy),
        )
        logger.info("Deny-all inline policy applied to role: %s", ATTACKER_ROLE_NAME)
    except Exception as exc:
        logger.error("Failed to apply deny policy: %s", exc)
        raise

    return {{
        "action": "revoked",
        "role": ATTACKER_ROLE_NAME,
        "policy": DENY_POLICY_NAME,
    }}
'''
    return code


def _build_lambda_zip(code_str: str) -> bytes:
    """Build an in-memory zip file containing lambda_function.py."""
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", code_str)
    buf.seek(0)
    return buf.read()


def _cfn_template(account_id: str, external_id: str, ts: int, region: str) -> str:
    """
    CloudFormation template that provisions the reactive control pipeline:
      1. S3 bucket for CloudTrail
      2. CloudTrail trail → CloudWatch Logs
      3. EventBridge rule matching DescribeInstances from the attacker role
      4. Lambda function that applies deny-all policy on the attacker role
      5. Simulated attacker IAM role (allowed to call DescribeInstances)
      6. Lambda execution role with iam:PutRolePolicy permission
    """
    trail_name = f"sce-react-trail-{ts}"
    log_group_name = f"/sce/reactive/{ts}"
    bucket_name = f"sce-react-bucket-{ts}"
    lambda_name = f"sce-react-lambda-{ts}"
    rule_name = f"sce-react-rule-{ts}"
    attacker_role_name = f"sce-react-attacker-{ts}"
    deny_policy_name = f"sce-deny-all-{ts}"

    _state["trail_name"] = trail_name
    _state["log_group_name"] = log_group_name
    _state["bucket_name"] = bucket_name
    _state["lambda_function_name"] = lambda_name
    _state["eventbridge_rule_name"] = rule_name
    _state["role_name"] = attacker_role_name
    _state["deny_policy_name"] = deny_policy_name

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.3 Reactive - Auto-revoke credentials on EC2 reconnaissance detection",
        "Resources": {
            # ── S3 Bucket for CloudTrail ──
            "TrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": bucket_name,
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Reactive"},
                        {"Key": "Timestamp", "Value": str(ts)},
                    ],
                },
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
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:GetBucketAcl",
                                "Resource": f"arn:aws:s3:::{bucket_name}",
                                "Condition": {
                                    "StringEquals": {"AWS:SourceAccount": account_id}
                                },
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/*",
                                "Condition": {
                                    "StringEquals": {
                                        "s3:x-amz-acl": "bucket-owner-full-control",
                                        "AWS:SourceAccount": account_id,
                                    }
                                },
                            },
                        ],
                    },
                },
            },
            # ── CloudWatch Log Group ──
            "TrailLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": log_group_name,
                    "RetentionInDays": 1,
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Reactive"},
                    ],
                },
            },
            # ── IAM Role for CloudTrail → CW Logs ──
            "TrailCWRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-react-trailcw-{ts}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "CTrailToCWLogs",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                        ],
                                        "Resource": f"arn:aws:logs:*:{account_id}:log-group:{log_group_name}:*",
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Reactive"},
                    ],
                },
            },
            # ── CloudTrail Trail ──
            "ReactiveTrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": ["TrailBucketPolicy", "TrailLogGroup", "TrailCWRole"],
                "Properties": {
                    "TrailName": trail_name,
                    "S3BucketName": {"Ref": "TrailBucket"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": True,
                    "EnableLogFileValidation": True,
                    "CloudWatchLogsLogGroupArn": {
                        "Fn::GetAtt": ["TrailLogGroup", "Arn"]
                    },
                    "CloudWatchLogsRoleArn": {
                        "Fn::GetAtt": ["TrailCWRole", "Arn"]
                    },
                    "EventSelectors": [
                        {
                            "ReadWriteType": "All",
                            "IncludeManagementEvents": True,
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Reactive"},
                        {"Key": "Timestamp", "Value": str(ts)},
                    ],
                },
            },
            # ── Simulated Attacker Role ──
            "AttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": attacker_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": f"arn:aws:iam::{account_id}:root"
                                },
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringEquals": {
                                        "sts:ExternalId": external_id,
                                    }
                                },
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "AllowEC2Describe",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:DescribeInstances",
                                        ],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Reactive"},
                        {"Key": "Purpose", "Value": "SimulatedAttacker"},
                    ],
                },
            },
            # ── Lambda Execution Role ──
            "LambdaExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-react-lambda-exec-{ts}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "ReactiveAutomation",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "AllowPutDenyPolicy",
                                        "Effect": "Allow",
                                        "Action": [
                                            "iam:PutRolePolicy",
                                        ],
                                        "Resource": f"arn:aws:iam::{account_id}:role/{attacker_role_name}",
                                    },
                                    {
                                        "Sid": "AllowLogs",
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogGroup",
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                        ],
                                        "Resource": f"arn:aws:logs:*:{account_id}:*",
                                    },
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Reactive"},
                    ],
                },
            },
            # ── EventBridge Rule ──
            "ReconEventRule": {
                "Type": "AWS::Events::Rule",
                "DependsOn": ["ReactiveTrail"],
                "Properties": {
                    "Name": rule_name,
                    "Description": "Matches DescribeInstances calls from attacker role for reactive response",
                    "State": "ENABLED",
                    "EventPattern": {
                        "source": ["aws.ec2"],
                        "detail-type": ["AWS API Call via CloudTrail"],
                        "detail": {
                            "eventSource": ["ec2.amazonaws.com"],
                            "eventName": ["DescribeInstances"],
                            "userIdentity": {
                                "sessionContext": {
                                    "sessionIssuer": {
                                        "userName": [attacker_role_name]
                                    }
                                }
                            },
                        },
                    },
                    "Targets": [
                        {
                            "Arn": {"Fn::GetAtt": ["ReactiveLambda", "Arn"]},
                            "Id": "ReactiveTarget",
                        }
                    ],
                },
            },
            # ── Lambda Permission for EventBridge ──
            "LambdaInvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "DependsOn": ["ReactiveLambda", "ReconEventRule"],
                "Properties": {
                    "FunctionName": {"Ref": "ReactiveLambda"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["ReconEventRule", "Arn"]},
                },
            },
        },
        "Outputs": {
            "AttackerRoleArn": {
                "Value": {"Fn::GetAtt": ["AttackerRole", "Arn"]},
            },
            "AttackerRoleName": {
                "Value": attacker_role_name,
            },
            "LambdaFunctionArn": {
                "Value": {"Fn::GetAtt": ["ReactiveLambda", "Arn"]},
            },
            "EventRuleArn": {
                "Value": {"Fn::GetAtt": ["ReconEventRule", "Arn"]},
            },
        },
    }
    return template, attacker_role_name, deny_policy_name, lambda_name


def _wait_for_stack(cfn_client, stack_name: str, target_status: str, timeout: int):
    start = time.monotonic()
    attempt = 0
    while True:
        attempt += 1
        elapsed = time.monotonic() - start
        if elapsed > timeout:
            raise TimeoutError(
                f"Stack {stack_name} did not reach {target_status} within {timeout}s"
            )
        try:
            resp = cfn_client.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            logger.info(
                "Stack status: %s (attempt %d, %.0fs elapsed)",
                status, attempt, elapsed,
            )
            if status == target_status:
                logger.info("Stack reached %s after %d attempts", target_status, attempt)
                return resp["Stacks"][0]
            if "FAILED" in status or status == "ROLLBACK_COMPLETE":
                reason = resp["Stacks"][0].get("StackStatusReason", "unknown")
                # Try to get detailed events
                try:
                    events_resp = cfn_client.describe_stack_events(StackName=stack_name)
                    for ev in events_resp.get("StackEvents", [])[:10]:
                        if "FAILED" in ev.get("ResourceStatus", ""):
                            logger.error(
                                "  Resource %s: %s - %s",
                                ev.get("LogicalResourceId"),
                                ev.get("ResourceStatus"),
                                ev.get("ResourceStatusReason", ""),
                            )
                except Exception:
                    pass
                raise RuntimeError(f"Stack {stack_name} entered {status}: {reason}")
        except ClientError as exc:
            if "does not exist" in str(exc):
                if target_status == "DELETE_COMPLETE":
                    logger.info("Stack deleted (no longer exists)")
                    return None
                raise
            logger.warning("Describe stack error: %s", exc)
        time.sleep(POLL_INTERVAL)


def _verify_role_assumable(sts_client, role_arn: str, external_id: str, retries: int = 12):
    for attempt in range(1, retries + 1):
        try:
            creds = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="sce-verify",
                ExternalId=external_id,
                DurationSeconds=900,
            )
            logger.info("Role verification completed after %d attempts", attempt)
            return creds
        except ClientError as exc:
            logger.warning(
                "Role not yet assumable (attempt %d/%d): %s", attempt, retries, exc,
            )
            if attempt == retries:
                raise
            time.sleep(5 + attempt * 2)


# ──────────────────────────────────────────────
# 1. STEADY STATE
# ──────────────────────────────────────────────
def steady_state():
    """
    Deploy the reactive control pipeline:
    CloudTrail → EventBridge rule → Lambda (applies deny-all to attacker role)
    Plus a simulated attacker IAM role allowed to call DescribeInstances.
    """
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.3 Reactive - Steady State Setup")
    logger.info("=" * 60)

    ts = int(time.time())
    _state["timestamp"] = ts
    _state["stack_name"] = f"sce-1-3-react-{ts}"
    _state["external_id"] = f"sce-react-{ts}"

    logger.info("Timestamp: %d", ts)
    logger.info("Stack name: %s", _state["stack_name"])

    account_id, region = _get_caller_identity()
    _state["account_id"] = account_id
    _state["region"] = region
    logger.info("Account: %s, Region: %s", account_id, region)

    # Build template (returns dict, not string, because we need to add Lambda inline)
    template_dict, attacker_role_name, deny_policy_name, lambda_name = _cfn_template(
        account_id, _state["external_id"], ts, region
    )

    # Generate Lambda zip code
    lambda_code_str = _lambda_code(attacker_role_name, deny_policy_name)
    lambda_zip = _build_lambda_zip(lambda_code_str)

    # We must create the Lambda outside CFN because CFN inline Code.ZipFile
    # has a 4096-char limit. Instead, we upload to S3 first, OR we use
    # the ZipFile property with a shorter code. Let's use ZipFile with
    # compact code.

    # Actually, let's use a compact inline lambda for CFN ZipFile (max 4096 chars)
    compact_lambda = (
        "import json, boto3, logging\n"
        "logger = logging.getLogger()\n"
        "logger.setLevel(logging.INFO)\n"
        f"ROLE = '{attacker_role_name}'\n"
        f"POL = '{deny_policy_name}'\n"
        "def handler(event, context):\n"
        "    logger.info('Reactive Lambda triggered: %s', json.dumps(event, default=str))\n"
        "    d = event.get('detail', {})\n"
        "    ui = d.get('userIdentity', {})\n"
        "    sc = ui.get('sessionContext', {})\n"
        "    si = sc.get('sessionIssuer', {})\n"
        "    arn = si.get('arn', '')\n"
        "    un = si.get('userName', '')\n"
        "    logger.info('Issuer ARN: %s, userName: %s', arn, un)\n"
        "    if ROLE not in arn and ROLE != un:\n"
        "        logger.info('Not attacker role, skip')\n"
        "        return {'action': 'skipped'}\n"
        "    iam = boto3.client('iam')\n"
        "    dp = {'Version': '2012-10-17', 'Statement': [{'Sid': 'DenyAll', 'Effect': 'Deny', 'Action': '*', 'Resource': '*'}]}\n"
        "    iam.put_role_policy(RoleName=ROLE, PolicyName=POL, PolicyDocument=json.dumps(dp))\n"
        "    logger.info('Deny-all applied to %s', ROLE)\n"
        "    return {'action': 'revoked', 'role': ROLE}\n"
    )

    # Add Lambda resource to template
    template_dict["Resources"]["ReactiveLambda"] = {
        "Type": "AWS::Lambda::Function",
        "DependsOn": ["LambdaExecRole"],
        "Properties": {
            "FunctionName": lambda_name,
            "Runtime": "python3.12",
            "Handler": "index.handler",
            "Timeout": 60,
            "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
            "Code": {
                "ZipFile": compact_lambda,
            },
            "Tags": [
                {"Key": "Experiment", "Value": "SCE-1.3-Reactive"},
                {"Key": "Timestamp", "Value": str(ts)},
            ],
        },
    }

    template_body = json.dumps(template_dict)

    cfn = boto3.client("cloudformation", region_name=region)

    # Create stack
    for attempt in range(1, 4):
        try:
            logger.info("Creating CloudFormation stack (attempt %d)...", attempt)
            cfn.create_stack(
                StackName=_state["stack_name"],
                TemplateBody=template_body,
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Tags=[
                    {"Key": "Experiment", "Value": "SCE-1.3-Reactive"},
                    {"Key": "Timestamp", "Value": str(ts)},
                    {"Key": "Purpose", "Value": "ChaosEngineering"},
                ],
                TimeoutInMinutes=15,
            )
            logger.info("Stack creation initiated")
            break
        except ClientError as exc:
            if "AlreadyExistsException" in str(exc):
                logger.warning("Stack already exists — reusing")
                break
            if attempt == 3:
                logger.error("Failed to create stack after 3 attempts: %s", exc)
                raise
            logger.warning("Stack creation error (attempt %d): %s", attempt, exc)
            time.sleep(5 * attempt)

    logger.info("Waiting up to %ds for stack creation...", STACK_CREATION_TIMEOUT)
    stack = _wait_for_stack(
        cfn, _state["stack_name"], "CREATE_COMPLETE", STACK_CREATION_TIMEOUT
    )

    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    _state["role_arn"] = outputs.get("AttackerRoleArn")
    logger.info("Attacker Role ARN: %s", _state["role_arn"])
    logger.info("Lambda Function: %s", _state["lambda_function_name"])
    logger.info("EventBridge Rule: %s", _state["eventbridge_rule_name"])
    logger.info("Trail: %s", _state["trail_name"])

    if not _state["role_arn"]:
        raise RuntimeError("AttackerRoleArn output not found in stack outputs")

    # Wait for IAM propagation
    logger.info("Waiting %ds for IAM propagation...", IAM_PROPAGATION_WAIT)
    time.sleep(IAM_PROPAGATION_WAIT)

    # Verify attacker role assumable
    logger.info("Verifying attacker role assumability...")
    sts = boto3.client("sts", region_name=region)
    _verify_role_assumable(sts, _state["role_arn"], _state["external_id"])

    # Verify trail is logging
    ct = boto3.client("cloudtrail", region_name=region)
    for attempt in range(1, 6):
        try:
            status = ct.get_trail_status(Name=_state["trail_name"])
            if status.get("IsLogging"):
                logger.info("CloudTrail trail is actively logging")
                break
            logger.warning("Trail not yet logging (attempt %d)", attempt)
        except ClientError as exc:
            logger.warning("Trail status check error (attempt %d): %s", attempt, exc)
        time.sleep(10)

    # Verify EventBridge rule is enabled
    eb = boto3.client("events", region_name=region)
    for attempt in range(1, 6):
        try:
            rule = eb.describe_rule(Name=_state["eventbridge_rule_name"])
            logger.info("EventBridge rule state: %s", rule.get("State"))
            if rule.get("State") == "ENABLED":
                break
        except ClientError as exc:
            logger.warning("EventBridge rule check error (attempt %d): %s", attempt, exc)
        time.sleep(5)

    # Verify Lambda is active
    lam = boto3.client("lambda", region_name=region)
    for attempt in range(1, 6):
        try:
            fn = lam.get_function(FunctionName=_state["lambda_function_name"])
            fn_state = fn["Configuration"].get("State", "Unknown")
            logger.info("Lambda state: %s", fn_state)
            if fn_state == "Active":
                break
        except ClientError as exc:
            logger.warning("Lambda check error (attempt %d): %s", attempt, exc)
        time.sleep(5)

    # Verify the attacker role does NOT yet have the deny policy
    iam = boto3.client("iam", region_name=region)
    try:
        policies = iam.list_role_policies(RoleName=_state["role_name"])
        policy_names = policies.get("PolicyNames", [])
        logger.info("Current inline policies on attacker role: %s", policy_names)
        if _state["deny_policy_name"] in policy_names:
            logger.warning("Deny policy already exists — removing for clean test")
            iam.delete_role_policy(
                RoleName=_state["role_name"],
                PolicyName=_state["deny_policy_name"],
            )
    except ClientError as exc:
        logger.warning("Policy check error: %s", exc)

    logger.info("=" * 60)
    logger.info("Steady state setup COMPLETED")
    logger.info("=" * 60)


# ──────────────────────────────────────────────
# 2. ATTACK
# ──────────────────────────────────────────────
def attack() -> bool:
    """
    Execute Attack Node 1.2: ec2:DescribeInstances from the attacker role.
    The call should succeed (no boundary), generating a CloudTrail event
    that triggers the EventBridge → Lambda reactive chain.
    """
    logger.info("=" * 60)
    logger.info("SCE 1.3 Reactive - Attack Node 1.2: EC2 Reconnaissance")
    logger.info("TTP: T1580 - Cloud Infrastructure Discovery")
    logger.info("=" * 60)

    region = _state["region"]
    role_arn = _state["role_arn"]
    external_id = _state["external_id"]

    if not role_arn:
        logger.error("Role ARN not available — steady_state may have failed")
        _state["attack_executed"] = False
        return True

    # Assume attacker role
    logger.info("Assuming attacker role: %s", role_arn)
    sts = boto3.client("sts", region_name=region)
    try:
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="sce-reactive-attack",
            ExternalId=external_id,
            DurationSeconds=900,
        )
        logger.info("Role assumed successfully")
        _state["attack_principal_arn"] = assumed["AssumedRoleUser"]["Arn"]
        logger.info("Attack principal ARN: %s", _state["attack_principal_arn"])
    except ClientError as exc:
        logger.error("Failed to assume attacker role: %s", exc)
        _state["attack_executed"] = False
        return True

    creds = assumed["Credentials"]
    ec2 = boto3.client(
        "ec2",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

    import datetime
    _state["attack_time_utc"] = datetime.datetime.utcnow()
    logger.info("Attack timestamp (UTC): %s", _state["attack_time_utc"].isoformat())

    # Execute reconnaissance
    logger.info("Executing: aws ec2 describe-instances")
    logger.info("Expected: SUCCESS (to generate CloudTrail event for reactive chain)")
    start_time = time.monotonic()
    try:
        response = ec2.describe_instances(MaxResults=5)
        duration = time.monotonic() - start_time
        instance_count = sum(
            len(r.get("Instances", [])) for r in response.get("Reservations", [])
        )
        logger.info("DescribeInstances SUCCEEDED (expected)")
        logger.info("Instances returned: %d", instance_count)
        logger.info("Duration: %.2fs", duration)
        _state["attack_executed"] = True
    except ClientError as exc:
        duration = time.monotonic() - start_time
        error_code = exc.response["Error"]["Code"]
        logger.warning("DescribeInstances returned: %s", error_code)
        logger.info("Duration: %.2fs", duration)
        # Still generates a CloudTrail event
        _state["attack_executed"] = True

    # Execute a few more calls to increase likelihood of EventBridge triggering
    logger.info("Executing additional DescribeInstances calls for reactive trigger confidence")
    for i in range(3):
        try:
            ec2.describe_instances(MaxResults=5)
            logger.info("Additional call %d/3 succeeded", i + 1)
        except ClientError as exc:
            logger.info("Additional call %d/3 error: %s", i + 1, exc)
        time.sleep(2)

    logger.info("=" * 60)
    logger.info("Attack execution completed — waiting for reactive chain to trigger")
    logger.info("=" * 60)

    return True


# ──────────────────────────────────────────────
# 3. HYPOTHESIS VERIFICATION
# ──────────────────────────────────────────────
def hypothesis_verification() -> bool:
    """
    Verify reactive controls responded to the attack by:
      1. Checking the attacker role now has a deny-all inline policy
         (applied by the Lambda function)
      2. Verifying that a new assume-role + DescribeInstances attempt
         is now blocked by the deny-all policy
      3. Checking Lambda invocation logs for evidence of execution

    Uses 30-minute SLA polling for EventBridge/Lambda latency.
    Returns True if the reactive chain executed successfully.
    """
    logger.info("=" * 60)
    logger.info("SCE 1.3 Reactive - Hypothesis Verification")
    logger.info("=" * 60)

    if not _state.get("attack_executed"):
        logger.error("Attack was not executed — cannot verify reactive response")
        return False

    region = _state["region"]
    role_name = _state["role_name"]
    role_arn = _state["role_arn"]
    external_id = _state["external_id"]
    deny_policy_name = _state["deny_policy_name"]
    lambda_name = _state["lambda_function_name"]

    iam = boto3.client("iam", region_name=region)

    deny_policy_found = False
    post_attack_blocked = False
    lambda_invoked = False

    start = time.monotonic()
    attempt = 0

    logger.info("Starting reactive verification (SLA: %ds)", SLA_TIMEOUT)
    logger.info("Checking for deny-all policy '%s' on role '%s'", deny_policy_name, role_name)

    while time.monotonic() - start < SLA_TIMEOUT:
        attempt += 1
        elapsed = time.monotonic() - start
        logger.info(
            "Verification attempt %d (%.0fs / %ds elapsed)",
            attempt, elapsed, SLA_TIMEOUT,
        )

        # ── Check 1: Deny-all inline policy on attacker role ──
        if not deny_policy_found:
            try:
                policies = iam.list_role_policies(RoleName=role_name)
                policy_names = policies.get("PolicyNames", [])
                logger.info("Inline policies on attacker role: %s", policy_names)

                if deny_policy_name in policy_names:
                    logger.info("DETECTED: Deny-all policy '%s' found on attacker role", deny_policy_name)
                    deny_policy_found = True

                    # Verify the policy content
                    try:
                        pol = iam.get_role_policy(
                            RoleName=role_name,
                            PolicyName=deny_policy_name,
                        )
                        doc = pol.get("PolicyDocument", {})
                        statements = doc.get("Statement", [])
                        for stmt in statements:
                            if stmt.get("Effect") == "Deny" and stmt.get("Action") == "*":
                                logger.info("Policy confirmed: Deny * on *")
                                break
                    except ClientError as exc:
                        logger.warning("Could not read policy content: %s", exc)
                else:
                    logger.info("Deny policy not yet applied (reactive chain pending)")
            except ClientError as exc:
                logger.warning("IAM policy check error: %s", exc)

        # ── Check 2: Verify post-attack calls are blocked ──
        if deny_policy_found and not post_attack_blocked:
            logger.info("Testing that attacker role is now blocked...")
            # Wait a moment for IAM policy propagation
            time.sleep(10)
            sts = boto3.client("sts", region_name=region)
            try:
                assumed = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="sce-post-attack-verify",
                    ExternalId=external_id,
                    DurationSeconds=900,
                )
                creds = assumed["Credentials"]
                ec2 = boto3.client(
                    "ec2",
                    region_name=region,
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                )
                try:
                    ec2.describe_instances(MaxResults=5)
                    logger.warning("Post-attack DescribeInstances SUCCEEDED — deny policy may not have propagated yet")
                    # IAM eventual consistency — retry
                except ClientError as exc:
                    error_code = exc.response["Error"]["Code"]
                    if error_code in ("UnauthorizedOperation", "AccessDenied"):
                        logger.info("CONFIRMED: Post-attack DescribeInstances BLOCKED (%s)", error_code)
                        post_attack_blocked = True
                    else:
                        logger.warning("Unexpected error on post-attack call: %s", exc)
            except ClientError as exc:
                error_code = exc.response["Error"]["Code"]
                if error_code in ("AccessDenied",):
                    logger.info("CONFIRMED: Even AssumeRole is now denied (%s)", error_code)
                    post_attack_blocked = True
                else:
                    logger.warning("Post-attack assume role error: %s", exc)

        # ── Check 3: Lambda invocation evidence ──
        if deny_policy_found and not lambda_invoked:
            try:
                logs_client = boto3.client("logs", region_name=region)
                lambda_log_group = f"/aws/lambda/{lambda_name}"
                resp = logs_client.filter_log_events(
                    logGroupName=lambda_log_group,
                    filterPattern="Reactive Lambda triggered",
                    limit=10,
                )
                events = resp.get("events", [])
                if events:
                    logger.info("Lambda invocation evidence found (%d log entries)", len(events))
                    for ev in events[:3]:
                        logger.info("  Log: %s", ev.get("message", "").strip()[:200])
                    lambda_invoked = True
                else:
                    logger.info("No Lambda invocation logs yet")
            except ClientError as exc:
                if "ResourceNotFoundException" in str(exc):
                    logger.info("Lambda log group not yet created")
                else:
                    logger.warning("Lambda log check error: %s", exc)

        # ── Evaluate ──
        if deny_policy_found and post_attack_blocked:
            logger.info("Core reactive verification criteria met")
            break

        if deny_policy_found and not post_attack_blocked:
            # Policy exists but calls not blocked yet — IAM propagation delay
            logger.info("Policy found but calls not yet blocked — waiting for propagation")
            time.sleep(15)
            continue

        time.sleep(30)

    # ── Final Assessment ──
    logger.info("=" * 60)
    logger.info("SCE 1.3 Reactive - Verification Results")
    logger.info("=" * 60)
    logger.info("Deny-all policy applied:       %s", deny_policy_found)
    logger.info("Post-attack calls blocked:     %s", post_attack_blocked)
    logger.info("Lambda invocation confirmed:   %s", lambda_invoked)

    verified = deny_policy_found and post_attack_blocked

    if verified:
        logger.info("=" * 60)
        logger.info("HYPOTHESIS VERIFIED: Reactive controls responded to the attack")
        logger.info("=" * 60)
        logger.info("Evidence summary:")
        logger.info("  - Deny-all inline policy '%s' applied to attacker role", deny_policy_name)
        logger.info("  - Subsequent DescribeInstances calls are now blocked")
        if lambda_invoked:
            logger.info("  - Lambda execution logs confirm automated invocation")
    else:
        logger.error("=" * 60)
        logger.error("HYPOTHESIS FAILED: Reactive controls did not respond within SLA")
        logger.error("=" * 60)
        if not deny_policy_found:
            logger.error("  - Deny-all policy was NOT applied (EventBridge/Lambda chain may have failed)")
        if not post_attack_blocked:
            logger.error("  - Post-attack calls were NOT blocked")

    return verified


# ──────────────────────────────────────────────
# 4. ROLLBACK
# ──────────────────────────────────────────────
def rollback():
    """
    Clean up: remove the deny-all inline policy (if it exists) before
    deleting the CFN stack, then empty S3 bucket and delete stack.
    """
    logger.info("=" * 60)
    logger.info("SCE 1.3 Reactive - Rollback / Cleanup")
    logger.info("=" * 60)

    stack_name = _state.get("stack_name")
    region = _state.get("region")
    bucket_name = _state.get("bucket_name")
    role_name = _state.get("role_name")
    deny_policy_name = _state.get("deny_policy_name")

    if not region:
        try:
            _, region = _get_caller_identity()
        except Exception:
            region = "us-east-1"

    # Remove the deny-all inline policy from attacker role
    if role_name and deny_policy_name:
        logger.info("Removing deny-all policy from attacker role (if present)...")
        try:
            iam = boto3.client("iam", region_name=region)
            iam.delete_role_policy(
                RoleName=role_name,
                PolicyName=deny_policy_name,
            )
            logger.info("Deny-all policy removed")
        except ClientError as exc:
            if "NoSuchEntity" in str(exc):
                logger.info("Deny-all policy does not exist (nothing to remove)")
            else:
                logger.warning("Error removing deny-all policy: %s", exc)

    # Empty the S3 bucket
    if bucket_name:
        logger.info("Emptying S3 bucket: %s", bucket_name)
        try:
            s3 = boto3.resource("s3", region_name=region)
            bucket = s3.Bucket(bucket_name)
            bucket.object_versions.all().delete()
            logger.info("All object versions deleted from bucket")
        except ClientError as exc:
            if "NoSuchBucket" in str(exc):
                logger.info("Bucket already deleted")
            else:
                logger.warning("Error emptying bucket: %s", exc)
        except Exception as exc:
            logger.warning("Unexpected error emptying bucket: %s", exc)
            try:
                s3_client = boto3.client("s3", region_name=region)
                paginator = s3_client.get_paginator("list_objects_v2")
                for page in paginator.paginate(Bucket=bucket_name):
                    objects = page.get("Contents", [])
                    if objects:
                        delete_keys = [{"Key": obj["Key"]} for obj in objects]
                        s3_client.delete_objects(
                            Bucket=bucket_name,
                            Delete={"Objects": delete_keys},
                        )
                logger.info("Bucket emptied via alternative method")
            except Exception as alt_exc:
                logger.warning("Alternative bucket cleanup failed: %s", alt_exc)

    # Delete Lambda log group (not managed by CFN)
    lambda_name = _state.get("lambda_function_name")
    if lambda_name:
        try:
            logs_client = boto3.client("logs", region_name=region)
            logs_client.delete_log_group(logGroupName=f"/aws/lambda/{lambda_name}")
            logger.info("Lambda log group deleted")
        except ClientError as exc:
            if "ResourceNotFoundException" in str(exc):
                logger.info("Lambda log group does not exist")
            else:
                logger.warning("Error deleting Lambda log group: %s", exc)

    if not stack_name:
        logger.warning("No stack name recorded — nothing to clean up")
        return

    cfn = boto3.client("cloudformation", region_name=region)

    try:
        logger.info("Deleting stack: %s", stack_name)
        cfn.delete_stack(StackName=stack_name)
        logger.info("Deletion initiated")
    except ClientError as exc:
        if "does not exist" in str(exc):
            logger.info("Stack already deleted or does not exist")
            logger.info("=" * 60)
            logger.info("Cleanup completed")
            logger.info("=" * 60)
            return
        logger.error("Error initiating stack deletion: %s", exc)
        raise

    try:
        logger.info("Waiting for deletion...")
        _wait_for_stack(cfn, stack_name, "DELETE_COMPLETE", STACK_DELETION_TIMEOUT)
    except ClientError as exc:
        if "does not exist" in str(exc):
            logger.info("Stack deleted successfully")
        else:
            logger.error("Error waiting for stack deletion: %s", exc)
    except TimeoutError:
        logger.error(
            "Stack deletion did not complete within %ds — manual cleanup may be needed",
            STACK_DELETION_TIMEOUT,
        )

    logger.info("=" * 60)
    logger.info("Cleanup completed")
    logger.info("=" * 60)


# ──────────────────────────────────────────────
# Direct execution support
# ──────────────────────────────────────────────
if __name__ == "__main__":
    try:
        steady_state()
        attack()
        result = hypothesis_verification()
        print(f"\nExperiment result: {'PASS' if result else 'FAIL'}")
        sys.exit(0 if result else 1)
    except Exception as exc:
        logger.exception("Experiment failed with exception: %s", exc)
        sys.exit(2)
    finally:
        try:
            rollback()
        except Exception as exc:
            logger.exception("Rollback failed: %s", exc)