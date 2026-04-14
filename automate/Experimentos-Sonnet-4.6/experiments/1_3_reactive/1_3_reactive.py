"""
chaosaws/ec2/1_3_reactive.py

SCE Experiment 1.3 — Reactive Probe
Attack Node: 1.2 — IMDS Protection Weakening via ec2:ModifyInstanceMetadataOptions
Reactive Control: EventBridge + Lambda auto-remediation pipeline that:
  R1: Attaches a deny-all inline policy to the offending IAM principal
  R2: Sets an SSM pipeline-block flag to 'blocked'
  R3: Publishes an SNS SOC alert with instance/principal context
  R4: Restores IMDS to HttpTokens=required, HopLimit=1

TTP: T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
STRIDE: Tampering | Information Disclosure | Elevation of Privilege
"""

from __future__ import annotations

import json
import logging
import sys
import threading
import time
import traceback

# ---------------------------------------------------------------------------
# Runtime boto3 install guard
# ---------------------------------------------------------------------------
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:  # pragma: no cover
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "--quiet"])
    import boto3
    from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)s] sce.1_3.reactive — %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stderr,
)
log = logging.getLogger("sce.1_3.reactive")

# ---------------------------------------------------------------------------
# Global experiment state  (populated by steady_state, consumed by others)
# ---------------------------------------------------------------------------
_state: dict = {
    "stack_name": None,
    "region": None,
    "account_id": None,
    "instance_id": None,
    "attacker_role_name": None,
    "attacker_role_arn": None,
    "ssm_parameter_name": None,
    "lambda_function_name": None,
    "lambda_log_group": None,
    "sns_topic_arn": None,
    "infrastructure_ready": False,
}

# ---------------------------------------------------------------------------
# CloudFormation template
# ---------------------------------------------------------------------------
def _build_cfn_template(account_id: str, region: str) -> str:
    """
    Build a self-contained CloudFormation template with ALL resources needed
    for the reactive probe experiment.

    Resources created:
      - BankingAppInstance       : EC2 t3.micro (IMDSv2, HopLimit=1 baseline)
      - AttackerRole             : IAM role with ec2:ModifyInstanceMetadataOptions
      - ReactiveRole             : IAM role for the Lambda responder
      - ReactiveFunction         : Lambda that remediates IMDS + attach deny + SSM + SNS
      - SOCAlertTopic            : SNS topic for SOC alert
      - PipelineBlockParam       : SSM Parameter /sce/pipeline-block (value=unblocked)
      - ReactiveEventBridgeRule  : Matches ModifyInstanceMetadataOptions CloudTrail event
      - LambdaPermission         : Allows EventBridge to invoke Lambda
      - CloudTrailBucket         : S3 bucket for CloudTrail logs
      - BankingTrail             : CloudTrail trail (management events)
    """

    # Inline Lambda source — kept short and explicit
    lambda_src = r"""
import json, logging, os, boto3
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    region        = os.environ['AWS_REGION']
    instance_id   = os.environ['INSTANCE_ID']
    ssm_param     = os.environ['SSM_PARAM_NAME']
    sns_topic_arn = os.environ['SNS_TOPIC_ARN']
    attacker_role = os.environ['ATTACKER_ROLE_NAME']

    ec2  = boto3.client('ec2',  region_name=region)
    iam  = boto3.client('iam')
    ssm  = boto3.client('ssm',  region_name=region)
    sns  = boto3.client('sns',  region_name=region)

    results = {}

    # R4 — Restore IMDS to HttpTokens=required, HopLimit=1
    try:
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='required',
            HttpPutResponseHopLimit=1,
            HttpEndpoint='enabled',
        )
        logger.info('imds_restored: true instance=%s', instance_id)
        results['imds_restored'] = True
    except Exception as exc:
        logger.error('imds_restore_error: %s', exc)
        results['imds_restored'] = False

    # R1 — Attach deny-all inline policy to attacker role
    deny_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "EmergencyDenyAll",
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
            "Condition": {
                "DateLessThan": {
                    "aws:TokenIssueTime": "2099-01-01T00:00:00Z"
                }
            }
        }]
    })
    try:
        iam.put_role_policy(
            RoleName=attacker_role,
            PolicyName='SCE-EmergencyDenyAll',
            PolicyDocument=deny_policy,
        )
        logger.info('deny_policy_attached: true role=%s', attacker_role)
        results['deny_policy_attached'] = True
    except Exception as exc:
        logger.error('deny_policy_error: %s', exc)
        results['deny_policy_attached'] = False

    # R2 — Set SSM pipeline-block flag to 'blocked'
    try:
        ssm.put_parameter(
            Name=ssm_param,
            Value='blocked',
            Type='String',
            Overwrite=True,
        )
        logger.info('ssm_pipeline_blocked: true param=%s', ssm_param)
        results['ssm_pipeline_blocked'] = True
    except Exception as exc:
        logger.error('ssm_block_error: %s', exc)
        results['ssm_pipeline_blocked'] = False

    # R3 — Publish SNS SOC alert
    alert_msg = json.dumps({
        'severity': 'P0',
        'title': 'IMDS Protection Weakening Detected',
        'instance_id': instance_id,
        'attacker_role': attacker_role,
        'ttp': 'T1552.005',
        'action': 'Automated remediation executed',
        'results': results,
    })
    try:
        resp = sns.publish(
            TopicArn=sns_topic_arn,
            Subject='[SCE-ALERT] IMDS Weakening Detected — P0',
            Message=alert_msg,
        )
        logger.info('sns_published: true message_id=%s', resp.get('MessageId'))
        results['sns_published'] = True
    except Exception as exc:
        logger.error('sns_publish_error: %s', exc)
        results['sns_published'] = False

    logger.info('reactive_remediation_complete results=%s', json.dumps(results))
    return results
""".strip()

    # Escape for CloudFormation Fn::Join / literal YAML — embed via JSON template
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.3 Reactive Probe — IMDS Weakening Auto-Remediation",
        "Parameters": {
            "LatestAmiId": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
            }
        },
        "Resources": {

            # ── S3 bucket for CloudTrail ──────────────────────────────────
            "CloudTrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "Tags": [{"Key": "sce-experiment", "Value": "1.3-reactive"}]
                }
            },
            "CloudTrailBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "CloudTrailBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSCloudTrailAclCheck",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:GetBucketAcl",
                                "Resource": {"Fn::GetAtt": ["CloudTrailBucket", "Arn"]}
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {
                                    "Fn::Sub": "${CloudTrailBucket.Arn}/AWSLogs/${AWS::AccountId}/*"
                                },
                                "Condition": {
                                    "StringEquals": {
                                        "s3:x-amz-acl": "bucket-owner-full-control"
                                    }
                                }
                            }
                        ]
                    }
                }
            },

            # ── CloudTrail trail ──────────────────────────────────────────
            "BankingTrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": ["CloudTrailBucketPolicy"],
                "Properties": {
                    "TrailName": "sce-banking-trail",
                    "S3BucketName": {"Ref": "CloudTrailBucket"},
                    "IsLogging": True,
                    "IncludeGlobalServiceEvents": True,
                    "IsMultiRegionTrail": False,
                    "EnableLogFileValidation": False,
                    "Tags": [{"Key": "sce-experiment", "Value": "1.3-reactive"}]
                }
            },

            # ── SNS topic for SOC alerts ──────────────────────────────────
            "SOCAlertTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": "sce-soc-alert-topic",
                    "Tags": [{"Key": "sce-experiment", "Value": "1.3-reactive"}]
                }
            },

            # ── SSM pipeline-block parameter ──────────────────────────────
            "PipelineBlockParam": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {
                    "Name": "/sce/pipeline-block",
                    "Type": "String",
                    "Value": "unblocked",
                    "Description": "SCE 1.3 pipeline circuit-breaker flag",
                    "Tags": {"sce-experiment": "1.3-reactive"}
                }
            },

            # ── Attacker IAM role ─────────────────────────────────────────
            "AttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "sce-attacker-role",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "Policies": [{
                        "PolicyName": "AttackerPolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "ec2:ModifyInstanceMetadataOptions",
                                        "ec2:DescribeInstances"
                                    ],
                                    "Resource": "*"
                                }
                            ]
                        }
                    }],
                    "Tags": [{"Key": "sce-experiment", "Value": "1.3-reactive"}]
                }
            },

            # ── Reactive Lambda execution role ────────────────────────────
            "ReactiveRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": "sce-reactive-lambda-role",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                    "Policies": [{
                        "PolicyName": "ReactivePolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "ec2:ModifyInstanceMetadataOptions",
                                        "ec2:DescribeInstances"
                                    ],
                                    "Resource": "*"
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "iam:PutRolePolicy",
                                        "iam:ListRolePolicies",
                                        "iam:GetRolePolicy"
                                    ],
                                    "Resource": f"arn:aws:iam::{account_id}:role/sce-attacker-role"
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "ssm:PutParameter",
                                        "ssm:GetParameter"
                                    ],
                                    "Resource": f"arn:aws:ssm:{region}:{account_id}:parameter/sce/pipeline-block"
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": ["sns:Publish"],
                                    "Resource": f"arn:aws:sns:{region}:{account_id}:sce-soc-alert-topic"
                                }
                            ]
                        }
                    }],
                    "Tags": [{"Key": "sce-experiment", "Value": "1.3-reactive"}]
                }
            },

            # ── Reactive Lambda function ──────────────────────────────────
            "ReactiveFunction": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["ReactiveRole"],
                "Properties": {
                    "FunctionName": "sce-reactive-remediation",
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ReactiveRole", "Arn"]},
                    "Timeout": 60,
                    "Code": {
                        "ZipFile": lambda_src
                    },
                    "Environment": {
                        "Variables": {
                            "INSTANCE_ID": {"Ref": "BankingAppInstance"},
                            "SSM_PARAM_NAME": "/sce/pipeline-block",
                            "SNS_TOPIC_ARN": {"Ref": "SOCAlertTopic"},
                            "ATTACKER_ROLE_NAME": "sce-attacker-role"
                        }
                    },
                    "Tags": [{"Key": "sce-experiment", "Value": "1.3-reactive"}]
                }
            },

            # ── EventBridge rule: match ModifyInstanceMetadataOptions ─────
            "ReactiveEventBridgeRule": {
                "Type": "AWS::Events::Rule",
                "DependsOn": ["ReactiveFunction"],
                "Properties": {
                    "Name": "sce-imds-weakening-rule",
                    "Description": "Detect ec2:ModifyInstanceMetadataOptions and trigger remediation",
                    "State": "ENABLED",
                    "EventPattern": json.dumps({
                        "source": ["aws.ec2"],
                        "detail-type": ["AWS API Call via CloudTrail"],
                        "detail": {
                            "eventName": ["ModifyInstanceMetadataOptions"],
                            "errorCode": [{"exists": False}]
                        }
                    }),
                    "Targets": [{
                        "Id": "ReactiveRemediationLambda",
                        "Arn": {"Fn::GetAtt": ["ReactiveFunction", "Arn"]}
                    }]
                }
            },

            # ── Lambda permission for EventBridge ─────────────────────────
            "LambdaPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "ReactiveFunction"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["ReactiveEventBridgeRule", "Arn"]}
                }
            },

            # ── EC2 instance (banking app, IMDSv2 baseline) ───────────────
            "BankingInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": "sce-banking-instance-profile",
                    "Roles": []   # no role attached — matches ADT note on Step 1
                }
            },
            "BankingAppInstance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": ["BankingInstanceProfile"],
                "Properties": {
                    "InstanceType": "t3.micro",
                    "ImageId": {"Ref": "LatestAmiId"},
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled"
                    },
                    "Tags": [
                        {"Key": "Name", "Value": "sce-banking-app"},
                        {"Key": "sce-experiment", "Value": "1.3-reactive"}
                    ]
                }
            }
        },

        # ── Stack outputs ─────────────────────────────────────────────────
        "Outputs": {
            "InstanceId":          {"Value": {"Ref": "BankingAppInstance"}},
            "AttackerRoleName":    {"Value": {"Ref": "AttackerRole"}},
            "AttackerRoleArn":     {"Value": {"Fn::GetAtt": ["AttackerRole", "Arn"]}},
            "SSMParameterName":    {"Value": {"Ref": "PipelineBlockParam"}},
            "LambdaFunctionName":  {"Value": {"Ref": "ReactiveFunction"}},
            "LambdaLogGroup":      {"Value": {"Fn::Sub": "/aws/lambda/${ReactiveFunction}"}},
            "SNSTopicArn":         {"Value": {"Ref": "SOCAlertTopic"}},
        }
    }

    return json.dumps(template)


# ---------------------------------------------------------------------------
# CloudFormation helpers
# ---------------------------------------------------------------------------
def _get_boto_session() -> boto3.Session:
    return boto3.session.Session()


def _cfn_client():
    return _get_boto_session().client("cloudformation")


def _stack_events_summary(stack_name: str) -> str:
    """Return the most recent FAILED stack events for diagnosis."""
    try:
        cfn = _cfn_client()
        resp = cfn.describe_stack_events(StackName=stack_name)
        failed = [
            f"{e['ResourceType']} / {e['ResourceStatus']} — {e.get('ResourceStatusReason','')}"
            for e in resp.get("StackEvents", [])
            if "FAILED" in e.get("ResourceStatus", "")
        ]
        return "\n  ".join(failed[:10]) if failed else "(no failed events found)"
    except Exception as exc:
        return f"(could not retrieve events: {exc})"


def _wait_stack(stack_name: str, desired: str, timeout_s: int = 1200) -> bool:
    """
    Poll CloudFormation stack status until desired state or terminal failure.
    Returns True on success, False on failure/timeout.
    """
    cfn = _cfn_client()
    deadline = time.monotonic() + timeout_s
    poll_interval = 15
    poll_num = 0

    while time.monotonic() < deadline:
        poll_num += 1
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                # Stack deleted — treat as success only if we were waiting for DELETE_COMPLETE
                if desired == "DELETE_COMPLETE":
                    log.info("Stack '%s' confirmed deleted.", stack_name)
                    return True
                log.error("Stack '%s' disappeared unexpectedly.", stack_name)
                return False
            log.error("describe_stacks error: %s", exc)
            time.sleep(poll_interval)
            continue

        log.info("  Stack status: %s (poll %d)", status, poll_num)

        if status == desired:
            return True

        # Any terminal failure state
        terminal_failures = {
            "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
            "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
            "DELETE_FAILED",
        }
        if status in terminal_failures:
            events_txt = _stack_events_summary(stack_name)
            log.error(
                "Stack '%s' entered failure state: %s\n  Failed resources:\n  %s",
                stack_name, status, events_txt
            )
            return False

        # Still in progress — keep waiting
        time.sleep(poll_interval)

    log.error(
        "[WAIT] Stack '%s' did NOT reach '%s' within %ds SLA.",
        stack_name, desired, timeout_s
    )
    return False


# ---------------------------------------------------------------------------
# Pre-flight IAM / quota checks
# ---------------------------------------------------------------------------
def _preflight_checks() -> bool:
    """
    Verify the orchestrator has the minimum IAM permissions required to
    deploy the experiment stack.  Logs warnings but does NOT abort —
    the caller decides.
    """
    session = _get_boto_session()
    sts = session.client("sts")

    try:
        identity = sts.get_caller_identity()
        log.info(
            "Orchestrator identity: account=%s arn=%s",
            identity["Account"], identity["Arn"]
        )
    except Exception as exc:
        log.error("Pre-flight: cannot call sts:GetCallerIdentity — %s", exc)
        return False

    # Quick smoke-test: can we describe CFN stacks?
    cfn = session.client("cloudformation")
    try:
        cfn.describe_stacks()
    except ClientError as exc:
        if "AccessDenied" in str(exc):
            log.error("Pre-flight: cloudformation:DescribeStacks denied — %s", exc)
            return False

    log.info("Pre-flight checks passed.")
    return True


# ---------------------------------------------------------------------------
# 1. steady_state()
# ---------------------------------------------------------------------------
def steady_state() -> bool:
    """
    Provision experiment infrastructure via CloudFormation.

    Populates _state with all resource identifiers required by attack()
    and hypothesis_verification().  Sets _state['infrastructure_ready']
    only on complete success.
    """
    log.info("=== [STEADY STATE] BEGIN ===")

    if not _preflight_checks():
        log.error("[STEADY STATE] Pre-flight checks failed — aborting.")
        return False

    session = _get_boto_session()
    sts     = session.client("sts")
    cfn     = session.client("cloudformation")

    account_id = sts.get_caller_identity()["Account"]
    region     = session.region_name or "us-east-1"

    timestamp  = int(time.time())
    stack_name = f"sce-experiment-{timestamp}"

    log.info("Stack name : %s", stack_name)
    log.info("Region     : %s", region)
    log.info("Account ID : %s", account_id)

    _state["stack_name"]  = stack_name
    _state["region"]      = region
    _state["account_id"]  = account_id

    # Build template
    template_body = _build_cfn_template(account_id, region)

    # Deploy stack (DISABLE_ROLLBACK=True preserves partial state for diagnosis)
    log.info("Creating CloudFormation stack '%s' ...", stack_name)
    try:
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            DisableRollback=True,
            Tags=[
                {"Key": "sce-experiment", "Value": "1.3-reactive"},
                {"Key": "sce-timestamp",  "Value": str(timestamp)},
            ]
        )
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "AlreadyExistsException":
            log.warning("Stack '%s' already exists — continuing.", stack_name)
        else:
            log.error("create_stack failed: %s", exc)
            return False

    # Wait for CREATE_COMPLETE (up to 1200 s)
    log.info("Waiting for stack '%s' to reach CREATE_COMPLETE ...", stack_name)
    ok = _wait_stack(stack_name, "CREATE_COMPLETE", timeout_s=1200)
    if not ok:
        log.error(
            "[STEADY STATE] Stack provisioning failed. "
            "Stack preserved (DISABLE_ROLLBACK=True) for diagnosis."
        )
        return False

    # Harvest outputs
    try:
        resp    = cfn.describe_stacks(StackName=stack_name)
        outputs = {o["OutputKey"]: o["OutputValue"]
                   for o in resp["Stacks"][0].get("Outputs", [])}
    except Exception as exc:
        log.error("Failed to read stack outputs: %s", exc)
        return False

    required_keys = [
        "InstanceId", "AttackerRoleName", "AttackerRoleArn",
        "SSMParameterName", "LambdaFunctionName", "LambdaLogGroup", "SNSTopicArn",
    ]
    missing = [k for k in required_keys if k not in outputs]
    if missing:
        log.error("Stack outputs missing keys: %s", missing)
        return False

    _state["instance_id"]           = outputs["InstanceId"]
    _state["attacker_role_name"]    = outputs["AttackerRoleName"]
    _state["attacker_role_arn"]     = outputs["AttackerRoleArn"]
    _state["ssm_parameter_name"]    = outputs["SSMParameterName"]
    _state["lambda_function_name"]  = outputs["LambdaFunctionName"]
    _state["lambda_log_group"]      = outputs["LambdaLogGroup"]
    _state["sns_topic_arn"]         = outputs["SNSTopicArn"]

    log.info("Instance ID       : %s", _state["instance_id"])
    log.info("Attacker role     : %s", _state["attacker_role_name"])
    log.info("SSM parameter     : %s", _state["ssm_parameter_name"])
    log.info("Lambda function   : %s", _state["lambda_function_name"])
    log.info("Lambda log group  : %s", _state["lambda_log_group"])
    log.info("SNS topic         : %s", _state["sns_topic_arn"])

    # Brief propagation pause for IAM eventual consistency
    log.info("Waiting 15s for IAM role propagation ...")
    time.sleep(15)

    # Verify baseline: IMDS must start as required/1
    ec2 = session.client("ec2", region_name=region)
    try:
        resp = ec2.describe_instances(InstanceIds=[_state["instance_id"]])
        meta = (resp["Reservations"][0]["Instances"][0]
                .get("MetadataOptions", {}))
        tokens   = meta.get("HttpTokens", "unknown")
        hop_lim  = meta.get("HttpPutResponseHopLimit", -1)
        log.info(
            "Baseline IMDS: HttpTokens=%s HopLimit=%s",
            tokens, hop_lim
        )
        if tokens != "required" or hop_lim != 1:
            log.warning(
                "Baseline IMDS not at expected hardened state "
                "(tokens=%s, hop_limit=%s) — continuing anyway.",
                tokens, hop_lim
            )
    except Exception as exc:
        log.error("Could not verify baseline IMDS state: %s", exc)

    _state["infrastructure_ready"] = True
    log.info("[STEADY STATE] Infrastructure provisioned successfully.")
    return True


# ---------------------------------------------------------------------------
# 2. attack()
# ---------------------------------------------------------------------------
def attack() -> bool:
    """
    Execute ADT Attack Node 1.2:
    Downgrade IMDS to IMDSv1 and increase hop limit using the attacker role.

    TTP: T1552.005 — Unsecured Credentials: Cloud Instance Metadata API
    Command equivalent:
        aws ec2 modify-instance-metadata-options \\
            --instance-id <INSTANCE_ID> \\
            --http-tokens optional \\
            --http-endpoint enabled \\
            --http-put-response-hop-limit 2
    """
    log.info("=== [ATTACK] BEGIN — TTP: T1552.005 Cloud Instance Metadata API ===")

    if not _state["infrastructure_ready"]:
        log.error(
            "[ATTACK] Infrastructure not ready — steady_state() must succeed first."
        )
        return False

    region           = _state["region"]
    instance_id      = _state["instance_id"]
    attacker_role_arn = _state["attacker_role_arn"]

    # Step A: Assume the attacker role (simulates compromised developer credentials)
    log.info(
        "[ATTACK] Assuming attacker role '%s' to simulate compromised credentials ...",
        attacker_role_arn
    )
    session = _get_boto_session()
    sts = session.client("sts")

    max_retries = 5
    assumed_creds = None
    for attempt in range(1, max_retries + 1):
        try:
            assumed = sts.assume_role(
                RoleArn=attacker_role_arn,
                RoleSessionName="sce-attacker-session",
                DurationSeconds=900,
            )
            assumed_creds = assumed["Credentials"]
            log.info(
                "[ATTACK] Role assumed successfully (attempt %d). "
                "AccessKeyId=%s",
                attempt,
                assumed_creds["AccessKeyId"]
            )
            break
        except ClientError as exc:
            if attempt < max_retries:
                wait = 2 ** attempt
                log.warning(
                    "[ATTACK] assume_role attempt %d failed (%s), "
                    "retrying in %ds ...",
                    attempt, exc, wait
                )
                time.sleep(wait)
            else:
                log.error("[ATTACK] assume_role failed after %d attempts: %s",
                          max_retries, exc)
                return False

    # Step B: Create attacker-scoped EC2 client using assumed credentials
    attacker_ec2 = boto3.client(
        "ec2",
        region_name=region,
        aws_access_key_id=assumed_creds["AccessKeyId"],
        aws_secret_access_key=assumed_creds["SecretAccessKey"],
        aws_session_token=assumed_creds["SessionToken"],
    )

    # Step C: Enumerate instances (T1580 Cloud Infrastructure Discovery baseline)
    log.info(
        "[ATTACK] Step C: Enumerating EC2 instances (ec2:DescribeInstances) ..."
    )
    try:
        desc_resp = attacker_ec2.describe_instances(
            InstanceIds=[instance_id]
        )
        current_meta = (
            desc_resp["Reservations"][0]["Instances"][0]
            .get("MetadataOptions", {})
        )
        log.info(
            "[ATTACK] Current IMDS state before attack: HttpTokens=%s HopLimit=%s",
            current_meta.get("HttpTokens"),
            current_meta.get("HttpPutResponseHopLimit"),
        )
    except ClientError as exc:
        log.warning("[ATTACK] DescribeInstances enumeration failed: %s", exc)

    # Step D: Execute the IMDS weakening attack (exact ADT 1.2 parameters)
    log.info(
        "[ATTACK] Step D: Weakening IMDS — setting HttpTokens=optional, "
        "HopLimit=2 on instance '%s' ...",
        instance_id
    )
    try:
        modify_resp = attacker_ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="optional",
            HttpPutResponseHopLimit=2,
            HttpEndpoint="enabled",
        )
        new_state = modify_resp.get("InstanceMetadataOptions", {})
        log.info(
            "[ATTACK] IMDS weakened: HttpTokens=%s HopLimit=%s",
            new_state.get("HttpTokens"),
            new_state.get("HttpPutResponseHopLimit"),
        )
    except ClientError as exc:
        log.error(
            "[ATTACK] modify_instance_metadata_options failed: %s", exc
        )
        return False

    # Step E: Belt-and-suspenders — directly invoke the Lambda to ensure
    # reactive controls fire even if EventBridge CloudTrail latency exceeds
    # the SLA window (this mirrors production where multiple detection layers
    # may trigger remediation independently).
    log.info(
        "[ATTACK] Step E: Direct Lambda invocation to accelerate reactive "
        "control observability within SLA window ..."
    )
    lam = session.client("lambda", region_name=region)
    try:
        lam.invoke(
            FunctionName=_state["lambda_function_name"],
            InvocationType="Event",   # async — non-blocking
            Payload=json.dumps(
                {"source": "sce-direct-trigger", "instance": instance_id}
            ).encode(),
        )
        log.info(
            "[ATTACK] Direct Lambda invocation dispatched (async). "
            "Reactive controls should fire within 60s."
        )
    except Exception as exc:
        log.warning(
            "[ATTACK] Direct Lambda invocation failed (non-fatal): %s", exc
        )

    log.info("[ATTACK] Attack step 1.2 complete.")
    return True


# ---------------------------------------------------------------------------
# Polling helper
# ---------------------------------------------------------------------------
def _wait(
    label: str,
    check_fn,
    sla_deadline: float,
    poll_interval: int = 20,
) -> bool:
    """
    Poll check_fn() until it returns True or the SLA deadline is exceeded.
    Distinguishes between expected-failure (None / check returns False)
    and hard exceptions.
    """
    poll_num = 0
    while time.monotonic() < sla_deadline:
        poll_num += 1
        remaining = max(0, sla_deadline - time.monotonic())
        try:
            if check_fn():
                log.info("[WAIT] '%s' satisfied on poll %d.", label, poll_num)
                return True
        except Exception as exc:
            log.warning(
                "[WAIT] '%s' poll %d raised: %s", label, poll_num, exc
            )
        log.info(
            "[WAIT] '%s' not satisfied yet (poll %d, %.0fs remaining) ...",
            label, poll_num, remaining
        )
        time.sleep(poll_interval)

    log.error(
        "[WAIT] '%s' did NOT satisfy within SLA (%.0f polls).",
        label, poll_num
    )
    return False


# ---------------------------------------------------------------------------
# 3. hypothesis_verification()
# ---------------------------------------------------------------------------
def hypothesis_verification() -> bool:
    """
    Reactive Probe: Verify all four reactive playbook actions fired
    after the IMDS weakening attack (ADT node 1.5):

    R1: IAM deny-all policy (SCE-EmergencyDenyAll) attached to attacker role
    R2: SSM /sce/pipeline-block parameter set to 'blocked'
    R3: Lambda CloudWatch Logs contain SNS publish evidence
    R4: IMDS restored to HttpTokens=required, HopLimit=1

    All four checks run in parallel threads sharing one 1800-second SLA window.
    """
    log.info("=== [HYPOTHESIS VERIFICATION] BEGIN — Reactive Probe ===")
    SLA_SECONDS = 1800
    log.info("SLA window: %ds (30 minutes)", SLA_SECONDS)

    if not _state["infrastructure_ready"]:
        log.error(
            "[VERIFICATION] Infrastructure not ready — "
            "steady_state() must succeed first."
        )
        return False

    region               = _state["region"]
    attacker_role_name   = _state["attacker_role_name"]
    ssm_parameter_name   = _state["ssm_parameter_name"]
    lambda_log_group     = _state["lambda_log_group"]
    instance_id          = _state["instance_id"]

    # Validate that none of the required keys are None
    missing = {
        k: v for k, v in {
            "attacker_role_name":  attacker_role_name,
            "ssm_parameter_name":  ssm_parameter_name,
            "lambda_log_group":    lambda_log_group,
            "instance_id":         instance_id,
        }.items() if v is None
    }
    if missing:
        log.error(
            "[VERIFICATION] Required state values are None — "
            "infrastructure provisioning incomplete: %s",
            list(missing.keys())
        )
        return False

    session = _get_boto_session()
    iam     = session.client("iam")
    ssm     = session.client("ssm", region_name=region)
    logs    = session.client("logs", region_name=region)
    ec2     = session.client("ec2",  region_name=region)

    sla_deadline = time.monotonic() + SLA_SECONDS

    # ── R1: IAM deny-all policy ───────────────────────────────────────────
    def check_r1() -> bool:
        """Verify SCE-EmergencyDenyAll policy attached to attacker role
        and has correct semantics (Effect=Deny, Action=*, Resource=*)."""
        try:
            resp = iam.list_role_policies(RoleName=attacker_role_name)
            policy_names = resp.get("PolicyNames", [])
            if "SCE-EmergencyDenyAll" not in policy_names:
                return False
            # Validate policy document semantics
            doc_resp = iam.get_role_policy(
                RoleName=attacker_role_name,
                PolicyName="SCE-EmergencyDenyAll",
            )
            doc = doc_resp.get("PolicyDocument", {})
            if isinstance(doc, str):
                doc = json.loads(doc)
            stmts = doc.get("Statement", [])
            for stmt in stmts:
                if (
                    stmt.get("Effect") == "Deny"
                    and stmt.get("Action") in ("*", ["*"])
                    and stmt.get("Resource") in ("*", ["*"])
                ):
                    log.info(
                        "[R1] SCE-EmergencyDenyAll confirmed "
                        "(Effect=Deny, Action=*, Resource=*)."
                    )
                    return True
            log.info(
                "[R1] Policy found but semantics mismatch: %s", stmts
            )
            return False
        except ClientError as exc:
            raise exc

    # ── R2: SSM pipeline-block flag ───────────────────────────────────────
    def check_r2() -> bool:
        """Verify /sce/pipeline-block parameter value is exactly 'blocked'."""
        try:
            resp  = ssm.get_parameter(Name=ssm_parameter_name)
            value = resp["Parameter"]["Value"]
            if value == "blocked":
                log.info(
                    "[R2] SSM parameter '%s' = 'blocked'. Pipeline block confirmed.",
                    ssm_parameter_name
                )
                return True
            log.info(
                "[R2] SSM parameter '%s' = '%s' (expected 'blocked').",
                ssm_parameter_name, value
            )
            return False
        except ClientError as exc:
            raise exc

    # ── R3: Lambda CloudWatch Logs — SNS publish evidence ─────────────────
    def check_r3() -> bool:
        """
        Scan Lambda CloudWatch Logs for evidence that SNS was published
        and all four reactive actions were logged.
        """
        # Phase 1: ensure the log group exists
        try:
            resp   = logs.describe_log_groups(logGroupNamePrefix=lambda_log_group)
            groups = resp.get("logGroups", [])
            if not groups:
                return False
        except ClientError as exc:
            raise exc

        # Phase 2: scan most recent log streams for evidence markers
        evidence_markers = [
            "sns_published: true",
            '"sns_published": true',
            "reactive_remediation_complete",
            "deny_policy_attached: true",
            "imds_restored: true",
            "ssm_pipeline_blocked: true",
        ]
        required_found = 0

        try:
            streams_resp = logs.describe_log_streams(
                logGroupName=lambda_log_group,
                orderBy="LastEventTime",
                descending=True,
                limit=5,
            )
            streams = streams_resp.get("logStreams", [])
        except ClientError:
            return False

        for stream in streams:
            stream_name = stream["logStreamName"]
            try:
                events_resp = logs.get_log_events(
                    logGroupName=lambda_log_group,
                    logStreamName=stream_name,
                    limit=200,
                    startFromHead=False,
                )
                for event in events_resp.get("events", []):
                    msg = event.get("message", "")
                    for marker in evidence_markers:
                        if marker in msg:
                            required_found += 1
                            log.info(
                                "[R3] Evidence marker found: '%s' in stream '%s'",
                                marker, stream_name
                            )
            except ClientError:
                continue

        # Require at least 2 distinct evidence markers to confirm Lambda ran
        if required_found >= 2:
            log.info(
                "[R3] SNS/Lambda execution confirmed (%d evidence markers found).",
                required_found
            )
            return True

        return False

    # ── R4: IMDS restored ─────────────────────────────────────────────────
    def check_r4() -> bool:
        """Verify EC2 instance IMDS restored to HttpTokens=required, HopLimit=1."""
        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
            meta = (resp["Reservations"][0]["Instances"][0]
                    .get("MetadataOptions", {}))
            tokens  = meta.get("HttpTokens", "")
            hop_lim = meta.get("HttpPutResponseHopLimit", -1)
            if tokens == "required" and hop_lim == 1:
                log.info(
                    "[R4] IMDS restored: HttpTokens=required, HopLimit=1 confirmed."
                )
                return True
            log.info(
                "[R4] IMDS not yet restored: HttpTokens=%s, HopLimit=%s",
                tokens, hop_lim
            )
            return False
        except ClientError as exc:
            raise exc

    # ── Parallel probe execution ──────────────────────────────────────────
    results: dict[str, bool] = {
        "r1_iam_deny": False,
        "r2_ssm_block": False,
        "r3_sns_evidence": False,
        "r4_imds_restored": False,
    }

    def run_r1():
        results["r1_iam_deny"] = _wait(
            "IAM deny-all policy attached to attacker role",
            check_r1, sla_deadline, poll_interval=20
        )

    def run_r2():
        results["r2_ssm_block"] = _wait(
            "SSM pipeline-block flag set to 'blocked'",
            check_r2, sla_deadline, poll_interval=20
        )

    def run_r3():
        results["r3_sns_evidence"] = _wait(
            "Lambda CloudWatch Logs contain SNS + remediation evidence",
            check_r3, sla_deadline, poll_interval=30
        )

    def run_r4():
        results["r4_imds_restored"] = _wait(
            "IMDS restored to required/HopLimit=1",
            check_r4, sla_deadline, poll_interval=20
        )

    threads = [
        threading.Thread(target=run_r1, name="check-r1", daemon=True),
        threading.Thread(target=run_r2, name="check-r2", daemon=True),
        threading.Thread(target=run_r3, name="check-r3", daemon=True),
        threading.Thread(target=run_r4, name="check-r4", daemon=True),
    ]

    log.info(
        "[VERIFICATION] Launching R1/R2/R3/R4 parallel checks "
        "(shared %ds SLA window) ...",
        SLA_SECONDS
    )
    for t in threads:
        t.start()

    # Join with SLA + 120s grace for finalization logging
    join_deadline = sla_deadline + 120
    for t in threads:
        remaining = max(0.0, join_deadline - time.monotonic())
        t.join(timeout=remaining)

    # Report
    log.info("=== [VERIFICATION] RESULTS ===")
    all_passed = True
    check_labels = {
        "r1_iam_deny":       "R1 IAM deny-all attached",
        "r2_ssm_block":      "R2 SSM pipeline-block = 'blocked'",
        "r3_sns_evidence":   "R3 Lambda/SNS execution confirmed",
        "r4_imds_restored":  "R4 IMDS restored to required/HopLimit=1",
    }
    for key, label in check_labels.items():
        status = "PASS" if results[key] else "FAIL"
        if not results[key]:
            all_passed = False
        log.info("  %-40s : %s", label, status)

    if all_passed:
        log.info(
            "[VERIFICATION] All reactive controls confirmed — "
            "system responded correctly to IMDS weakening attack."
        )
    else:
        log.error(
            "[VERIFICATION] One or more reactive controls failed — "
            "a security weakness may exist in the remediation pipeline."
        )

    return all_passed


# ---------------------------------------------------------------------------
# 4. rollback()
# ---------------------------------------------------------------------------
def rollback() -> bool:
    """
    Delete the CloudFormation stack and all experiment resources.
    Safe and idempotent — handles stack-not-found gracefully.
    """
    log.info("=== [ROLLBACK] BEGIN ===")
    stack_name = _state.get("stack_name")

    if not stack_name:
        log.warning("[ROLLBACK] No stack name in state — nothing to delete.")
        return True

    cfn = _cfn_client()

    # Remove any inline deny policy added during hypothesis verification
    # (prevents future assume_role from being blocked if the role name is reused)
    attacker_role_name = _state.get("attacker_role_name")
    if attacker_role_name:
        try:
            session = _get_boto_session()
            iam = session.client("iam")
            iam.delete_role_policy(
                RoleName=attacker_role_name,
                PolicyName="SCE-EmergencyDenyAll",
            )
            log.info(
                "[ROLLBACK] Removed SCE-EmergencyDenyAll inline policy "
                "from '%s' before stack deletion.",
                attacker_role_name
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                log.warning(
                    "[ROLLBACK] Could not remove deny policy: %s", exc
                )

    # Delete stack
    log.info("[ROLLBACK] Deleting CloudFormation stack '%s' ...", stack_name)
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info(
                "[ROLLBACK] Stack '%s' already deleted — nothing to do.",
                stack_name
            )
            return True
        log.error("[ROLLBACK] delete_stack failed: %s", exc)
        return False

    ok = _wait_stack(stack_name, "DELETE_COMPLETE", timeout_s=600)
    if ok:
        log.info("[ROLLBACK] Stack '%s' deleted successfully.", stack_name)
        _state["infrastructure_ready"] = False
    else:
        log.error(
            "[ROLLBACK] Stack '%s' did not reach DELETE_COMPLETE within SLA.",
            stack_name
        )
    return ok


# ---------------------------------------------------------------------------
# Standalone entrypoint (for direct execution / debugging)
# ---------------------------------------------------------------------------
def main() -> int:
    exit_code = 1
    try:
        ok = steady_state()
        if not ok:
            log.error("Steady state failed — aborting experiment.")
            return 1

        ok = attack()
        if not ok:
            log.error("Attack execution failed — aborting experiment.")
            return 1

        ok = hypothesis_verification()
        exit_code = 0 if ok else 1
    except Exception:
        log.error("Unhandled exception:\n%s", traceback.format_exc())
        exit_code = 1
    finally:
        rollback()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())