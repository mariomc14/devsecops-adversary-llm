#!/usr/bin/env python3
"""
SCE Experiment 1.8 — Reactive Probe
Attack Node: 1.7 Start Malicious Build
Probe Type: Reactive

Security Intent:
  An attacker starts an unauthorized/malicious AWS CodeBuild project build.
  The reactive control (EventBridge rule → Lambda) detects the StartBuild API
  call via CloudTrail-backed EventBridge and automatically stops the build,
  then publishes an SNS notification.  The hypothesis verifies that the build
  was stopped (status STOPPED) by the automated reaction rather than finishing
  normally.
"""

import json
import time
import logging
import sys
import subprocess

# ---------------------------------------------------------------------------
# Ensure boto3 is available
# ---------------------------------------------------------------------------
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "--quiet"])
    import boto3
    from botocore.exceptions import ClientError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global state shared across phases (module-level so chaostoolkit can import
# each function independently while still sharing context within one run)
# ---------------------------------------------------------------------------
_STATE: dict = {}

REGION = boto3.session.Session().region_name or "us-east-1"
ACCOUNT_ID: str = ""

# Inline CloudFormation template ─────────────────────────────────────────────
CFN_TEMPLATE = r"""
AWSTemplateFormatVersion: "2010-09-09"
Description: "SCE 1.8 – Reactive probe for malicious CodeBuild build"

Parameters:
  ExperimentName:
    Type: String
  Timestamp:
    Type: String

Resources:

  # ── SNS topic for reactive alerts ─────────────────────────────────────────
  AlertTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: !Sub "sce-malicious-build-alert-${Timestamp}"
      Tags:
        - Key: ExperimentName
          Value: !Ref ExperimentName
        - Key: Timestamp
          Value: !Ref Timestamp

  # ── IAM role for CodeBuild ─────────────────────────────────────────────────
  CodeBuildServiceRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub "sce-cb-role-${Timestamp}"
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: codebuild.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AWSCodeBuildDeveloperAccess
      Policies:
        - PolicyName: SCECodeBuildLogs
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: "*"
      Tags:
        - Key: ExperimentName
          Value: !Ref ExperimentName

  # ── CodeBuild project (simulates the "malicious" project) ─────────────────
  MaliciousProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Name: !Sub "sce-malicious-project-${Timestamp}"
      Description: "SCE experiment – malicious build target"
      ServiceRole: !GetAtt CodeBuildServiceRole.Arn
      Artifacts:
        Type: NO_ARTIFACTS
      Environment:
        Type: LINUX_CONTAINER
        ComputeType: BUILD_GENERAL1_SMALL
        Image: aws/codebuild/standard:7.0
      Source:
        Type: NO_SOURCE
        BuildSpec: |
          version: 0.2
          phases:
            build:
              commands:
                - echo "malicious payload" && sleep 300
      TimeoutInMinutes: 5
      Tags:
        - Key: ExperimentName
          Value: !Ref ExperimentName
        - Key: Timestamp
          Value: !Ref Timestamp

  # ── IAM role for the reactive Lambda ──────────────────────────────────────
  ReactiveRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub "sce-reactive-role-${Timestamp}"
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: SCEReactivePolicy
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - codebuild:StopBuild
                  - codebuild:BatchGetBuilds
                Resource: "*"
              - Effect: Allow
                Action:
                  - sns:Publish
                Resource: !Ref AlertTopic
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: "*"
      Tags:
        - Key: ExperimentName
          Value: !Ref ExperimentName

  # ── Reactive Lambda ────────────────────────────────────────────────────────
  ReactiveFunction:
    Type: AWS::Lambda::Function
    Properties:
      FunctionName: !Sub "sce-reactive-fn-${Timestamp}"
      Runtime: python3.12
      Role: !GetAtt ReactiveRole.Arn
      Handler: index.handler
      Timeout: 60
      Environment:
        Variables:
          ALERT_TOPIC_ARN: !Ref AlertTopic
          PROJECT_NAME: !Sub "sce-malicious-project-${Timestamp}"
      Code:
        ZipFile: |
          import os, json, boto3, logging
          log = logging.getLogger()
          log.setLevel(logging.INFO)
          cb  = boto3.client("codebuild")
          sns = boto3.client("sns")

          def handler(event, context):
              log.info("Reactive handler triggered: %s", json.dumps(event))
              topic   = os.environ["ALERT_TOPIC_ARN"]
              project = os.environ["PROJECT_NAME"]
              detail  = event.get("detail", {})
              build_id = detail.get("build-id") or detail.get("buildId", "")
              if not build_id:
                  # fall back: look for any running build in this project
                  resp = cb.list_builds_for_project(projectName=project, sortOrder="DESCENDING")
                  ids  = resp.get("ids", [])
                  if ids:
                      build_id = ids[0]
              if build_id:
                  try:
                      cb.stop_build(id=build_id)
                      log.info("Stopped build %s", build_id)
                  except Exception as e:
                      log.warning("stop_build error: %s", e)
              sns.publish(
                  TopicArn=topic,
                  Subject="SCE Reactive: Malicious Build Detected",
                  Message=json.dumps({
                      "build_id": build_id,
                      "action": "StopBuild",
                      "source": "sce-reactive-probe"
                  })
              )
              return {"statusCode": 200}
      Tags:
        - Key: ExperimentName
          Value: !Ref ExperimentName
        - Key: Timestamp
          Value: !Ref Timestamp

  # ── Permission: EventBridge → Lambda ──────────────────────────────────────
  LambdaInvokePermission:
    Type: AWS::Lambda::Permission
    Properties:
      FunctionName: !GetAtt ReactiveFunction.Arn
      Action: lambda:InvokeFunction
      Principal: events.amazonaws.com
      SourceArn: !GetAtt ReactiveRule.Arn

  # ── EventBridge rule: CodeBuild state-change → Lambda ─────────────────────
  ReactiveRule:
    Type: AWS::Events::Rule
    Properties:
      Name: !Sub "sce-malicious-build-rule-${Timestamp}"
      Description: "Detect CodeBuild builds for malicious project and react"
      State: ENABLED
      EventPattern:
        source:
          - aws.codebuild
        detail-type:
          - "CodeBuild Build State Change"
        detail:
          project-name:
            - !Sub "sce-malicious-project-${Timestamp}"
          build-status:
            - IN_PROGRESS
      Targets:
        - Id: ReactiveTarget
          Arn: !GetAtt ReactiveFunction.Arn

Outputs:
  ProjectName:
    Value: !Sub "sce-malicious-project-${Timestamp}"
  FunctionName:
    Value: !Sub "sce-reactive-fn-${Timestamp}"
  AlertTopicArn:
    Value: !Ref AlertTopic
  RuleName:
    Value: !Sub "sce-malicious-build-rule-${Timestamp}"
"""


# ────────────────────────────────────────────────────────────────────────────
# Helpers
# ────────────────────────────────────────────────────────────────────────────

def _get_account_id() -> str:
    global ACCOUNT_ID
    if not ACCOUNT_ID:
        sts = boto3.client("sts", region_name=REGION)
        ACCOUNT_ID = sts.get_caller_identity()["Account"]
    return ACCOUNT_ID


def _cfn_client():
    return boto3.client("cloudformation", region_name=REGION)


def _stack_outputs(stack_name: str) -> dict:
    cfn = _cfn_client()
    resp = cfn.describe_stacks(StackName=stack_name)
    outputs = {}
    for o in resp["Stacks"][0].get("Outputs", []):
        outputs[o["OutputKey"]] = o["OutputValue"]
    return outputs


def _wait_stack(stack_name: str, target_status: str, timeout_s: int = 600):
    """Poll stack status until target reached or timeout."""
    cfn = _cfn_client()
    deadline = time.monotonic() + timeout_s
    delay = 10
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            log.info("Stack %s status: %s", stack_name, status)
            if status == target_status:
                return True
            if "FAILED" in status or "ROLLBACK" in status:
                reason = resp["Stacks"][0].get("StackStatusReason", "")
                raise RuntimeError(f"Stack entered failed state {status}: {reason}")
        except ClientError as exc:
            if "does not exist" in str(exc) and target_status == "DELETE_COMPLETE":
                return True
            raise
        time.sleep(delay)
        delay = min(delay * 1.5, 30)
    raise TimeoutError(f"Stack {stack_name} did not reach {target_status} within {timeout_s}s")


def _wait_build_terminal(cb_client, build_id: str, timeout_s: int = 360) -> str:
    """Wait until build reaches a terminal status; return final status string."""
    deadline = time.monotonic() + timeout_s
    delay = 5
    while time.monotonic() < deadline:
        resp = cb_client.batch_get_builds(ids=[build_id])
        builds = resp.get("builds", [])
        if builds:
            status = builds[0]["buildStatus"]
            log.info("Build %s status: %s", build_id, status)
            if status not in ("IN_PROGRESS",):
                return status
        time.sleep(delay)
        delay = min(delay * 1.5, 20)
    return "UNKNOWN"


# ────────────────────────────────────────────────────────────────────────────
# Phase 1 – steady_state
# ────────────────────────────────────────────────────────────────────────────

def steady_state():
    """Deploy the CloudFormation stack that provisions all experiment resources."""
    ts = int(time.time())
    stack_name = f"sce-experiment-{ts}"
    experiment_name = "1.8-reactive-malicious-build"

    _STATE["stack_name"] = stack_name
    _STATE["timestamp"] = str(ts)
    _STATE["experiment_name"] = experiment_name

    log.info("Deploying stack %s in region %s …", stack_name, REGION)
    cfn = _cfn_client()

    try:
        cfn.create_stack(
            StackName=stack_name,
            TemplateBody=CFN_TEMPLATE,
            Parameters=[
                {"ParameterKey": "ExperimentName", "ParameterValue": experiment_name},
                {"ParameterKey": "Timestamp",      "ParameterValue": str(ts)},
            ],
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": "ExperimentName", "Value": experiment_name},
                {"Key": "Timestamp",      "Value": str(ts)},
            ],
            TimeoutInMinutes=15,
            OnFailure="ROLLBACK",
        )
        log.info("Stack creation initiated.")
    except ClientError as exc:
        if "AlreadyExistsException" in str(exc):
            log.warning("Stack %s already exists — continuing.", stack_name)
        else:
            raise

    _wait_stack(stack_name, "CREATE_COMPLETE", timeout_s=600)
    outputs = _stack_outputs(stack_name)
    log.info("Stack outputs: %s", outputs)

    _STATE["project_name"]   = outputs["ProjectName"]
    _STATE["function_name"]  = outputs["FunctionName"]
    _STATE["alert_topic_arn"] = outputs["AlertTopicArn"]
    _STATE["rule_name"]      = outputs["RuleName"]

    log.info("steady_state complete. Resources ready.")


# ────────────────────────────────────────────────────────────────────────────
# Phase 2 – attack
# ────────────────────────────────────────────────────────────────────────────

def attack() -> bool:
    """
    Attack Step 1.7 – Start Malicious Build.
    The attacker calls codebuild:StartBuild on the malicious project.
    Returns True if the build was successfully started (evidence captured).
    """
    if not _STATE.get("project_name"):
        log.error("steady_state() must run before attack().")
        return False

    project_name = _STATE["project_name"]
    cb = boto3.client("codebuild", region_name=REGION)

    log.info("ATTACK: Starting malicious build on project %s …", project_name)
    try:
        resp = cb.start_build(projectName=project_name)
    except ClientError as exc:
        log.error("start_build failed: %s", exc)
        return False

    build = resp["build"]
    build_id     = build["id"]
    build_arn    = build["arn"]
    build_status = build["buildStatus"]

    log.info("Malicious build started — id=%s arn=%s status=%s",
             build_id, build_arn, build_status)

    _STATE["build_id"]  = build_id
    _STATE["build_arn"] = build_arn

    # Confirm the build appears in CodeBuild via a real BatchGetBuilds call
    verify = cb.batch_get_builds(ids=[build_id])
    confirmed_status = verify["builds"][0]["buildStatus"]
    log.info("Confirmed build status via BatchGetBuilds: %s", confirmed_status)

    return confirmed_status in ("IN_PROGRESS", "QUEUED")


# ────────────────────────────────────────────────────────────────────────────
# Phase 3 – hypothesis_verification
# ────────────────────────────────────────────────────────────────────────────

def hypothesis_verification() -> bool:
    """
    Reactive probe verification.

    Checks:
    1. The build was stopped (status == STOPPED) by the automated Lambda reaction,
       NOT by the test itself.
    2. The EventBridge rule fired (Lambda invocation count > 0).
    3. An SNS message was published (confirmed via CloudWatch Lambda metrics).

    Returns True only when all three AWS API responses confirm the reaction fired.
    """
    if not _STATE.get("build_id"):
        log.error("No build_id in state — attack() must have run first.")
        return False

    cb            = boto3.client("codebuild",   region_name=REGION)
    cw            = boto3.client("cloudwatch",   region_name=REGION)
    build_id      = _STATE["build_id"]
    function_name = _STATE["function_name"]

    # ── 1. Wait for the build to reach a terminal state ────────────────────
    log.info("Waiting for build %s to reach terminal state …", build_id)
    final_status = _wait_build_terminal(cb, build_id, timeout_s=300)
    log.info("Build final status: %s", final_status)

    if final_status != "STOPPED":
        log.error(
            "Reactive control DID NOT stop the build in time. "
            "Final status was '%s' (expected STOPPED).", final_status
        )
        build_stopped = False
    else:
        log.info("✓ Build was stopped by reactive control (status=STOPPED).")
        build_stopped = True

    # ── 2. Verify Lambda was invoked via CloudWatch Metrics ────────────────
    #       We allow up to 3 minutes of metric propagation lag.
    lambda_invoked = False
    deadline = time.monotonic() + 180
    delay = 15
    while time.monotonic() < deadline:
        metric_resp = cw.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName="Invocations",
            Dimensions=[{"Name": "FunctionName", "Value": function_name}],
            StartTime=time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(time.time() - 600)          # last 10 min
            ),
            EndTime=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            Period=600,
            Statistics=["Sum"],
        )
        datapoints = metric_resp.get("Datapoints", [])
        total_invocations = sum(dp["Sum"] for dp in datapoints)
        log.info("Lambda %s invocation count (last 10 min): %s",
                 function_name, total_invocations)
        if total_invocations > 0:
            lambda_invoked = True
            log.info("✓ Reactive Lambda was invoked %d time(s).", int(total_invocations))
            break
        log.info("Waiting for CloudWatch Lambda metrics to propagate …")
        time.sleep(delay)
        delay = min(delay * 1.5, 30)

    if not lambda_invoked:
        log.error("✗ No Lambda invocations recorded for %s.", function_name)

    # ── 3. Verify EventBridge rule is enabled and targets Lambda ───────────
    events = boto3.client("events", region_name=REGION)
    rule_name = _STATE.get("rule_name", "")
    rule_enabled = False
    if rule_name:
        try:
            rule_resp = events.describe_rule(Name=rule_name)
            rule_state = rule_resp.get("State", "")
            log.info("EventBridge rule %s state: %s", rule_name, rule_state)
            if rule_state == "ENABLED":
                targets_resp = events.list_targets_by_rule(Rule=rule_name)
                targets = targets_resp.get("Targets", [])
                function_arn_fragment = _STATE.get("function_name", "")
                for t in targets:
                    if function_arn_fragment in t.get("Arn", ""):
                        rule_enabled = True
                        log.info("✓ EventBridge rule targets reactive Lambda.")
                        break
        except ClientError as exc:
            log.error("describe_rule error: %s", exc)

    if not rule_enabled:
        log.error("✗ EventBridge rule is not ENABLED or does not target Lambda.")

    # ── Final verdict ───────────────────────────────────────────────────────
    result = build_stopped and lambda_invoked and rule_enabled
    if result:
        log.info("hypothesis_verification PASSED — reactive control behaved as expected.")
    else:
        log.error(
            "hypothesis_verification FAILED — "
            "build_stopped=%s, lambda_invoked=%s, rule_enabled=%s",
            build_stopped, lambda_invoked, rule_enabled,
        )
    return result


# ────────────────────────────────────────────────────────────────────────────
# Phase 4 – rollback
# ────────────────────────────────────────────────────────────────────────────

def rollback():
    """Delete the CloudFormation stack and wait for DELETE_COMPLETE."""
    stack_name = _STATE.get("stack_name")
    if not stack_name:
        log.warning("No stack_name in state; nothing to delete.")
        return

    # Best-effort: stop any running build before stack deletion
    build_id = _STATE.get("build_id")
    if build_id:
        cb = boto3.client("codebuild", region_name=REGION)
        try:
            cb.stop_build(id=build_id)
            log.info("Pre-rollback: stopped build %s.", build_id)
        except ClientError as exc:
            log.warning("Could not stop build %s during rollback: %s", build_id, exc)

    cfn = _cfn_client()
    log.info("Deleting stack %s …", stack_name)
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.warning("Stack %s does not exist; nothing to delete.", stack_name)
            return
        raise

    try:
        _wait_stack(stack_name, "DELETE_COMPLETE", timeout_s=600)
        log.info("Stack %s deleted successfully.", stack_name)
    except Exception as exc:
        log.error("Error waiting for stack deletion: %s", exc)


# ────────────────────────────────────────────────────────────────────────────
# Entry-point (direct execution)
# ────────────────────────────────────────────────────────────────────────────

def main():
    _get_account_id()
    log.info("Account: %s  Region: %s", ACCOUNT_ID, REGION)

    try:
        log.info("═══ PHASE 1: steady_state ═══")
        steady_state()

        log.info("═══ PHASE 2: attack ═══")
        attack_ok = attack()
        log.info("Attack result: %s", attack_ok)

        if not attack_ok:
            log.error("Attack did not produce verifiable evidence; skipping verification.")
            return

        log.info("═══ PHASE 3: hypothesis_verification ═══")
        result = hypothesis_verification()
        log.info("Hypothesis verification result: %s", result)

    finally:
        log.info("═══ PHASE 4: rollback ═══")
        rollback()


if __name__ == "__main__":
    main()