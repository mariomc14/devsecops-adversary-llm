"""
SCE Experiment 1.8 – Detective Probe
Attack Node: 1.7 Start Malicious Build

Security Intent:
  Detect when a malicious/unauthorized CodeBuild project is started (or an
  existing project is hijacked to run arbitrary commands). The detective
  control uses CloudTrail + CloudWatch Events (EventBridge) to alert on
  unexpected StartBuild API calls and verifies that the event was captured
  and the corresponding CloudWatch Alarm transitions to ALARM state.

Attack Simulation:
  1. Create a rogue CodeBuild project whose build spec runs a clearly
     malicious command (e.g. exfiltrates environment variables).
  2. Trigger a build (StartBuild) against that project.
  3. The detective control – an EventBridge rule that matches
     codebuild:StartBuild events and routes them to a CloudWatch log group,
     plus a metric filter + alarm – must fire.

Verification:
  Query CloudWatch to confirm the alarm is in ALARM state (or that at least
  one matched event was delivered to the log group), proving the detective
  control observed the malicious build invocation.
"""

import json
import time
import logging
import sys
import subprocess

# ── ensure boto3 is available ──────────────────────────────────────────────────
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
    import boto3
    from botocore.exceptions import ClientError

# ── logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── module-level state (shared between phases) ─────────────────────────────────
_state: dict = {}

# ── helpers ────────────────────────────────────────────────────────────────────

def _boto(service: str):
    return boto3.client(service)


def _account_id() -> str:
    return boto3.client("sts").get_caller_identity()["Account"]


def _region() -> str:
    return boto3.session.Session().region_name or "us-east-1"


def _wait_stack(cf, stack_name: str, target_status: str, timeout: int = 600):
    """Poll until the stack reaches *target_status* or timeout."""
    deadline = time.monotonic() + timeout
    delay = 10
    while time.monotonic() < deadline:
        try:
            resp = cf.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            log.info("Stack %s → %s", stack_name, status)
            if status == target_status:
                return True
            if "FAILED" in status or "ROLLBACK" in status:
                log.error("Stack entered failure state: %s", status)
                return False
        except ClientError as exc:
            if "does not exist" in str(exc):
                if target_status == "DELETE_COMPLETE":
                    return True
                log.error("Stack disappeared unexpectedly.")
                return False
            log.error("describe_stacks error: %s", exc)
        time.sleep(delay)
        delay = min(delay * 1.5, 60)
    log.error("Timed out waiting for stack %s → %s", stack_name, target_status)
    return False


# ── CloudFormation template ────────────────────────────────────────────────────

def _cfn_template(stack_name: str, account_id: str, region: str) -> str:
    """
    Provisions:
      • IAM role for CodeBuild
      • CodeBuild project (the 'malicious' build target)
      • CloudWatch Log Group for EventBridge delivery
      • EventBridge rule – matches codebuild:StartBuild events
      • CloudWatch metric filter + alarm on the log group
      • IAM role allowing EventBridge to put log events
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 – detective probe for malicious build detection",
        "Resources": {

            # ── CodeBuild service role ────────────────────────────────────────
            "CodeBuildRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"{stack_name}-cb-role",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "codebuild.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/AWSCodeBuildDeveloperAccess"
                    ],
                    "Policies": [{
                        "PolicyName": "cb-logs",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": [
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": "*"
                            }]
                        }
                    }],
                    "Tags": [{"Key": "sce-experiment", "Value": stack_name}]
                }
            },

            # ── CodeBuild project (simulates rogue build) ─────────────────────
            "MaliciousBuildProject": {
                "Type": "AWS::CodeBuild::Project",
                "DependsOn": "CodeBuildRole",
                "Properties": {
                    "Name": f"{stack_name}-malicious-build",
                    "ServiceRole": {"Fn::GetAtt": ["CodeBuildRole", "Arn"]},
                    "Artifacts": {"Type": "NO_ARTIFACTS"},
                    "Environment": {
                        "Type": "LINUX_CONTAINER",
                        "ComputeType": "BUILD_GENERAL1_SMALL",
                        "Image": "aws/codebuild/standard:7.0"
                    },
                    "Source": {
                        "Type": "NO_SOURCE",
                        "BuildSpec": json.dumps({
                            "version": "0.2",
                            "phases": {
                                "build": {
                                    "commands": [
                                        "echo MALICIOUS_COMMAND: exfiltrating env",
                                        "env | base64"
                                    ]
                                }
                            }
                        })
                    },
                    "Tags": [{"Key": "sce-experiment", "Value": stack_name}]
                }
            },

            # ── CloudWatch log group (EventBridge target) ─────────────────────
            "DetectiveLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": f"/sce/{stack_name}/malicious-build-events",
                    "RetentionInDays": 1
                }
            },

            # ── EventBridge role to deliver to CloudWatch Logs ─────────────────
            "EventsToLogsRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"{stack_name}-eb-logs-role",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "Policies": [{
                        "PolicyName": "put-log-events",
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
                                        f"arn:aws:logs:{region}:{account_id}:"
                                        f"log-group:/sce/{stack_name}/malicious-build-events:*"
                                    )
                                }
                            }]
                        }
                    }]
                }
            },

            # ── EventBridge rule – detect StartBuild calls ─────────────────────
            "MaliciousBuildRule": {
                "Type": "AWS::Events::Rule",
                "DependsOn": ["DetectiveLogGroup", "EventsToLogsRole"],
                "Properties": {
                    "Name": f"{stack_name}-detect-start-build",
                    "Description": "Detect StartBuild API calls (malicious build detection)",
                    "EventPattern": json.dumps({
                        "source": ["aws.codebuild"],
                        "detail-type": ["CodeBuild Build State Change"],
                        "detail": {
                            "build-status": ["IN_PROGRESS"]
                        }
                    }),
                    "State": "ENABLED",
                    "Targets": [{
                        "Id": "SendToLogGroup",
                        "Arn": {
                            "Fn::Sub": (
                                f"arn:aws:logs:{region}:{account_id}:"
                                f"log-group:/sce/{stack_name}/malicious-build-events"
                            )
                        }
                    }]
                }
            },

            # ── Metric filter: count events arriving in the log group ──────────
            "BuildEventMetricFilter": {
                "Type": "AWS::Logs::MetricFilter",
                "DependsOn": "DetectiveLogGroup",
                "Properties": {
                    "LogGroupName": f"/sce/{stack_name}/malicious-build-events",
                    "FilterPattern": "",          # match every log event
                    "MetricTransformations": [{
                        "MetricNamespace": f"SCE/{stack_name}",
                        "MetricName": "MaliciousBuildDetected",
                        "MetricValue": "1",
                        "DefaultValue": 0
                    }]
                }
            },

            # ── CloudWatch Alarm ──────────────────────────────────────────────
            "MaliciousBuildAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "DependsOn": "BuildEventMetricFilter",
                "Properties": {
                    "AlarmName": f"{stack_name}-malicious-build-alarm",
                    "AlarmDescription": "Fires when a malicious build is detected",
                    "Namespace": f"SCE/{stack_name}",
                    "MetricName": "MaliciousBuildDetected",
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "TreatMissingData": "notBreaching"
                }
            }
        },

        "Outputs": {
            "ProjectName": {
                "Value": f"{stack_name}-malicious-build"
            },
            "LogGroupName": {
                "Value": f"/sce/{stack_name}/malicious-build-events"
            },
            "AlarmName": {
                "Value": f"{stack_name}-malicious-build-alarm"
            }
        }
    }
    return json.dumps(template)


# ══════════════════════════════════════════════════════════════════════════════
# 1. STEADY STATE
# ══════════════════════════════════════════════════════════════════════════════

def steady_state() -> bool:
    """Deploy CloudFormation stack with all resources required for the experiment."""
    ts = int(time.time())
    stack_name = f"sce-experiment-{ts}"
    _state["stack_name"] = stack_name
    _state["timestamp"] = ts

    account_id = _account_id()
    region = _region()
    _state["account_id"] = account_id
    _state["region"] = region

    log.info("=== STEADY STATE  stack=%s  account=%s  region=%s ===",
             stack_name, account_id, region)

    cf = _boto("cloudformation")
    template_body = _cfn_template(stack_name, account_id, region)

    try:
        cf.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": "sce-experiment", "Value": stack_name},
                {"Key": "sce-timestamp", "Value": str(ts)},
            ],
        )
        log.info("Stack creation initiated: %s", stack_name)
    except ClientError as exc:
        if "AlreadyExistsException" in str(exc):
            log.warning("Stack %s already exists – continuing.", stack_name)
        else:
            log.error("create_stack failed: %s", exc)
            return False

    ok = _wait_stack(cf, stack_name, "CREATE_COMPLETE")
    if not ok:
        log.error("Stack did not reach CREATE_COMPLETE.")
        return False

    # Capture outputs
    resp = cf.describe_stacks(StackName=stack_name)
    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in resp["Stacks"][0].get("Outputs", [])}
    _state["project_name"] = outputs.get("ProjectName",
                                          f"{stack_name}-malicious-build")
    _state["log_group_name"] = outputs.get("LogGroupName",
                                            f"/sce/{stack_name}/malicious-build-events")
    _state["alarm_name"] = outputs.get("AlarmName",
                                        f"{stack_name}-malicious-build-alarm")

    log.info("Resources ready → project=%s  log_group=%s  alarm=%s",
             _state["project_name"], _state["log_group_name"], _state["alarm_name"])
    return True


# ══════════════════════════════════════════════════════════════════════════════
# 2. ATTACK
# ══════════════════════════════════════════════════════════════════════════════

def attack() -> bool:
    """
    Attack step 1.7 – Start Malicious Build.
    Calls codebuild:StartBuild against the rogue project created in steady_state().
    Captures the build ARN as evidence.
    """
    project_name = _state.get("project_name")
    if not project_name:
        log.error("project_name not set – was steady_state() called?")
        return False

    log.info("=== ATTACK  project=%s ===", project_name)
    cb = _boto("codebuild")

    # Give IAM propagation a moment (role was just created)
    time.sleep(15)

    try:
        resp = cb.start_build(projectName=project_name)
        build = resp["build"]
        build_arn = build["arn"]
        build_id  = build["id"]
        _state["build_arn"] = build_arn
        _state["build_id"]  = build_id
        log.info("Malicious build started  arn=%s  status=%s",
                 build_arn, build["buildStatus"])
        return True
    except ClientError as exc:
        log.error("start_build failed: %s", exc)
        return False


# ══════════════════════════════════════════════════════════════════════════════
# 3. HYPOTHESIS VERIFICATION
# ══════════════════════════════════════════════════════════════════════════════

def hypothesis_verification() -> bool:
    """
    Detective control verification.

    Strategy (two independent signals, either suffices):
      A) CloudWatch Alarm transitions to ALARM state
         (metric filter increments the counter when the EventBridge rule
          delivers the build-state-change event to the log group)
      B) Direct log group inspection – at least one log stream / event
         appeared in the detective log group after the build was started

    We poll for up to 10 minutes with exponential backoff to account for
    the latency of EventBridge → CloudWatch Logs → metric filter pipeline.
    """
    alarm_name     = _state.get("alarm_name")
    log_group_name = _state.get("log_group_name")

    if not alarm_name or not log_group_name:
        log.error("State missing alarm_name or log_group_name.")
        return False

    log.info("=== HYPOTHESIS VERIFICATION  alarm=%s  log_group=%s ===",
             alarm_name, log_group_name)

    cw   = _boto("cloudwatch")
    logs = _boto("logs")

    deadline = time.monotonic() + 600   # 10 minutes total
    delay    = 20
    attempt  = 0

    while time.monotonic() < deadline:
        attempt += 1
        log.info("Verification attempt #%d …", attempt)

        # ── Signal A: CloudWatch Alarm ────────────────────────────────────────
        try:
            alarm_resp = cw.describe_alarms(AlarmNames=[alarm_name])
            alarms = alarm_resp.get("MetricAlarms", [])
            if alarms:
                state = alarms[0]["StateValue"]
                log.info("Alarm %s → %s", alarm_name, state)
                if state == "ALARM":
                    log.info("✓ Detective control FIRED – alarm in ALARM state.")
                    return True
            else:
                log.warning("Alarm %s not found in describe_alarms response.", alarm_name)
        except ClientError as exc:
            log.error("describe_alarms error: %s", exc)

        # ── Signal B: Log group has events ────────────────────────────────────
        try:
            streams_resp = logs.describe_log_streams(
                logGroupName=log_group_name,
                orderBy="LastEventTime",
                descending=True,
                limit=5,
            )
            streams = streams_resp.get("logStreams", [])
            for stream in streams:
                last_event_ts = stream.get("lastEventTimestamp", 0)
                attack_start_ms = _state.get("timestamp", 0) * 1000
                if last_event_ts >= attack_start_ms:
                    log.info("✓ Detective control FIRED – log events found in %s "
                             "stream=%s  lastEvent=%s",
                             log_group_name,
                             stream.get("logStreamName"),
                             last_event_ts)
                    return True
            if streams:
                log.info("Log streams exist but no post-attack events yet "
                         "(last_event_ts=%s  attack_start_ms=%s).",
                         streams[0].get("lastEventTimestamp", "n/a"),
                         attack_start_ms)
            else:
                log.info("No log streams in %s yet.", log_group_name)
        except ClientError as exc:
            log.error("describe_log_streams error: %s", exc)

        log.info("Sleeping %ds before next check …", int(delay))
        time.sleep(delay)
        delay = min(delay * 1.4, 90)

    log.error("Hypothesis verification timed out – detective control did NOT fire.")
    return False


# ══════════════════════════════════════════════════════════════════════════════
# 4. ROLLBACK
# ══════════════════════════════════════════════════════════════════════════════

def rollback() -> bool:
    """Delete the CloudFormation stack and all resources it owns."""
    stack_name = _state.get("stack_name")
    if not stack_name:
        log.warning("No stack_name in state – nothing to roll back.")
        return True

    log.info("=== ROLLBACK  stack=%s ===", stack_name)
    cf = _boto("cloudformation")

    # Stop any running build so CFN can delete the project cleanly
    build_id = _state.get("build_id")
    if build_id:
        try:
            cb = _boto("codebuild")
            cb.stop_build(id=build_id)
            log.info("Stopped build %s.", build_id)
        except ClientError as exc:
            log.warning("Could not stop build %s: %s", build_id, exc)

    try:
        cf.delete_stack(StackName=stack_name)
        log.info("delete_stack called for %s.", stack_name)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info("Stack %s already gone.", stack_name)
            return True
        log.error("delete_stack error: %s", exc)
        return False

    ok = _wait_stack(cf, stack_name, "DELETE_COMPLETE", timeout=600)
    if ok:
        log.info("Stack %s deleted successfully.", stack_name)
    else:
        log.error("Stack %s deletion did not complete cleanly.", stack_name)
    return ok


# ══════════════════════════════════════════════════════════════════════════════
# MAIN RUNNER
# ══════════════════════════════════════════════════════════════════════════════

def main():
    results = {}
    try:
        log.info("━━━ Phase 1: Steady State ━━━")
        results["steady_state"] = steady_state()
        if not results["steady_state"]:
            log.error("Steady state setup failed – aborting experiment.")
            return

        log.info("━━━ Phase 2: Attack ━━━")
        results["attack"] = attack()

        log.info("━━━ Phase 3: Hypothesis Verification ━━━")
        results["hypothesis"] = hypothesis_verification()

        log.info("━━━ Experiment Results ━━━")
        for phase, outcome in results.items():
            symbol = "✓" if outcome else "✗"
            log.info("  %s  %s → %s", symbol, phase, outcome)

        if results.get("hypothesis"):
            log.info("RESULT: Detective control is EFFECTIVE – malicious build was detected.")
        else:
            log.warning("RESULT: Detective control FAILED – malicious build was NOT detected.")

    finally:
        log.info("━━━ Phase 4: Rollback ━━━")
        rollback()


if __name__ == "__main__":
    main()