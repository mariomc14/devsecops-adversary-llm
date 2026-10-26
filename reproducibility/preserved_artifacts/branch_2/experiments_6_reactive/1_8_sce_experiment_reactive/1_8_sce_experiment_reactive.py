"""
SCE Experiment 1.8 — Reactive Probe for Attack Node 1.7: Start Malicious Build

This experiment validates that when an unauthorized/malicious CodeBuild build is
started, a reactive control (CloudWatch Events → Lambda) detects and stops the build.

Flow:
1. steady_state(): Deploy a CloudFormation stack with a CodeBuild project, a Lambda
   function that stops builds, and a CloudWatch Events rule that triggers the Lambda
   when a build starts on the project.
2. attack(): Start a build on the CodeBuild project (simulating a malicious build start).
3. hypothesis_verification(): Verify that the reactive control stopped the build.
4. rollback(): Delete the CloudFormation stack.
"""

import json
import logging
import time
import hashlib
import boto3
import botocore.exceptions

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

TIMESTAMP = int(time.time())
STACK_NAME = f"sce-experiment-{TIMESTAMP}"
EXPERIMENT_TAG = "1.8-SCE-Experiment-Reactive-MaliciousBuild"
PROJECT_NAME = f"sce-malicious-build-{TIMESTAMP}"
LAMBDA_FUNCTION_NAME = f"sce-stop-build-{TIMESTAMP}"
RULE_NAME = f"sce-stop-build-rule-{TIMESTAMP}"

# Store state across phases
_state = {
    "stack_name": STACK_NAME,
    "project_name": PROJECT_NAME,
    "lambda_function_name": LAMBDA_FUNCTION_NAME,
    "build_id": None,
    "region": None,
    "account_id": None,
}


def _get_region():
    session = boto3.session.Session()
    region = session.region_name or "us-east-1"
    _state["region"] = region
    return region


def _get_account_id():
    if _state.get("account_id"):
        return _state["account_id"]
    sts = boto3.client("sts", region_name=_get_region())
    account_id = sts.get_caller_identity()["Account"]
    _state["account_id"] = account_id
    return account_id


def _get_cfn_template():
    """Return the CloudFormation template as a JSON string."""
    region = _get_region()
    account_id = _get_account_id()
    project_name = _state["project_name"]
    lambda_name = _state["lambda_function_name"]
    rule_name = RULE_NAME

    # Lambda code that stops any build that starts on our project
    lambda_code = r"""
import json
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    logger.info("Received event: %s", json.dumps(event))
    detail = event.get("detail", {})
    build_id = detail.get("build-id", "")
    build_status = detail.get("build-status", "")
    project = detail.get("project-name", "")

    if build_status == "IN_PROGRESS":
        logger.info("Stopping build %s on project %s", build_id, project)
        cb = boto3.client("codebuild")
        try:
            resp = cb.stop_build(id=build_id)
            logger.info("Stop build response: %s", json.dumps(str(resp)))
            return {"stopped": True, "build_id": build_id}
        except Exception as e:
            logger.error("Failed to stop build: %s", str(e))
            return {"stopped": False, "error": str(e)}
    else:
        logger.info("Build status is %s, not stopping.", build_status)
        return {"stopped": False, "reason": "not_in_progress"}
"""

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 Reactive probe - Stop malicious CodeBuild builds",
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
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            "LambdaExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-lambda-role-{TIMESTAMP}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "Policies": [
                        {
                            "PolicyName": "LambdaStopBuildPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "codebuild:StopBuild",
                                            "codebuild:BatchGetBuilds"
                                        ],
                                        "Resource": f"arn:aws:codebuild:{region}:{account_id}:project/{project_name}"
                                    },
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
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            "MaliciousBuildProject": {
                "Type": "AWS::CodeBuild::Project",
                "DependsOn": "CodeBuildServiceRole",
                "Properties": {
                    "Name": project_name,
                    "Description": "SCE test project for malicious build detection",
                    "ServiceRole": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]},
                    "Source": {
                        "Type": "NO_SOURCE",
                        "BuildSpec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo 'Malicious payload executing'\n      - sleep 120\n"
                    },
                    "Artifacts": {
                        "Type": "NO_ARTIFACTS"
                    },
                    "Environment": {
                        "Type": "LINUX_CONTAINER",
                        "ComputeType": "BUILD_GENERAL1_SMALL",
                        "Image": "aws/codebuild/amazonlinux2-x86_64-standard:4.0"
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            "StopBuildLambda": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": "LambdaExecutionRole",
                "Properties": {
                    "FunctionName": lambda_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecutionRole", "Arn"]},
                    "Timeout": 60,
                    "Code": {
                        "ZipFile": lambda_code
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            "BuildEventRule": {
                "Type": "AWS::Events::Rule",
                "DependsOn": ["StopBuildLambda", "MaliciousBuildProject"],
                "Properties": {
                    "Name": rule_name,
                    "Description": "Triggers Lambda to stop malicious builds reactively",
                    "State": "ENABLED",
                    "EventPattern": {
                        "source": ["aws.codebuild"],
                        "detail-type": ["CodeBuild Build State Change"],
                        "detail": {
                            "project-name": [project_name],
                            "build-status": ["IN_PROGRESS"]
                        }
                    },
                    "Targets": [
                        {
                            "Arn": {"Fn::GetAtt": ["StopBuildLambda", "Arn"]},
                            "Id": "StopBuildTarget"
                        }
                    ]
                }
            },
            "LambdaInvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "DependsOn": ["StopBuildLambda", "BuildEventRule"],
                "Properties": {
                    "FunctionName": {"Ref": "StopBuildLambda"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["BuildEventRule", "Arn"]}
                }
            }
        },
        "Outputs": {
            "ProjectName": {
                "Value": {"Ref": "MaliciousBuildProject"}
            },
            "LambdaArn": {
                "Value": {"Fn::GetAtt": ["StopBuildLambda", "Arn"]}
            },
            "EventRuleArn": {
                "Value": {"Fn::GetAtt": ["BuildEventRule", "Arn"]}
            }
        }
    }

    return json.dumps(template)


def _wait_for_stack(cfn_client, stack_name, target_status, timeout=600):
    """Wait for a CloudFormation stack to reach a target status."""
    deadline = time.monotonic() + timeout
    wait_interval = 10
    while time.monotonic() < deadline:
        try:
            resp = cfn_client.describe_stacks(StackName=stack_name)
            stacks = resp.get("Stacks", [])
            if not stacks:
                if "DELETE_COMPLETE" in target_status:
                    logger.info("Stack %s no longer exists (DELETE_COMPLETE).", stack_name)
                    return True
                time.sleep(wait_interval)
                continue
            status = stacks[0]["StackStatus"]
            logger.info("Stack %s status: %s", stack_name, status)
            if status == target_status:
                return True
            if "FAILED" in status or "ROLLBACK_COMPLETE" == status:
                logger.error("Stack %s reached terminal status: %s", stack_name, status)
                # Try to get events for debugging
                try:
                    events = cfn_client.describe_stack_events(StackName=stack_name)
                    for ev in events.get("StackEvents", [])[:10]:
                        if "FAILED" in ev.get("ResourceStatus", ""):
                            logger.error("  %s: %s - %s",
                                         ev.get("LogicalResourceId"),
                                         ev.get("ResourceStatus"),
                                         ev.get("ResourceStatusReason", ""))
                except Exception:
                    pass
                return False
        except botocore.exceptions.ClientError as e:
            if "does not exist" in str(e):
                if "DELETE_COMPLETE" in target_status:
                    logger.info("Stack %s deleted.", stack_name)
                    return True
            logger.warning("Error describing stack: %s", e)
        time.sleep(wait_interval)
    logger.error("Timed out waiting for stack %s to reach %s", stack_name, target_status)
    return False


def steady_state():
    """Deploy the CloudFormation stack with CodeBuild project, Lambda, and EventBridge rule."""
    logger.info("=== STEADY STATE: Deploying stack %s ===", STACK_NAME)
    region = _get_region()
    cfn = boto3.client("cloudformation", region_name=region)

    # Check if stack already exists
    try:
        resp = cfn.describe_stacks(StackName=STACK_NAME)
        if resp["Stacks"]:
            status = resp["Stacks"][0]["StackStatus"]
            logger.warning("Stack %s already exists with status %s", STACK_NAME, status)
            if status == "CREATE_COMPLETE":
                logger.info("Stack already in desired state, proceeding.")
                return True
            elif "IN_PROGRESS" in status:
                logger.info("Stack operation in progress, waiting...")
                _wait_for_stack(cfn, STACK_NAME, "CREATE_COMPLETE")
                return True
            elif status in ("ROLLBACK_COMPLETE", "DELETE_FAILED"):
                logger.info("Deleting failed stack first...")
                cfn.delete_stack(StackName=STACK_NAME)
                _wait_for_stack(cfn, STACK_NAME, "DELETE_COMPLETE")
    except botocore.exceptions.ClientError as e:
        if "does not exist" not in str(e):
            logger.error("Error checking stack: %s", e)

    template_body = _get_cfn_template()

    logger.info("Creating CloudFormation stack %s...", STACK_NAME)
    try:
        cfn.create_stack(
            StackName=STACK_NAME,
            TemplateBody=template_body,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                {"Key": "Timestamp", "Value": str(TIMESTAMP)}
            ]
        )
    except botocore.exceptions.ClientError as e:
        if "AlreadyExistsException" in str(e):
            logger.warning("Stack already exists, waiting for completion...")
        else:
            logger.error("Failed to create stack: %s", e)
            return False

    success = _wait_for_stack(cfn, STACK_NAME, "CREATE_COMPLETE", timeout=600)
    if success:
        logger.info("Stack %s created successfully.", STACK_NAME)

        # Wait a bit for IAM role propagation and EventBridge rule activation
        logger.info("Waiting 15 seconds for IAM role propagation and EventBridge rule activation...")
        time.sleep(15)
    else:
        logger.error("Stack creation failed.")

    return success


def attack():
    """
    Attack: Start a malicious build on the CodeBuild project.
    This simulates attack node 1.7 - Start Malicious Build.
    The reactive control (EventBridge + Lambda) should detect and stop it.
    """
    logger.info("=== ATTACK: Starting malicious build on project %s ===", PROJECT_NAME)
    region = _get_region()
    cb = boto3.client("codebuild", region_name=region)

    try:
        response = cb.start_build(projectName=PROJECT_NAME)
        build = response.get("build", {})
        build_id = build.get("id", "")
        build_status = build.get("buildStatus", "")
        build_arn = build.get("arn", "")

        _state["build_id"] = build_id

        logger.info("Build started successfully!")
        logger.info("  Build ID: %s", build_id)
        logger.info("  Build ARN: %s", build_arn)
        logger.info("  Initial Status: %s", build_status)

        if build_id:
            logger.info("Attack executed — malicious build started with ID: %s", build_id)
            return True
        else:
            logger.error("Build started but no build ID returned.")
            return False

    except botocore.exceptions.ClientError as e:
        logger.error("Failed to start build: %s", e)
        return False


def hypothesis_verification():
    """
    Reactive Probe Verification:
    Verify that the reactive control (EventBridge → Lambda) stopped the malicious build.

    The build should transition from IN_PROGRESS to STOPPED within a reasonable time window,
    indicating the Lambda function successfully reacted to the build event and stopped it.

    Returns True if the build was stopped by the reactive control, False otherwise.
    """
    logger.info("=== HYPOTHESIS VERIFICATION: Checking if reactive control stopped the build ===")
    region = _get_region()
    cb = boto3.client("codebuild", region_name=region)

    build_id = _state.get("build_id")
    if not build_id:
        logger.error("No build ID available for verification.")
        return False

    # Wait for the reactive control to kick in
    # EventBridge → Lambda pipeline can take 10-60 seconds
    max_wait = 180  # 3 minutes
    poll_interval = 10
    deadline = time.monotonic() + max_wait

    logger.info("Polling build %s for STOPPED status (max %ds)...", build_id, max_wait)

    final_status = None
    while time.monotonic() < deadline:
        try:
            resp = cb.batch_get_builds(ids=[build_id])
            builds = resp.get("builds", [])
            if not builds:
                logger.warning("No build found for ID %s", build_id)
                time.sleep(poll_interval)
                continue

            build = builds[0]
            current_status = build.get("buildStatus", "")
            logger.info("  Build %s status: %s", build_id, current_status)
            final_status = current_status

            if current_status == "STOPPED":
                logger.info("SUCCESS: Build was STOPPED by the reactive control!")
                return True
            elif current_status in ("SUCCEEDED", "FAILED", "FAULT", "TIMED_OUT"):
                logger.warning("Build completed with status %s — reactive control did NOT stop it in time.", current_status)
                return False
            # Still IN_PROGRESS, keep waiting
            time.sleep(poll_interval)

        except botocore.exceptions.ClientError as e:
            logger.error("Error checking build status: %s", e)
            time.sleep(poll_interval)

    logger.error("Timed out waiting for build to be stopped. Final status: %s", final_status)

    # One final check
    try:
        resp = cb.batch_get_builds(ids=[build_id])
        builds = resp.get("builds", [])
        if builds:
            final_status = builds[0].get("buildStatus", "")
            logger.info("Final build status after timeout: %s", final_status)
            if final_status == "STOPPED":
                return True
    except Exception as e:
        logger.error("Final status check failed: %s", e)

    return False


def rollback():
    """Delete the CloudFormation stack and all resources."""
    logger.info("=== ROLLBACK: Deleting stack %s ===", STACK_NAME)
    region = _get_region()
    cfn = boto3.client("cloudformation", region_name=region)

    # Also try to stop any running build to avoid charges
    build_id = _state.get("build_id")
    if build_id:
        try:
            cb = boto3.client("codebuild", region_name=region)
            resp = cb.batch_get_builds(ids=[build_id])
            builds = resp.get("builds", [])
            if builds and builds[0].get("buildStatus") == "IN_PROGRESS":
                logger.info("Stopping build %s during rollback...", build_id)
                cb.stop_build(id=build_id)
                logger.info("Build stop requested.")
        except Exception as e:
            logger.warning("Could not stop build during rollback: %s", e)

    try:
        cfn.delete_stack(StackName=STACK_NAME)
        logger.info("Delete request sent for stack %s.", STACK_NAME)
        success = _wait_for_stack(cfn, STACK_NAME, "DELETE_COMPLETE", timeout=600)
        if success:
            logger.info("Stack %s deleted successfully.", STACK_NAME)
        else:
            logger.error("Stack %s deletion may not have completed.", STACK_NAME)
        return success
    except botocore.exceptions.ClientError as e:
        if "does not exist" in str(e):
            logger.info("Stack %s does not exist, nothing to delete.", STACK_NAME)
            return True
        logger.error("Error deleting stack: %s", e)
        return False


def run_experiment():
    """Run the full experiment end-to-end."""
    logger.info("=" * 70)
    logger.info("SCE Experiment 1.8: Reactive Probe for Attack 1.7 (Start Malicious Build)")
    logger.info("Stack Name: %s", STACK_NAME)
    logger.info("Project Name: %s", PROJECT_NAME)
    logger.info("=" * 70)

    result = {
        "steady_state": False,
        "attack": False,
        "hypothesis": False,
        "rollback": False,
    }

    try:
        # Phase 1: Steady State
        result["steady_state"] = steady_state()
        if not result["steady_state"]:
            logger.error("Steady state setup failed. Aborting experiment.")
            return result

        # Phase 2: Attack
        result["attack"] = attack()
        if not result["attack"]:
            logger.error("Attack phase failed. Proceeding to verification anyway.")

        # Phase 3: Hypothesis Verification
        result["hypothesis"] = hypothesis_verification()

    except Exception as e:
        logger.error("Unexpected error during experiment: %s", e)
    finally:
        # Phase 4: Rollback (always attempted)
        try:
            result["rollback"] = rollback()
        except Exception as e:
            logger.error("Rollback failed: %s", e)

    logger.info("=" * 70)
    logger.info("EXPERIMENT RESULTS:")
    logger.info("  Steady State: %s", "PASS" if result["steady_state"] else "FAIL")
    logger.info("  Attack:       %s", "PASS" if result["attack"] else "FAIL")
    logger.info("  Hypothesis:   %s", "PASS" if result["hypothesis"] else "FAIL")
    logger.info("  Rollback:     %s", "PASS" if result["rollback"] else "FAIL")
    logger.info("=" * 70)

    overall = all(result.values())
    logger.info("OVERALL: %s", "PASS" if overall else "FAIL")

    return result


if __name__ == "__main__":
    run_experiment()