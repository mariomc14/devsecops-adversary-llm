#!/usr/bin/env python3
"""
Security Chaos Engineering Unit Test
SCE Node: 1.3 SCE Experiment
Probe Type: Reactive
Attack: 1.2 Create Malicious CodeBuild Project

This experiment validates reactive controls that detect and respond to
the creation of malicious CodeBuild projects.
"""

import sys
import time
import json
import logging
from typing import Dict, Any, Optional

# Install boto3 if not available
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "boto3"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state to track resources
EXPERIMENT_STATE = {
    "stack_name": None,
    "timestamp": None,
    "region": None,
    "account_id": None,
    "codebuild_project_name": None,
    "alarm_name": None
}


def get_aws_clients():
    """Initialize AWS clients with current session."""
    session = boto3.Session()
    region = session.region_name or "us-east-1"
    EXPERIMENT_STATE["region"] = region
    
    sts = session.client("sts", region_name=region)
    try:
        identity = sts.get_caller_identity()
        EXPERIMENT_STATE["account_id"] = identity["Account"]
        logger.info(f"Running in account {identity['Account']} as {identity['Arn']}")
    except ClientError as e:
        logger.error(f"Failed to get caller identity: {e}")
        raise
    
    return {
        "cfn": session.client("cloudformation", region_name=region),
        "codebuild": session.client("codebuild", region_name=region),
        "iam": session.client("iam", region_name=region),
        "logs": session.client("logs", region_name=region),
        "cloudwatch": session.client("cloudwatch", region_name=region),
        "sns": session.client("sns", region_name=region),
        "sts": sts
    }


def wait_with_backoff(check_fn, max_wait=300, interval=5):
    """Generic wait function with exponential backoff."""
    start = time.monotonic()
    current_interval = interval
    
    while time.monotonic() - start < max_wait:
        try:
            result = check_fn()
            if result:
                return True
        except Exception as e:
            logger.debug(f"Wait check raised exception: {e}")
        
        time.sleep(current_interval)
        current_interval = min(current_interval * 1.2, 30)
    
    return False


def steady_state() -> bool:
    """
    Deploy CloudFormation stack with:
    - IAM role for CodeBuild
    - CloudWatch Log Group for CodeBuild
    - CloudWatch Metric Filter to detect malicious patterns
    - CloudWatch Alarm (reactive control)
    - SNS Topic for alarm notifications
    """
    try:
        clients = get_aws_clients()
        cfn = clients["cfn"]
        
        # Generate unique timestamp-based stack name
        timestamp = int(time.time())
        EXPERIMENT_STATE["timestamp"] = timestamp
        stack_name = f"sce-experiment-{timestamp}"
        EXPERIMENT_STATE["stack_name"] = stack_name
        EXPERIMENT_STATE["codebuild_project_name"] = f"malicious-build-{timestamp}"
        EXPERIMENT_STATE["alarm_name"] = f"MaliciousCodeBuildAlarm-{timestamp}"
        
        logger.info(f"Creating stack: {stack_name}")
        
        # CloudFormation template
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "SCE 1.3 Reactive Probe - Malicious CodeBuild Detection",
            "Resources": {
                "CodeBuildRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": f"CodeBuildRole-{timestamp}",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"Service": "codebuild.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }]
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
                        ],
                        "Tags": [
                            {"Key": "Experiment", "Value": stack_name},
                            {"Key": "Timestamp", "Value": str(timestamp)}
                        ]
                    }
                },
                "CodeBuildLogGroup": {
                    "Type": "AWS::Logs::LogGroup",
                    "Properties": {
                        "LogGroupName": f"/aws/codebuild/malicious-build-{timestamp}",
                        "RetentionInDays": 1
                    }
                },
                "MaliciousActivityMetricFilter": {
                    "Type": "AWS::Logs::MetricFilter",
                    "DependsOn": "CodeBuildLogGroup",
                    "Properties": {
                        "LogGroupName": f"/aws/codebuild/malicious-build-{timestamp}",
                        "FilterPattern": "[time, request_id, event_type = COMMAND_EXECUTION, phase_type, phase_status, command = *exfiltrate* || command = *backdoor* || command = *malicious*]",
                        "MetricTransformations": [{
                            "MetricName": f"MaliciousCodeBuildActivity-{timestamp}",
                            "MetricNamespace": "SecurityChaos/CodeBuild",
                            "MetricValue": "1",
                            "DefaultValue": 0
                        }]
                    }
                },
                "SNSTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": f"CodeBuildSecurityAlerts-{timestamp}",
                        "Tags": [
                            {"Key": "Experiment", "Value": stack_name}
                        ]
                    }
                },
                "MaliciousActivityAlarm": {
                    "Type": "AWS::CloudWatch::Alarm",
                    "DependsOn": "MaliciousActivityMetricFilter",
                    "Properties": {
                        "AlarmName": f"MaliciousCodeBuildAlarm-{timestamp}",
                        "AlarmDescription": "Reactive control - alerts on malicious CodeBuild activity",
                        "MetricName": f"MaliciousCodeBuildActivity-{timestamp}",
                        "Namespace": "SecurityChaos/CodeBuild",
                        "Statistic": "Sum",
                        "Period": 60,
                        "EvaluationPeriods": 1,
                        "Threshold": 1,
                        "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                        "TreatMissingData": "notBreaching",
                        "ActionsEnabled": True,
                        "AlarmActions": [{"Ref": "SNSTopic"}]
                    }
                }
            },
            "Outputs": {
                "CodeBuildRoleArn": {
                    "Value": {"Fn::GetAtt": ["CodeBuildRole", "Arn"]}
                },
                "LogGroupName": {
                    "Value": {"Ref": "CodeBuildLogGroup"}
                },
                "AlarmName": {
                    "Value": {"Ref": "MaliciousActivityAlarm"}
                },
                "SNSTopicArn": {
                    "Value": {"Ref": "SNSTopic"}
                }
            }
        }
        
        # Check if stack already exists
        try:
            existing = cfn.describe_stacks(StackName=stack_name)
            logger.warning(f"Stack {stack_name} already exists, continuing with existing stack")
            return True
        except ClientError as e:
            if "does not exist" not in str(e):
                logger.error(f"Error checking stack existence: {e}")
                raise
        
        # Create stack
        try:
            response = cfn.create_stack(
                StackName=stack_name,
                TemplateBody=json.dumps(template),
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Tags=[
                    {"Key": "Experiment", "Value": "SCE-1.3"},
                    {"Key": "ProbeType", "Value": "Reactive"},
                    {"Key": "Timestamp", "Value": str(timestamp)}
                ]
            )
            logger.info(f"Stack creation initiated: {response['StackId']}")
        except ClientError as e:
            logger.error(f"Failed to create stack: {e}")
            return False
        
        # Wait for stack creation
        def check_stack_complete():
            try:
                stacks = cfn.describe_stacks(StackName=stack_name)
                status = stacks["Stacks"][0]["StackStatus"]
                logger.info(f"Stack status: {status}")
                
                if status == "CREATE_COMPLETE":
                    return True
                elif "FAILED" in status or "ROLLBACK" in status:
                    logger.error(f"Stack creation failed with status: {status}")
                    raise Exception(f"Stack creation failed: {status}")
                return False
            except ClientError as e:
                logger.error(f"Error checking stack status: {e}")
                return False
        
        if not wait_with_backoff(check_stack_complete, max_wait=600):
            logger.error("Stack creation timed out")
            return False
        
        logger.info("Stack created successfully")
        
        # Retrieve outputs
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)
            outputs = stacks["Stacks"][0].get("Outputs", [])
            for output in outputs:
                logger.info(f"Output {output['OutputKey']}: {output['OutputValue']}")
        except ClientError as e:
            logger.error(f"Failed to retrieve stack outputs: {e}")
        
        return True
        
    except Exception as e:
        logger.error(f"steady_state failed: {e}", exc_info=True)
        return False


def attack() -> bool:
    """
    Execute the attack: Create a malicious CodeBuild project and run a build
    that logs suspicious commands to trigger the reactive control.
    """
    try:
        clients = get_aws_clients()
        codebuild = clients["codebuild"]
        cfn = clients["cfn"]
        logs_client = clients["logs"]
        
        stack_name = EXPERIMENT_STATE["stack_name"]
        project_name = EXPERIMENT_STATE["codebuild_project_name"]
        
        if not stack_name:
            logger.error("Stack name not set - steady_state may have failed")
            return False
        
        logger.info(f"Executing attack: Creating malicious CodeBuild project {project_name}")
        
        # Get IAM role ARN from stack outputs
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)
            outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks["Stacks"][0].get("Outputs", [])}
            role_arn = outputs.get("CodeBuildRoleArn")
            
            if not role_arn:
                logger.error("CodeBuildRoleArn not found in stack outputs")
                return False
            
            logger.info(f"Using IAM role: {role_arn}")
        except ClientError as e:
            logger.error(f"Failed to get stack outputs: {e}")
            return False
        
        # Create malicious CodeBuild project
        buildspec = """version: 0.2
phases:
  build:
    commands:
      - echo "Starting malicious activity"
      - echo "Executing exfiltrate data command"
      - echo "Installing backdoor payload"
      - echo "Malicious operations complete"
"""
        
        try:
            response = codebuild.create_project(
                name=project_name,
                description="Malicious CodeBuild project for SCE testing",
                source={
                    "type": "NO_SOURCE",
                    "buildspec": buildspec
                },
                artifacts={
                    "type": "NO_ARTIFACTS"
                },
                environment={
                    "type": "LINUX_CONTAINER",
                    "image": "aws/codebuild/standard:5.0",
                    "computeType": "BUILD_GENERAL1_SMALL"
                },
                serviceRole=role_arn,
                logsConfig={
                    "cloudWatchLogs": {
                        "status": "ENABLED",
                        "groupName": f"/aws/codebuild/{project_name}"
                    }
                },
                tags=[
                    {"key": "Experiment", "value": stack_name},
                    {"key": "AttackType", "value": "MaliciousCodeBuild"}
                ]
            )
            
            project_arn = response["project"]["arn"]
            logger.info(f"Created malicious CodeBuild project: {project_arn}")
            
        except ClientError as e:
            if "already exists" in str(e):
                logger.warning(f"Project {project_name} already exists, continuing")
            else:
                logger.error(f"Failed to create CodeBuild project: {e}")
                return False
        
        # Start a build to trigger the malicious activity
        try:
            build_response = codebuild.start_build(projectName=project_name)
            build_id = build_response["build"]["id"]
            logger.info(f"Started malicious build: {build_id}")
            
            # Wait for build to start and log events
            time.sleep(10)
            
            # Verify build was started (evidence of attack)
            build_info = codebuild.batch_get_builds(ids=[build_id])
            build_status = build_info["builds"][0]["buildStatus"]
            logger.info(f"Build status: {build_status}")
            
            # Wait for logs to be written
            def check_logs_exist():
                try:
                    log_group = f"/aws/codebuild/{project_name}"
                    streams = logs_client.describe_log_streams(
                        logGroupName=log_group,
                        orderBy="LastEventTime",
                        descending=True,
                        limit=1
                    )
                    if streams.get("logStreams"):
                        logger.info(f"Log streams found: {len(streams['logStreams'])}")
                        # Get log events to confirm malicious content
                        stream_name = streams["logStreams"][0]["logStreamName"]
                        events = logs_client.get_log_events(
                            logGroupName=log_group,
                            logStreamName=stream_name,
                            limit=50
                        )
                        for event in events.get("events", []):
                            message = event.get("message", "")
                            if "malicious" in message.lower() or "exfiltrate" in message.lower() or "backdoor" in message.lower():
                                logger.info(f"Found malicious log entry: {message[:100]}")
                                return True
                    return False
                except ClientError as e:
                    logger.debug(f"Waiting for logs: {e}")
                    return False
            
            # Wait up to 120 seconds for logs with malicious content
            if wait_with_backoff(check_logs_exist, max_wait=120, interval=5):
                logger.info("Attack executed successfully - malicious logs written")
                return True
            else:
                logger.warning("Logs not found in expected timeframe, but build started")
                return True
                
        except ClientError as e:
            logger.error(f"Failed to start build: {e}")
            return False
        
    except Exception as e:
        logger.error(f"attack failed: {e}", exc_info=True)
        return False


def hypothesis_verification() -> bool:
    """
    Verify the reactive control: Check if CloudWatch Alarm transitioned to ALARM state
    in response to the malicious CodeBuild activity.
    
    Returns True if the alarm detected the malicious activity, False otherwise.
    """
    try:
        clients = get_aws_clients()
        cloudwatch = clients["cloudwatch"]
        
        alarm_name = EXPERIMENT_STATE["alarm_name"]
        
        if not alarm_name:
            logger.error("Alarm name not set - steady_state may have failed")
            return False
        
        logger.info(f"Verifying reactive control: Checking alarm {alarm_name}")
        
        # Wait for metric data to be processed and alarm to evaluate
        # CloudWatch alarms evaluate on a period basis, we need to wait for evaluation
        time.sleep(90)  # Wait for at least one evaluation period plus processing time
        
        def check_alarm_state():
            try:
                response = cloudwatch.describe_alarms(AlarmNames=[alarm_name])
                
                if not response.get("MetricAlarms"):
                    logger.warning(f"Alarm {alarm_name} not found")
                    return False
                
                alarm = response["MetricAlarms"][0]
                state = alarm["StateValue"]
                state_reason = alarm.get("StateReason", "")
                state_updated = alarm.get("StateUpdatedTimestamp", "")
                
                logger.info(f"Alarm state: {state}")
                logger.info(f"State reason: {state_reason}")
                logger.info(f"State updated: {state_updated}")
                
                # Check if alarm is in ALARM state (reactive control triggered)
                if state == "ALARM":
                    logger.info("SUCCESS: Reactive control detected malicious activity - Alarm in ALARM state")
                    return True
                elif state == "INSUFFICIENT_DATA":
                    logger.info("Alarm state: INSUFFICIENT_DATA - waiting for metric data")
                    return False
                else:
                    logger.info(f"Alarm state: {state} - not yet triggered")
                    return False
                    
            except ClientError as e:
                logger.error(f"Error checking alarm state: {e}")
                return False
        
        # Check alarm state with retries (wait up to 180 seconds total)
        if wait_with_backoff(check_alarm_state, max_wait=180, interval=10):
            # Double-check by querying metric data
            try:
                timestamp = EXPERIMENT_STATE["timestamp"]
                response = cloudwatch.get_metric_statistics(
                    Namespace="SecurityChaos/CodeBuild",
                    MetricName=f"MaliciousCodeBuildActivity-{timestamp}",
                    StartTime=time.time() - 600,
                    EndTime=time.time(),
                    Period=60,
                    Statistics=["Sum"]
                )
                
                datapoints = response.get("Datapoints", [])
                logger.info(f"Metric datapoints: {len(datapoints)}")
                
                for dp in datapoints:
                    if dp.get("Sum", 0) > 0:
                        logger.info(f"Metric datapoint with value {dp['Sum']} at {dp['Timestamp']}")
                        return True
                
                # Alarm is in ALARM state even without visible datapoints (eventual consistency)
                logger.info("Alarm in ALARM state confirmed")
                return True
                
            except ClientError as e:
                logger.error(f"Error checking metric data: {e}")
                # If we confirmed ALARM state, that's sufficient
                return True
        
        # Final check of alarm state
        try:
            response = cloudwatch.describe_alarms(AlarmNames=[alarm_name])
            if response.get("MetricAlarms"):
                final_state = response["MetricAlarms"][0]["StateValue"]
                logger.info(f"Final alarm state: {final_state}")
                return final_state == "ALARM"
        except ClientError as e:
            logger.error(f"Error in final alarm check: {e}")
        
        logger.warning("Reactive control did not trigger within expected timeframe")
        return False
        
    except Exception as e:
        logger.error(f"hypothesis_verification failed: {e}", exc_info=True)
        return False


def rollback() -> bool:
    """
    Clean up all resources:
    - Delete CodeBuild project
    - Delete CloudFormation stack
    """
    success = True
    
    try:
        clients = get_aws_clients()
        codebuild = clients["codebuild"]
        cfn = clients["cfn"]
        
        project_name = EXPERIMENT_STATE.get("codebuild_project_name")
        stack_name = EXPERIMENT_STATE.get("stack_name")
        
        # Delete CodeBuild project
        if project_name:
            try:
                logger.info(f"Deleting CodeBuild project: {project_name}")
                codebuild.delete_project(name=project_name)
                logger.info("CodeBuild project deleted")
            except ClientError as e:
                if "does not exist" in str(e):
                    logger.info("CodeBuild project already deleted")
                else:
                    logger.error(f"Failed to delete CodeBuild project: {e}")
                    success = False
        
        # Delete CloudFormation stack
        if stack_name:
            try:
                logger.info(f"Deleting stack: {stack_name}")
                cfn.delete_stack(StackName=stack_name)
                logger.info("Stack deletion initiated")
                
                # Wait for stack deletion
                def check_stack_deleted():
                    try:
                        stacks = cfn.describe_stacks(StackName=stack_name)
                        status = stacks["Stacks"][0]["StackStatus"]
                        logger.info(f"Stack status: {status}")
                        
                        if status == "DELETE_COMPLETE":
                            return True
                        elif "FAILED" in status:
                            logger.error(f"Stack deletion failed: {status}")
                            return True  # Stop waiting
                        return False
                    except ClientError as e:
                        if "does not exist" in str(e):
                            logger.info("Stack deleted successfully")
                            return True
                        logger.debug(f"Checking stack deletion: {e}")
                        return False
                
                if wait_with_backoff(check_stack_deleted, max_wait=600):
                    logger.info("Stack deletion completed")
                else:
                    logger.error("Stack deletion timed out")
                    success = False
                    
            except ClientError as e:
                if "does not exist" in str(e):
                    logger.info("Stack already deleted")
                else:
                    logger.error(f"Failed to delete stack: {e}")
                    success = False
        
        return success
        
    except Exception as e:
        logger.error(f"rollback failed: {e}", exc_info=True)
        return False


def main():
    """Execute the complete SCE experiment."""
    logger.info("=" * 80)
    logger.info("Starting SCE Experiment 1.3 - Reactive Probe")
    logger.info("Attack: Create Malicious CodeBuild Project")
    logger.info("=" * 80)
    
    try:
        # Phase 1: Steady State
        logger.info("\n[PHASE 1] Establishing steady state...")
        if not steady_state():
            logger.error("Steady state setup failed")
            return 1
        
        # Phase 2: Attack
        logger.info("\n[PHASE 2] Executing attack...")
        attack_success = attack()
        if not attack_success:
            logger.error("Attack execution failed")
        
        # Phase 3: Hypothesis Verification
        logger.info("\n[PHASE 3] Verifying hypothesis...")
        hypothesis_result = hypothesis_verification()
        
        if hypothesis_result:
            logger.info("\n✓ HYPOTHESIS VERIFIED: Reactive control detected malicious activity")
        else:
            logger.warning("\n✗ HYPOTHESIS FAILED: Reactive control did not detect malicious activity")
        
        return 0 if hypothesis_result else 1
        
    except Exception as e:
        logger.error(f"Experiment failed with exception: {e}", exc_info=True)
        return 1
    finally:
        # Phase 4: Rollback
        logger.info("\n[PHASE 4] Rolling back resources...")
        rollback()
        logger.info("\n" + "=" * 80)
        logger.info("Experiment complete")
        logger.info("=" * 80)


if __name__ == "__main__":
    sys.exit(main())