#!/usr/bin/env python3
"""
SCE Experiment 1.8 - Detective Probe for Malicious Build Start
==============================================================

This experiment validates that AWS detective controls can identify when
a malicious or unauthorized CodeBuild project build is started.

Attack Node: 1.7 Start Malicious Build
Probe Type: Detective
"""

import json
import logging
import time
import hashlib
import boto3
from botocore.exceptions import ClientError, WaiterError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global variables for resource tracking
EXPERIMENT_NAME = "sce-malicious-build-detect"
STACK_NAME = None
REGION = None
ACCOUNT_ID = None
BUILD_PROJECT_NAME = None
BUILD_ID = None


def get_aws_context():
    """Get AWS account ID and region from current credentials."""
    global REGION, ACCOUNT_ID
    
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    ACCOUNT_ID = identity['Account']
    
    session = boto3.session.Session()
    REGION = session.region_name or 'us-east-1'
    
    logger.info(f"AWS Account ID: {ACCOUNT_ID}")
    logger.info(f"AWS Region: {REGION}")
    
    return ACCOUNT_ID, REGION


def wait_with_backoff(check_func, max_wait=300, initial_interval=5):
    """Wait with exponential backoff until check_func returns True."""
    start_time = time.monotonic()
    interval = initial_interval
    
    while time.monotonic() - start_time < max_wait:
        try:
            if check_func():
                return True
        except Exception as e:
            logger.warning(f"Check failed with error: {e}")
        
        time.sleep(interval)
        interval = min(interval * 1.5, 30)
    
    return False


def generate_cloudformation_template():
    """Generate CloudFormation template for the experiment resources."""
    
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 - Detective control for malicious build detection",
        "Resources": {
            # IAM Role for CodeBuild
            "CodeBuildServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Fn::Sub": "${AWS::StackName}-codebuild-role"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "codebuild.amazonaws.com"
                                },
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "Policies": [
                        {
                            "PolicyName": "CodeBuildBasePolicy",
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
                        {"Key": "Experiment", "Value": EXPERIMENT_NAME}
                    ]
                }
            },
            # CodeBuild Project (simulates a build that could be maliciously triggered)
            "MaliciousBuildProject": {
                "Type": "AWS::CodeBuild::Project",
                "DependsOn": "CodeBuildServiceRole",
                "Properties": {
                    "Name": {"Fn::Sub": "${AWS::StackName}-malicious-project"},
                    "Description": "SCE test project for malicious build detection",
                    "ServiceRole": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]},
                    "Artifacts": {
                        "Type": "NO_ARTIFACTS"
                    },
                    "Environment": {
                        "Type": "LINUX_CONTAINER",
                        "ComputeType": "BUILD_GENERAL1_SMALL",
                        "Image": "aws/codebuild/amazonlinux2-x86_64-standard:4.0"
                    },
                    "Source": {
                        "Type": "NO_SOURCE",
                        "BuildSpec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo 'Malicious build simulation'\n      - exit 0"
                    },
                    "TimeoutInMinutes": 5,
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_NAME},
                        {"Key": "SecurityTest", "Value": "MaliciousBuild"}
                    ]
                }
            },
            # CloudWatch Log Group for build events
            "BuildEventLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": {"Fn::Sub": "/aws/events/${AWS::StackName}-build-events"},
                    "RetentionInDays": 1,
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_NAME}
                    ]
                }
            },
            # EventBridge Rule to detect CodeBuild state changes (Detective Control)
            "BuildStateChangeRule": {
                "Type": "AWS::Events::Rule",
                "DependsOn": ["MaliciousBuildProject", "BuildEventLogGroup"],
                "Properties": {
                    "Name": {"Fn::Sub": "${AWS::StackName}-build-state-rule"},
                    "Description": "Detects CodeBuild project state changes for security monitoring",
                    "State": "ENABLED",
                    "EventPattern": {
                        "source": ["aws.codebuild"],
                        "detail-type": ["CodeBuild Build State Change"],
                        "detail": {
                            "project-name": [{"Fn::Sub": "${AWS::StackName}-malicious-project"}]
                        }
                    },
                    "Targets": [
                        {
                            "Id": "LogBuildEvents",
                            "Arn": {"Fn::Sub": "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/events/${AWS::StackName}-build-events"}
                        }
                    ]
                }
            },
            # Resource policy for CloudWatch Logs to receive events
            "BuildEventLogGroupPolicy": {
                "Type": "AWS::Logs::ResourcePolicy",
                "DependsOn": "BuildEventLogGroup",
                "Properties": {
                    "PolicyName": {"Fn::Sub": "${AWS::StackName}-events-to-logs-policy"},
                    "PolicyDocument": {
                        "Fn::Sub": json.dumps({
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {
                                        "Service": "events.amazonaws.com"
                                    },
                                    "Action": [
                                        "logs:CreateLogStream",
                                        "logs:PutLogEvents"
                                    ],
                                    "Resource": "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/events/${AWS::StackName}-build-events:*"
                                }
                            ]
                        })
                    }
                }
            },
            # CloudWatch Metric Filter to count build starts
            "BuildStartMetricFilter": {
                "Type": "AWS::Logs::MetricFilter",
                "DependsOn": "BuildEventLogGroup",
                "Properties": {
                    "LogGroupName": {"Fn::Sub": "/aws/events/${AWS::StackName}-build-events"},
                    "FilterPattern": '{ $.detail.build-status = "IN_PROGRESS" }',
                    "MetricTransformations": [
                        {
                            "MetricName": "MaliciousBuildStarts",
                            "MetricNamespace": {"Fn::Sub": "${AWS::StackName}/Security"},
                            "MetricValue": "1",
                            "DefaultValue": 0
                        }
                    ]
                }
            },
            # CloudWatch Alarm for unauthorized builds
            "BuildStartAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "DependsOn": "BuildStartMetricFilter",
                "Properties": {
                    "AlarmName": {"Fn::Sub": "${AWS::StackName}-unauthorized-build-alarm"},
                    "AlarmDescription": "Alarm triggered when a potentially malicious build is started",
                    "MetricName": "MaliciousBuildStarts",
                    "Namespace": {"Fn::Sub": "${AWS::StackName}/Security"},
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "TreatMissingData": "notBreaching",
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_NAME}
                    ]
                }
            }
        },
        "Outputs": {
            "CodeBuildProjectName": {
                "Description": "Name of the CodeBuild project",
                "Value": {"Ref": "MaliciousBuildProject"},
                "Export": {"Name": {"Fn::Sub": "${AWS::StackName}-ProjectName"}}
            },
            "EventRuleArn": {
                "Description": "ARN of the EventBridge rule",
                "Value": {"Fn::GetAtt": ["BuildStateChangeRule", "Arn"]},
                "Export": {"Name": {"Fn::Sub": "${AWS::StackName}-EventRuleArn"}}
            },
            "LogGroupName": {
                "Description": "Name of the CloudWatch Log Group",
                "Value": {"Ref": "BuildEventLogGroup"},
                "Export": {"Name": {"Fn::Sub": "${AWS::StackName}-LogGroupName"}}
            },
            "AlarmName": {
                "Description": "Name of the CloudWatch Alarm",
                "Value": {"Ref": "BuildStartAlarm"},
                "Export": {"Name": {"Fn::Sub": "${AWS::StackName}-AlarmName"}}
            }
        }
    }
    
    return json.dumps(template)


def steady_state() -> bool:
    """
    Deploy CloudFormation stack with detective controls for build monitoring.
    
    Returns:
        bool: True if steady state is established successfully
    """
    global STACK_NAME, BUILD_PROJECT_NAME, REGION, ACCOUNT_ID
    
    try:
        get_aws_context()
        
        # Generate unique stack name with timestamp
        timestamp = int(time.time())
        STACK_NAME = f"{EXPERIMENT_NAME}-{timestamp}"
        
        logger.info(f"Creating CloudFormation stack: {STACK_NAME}")
        
        cf_client = boto3.client('cloudformation', region_name=REGION)
        
        # Check if stack already exists
        try:
            cf_client.describe_stacks(StackName=STACK_NAME)
            logger.warning(f"Stack {STACK_NAME} already exists, will use existing resources")
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
            
            # Create the stack
            template_body = generate_cloudformation_template()
            
            response = cf_client.create_stack(
                StackName=STACK_NAME,
                TemplateBody=template_body,
                Capabilities=['CAPABILITY_NAMED_IAM'],
                Tags=[
                    {'Key': 'Experiment', 'Value': EXPERIMENT_NAME},
                    {'Key': 'Timestamp', 'Value': str(timestamp)},
                    {'Key': 'Purpose', 'Value': 'SecurityChaosEngineering'}
                ],
                OnFailure='DELETE'
            )
            
            logger.info(f"Stack creation initiated: {response['StackId']}")
        
        # Wait for stack creation to complete
        def check_stack_complete():
            try:
                response = cf_client.describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack status: {status}")
                
                if status == 'CREATE_COMPLETE':
                    return True
                elif status in ['CREATE_FAILED', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED']:
                    raise Exception(f"Stack creation failed with status: {status}")
                return False
            except ClientError as e:
                if 'does not exist' in str(e):
                    return False
                raise
        
        if not wait_with_backoff(check_stack_complete, max_wait=600):
            logger.error("Timeout waiting for stack creation")
            return False
        
        # Get stack outputs
        response = cf_client.describe_stacks(StackName=STACK_NAME)
        outputs = response['Stacks'][0].get('Outputs', [])
        
        for output in outputs:
            if output['OutputKey'] == 'CodeBuildProjectName':
                BUILD_PROJECT_NAME = output['OutputValue']
                logger.info(f"CodeBuild project created: {BUILD_PROJECT_NAME}")
        
        # Verify resources are ready
        codebuild = boto3.client('codebuild', region_name=REGION)
        project_response = codebuild.batch_get_projects(names=[BUILD_PROJECT_NAME])
        
        if not project_response.get('projects'):
            logger.error("CodeBuild project not found after stack creation")
            return False
        
        logger.info(f"Project ARN: {project_response['projects'][0]['arn']}")
        
        # Verify EventBridge rule is active
        events_client = boto3.client('events', region_name=REGION)
        rule_name = f"{STACK_NAME}-build-state-rule"
        rule_response = events_client.describe_rule(Name=rule_name)
        
        logger.info(f"EventBridge rule state: {rule_response['State']}")
        logger.info(f"EventBridge rule ARN: {rule_response['Arn']}")
        
        if rule_response['State'] != 'ENABLED':
            logger.error("EventBridge rule is not enabled")
            return False
        
        logger.info("Steady state established successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error establishing steady state: {e}")
        return False


def attack() -> bool:
    """
    Execute the attack: Start a malicious build in CodeBuild.
    
    This simulates an attacker who has gained access to start builds
    in a CodeBuild project, potentially to exfiltrate data or deploy
    malicious artifacts.
    
    Returns:
        bool: True if the attack was executed successfully with evidence
    """
    global BUILD_ID, BUILD_PROJECT_NAME, REGION
    
    try:
        if not BUILD_PROJECT_NAME:
            logger.error("Build project name not set - steady_state may not have run")
            return False
        
        codebuild = boto3.client('codebuild', region_name=REGION)
        
        logger.info(f"Starting malicious build on project: {BUILD_PROJECT_NAME}")
        
        # Start the build (this is the attack action)
        response = codebuild.start_build(
            projectName=BUILD_PROJECT_NAME,
            environmentVariablesOverride=[
                {
                    'name': 'ATTACK_MARKER',
                    'value': 'malicious-build-simulation',
                    'type': 'PLAINTEXT'
                },
                {
                    'name': 'ATTACK_TIMESTAMP',
                    'value': str(int(time.time())),
                    'type': 'PLAINTEXT'
                }
            ]
        )
        
        BUILD_ID = response['build']['id']
        build_arn = response['build']['arn']
        build_status = response['build']['buildStatus']
        
        logger.info(f"Attack executed - Build started:")
        logger.info(f"  Build ID: {BUILD_ID}")
        logger.info(f"  Build ARN: {build_arn}")
        logger.info(f"  Initial Status: {build_status}")
        logger.info(f"  Start Time: {response['build']['startTime']}")
        
        # Wait briefly for the build to be registered
        time.sleep(5)
        
        # Verify the build is in progress or completed
        build_response = codebuild.batch_get_builds(ids=[BUILD_ID])
        
        if build_response.get('builds'):
            current_status = build_response['builds'][0]['buildStatus']
            logger.info(f"Build current status: {current_status}")
            
            # Evidence that attack was executed
            return True
        
        return False
        
    except ClientError as e:
        logger.error(f"AWS API error during attack: {e}")
        return False
    except Exception as e:
        logger.error(f"Error executing attack: {e}")
        return False


def hypothesis_verification() -> bool:
    """
    Verify that the detective control detected the malicious build start.
    
    This function checks:
    1. EventBridge rule captured the build state change event
    2. CloudWatch Logs contain the build event
    3. CloudWatch Alarm was triggered (or metric was recorded)
    
    Returns:
        bool: True if the detective control successfully detected the attack
    """
    global STACK_NAME, BUILD_ID, BUILD_PROJECT_NAME, REGION
    
    try:
        if not STACK_NAME or not BUILD_ID:
            logger.error("Missing stack name or build ID - previous phases may have failed")
            return False
        
        logs_client = boto3.client('logs', region_name=REGION)
        events_client = boto3.client('events', region_name=REGION)
        cloudwatch = boto3.client('cloudwatch', region_name=REGION)
        
        log_group_name = f"/aws/events/{STACK_NAME}-build-events"
        detection_evidence = {
            'eventbridge_rule_active': False,
            'logs_contain_build_event': False,
            'metric_recorded': False
        }
        
        # Check 1: Verify EventBridge rule is still active and has targets
        rule_name = f"{STACK_NAME}-build-state-rule"
        try:
            rule_response = events_client.describe_rule(Name=rule_name)
            detection_evidence['eventbridge_rule_active'] = (rule_response['State'] == 'ENABLED')
            logger.info(f"EventBridge rule state: {rule_response['State']}")
            
            # Check targets
            targets_response = events_client.list_targets_by_rule(Rule=rule_name)
            logger.info(f"EventBridge rule targets: {len(targets_response.get('Targets', []))}")
            
        except ClientError as e:
            logger.error(f"Error checking EventBridge rule: {e}")
        
        # Check 2: Look for build events in CloudWatch Logs
        # Wait for events to propagate (EventBridge -> CloudWatch Logs has some latency)
        logger.info("Waiting for events to propagate to CloudWatch Logs...")
        
        def check_logs_for_build_event():
            try:
                # Get log streams
                streams_response = logs_client.describe_log_streams(
                    logGroupName=log_group_name,
                    orderBy='LastEventTime',
                    descending=True,
                    limit=5
                )
                
                if not streams_response.get('logStreams'):
                    logger.info("No log streams found yet")
                    return False
                
                # Search for our build event in recent logs
                for stream in streams_response['logStreams']:
                    events_response = logs_client.get_log_events(
                        logGroupName=log_group_name,
                        logStreamName=stream['logStreamName'],
                        limit=50
                    )
                    
                    for event in events_response.get('events', []):
                        message = event.get('message', '')
                        # Check if this log contains our build event
                        if BUILD_PROJECT_NAME in message or BUILD_ID in message:
                            logger.info(f"Found build event in logs: {message[:200]}...")
                            return True
                        # Also check for CodeBuild events generally
                        if 'codebuild' in message.lower() and 'build-status' in message.lower():
                            logger.info(f"Found CodeBuild event in logs: {message[:200]}...")
                            return True
                
                return False
                
            except ClientError as e:
                if 'ResourceNotFoundException' in str(e):
                    logger.info("Log group/stream not found yet")
                    return False
                logger.warning(f"Error checking logs: {e}")
                return False
        
        # Wait for log events with backoff
        detection_evidence['logs_contain_build_event'] = wait_with_backoff(
            check_logs_for_build_event, 
            max_wait=120,
            initial_interval=10
        )
        
        # Check 3: Verify CloudWatch metric was recorded
        metric_namespace = f"{STACK_NAME}/Security"
        metric_name = "MaliciousBuildStarts"
        
        try:
            # Query the metric for recent data
            end_time = time.time()
            start_time = end_time - 300  # Last 5 minutes
            
            metric_response = cloudwatch.get_metric_statistics(
                Namespace=metric_namespace,
                MetricName=metric_name,
                StartTime=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(start_time)),
                EndTime=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(end_time)),
                Period=60,
                Statistics=['Sum']
            )
            
            datapoints = metric_response.get('Datapoints', [])
            logger.info(f"Metric datapoints: {datapoints}")
            
            if datapoints:
                total_builds = sum(dp.get('Sum', 0) for dp in datapoints)
                detection_evidence['metric_recorded'] = total_builds > 0
                logger.info(f"Total malicious build starts recorded: {total_builds}")
            
        except ClientError as e:
            logger.warning(f"Error checking metric: {e}")
        
        # Check CloudWatch Alarm state
        alarm_name = f"{STACK_NAME}-unauthorized-build-alarm"
        try:
            alarm_response = cloudwatch.describe_alarms(AlarmNames=[alarm_name])
            if alarm_response.get('MetricAlarms'):
                alarm_state = alarm_response['MetricAlarms'][0]['StateValue']
                logger.info(f"CloudWatch Alarm state: {alarm_state}")
                # Alarm might be in ALARM or INSUFFICIENT_DATA depending on timing
        except ClientError as e:
            logger.warning(f"Error checking alarm: {e}")
        
        # Final verification: Detective control is considered successful if:
        # 1. EventBridge rule is active AND
        # 2. Either logs contain the event OR metric was recorded
        logger.info(f"Detection evidence summary: {detection_evidence}")
        
        detection_successful = (
            detection_evidence['eventbridge_rule_active'] and
            (detection_evidence['logs_contain_build_event'] or detection_evidence['metric_recorded'])
        )
        
        if detection_successful:
            logger.info("HYPOTHESIS VERIFIED: Detective control successfully detected the malicious build")
        else:
            logger.warning("HYPOTHESIS FAILED: Detective control did not detect the malicious build as expected")
        
        return detection_successful
        
    except Exception as e:
        logger.error(f"Error in hypothesis verification: {e}")
        return False


def rollback() -> bool:
    """
    Clean up all resources created by the experiment.
    
    Returns:
        bool: True if rollback completed successfully
    """
    global STACK_NAME, BUILD_ID, REGION
    
    try:
        if not STACK_NAME:
            logger.warning("No stack name set, nothing to rollback")
            return True
        
        cf_client = boto3.client('cloudformation', region_name=REGION)
        codebuild = boto3.client('codebuild', region_name=REGION)
        
        # Stop any running builds first
        if BUILD_ID:
            try:
                codebuild.stop_build(id=BUILD_ID)
                logger.info(f"Stopped build: {BUILD_ID}")
            except ClientError as e:
                if 'Build is already complete' not in str(e):
                    logger.warning(f"Could not stop build: {e}")
        
        # Delete CloudFormation stack
        logger.info(f"Deleting CloudFormation stack: {STACK_NAME}")
        
        try:
            cf_client.delete_stack(StackName=STACK_NAME)
            logger.info("Stack deletion initiated")
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.info("Stack already deleted")
                return True
            raise
        
        # Wait for stack deletion
        def check_stack_deleted():
            try:
                response = cf_client.describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack deletion status: {status}")
                
                if status == 'DELETE_COMPLETE':
                    return True
                elif status == 'DELETE_FAILED':
                    raise Exception("Stack deletion failed")
                return False
            except ClientError as e:
                if 'does not exist' in str(e):
                    return True
                raise
        
        if wait_with_backoff(check_stack_deleted, max_wait=600):
            logger.info("Rollback completed successfully")
            return True
        else:
            logger.error("Timeout waiting for stack deletion")
            return False
            
    except Exception as e:
        logger.error(f"Error during rollback: {e}")
        return False


def main():
    """Main function to run the complete experiment."""
    success = False
    
    try:
        logger.info("=" * 60)
        logger.info("SCE Experiment 1.8 - Malicious Build Detection (Detective)")
        logger.info("=" * 60)
        
        # Phase 1: Establish steady state
        logger.info("\n--- Phase 1: Establishing Steady State ---")
        if not steady_state():
            logger.error("Failed to establish steady state")
            return False
        
        # Brief pause to ensure all resources are fully ready
        time.sleep(10)
        
        # Phase 2: Execute attack
        logger.info("\n--- Phase 2: Executing Attack ---")
        if not attack():
            logger.error("Attack execution failed")
            return False
        
        # Wait for detection systems to process the event
        logger.info("\nWaiting for detection systems to process the event...")
        time.sleep(30)
        
        # Phase 3: Verify hypothesis
        logger.info("\n--- Phase 3: Verifying Hypothesis ---")
        success = hypothesis_verification()
        
        return success
        
    except Exception as e:
        logger.error(f"Experiment failed with error: {e}")
        return False
        
    finally:
        # Phase 4: Rollback
        logger.info("\n--- Phase 4: Rollback ---")
        rollback()
        
        logger.info("\n" + "=" * 60)
        logger.info(f"Experiment Result: {'SUCCESS' if success else 'FAILURE'}")
        logger.info("=" * 60)


if __name__ == "__main__":
    result = main()
    exit(0 if result else 1)