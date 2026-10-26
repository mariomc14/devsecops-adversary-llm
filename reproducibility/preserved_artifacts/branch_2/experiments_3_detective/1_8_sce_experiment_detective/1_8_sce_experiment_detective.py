#!/usr/bin/env python3
"""
SCE Experiment 1.8 - Detective Control for Malicious CodeBuild Activity

This experiment validates runtime container monitoring for AWS CodeBuild,
specifically testing whether CloudWatch-based detective controls can identify
credential exfiltration attempts during build execution.

Attack Node: 1.7 Start Malicious Build
Defense Node: 1.9 Runtime Container Monitoring
Probe Type: Detective
"""

import sys
import time
import json
import logging
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Install boto3 if not available
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    logger.info("Installing boto3...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "boto3"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Global state for resource tracking
STACK_NAME = None
REGION = None


def get_aws_clients():
    """Initialize AWS clients with retry configuration."""
    global REGION
    session = boto3.Session()
    REGION = session.region_name or 'us-east-1'
    
    config = boto3.session.Config(
        retries={'max_attempts': 10, 'mode': 'adaptive'}
    )
    
    return {
        'cfn': session.client('cloudformation', region_name=REGION, config=config),
        'codebuild': session.client('codebuild', region_name=REGION, config=config),
        'logs': session.client('logs', region_name=REGION, config=config),
        'cloudwatch': session.client('cloudwatch', region_name=REGION, config=config),
        'sts': session.client('sts', region_name=REGION, config=config)
    }


def get_cloudformation_template() -> str:
    """
    Returns CloudFormation template with FIXED metric filter pattern.
    
    Previous error: "Invalid character(s) in term '...message'"
    Root cause: The pattern [time, request_id, event_type, ...message] is invalid
    Fix: Use a simple substring match pattern that CloudWatch Logs accepts
    """
    return """
AWSTemplateFormatVersion: '2010-09-09'
Description: 'SCE 1.8 - Detective controls for CodeBuild malicious activity detection'

Resources:
  CodeBuildRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: codebuild.amazonaws.com
            Action: 'sts:AssumeRole'
      ManagedPolicyArns:
        - 'arn:aws:iam::aws:policy/CloudWatchLogsFullAccess'
      Policies:
        - PolicyName: CodeBuildBasePolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - 'logs:CreateLogGroup'
                  - 'logs:CreateLogStream'
                  - 'logs:PutLogEvents'
                Resource: '*'

  BuildLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: !Sub '/aws/codebuild/sce-malicious-build-${AWS::StackName}'
      RetentionInDays: 1

  MaliciousActivityMetricFilter:
    Type: AWS::Logs::MetricFilter
    Properties:
      FilterPattern: '?MALICIOUS ?EXFILTRATION ?SUSPICIOUS ?metadata ?credentials ?token'
      LogGroupName: !Ref BuildLogGroup
      MetricTransformations:
        - MetricName: MaliciousActivity
          MetricNamespace: SCE/CodeBuild
          MetricValue: '1'
          DefaultValue: 0

  MaliciousActivityAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: !Sub 'SCE-CodeBuild-MaliciousActivity-${AWS::StackName}'
      AlarmDescription: 'Detects malicious activity in CodeBuild containers'
      MetricName: MaliciousActivity
      Namespace: SCE/CodeBuild
      Statistic: Sum
      Period: 60
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      TreatMissingData: notBreaching

  MaliciousBuildProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Name: !Sub 'sce-malicious-build-${AWS::StackName}'
      ServiceRole: !GetAtt CodeBuildRole.Arn
      Artifacts:
        Type: NO_ARTIFACTS
      Environment:
        Type: LINUX_CONTAINER
        ComputeType: BUILD_GENERAL1_SMALL
        Image: 'aws/codebuild/standard:5.0'
        EnvironmentVariables:
          - Name: EXPERIMENT_ID
            Value: !Ref AWS::StackName
      Source:
        Type: NO_SOURCE
        BuildSpec: |
          version: 0.2
          phases:
            build:
              commands:
                - echo "=== MALICIOUS BUILD STARTING ==="
                - echo "Attempting credential EXFILTRATION..."
                - echo "SUSPICIOUS activity - querying metadata service"
                - |
                  # Attempt IMDSv2 token retrieval
                  TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || echo "failed")
                  echo "IMDS token attempt: $TOKEN"
                - |
                  # Attempt to query metadata for credentials
                  curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>/dev/null || echo "Metadata query failed"
                - |
                  # Try to extract AWS credentials from environment
                  echo "Scanning for AWS credentials in environment..."
                  env | grep -i aws || echo "No AWS env vars found"
                - echo "=== MALICIOUS indicators logged ==="
      LogsConfig:
        CloudWatchLogs:
          Status: ENABLED
          GroupName: !Ref BuildLogGroup

Outputs:
  BuildProjectName:
    Value: !Ref MaliciousBuildProject
    Description: CodeBuild project name
  AlarmName:
    Value: !Ref MaliciousActivityAlarm
    Description: CloudWatch alarm name
  MetricFilterName:
    Value: !Ref MaliciousActivityMetricFilter
    Description: Metric filter name
  LogGroupName:
    Value: !Ref BuildLogGroup
    Description: CloudWatch Logs group name
"""


def steady_state() -> None:
    """
    Deploy CloudFormation stack with CodeBuild project and detective controls.
    
    Creates:
    - CodeBuild project with malicious buildspec
    - CloudWatch Log Group for build output
    - Metric Filter to detect malicious patterns
    - CloudWatch Alarm to alert on detections
    """
    global STACK_NAME
    
    clients = get_aws_clients()
    cfn = clients['cfn']
    
    # Generate unique stack name with timestamp
    timestamp = int(time.time())
    STACK_NAME = f"sce-experiment-1-8-{timestamp}"
    
    logger.info(f"Deploying CloudFormation stack: {STACK_NAME}")
    
    try:
        # Check if stack already exists
        try:
            cfn.describe_stacks(StackName=STACK_NAME)
            logger.warning(f"Stack {STACK_NAME} already exists, continuing...")
            return
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
        
        # Create stack
        response = cfn.create_stack(
            StackName=STACK_NAME,
            TemplateBody=get_cloudformation_template(),
            Capabilities=['CAPABILITY_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': 'SCE-1.8'},
                {'Key': 'Timestamp', 'Value': str(timestamp)},
                {'Key': 'Purpose', 'Value': 'SecurityChaosEngineering'}
            ]
        )
        
        stack_id = response['StackId']
        logger.info(f"Stack creation initiated: {stack_id}")
        
        # Wait for stack creation with exponential backoff
        max_wait_time = 600  # 10 minutes
        start_time = time.monotonic()
        check_interval = 10
        
        while time.monotonic() - start_time < max_wait_time:
            try:
                response = cfn.describe_stacks(StackName=STACK_NAME)
                stack_status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack status: {stack_status}")
                
                if stack_status == 'CREATE_COMPLETE':
                    logger.info("Stack creation completed successfully")
                    return
                elif stack_status in ['CREATE_FAILED', 'ROLLBACK_IN_PROGRESS', 'ROLLBACK_COMPLETE']:
                    # Get failure reasons
                    events = cfn.describe_stack_events(StackName=STACK_NAME)
                    for event in events['StackEvents']:
                        if 'FAILED' in event.get('ResourceStatus', ''):
                            reason = event.get('ResourceStatusReason', 'Unknown')
                            logger.error(f"Resource {event['LogicalResourceId']}: {reason}")
                    raise Exception(f"Stack creation failed with status: {stack_status}")
                
                time.sleep(check_interval)
                
            except ClientError as e:
                logger.error(f"Error checking stack status: {e}")
                raise
        
        raise TimeoutError(f"Stack creation timed out after {max_wait_time} seconds")
        
    except Exception as e:
        logger.error(f"Failed to deploy infrastructure: {e}")
        raise


def attack() -> bool:
    """
    Execute malicious build that attempts credential exfiltration.
    
    Returns:
        bool: True if build was started and completed (regardless of success/failure),
              False if build could not be initiated.
    """
    global STACK_NAME
    
    if not STACK_NAME:
        logger.error("No stack name available - steady_state not executed")
        return False
    
    clients = get_aws_clients()
    cfn = clients['cfn']
    codebuild = clients['codebuild']
    
    logger.info("Executing malicious build with credential exfiltration attempt...")
    
    try:
        # Get stack outputs
        response = cfn.describe_stacks(StackName=STACK_NAME)
        outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
        
        project_name = outputs.get('BuildProjectName')
        if not project_name:
            logger.error("BuildProjectName not found in stack outputs")
            return False
        
        logger.info(f"Starting malicious build in project: {project_name}")
        
        # Start build
        build_response = codebuild.start_build(projectName=project_name)
        build_id = build_response['build']['id']
        build_arn = build_response['build']['arn']
        
        logger.info(f"Build started: {build_id}")
        logger.info(f"Build ARN: {build_arn}")
        
        # Wait for build to complete (with timeout)
        max_wait_time = 300  # 5 minutes
        start_time = time.monotonic()
        check_interval = 10
        
        while time.monotonic() - start_time < max_wait_time:
            build_info = codebuild.batch_get_builds(ids=[build_id])
            build_status = build_info['builds'][0]['buildStatus']
            
            logger.info(f"Build status: {build_status}")
            
            if build_status in ['SUCCEEDED', 'FAILED', 'STOPPED']:
                logger.info(f"Build completed with status: {build_status}")
                
                # Verify build logs contain malicious markers
                logs = build_info['builds'][0].get('logs', {})
                log_group = logs.get('groupName')
                log_stream = logs.get('streamName')
                
                if log_group and log_stream:
                    logger.info(f"Build logs: {log_group}/{log_stream}")
                    
                    # Give logs time to propagate
                    time.sleep(5)
                    
                    try:
                        logs_client = clients['logs']
                        log_events = logs_client.get_log_events(
                            logGroupName=log_group,
                            logStreamName=log_stream,
                            startFromHead=True
                        )
                        
                        malicious_markers = ['MALICIOUS', 'EXFILTRATION', 'SUSPICIOUS']
                        found_markers = []
                        
                        for event in log_events.get('events', []):
                            message = event['message']
                            for marker in malicious_markers:
                                if marker in message:
                                    found_markers.append(marker)
                        
                        if found_markers:
                            logger.info(f"Verified malicious markers in logs: {found_markers}")
                        else:
                            logger.warning("Malicious markers not found in logs")
                    
                    except ClientError as e:
                        logger.warning(f"Could not verify log content: {e}")
                
                # Return True because build executed (attack succeeded)
                return True
            
            time.sleep(check_interval)
        
        logger.warning(f"Build timed out after {max_wait_time} seconds")
        return True  # Build was initiated even if it timed out
        
    except ClientError as e:
        logger.error(f"Attack execution failed: {e}")
        return False
    except KeyError as e:
        logger.error(f"Missing expected data in response: {e}")
        return False


def hypothesis_verification() -> bool:
    """
    Verify that CloudWatch detective controls detected the malicious activity.
    
    Checks:
    1. CloudWatch Alarm state (should be in ALARM)
    2. Metric data shows detections
    3. Alarm history shows state change
    4. Metric filter processed log events
    
    Returns:
        bool: True if detective control detected malicious activity, False otherwise
    """
    global STACK_NAME
    
    if not STACK_NAME:
        logger.error("No stack name available - cannot verify hypothesis")
        return False
    
    clients = get_aws_clients()
    cfn = clients['cfn']
    cloudwatch = clients['cloudwatch']
    logs = clients['logs']
    
    logger.info("Verifying detective control detected malicious activity...")
    
    try:
        # Get stack outputs
        response = cfn.describe_stacks(StackName=STACK_NAME)
        outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
        
        alarm_name = outputs.get('AlarmName')
        log_group_name = outputs.get('LogGroupName')
        
        if not alarm_name or not log_group_name:
            logger.error("Required outputs not found in stack")
            return False
        
        logger.info(f"Checking alarm: {alarm_name}")
        logger.info(f"Log group: {log_group_name}")
        
        # Wait for metrics to propagate (CloudWatch has eventual consistency)
        logger.info("Waiting 90 seconds for metric propagation...")
        time.sleep(90)
        
        # Check 1: Alarm state
        alarm_response = cloudwatch.describe_alarms(AlarmNames=[alarm_name])
        if not alarm_response['MetricAlarms']:
            logger.error("Alarm not found")
            return False
        
        alarm = alarm_response['MetricAlarms'][0]
        alarm_state = alarm['StateValue']
        logger.info(f"Alarm state: {alarm_state}")
        
        if alarm_state == 'ALARM':
            logger.info("✓ Detective control DETECTED malicious activity (alarm in ALARM state)")
            return True
        
        # Check 2: Query metric data directly
        end_time = time.time()
        start_time = end_time - 600  # Last 10 minutes
        
        metric_response = cloudwatch.get_metric_statistics(
            Namespace='SCE/CodeBuild',
            MetricName='MaliciousActivity',
            StartTime=int(start_time),
            EndTime=int(end_time),
            Period=60,
            Statistics=['Sum']
        )
        
        datapoints = metric_response.get('Datapoints', [])
        logger.info(f"Metric datapoints retrieved: {len(datapoints)}")
        
        total_detections = sum(dp['Sum'] for dp in datapoints)
        logger.info(f"Total malicious activity detections: {total_detections}")
        
        if total_detections > 0:
            logger.info("✓ Detective control DETECTED malicious activity (metric data confirms)")
            return True
        
        # Check 3: Alarm history
        history_response = cloudwatch.describe_alarm_history(
            AlarmName=alarm_name,
            HistoryItemType='StateUpdate',
            MaxRecords=10
        )
        
        for item in history_response.get('AlarmHistoryItems', []):
            logger.info(f"Alarm history: {item['HistorySummary']}")
            if 'ALARM' in item['HistorySummary']:
                logger.info("✓ Detective control DETECTED malicious activity (alarm history confirms)")
                return True
        
        # Check 4: Verify log events exist and contain malicious markers
        logger.info("Checking log streams for malicious markers...")
        
        try:
            streams_response = logs.describe_log_streams(
                logGroupName=log_group_name,
                orderBy='LastEventTime',
                descending=True,
                limit=5
            )
            
            for stream in streams_response.get('logStreams', []):
                stream_name = stream['logStreamName']
                logger.info(f"Examining stream: {stream_name}")
                
                events_response = logs.get_log_events(
                    logGroupName=log_group_name,
                    logStreamName=stream_name,
                    startFromHead=True
                )
                
                malicious_count = 0
                for event in events_response.get('events', []):
                    message = event['message']
                    if any(marker in message for marker in ['MALICIOUS', 'EXFILTRATION', 'SUSPICIOUS']):
                        malicious_count += 1
                
                logger.info(f"Found {malicious_count} log events with malicious markers in stream {stream_name}")
                
        except ClientError as e:
            logger.warning(f"Could not analyze log streams: {e}")
        
        # If we got here, detection failed
        logger.warning("✗ Detective control FAILED to detect malicious activity")
        logger.warning(f"Alarm state: {alarm_state}, Metric detections: {total_detections}")
        logger.warning("Possible causes:")
        logger.warning("  - Metric filter pattern did not match log events")
        logger.warning("  - Insufficient time for metric propagation")
        logger.warning("  - Log events not yet indexed by CloudWatch")
        
        return False
        
    except ClientError as e:
        logger.error(f"Hypothesis verification failed with AWS error: {e}")
        return False
    except Exception as e:
        logger.error(f"Hypothesis verification failed: {e}")
        return False


def rollback() -> None:
    """
    Delete CloudFormation stack and all associated resources.
    """
    global STACK_NAME
    
    if not STACK_NAME:
        logger.warning("No stack name available - nothing to rollback")
        return
    
    clients = get_aws_clients()
    cfn = clients['cfn']
    
    logger.info(f"Rolling back: Deleting stack {STACK_NAME}")
    
    try:
        # Initiate stack deletion
        cfn.delete_stack(StackName=STACK_NAME)
        logger.info("Stack deletion initiated")
        
        # Wait for deletion with timeout
        max_wait_time = 600  # 10 minutes
        start_time = time.monotonic()
        check_interval = 10
        
        while time.monotonic() - start_time < max_wait_time:
            try:
                response = cfn.describe_stacks(StackName=STACK_NAME)
                stack_status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack deletion status: {stack_status}")
                
                if stack_status == 'DELETE_COMPLETE':
                    logger.info("Stack deleted successfully")
                    return
                elif stack_status == 'DELETE_FAILED':
                    logger.error("Stack deletion failed")
                    return
                
                time.sleep(check_interval)
                
            except ClientError as e:
                if 'does not exist' in str(e):
                    logger.info(f"Stack {STACK_NAME} does not exist (already deleted)")
                    return
                raise
        
        logger.warning(f"Stack deletion timed out after {max_wait_time} seconds")
        
    except ClientError as e:
        if 'does not exist' in str(e):
            logger.info(f"Stack {STACK_NAME} does not exist (already deleted)")
        else:
            logger.error(f"Error during rollback: {e}")
    except Exception as e:
        logger.error(f"Rollback failed: {e}")


def main():
    """
    Execute the complete experiment flow locally for testing.
    """
    logger.info("=" * 80)
    logger.info("SCE Experiment 1.8 - Detective Control Test")
    logger.info("=" * 80)
    
    try:
        # Phase 1: Deploy infrastructure
        logger.info("\n[PHASE 1] Deploying infrastructure with detective controls...")
        steady_state()
        
        # Phase 2: Execute attack
        logger.info("\n[PHASE 2] Executing malicious build attack...")
        attack_success = attack()
        logger.info(f"Attack execution result: {attack_success}")
        
        # Phase 3: Verify detection
        logger.info("\n[PHASE 3] Verifying detective control detected the attack...")
        detection_success = hypothesis_verification()
        logger.info(f"Detection result: {detection_success}")
        
        # Report results
        logger.info("\n" + "=" * 80)
        logger.info("EXPERIMENT RESULTS")
        logger.info("=" * 80)
        logger.info(f"Attack executed: {attack_success}")
        logger.info(f"Detection successful: {detection_success}")
        
        if detection_success:
            logger.info("\n✓ HYPOTHESIS CONFIRMED: Detective control is working")
            logger.info("The CloudWatch-based monitoring successfully detected malicious build activity")
        else:
            logger.info("\n✗ HYPOTHESIS REJECTED: Detective control failed")
            logger.info("The CloudWatch-based monitoring did not detect the malicious activity")
        
    except Exception as e:
        logger.error(f"\n✗ EXPERIMENT FAILED: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        # Always attempt cleanup
        logger.info("\n[CLEANUP] Rolling back infrastructure...")
        try:
            rollback()
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
    
    logger.info("\n" + "=" * 80)
    logger.info("Experiment complete")
    logger.info("=" * 80)


if __name__ == '__main__':
    main()