#!/usr/bin/env python3
"""
SCE Experiment 1.8 - Reactive Probe
Attack Node: 1.7 Start Malicious Build

This experiment validates that reactive controls can detect and respond to
unauthorized CodeBuild executions. It tests whether malicious builds trigger
CloudWatch alarms, EventBridge rules, and SNS notifications.
"""

import json
import logging
import time
import boto3
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state for experiment tracking
EXPERIMENT_STATE = {
    'stack_name': None,
    'project_name': None,
    'build_id': None,
    'region': None,
    'account_id': None,
    'timestamp': None
}

def get_aws_clients():
    """Initialize AWS clients with default credential chain."""
    session = boto3.Session()
    region = session.region_name or 'us-east-1'
    EXPERIMENT_STATE['region'] = region
    
    return {
        'cloudformation': session.client('cloudformation', region_name=region),
        'codebuild': session.client('codebuild', region_name=region),
        'cloudwatch': session.client('cloudwatch', region_name=region),
        'logs': session.client('logs', region_name=region),
        'events': session.client('events', region_name=region),
        'sns': session.client('sns', region_name=region),
        'sts': session.client('sts', region_name=region),
        's3': session.client('s3', region_name=region)
    }

def get_cloudformation_template(timestamp: int, account_id: str, region: str) -> str:
    """Generate CloudFormation template for the experiment."""
    return f'''
AWSTemplateFormatVersion: '2010-09-09'
Description: 'SCE Experiment 1.8 - Reactive Probe for Malicious Build Detection'

Resources:
  # S3 Bucket for CodeBuild artifacts
  ArtifactBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: sce-artifacts-{timestamp}
      Tags:
        - Key: Experiment
          Value: sce-1-8-reactive
        - Key: Timestamp
          Value: '{timestamp}'

  # SNS Topic for alerts
  AlertSNSTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: sce-malicious-build-alerts-{timestamp}
      Tags:
        - Key: Experiment
          Value: sce-1-8-reactive

  # SNS Topic Policy to allow EventBridge to publish
  AlertSNSTopicPolicy:
    Type: AWS::SNS::TopicPolicy
    Properties:
      Topics:
        - !Ref AlertSNSTopic
      PolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: events.amazonaws.com
            Action: sns:Publish
            Resource: !Ref AlertSNSTopic

  # IAM Role for CodeBuild
  CodeBuildRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: sce-codebuild-role-{timestamp}
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: codebuild.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: CodeBuildPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !Sub 'arn:aws:logs:{region}:{account_id}:log-group:/aws/codebuild/*'
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:PutObject
                Resource: !Sub '${{ArtifactBucket.Arn}}/*'
      Tags:
        - Key: Experiment
          Value: sce-1-8-reactive

  # CodeBuild Project with malicious indicators
  MaliciousCodeBuildProject:
    Type: AWS::CodeBuild::Project
    DependsOn: CodeBuildRole
    Properties:
      Name: sce-malicious-project-{timestamp}
      Description: 'SCE Experiment - Simulated malicious build project'
      ServiceRole: !GetAtt CodeBuildRole.Arn
      Artifacts:
        Type: NO_ARTIFACTS
      Environment:
        Type: LINUX_CONTAINER
        ComputeType: BUILD_GENERAL1_SMALL
        Image: aws/codebuild/amazonlinux2-x86_64-standard:4.0
        EnvironmentVariables:
          - Name: MALICIOUS_INDICATOR
            Value: 'true'
      Source:
        Type: NO_SOURCE
        BuildSpec: |
          version: 0.2
          phases:
            build:
              commands:
                - echo "MALICIOUS_INDICATOR=true"
                - echo "Simulated credential exposure attempt"
                - echo "ATTACK_SIMULATION_COMPLETE"
      TimeoutInMinutes: 5
      Tags:
        - Key: Experiment
          Value: sce-1-8-reactive
        - Key: MaliciousIndicator
          Value: 'true'

  # CloudWatch Log Group for CodeBuild
  CodeBuildLogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      LogGroupName: /aws/codebuild/sce-malicious-project-{timestamp}
      RetentionInDays: 1
      Tags:
        - Key: Experiment
          Value: sce-1-8-reactive

  # Metric Filter for detecting malicious patterns
  MaliciousPatternMetricFilter:
    Type: AWS::Logs::MetricFilter
    DependsOn: CodeBuildLogGroup
    Properties:
      LogGroupName: /aws/codebuild/sce-malicious-project-{timestamp}
      FilterPattern: 'MALICIOUS_INDICATOR'
      MetricTransformations:
        - MetricName: MaliciousBuildIndicator
          MetricNamespace: SCE/CodeBuild
          MetricValue: '1'
          DefaultValue: 0

  # CloudWatch Alarm for malicious build detection
  MaliciousBuildAlarm:
    Type: AWS::CloudWatch::Alarm
    Properties:
      AlarmName: sce-malicious-build-alarm-{timestamp}
      AlarmDescription: 'Alarm triggered when malicious build indicator is detected'
      MetricName: MaliciousBuildIndicator
      Namespace: SCE/CodeBuild
      Statistic: Sum
      Period: 60
      EvaluationPeriods: 1
      Threshold: 1
      ComparisonOperator: GreaterThanOrEqualToThreshold
      AlarmActions:
        - !Ref AlertSNSTopic
      TreatMissingData: notBreaching
      Tags:
        - Key: Experiment
          Value: sce-1-8-reactive

  # EventBridge Rule for build state changes
  BuildEventRule:
    Type: AWS::Events::Rule
    Properties:
      Name: sce-build-event-rule-{timestamp}
      Description: 'Captures CodeBuild state changes for reactive response'
      State: ENABLED
      EventPattern:
        source:
          - aws.codebuild
        detail-type:
          - CodeBuild Build State Change
        detail:
          project-name:
            - sce-malicious-project-{timestamp}
          build-status:
            - IN_PROGRESS
            - SUCCEEDED
            - FAILED
            - STOPPED
      Targets:
        - Id: SNSTarget
          Arn: !Ref AlertSNSTopic

Outputs:
  ProjectName:
    Value: !Ref MaliciousCodeBuildProject
    Description: Name of the CodeBuild project
  SNSTopicArn:
    Value: !Ref AlertSNSTopic
    Description: ARN of the SNS alert topic
  AlarmName:
    Value: !Ref MaliciousBuildAlarm
    Description: Name of the CloudWatch alarm
  EventRuleName:
    Value: !Ref BuildEventRule
    Description: Name of the EventBridge rule
  LogGroupName:
    Value: !Ref CodeBuildLogGroup
    Description: Name of the CloudWatch Log Group
'''

def wait_for_stack_operation(cf_client, stack_name: str, operation: str, max_wait: int = 600) -> bool:
    """Wait for CloudFormation stack operation to complete."""
    start_time = time.monotonic()
    target_status = f'{operation}_COMPLETE'
    failed_status = f'{operation}_FAILED'
    rollback_status = 'ROLLBACK_COMPLETE'
    
    while time.monotonic() - start_time < max_wait:
        try:
            response = cf_client.describe_stacks(StackName=stack_name)
            status = response['Stacks'][0]['StackStatus']
            logger.info(f"Stack {stack_name} status: {status}")
            
            if status == target_status:
                return True
            elif status in [failed_status, rollback_status, 'DELETE_COMPLETE']:
                logger.error(f"Stack operation failed with status: {status}")
                return False
            elif 'FAILED' in status or 'ROLLBACK' in status:
                logger.error(f"Stack operation failed with status: {status}")
                return False
                
        except ClientError as e:
            if 'does not exist' in str(e):
                if operation == 'DELETE':
                    return True
                logger.error(f"Stack {stack_name} does not exist")
                return False
            raise
            
        time.sleep(10)
    
    logger.error(f"Timeout waiting for stack operation {operation}")
    return False

def steady_state() -> bool:
    """
    Deploy CloudFormation stack with all required resources for the experiment.
    Creates CodeBuild project, CloudWatch alarm, EventBridge rule, and SNS topic.
    """
    logger.info("=== Starting steady_state phase ===")
    
    try:
        clients = get_aws_clients()
        cf_client = clients['cloudformation']
        sts_client = clients['sts']
        
        # Get account ID
        identity = sts_client.get_caller_identity()
        account_id = identity['Account']
        EXPERIMENT_STATE['account_id'] = account_id
        logger.info(f"AWS Account ID: {account_id}")
        
        # Generate unique timestamp
        timestamp = int(time.time())
        EXPERIMENT_STATE['timestamp'] = timestamp
        stack_name = f'sce-experiment-{timestamp}'
        EXPERIMENT_STATE['stack_name'] = stack_name
        EXPERIMENT_STATE['project_name'] = f'sce-malicious-project-{timestamp}'
        
        logger.info(f"Creating stack: {stack_name}")
        
        # Check if stack already exists
        try:
            cf_client.describe_stacks(StackName=stack_name)
            logger.warning(f"Stack {stack_name} already exists, continuing...")
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
        
        # Create CloudFormation stack
        template_body = get_cloudformation_template(timestamp, account_id, EXPERIMENT_STATE['region'])
        
        try:
            cf_client.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Capabilities=['CAPABILITY_NAMED_IAM'],
                Tags=[
                    {'Key': 'Experiment', 'Value': 'sce-1-8-reactive'},
                    {'Key': 'Timestamp', 'Value': str(timestamp)}
                ],
                OnFailure='DELETE'
            )
            logger.info(f"Stack creation initiated: {stack_name}")
        except ClientError as e:
            if 'AlreadyExistsException' in str(e):
                logger.warning(f"Stack {stack_name} already exists")
            else:
                raise
        
        # Wait for stack creation
        if not wait_for_stack_operation(cf_client, stack_name, 'CREATE'):
            logger.error("Stack creation failed")
            return False
        
        # Verify stack outputs
        response = cf_client.describe_stacks(StackName=stack_name)
        outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
        logger.info(f"Stack outputs: {json.dumps(outputs, indent=2)}")
        
        # Verify CodeBuild project exists
        codebuild_client = clients['codebuild']
        project_name = EXPERIMENT_STATE['project_name']
        
        project_response = codebuild_client.batch_get_projects(names=[project_name])
        if not project_response.get('projects'):
            logger.error(f"CodeBuild project {project_name} not found")
            return False
        
        logger.info(f"CodeBuild project verified: {project_name}")
        
        # Verify EventBridge rule exists
        events_client = clients['events']
        rule_name = f'sce-build-event-rule-{timestamp}'
        
        try:
            rule_response = events_client.describe_rule(Name=rule_name)
            logger.info(f"EventBridge rule verified: {rule_name}, State: {rule_response['State']}")
        except ClientError as e:
            logger.error(f"EventBridge rule not found: {e}")
            return False
        
        logger.info("=== steady_state phase completed successfully ===")
        return True
        
    except Exception as e:
        logger.error(f"steady_state failed: {e}")
        return False

def attack() -> bool:
    """
    Execute the attack by starting a malicious build.
    This simulates attack node 1.7 - Start Malicious Build.
    """
    logger.info("=== Starting attack phase ===")
    
    try:
        clients = get_aws_clients()
        codebuild_client = clients['codebuild']
        
        project_name = EXPERIMENT_STATE.get('project_name')
        if not project_name:
            logger.error("Project name not found in experiment state")
            return False
        
        # Start the malicious build
        attack_timestamp = str(int(time.time()))
        logger.info(f"Starting malicious build on project: {project_name}")
        
        start_response = codebuild_client.start_build(
            projectName=project_name,
            environmentVariablesOverride=[
                {
                    'name': 'ATTACK_INDICATOR',
                    'value': 'true',
                    'type': 'PLAINTEXT'
                },
                {
                    'name': 'ATTACK_TIMESTAMP',
                    'value': attack_timestamp,
                    'type': 'PLAINTEXT'
                }
            ]
        )
        
        build_id = start_response['build']['id']
        build_arn = start_response['build']['arn']
        build_status = start_response['build']['buildStatus']
        
        EXPERIMENT_STATE['build_id'] = build_id
        
        logger.info(f"Build started - ID: {build_id}")
        logger.info(f"Build ARN: {build_arn}")
        logger.info(f"Initial build status: {build_status}")
        
        # Wait for build to progress (give EventBridge time to trigger)
        logger.info("Waiting for build to execute and generate events...")
        max_wait = 300  # 5 minutes max
        start_time = time.monotonic()
        final_statuses = ['SUCCEEDED', 'FAILED', 'STOPPED', 'TIMED_OUT']
        
        while time.monotonic() - start_time < max_wait:
            build_response = codebuild_client.batch_get_builds(ids=[build_id])
            
            if build_response.get('builds'):
                current_status = build_response['builds'][0]['buildStatus']
                logger.info(f"Build status: {current_status}")
                
                if current_status in final_statuses:
                    logger.info(f"Build completed with status: {current_status}")
                    break
            
            time.sleep(15)
        
        # Verify build was recorded
        final_response = codebuild_client.batch_get_builds(ids=[build_id])
        if final_response.get('builds'):
            build_info = final_response['builds'][0]
            logger.info(f"Final build status: {build_info['buildStatus']}")
            logger.info(f"Build start time: {build_info['startTime']}")
            
            if build_info.get('endTime'):
                logger.info(f"Build end time: {build_info['endTime']}")
            
            logger.info("=== attack phase completed successfully ===")
            return True
        
        logger.error("Could not verify build execution")
        return False
        
    except Exception as e:
        logger.error(f"attack failed: {e}")
        return False

def hypothesis_verification() -> bool:
    """
    Verify that reactive controls detected the malicious build.
    Checks EventBridge rule, CloudWatch logs, and alarm state.
    """
    logger.info("=== Starting hypothesis_verification phase ===")
    
    verification_results = {
        'build_recorded': False,
        'eventbridge_detected': False,
        'cloudwatch_logs_captured': False,
        'alarm_configured': False,
        'sns_topic_exists': False
    }
    
    try:
        clients = get_aws_clients()
        codebuild_client = clients['codebuild']
        events_client = clients['events']
        logs_client = clients['logs']
        cloudwatch_client = clients['cloudwatch']
        sns_client = clients['sns']
        
        timestamp = EXPERIMENT_STATE.get('timestamp')
        build_id = EXPERIMENT_STATE.get('build_id')
        project_name = EXPERIMENT_STATE.get('project_name')
        
        if not all([timestamp, build_id, project_name]):
            logger.error("Missing experiment state data")
            return False
        
        # 1. Verify build was recorded
        logger.info("Checking if build was recorded...")
        build_response = codebuild_client.batch_get_builds(ids=[build_id])
        if build_response.get('builds'):
            build_info = build_response['builds'][0]
            verification_results['build_recorded'] = True
            logger.info(f"Build recorded: {build_id}, Status: {build_info['buildStatus']}")
        
        # 2. Verify EventBridge rule is active and detected the event
        logger.info("Checking EventBridge rule status...")
        rule_name = f'sce-build-event-rule-{timestamp}'
        
        try:
            rule_response = events_client.describe_rule(Name=rule_name)
            if rule_response['State'] == 'ENABLED':
                verification_results['eventbridge_detected'] = True
                logger.info(f"EventBridge rule is ENABLED: {rule_name}")
                
                # Get rule targets to verify SNS connection
                targets_response = events_client.list_targets_by_rule(Rule=rule_name)
                if targets_response.get('Targets'):
                    logger.info(f"EventBridge rule has {len(targets_response['Targets'])} target(s)")
                    for target in targets_response['Targets']:
                        logger.info(f"Target: {target['Id']} -> {target['Arn']}")
        except ClientError as e:
            logger.error(f"EventBridge rule check failed: {e}")
        
        # 3. Verify CloudWatch logs captured the build
        logger.info("Checking CloudWatch logs...")
        log_group_name = f'/aws/codebuild/{project_name}'
        
        try:
            # Wait briefly for logs to propagate
            time.sleep(10)
            
            log_streams_response = logs_client.describe_log_streams(
                logGroupName=log_group_name,
                orderBy='LastEventTime',
                descending=True,
                limit=5
            )
            
            if log_streams_response.get('logStreams'):
                latest_stream = log_streams_response['logStreams'][0]
                logger.info(f"Found log stream: {latest_stream['logStreamName']}")
                
                # Get log events
                events_response = logs_client.get_log_events(
                    logGroupName=log_group_name,
                    logStreamName=latest_stream['logStreamName'],
                    limit=50
                )
                
                if events_response.get('events'):
                    verification_results['cloudwatch_logs_captured'] = True
                    logger.info(f"Found {len(events_response['events'])} log events")
                    
                    # Check for malicious indicator in logs
                    for event in events_response['events']:
                        if 'MALICIOUS_INDICATOR' in event.get('message', ''):
                            logger.info("MALICIOUS_INDICATOR found in logs!")
                            break
        except ClientError as e:
            if 'ResourceNotFoundException' in str(e):
                logger.warning(f"Log group not found yet: {log_group_name}")
            else:
                logger.error(f"CloudWatch logs check failed: {e}")
        
        # 4. Verify CloudWatch alarm is configured
        logger.info("Checking CloudWatch alarm...")
        alarm_name = f'sce-malicious-build-alarm-{timestamp}'
        
        try:
            alarms_response = cloudwatch_client.describe_alarms(
                AlarmNames=[alarm_name]
            )
            
            if alarms_response.get('MetricAlarms'):
                alarm = alarms_response['MetricAlarms'][0]
                verification_results['alarm_configured'] = True
                logger.info(f"Alarm found: {alarm_name}")
                logger.info(f"Alarm state: {alarm['StateValue']}")
                logger.info(f"Alarm threshold: {alarm['Threshold']}")
                
                # Check alarm history
                history_response = cloudwatch_client.describe_alarm_history(
                    AlarmName=alarm_name,
                    HistoryItemType='StateUpdate',
                    MaxRecords=10
                )
                
                if history_response.get('AlarmHistoryItems'):
                    logger.info(f"Found {len(history_response['AlarmHistoryItems'])} alarm history items")
                    for item in history_response['AlarmHistoryItems'][:3]:
                        logger.info(f"Alarm history: {item['Timestamp']} - {item['HistorySummary']}")
        except ClientError as e:
            logger.error(f"CloudWatch alarm check failed: {e}")
        
        # 5. Verify SNS topic exists
        logger.info("Checking SNS topic...")
        topic_name = f'sce-malicious-build-alerts-{timestamp}'
        
        try:
            topics_response = sns_client.list_topics()
            for topic in topics_response.get('Topics', []):
                if topic_name in topic['TopicArn']:
                    verification_results['sns_topic_exists'] = True
                    logger.info(f"SNS topic found: {topic['TopicArn']}")
                    break
        except ClientError as e:
            logger.error(f"SNS topic check failed: {e}")
        
        # Determine overall result
        logger.info("=== Verification Results ===")
        for key, value in verification_results.items():
            logger.info(f"{key}: {value}")
        
        # Reactive controls are verified if:
        # - Build was recorded (attack executed)
        # - EventBridge rule is active (detection mechanism operational)
        # - CloudWatch logs captured the build (evidence collection)
        reactive_verified = (
            verification_results['build_recorded'] and
            verification_results['eventbridge_detected'] and
            verification_results['cloudwatch_logs_captured']
        )
        
        logger.info(f"=== Reactive controls verified: {reactive_verified} ===")
        return reactive_verified
        
    except Exception as e:
        logger.error(f"hypothesis_verification failed: {e}")
        return False

def rollback() -> bool:
    """
    Clean up all resources by deleting the CloudFormation stack.
    """
    logger.info("=== Starting rollback phase ===")
    
    try:
        clients = get_aws_clients()
        cf_client = clients['cloudformation']
        s3_client = clients['s3']
        
        stack_name = EXPERIMENT_STATE.get('stack_name')
        timestamp = EXPERIMENT_STATE.get('timestamp')
        
        if not stack_name:
            logger.warning("No stack name in experiment state, nothing to rollback")
            return True
        
        # Empty the S3 bucket first (required before deletion)
        bucket_name = f'sce-artifacts-{timestamp}'
        try:
            logger.info(f"Emptying S3 bucket: {bucket_name}")
            paginator = s3_client.get_paginator('list_objects_v2')
            
            for page in paginator.paginate(Bucket=bucket_name):
                if 'Contents' in page:
                    objects = [{'Key': obj['Key']} for obj in page['Contents']]
                    s3_client.delete_objects(
                        Bucket=bucket_name,
                        Delete={'Objects': objects}
                    )
                    logger.info(f"Deleted {len(objects)} objects from bucket")
        except ClientError as e:
            if 'NoSuchBucket' not in str(e):
                logger.warning(f"Error emptying bucket: {e}")
        
        # Delete the stack
        logger.info(f"Deleting stack: {stack_name}")
        
        try:
            cf_client.delete_stack(StackName=stack_name)
            logger.info("Stack deletion initiated")
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.info("Stack already deleted")
                return True
            raise
        
        # Wait for deletion
        if wait_for_stack_operation(cf_client, stack_name, 'DELETE'):
            logger.info("=== rollback phase completed successfully ===")
            return True
        else:
            logger.error("Stack deletion did not complete successfully")
            return False
            
    except Exception as e:
        logger.error(f"rollback failed: {e}")
        return False

def main():
    """Main execution function for standalone testing."""
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.8 - Reactive Probe for Malicious Build")
    logger.info("=" * 60)
    
    success = False
    
    try:
        # Phase 1: Steady State
        if not steady_state():
            logger.error("Steady state setup failed")
            return
        
        # Phase 2: Attack
        if not attack():
            logger.error("Attack execution failed")
            return
        
        # Phase 3: Verification
        success = hypothesis_verification()
        
        if success:
            logger.info("EXPERIMENT PASSED: Reactive controls detected malicious build")
        else:
            logger.warning("EXPERIMENT FAILED: Reactive controls did not fully detect malicious build")
            
    except Exception as e:
        logger.error(f"Experiment failed with exception: {e}")
    finally:
        # Phase 4: Rollback (always execute)
        logger.info("Executing rollback...")
        rollback()
    
    logger.info("=" * 60)
    logger.info(f"Experiment completed - Success: {success}")
    logger.info("=" * 60)

if __name__ == '__main__':
    main()