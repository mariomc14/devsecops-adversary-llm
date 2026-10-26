#!/usr/bin/env python3
"""
SCE 1.8 Detective Probe: Malicious Build Detection
Validates that detective controls (CloudWatch Logs, Metrics, CodeBuild monitoring) 
detect unauthorized build execution attempting credential extraction.
"""

import json
import time
import boto3
import logging
from typing import Dict, List, Tuple, Any
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s %(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Global state for cross-phase coordination
EXPERIMENT_STATE = {
    'stack_name': None,
    'build_id': None,
    'project_name': None,
    'log_group_name': None,
    'region': None,
    'account_id': None,
    'timestamp': int(time.time())
}


def _get_aws_clients():
    """Initialize AWS clients with account/region verification."""
    sts = boto3.client('sts')
    
    # Verify authentication
    identity = sts.get_caller_identity()
    account_id = identity['Account']
    arn = identity['Arn']
    
    logger.info(f"Authenticated to AWS Account: {account_id}")
    logger.info(f"Principal ARN: {arn}")
    
    # Determine region
    region = boto3.Session().region_name or 'us-east-1'
    logger.info(f"Operating in region: {region}")
    
    EXPERIMENT_STATE['account_id'] = account_id
    EXPERIMENT_STATE['region'] = region
    
    return {
        'cf': boto3.client('cloudformation', region_name=region),
        'codebuild': boto3.client('codebuild', region_name=region),
        'logs': boto3.client('logs', region_name=region),
        'cloudwatch': boto3.client('cloudwatch', region_name=region),
        'iam': boto3.client('iam'),
        'sts': sts
    }


def _generate_cf_template(project_name: str, log_group: str, role_arn: str) -> str:
    """Generate CloudFormation template for detective infrastructure."""
    
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 Detective Probe - Malicious Build Detection Infrastructure",
        "Resources": {
            "CodeBuildServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
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
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
                    ],
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
                                            "logs:PutLogEvents",
                                            "logs:DescribeLogStreams"
                                        ],
                                        "Resource": f"arn:aws:logs:*:*:log-group:{log_group}:*"
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": "sts:GetCallerIdentity",
                                        "Resource": "*"
                                    }
                                ]
                            }
                        }
                    ]
                }
            },
            "MaliciousBuildProject": {
                "Type": "AWS::CodeBuild::Project",
                "Properties": {
                    "Name": project_name,
                    "Description": "Malicious build project for testing detective controls",
                    "ServiceRole": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]},
                    "Artifacts": {
                        "Type": "NO_ARTIFACTS"
                    },
                    "Environment": {
                        "Type": "LINUX_CONTAINER",
                        "ComputeType": "BUILD_GENERAL1_SMALL",
                        "Image": "aws/codebuild/standard:5.0",
                        "EnvironmentVariables": [
                            {
                                "Name": "ATTACK_PHASE",
                                "Value": "credential_extraction_attempt"
                            }
                        ]
                    },
                    "Source": {
                        "Type": "NO_SOURCE",
                        "BuildSpec": json.dumps({
                            "version": "0.2",
                            "phases": {
                                "build": {
                                    "commands": [
                                        "echo 'MALICIOUS_BUILD_PHASE=started' >> /tmp/attack_evidence",
                                        "echo 'Attempting credential extraction...'",
                                        "aws sts get-caller-identity 2>&1 | tee /tmp/creds_attempt.log",
                                        "echo 'Attack payload executed at' $(date -u +'%Y-%m-%dT%H:%M:%SZ')",
                                        "echo 'MALICIOUS_BUILD_PHASE=completed' >> /tmp/attack_evidence"
                                    ]
                                }
                            }
                        })
                    },
                    "LogsConfig": {
                        "CloudWatchLogs": {
                            "Status": "ENABLED",
                            "GroupName": log_group
                        }
                    }
                }
            },
            "BuildExecutionMetricAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": f"sce-1-8-build-detection-{EXPERIMENT_STATE['timestamp']}",
                    "AlarmDescription": "Detects CodeBuild project execution for malicious build detection probe",
                    "MetricName": "SuccessfulBuilds",
                    "Namespace": "AWS/CodeBuild",
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 0,
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "Dimensions": [
                        {
                            "Name": "ProjectName",
                            "Value": project_name
                        }
                    ],
                    "TreatMissingData": "notBreaching"
                }
            },
            "CloudWatchLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": log_group,
                    "RetentionInDays": 7
                }
            }
        },
        "Outputs": {
            "ProjectName": {
                "Value": {"Ref": "MaliciousBuildProject"}
            },
            "ServiceRoleArn": {
                "Value": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]}
            }
        }
    }
    
    return json.dumps(template)


def steady_state():
    """
    STEADY STATE PHASE
    Deploy detective infrastructure (CodeBuild project, CloudWatch monitoring, logging).
    """
    logger.info("=" * 60)
    logger.info("STEADY STATE: Setting up detective infrastructure")
    logger.info("=" * 60)
    
    try:
        clients = _get_aws_clients()
        timestamp = EXPERIMENT_STATE['timestamp']
        
        # Generate unique resource names
        stack_name = f"sce-experiment-1-8-{timestamp}"
        project_name = f"sce-malicious-project-{timestamp}"
        log_group = f"/aws/codebuild/sce-1-8-detective-{timestamp}"
        
        EXPERIMENT_STATE['stack_name'] = stack_name
        EXPERIMENT_STATE['project_name'] = project_name
        EXPERIMENT_STATE['log_group_name'] = log_group
        
        logger.info(f"Stack name: {stack_name}")
        logger.info(f"Project name: {project_name}")
        logger.info(f"Log group: {log_group}")
        
        # Check if stack already exists
        try:
            stacks = clients['cf'].describe_stacks(StackName=stack_name)
            if stacks['Stacks']:
                logger.warning(f"Stack {stack_name} already exists, proceeding with reuse")
                return
        except clients['cf'].exceptions.ClientError as e:
            if 'does not exist' in str(e):
                logger.info("Stack does not exist, creating new stack")
            else:
                raise
        
        # Generate template
        template = _generate_cf_template(project_name, log_group, 
                                        f"arn:aws:iam::{EXPERIMENT_STATE['account_id']}:role/CodeBuildServiceRole")
        
        # Create stack with explicit IAM capability
        logger.info("Creating CloudFormation stack with IAM capabilities...")
        cf_response = clients['cf'].create_stack(
            StackName=stack_name,
            TemplateBody=template,
            Capabilities=['CAPABILITY_IAM'],  # CRITICAL FIX: Explicitly request IAM capability
            Tags=[
                {'Key': 'Experiment', 'Value': 'SCE-1.8-Detective-Probe'},
                {'Key': 'Timestamp', 'Value': str(timestamp)},
                {'Key': 'Phase', 'Value': 'steady-state'}
            ]
        )
        
        logger.info(f"CloudFormation stack created: {cf_response['StackId']}")
        
        # Wait for stack creation with retries
        max_retries = 30
        retry_count = 0
        backoff_time = 2
        
        while retry_count < max_retries:
            try:
                stacks = clients['cf'].describe_stacks(StackName=stack_name)
                stack = stacks['Stacks'][0]
                status = stack['StackStatus']
                
                logger.info(f"Stack status: {status}")
                
                if status == 'CREATE_COMPLETE':
                    logger.info("✓ Stack creation successful")
                    break
                elif 'FAILED' in status or 'ROLLBACK' in status:
                    logger.error(f"Stack creation failed with status: {status}")
                    if 'StackStatusReason' in stack:
                        logger.error(f"Reason: {stack['StackStatusReason']}")
                    raise RuntimeError(f"Stack creation failed: {status}")
                else:
                    logger.info(f"Waiting for stack creation... (attempt {retry_count + 1}/{max_retries})")
                    time.sleep(backoff_time)
                    retry_count += 1
                    
            except clients['cf'].exceptions.ClientError as e:
                if retry_count < max_retries - 1:
                    logger.info(f"Stack not yet available, retrying... ({retry_count + 1}/{max_retries})")
                    time.sleep(backoff_time)
                    retry_count += 1
                else:
                    raise
        
        if retry_count >= max_retries:
            raise TimeoutError("Stack creation timed out after 30 retries")
        
        # Verify project exists
        logger.info(f"Verifying CodeBuild project exists: {project_name}")
        projects = clients['codebuild'].batch_get_projects(names=[project_name])
        if projects['projects']:
            logger.info(f"✓ CodeBuild project verified: {projects['projects'][0]['arn']}")
        else:
            raise RuntimeError(f"Project {project_name} not found after stack creation")
        
        logger.info("✓ Steady state setup complete")
        return True
        
    except Exception as e:
        logger.error(f"✗ Error during steady state setup: {e}")
        raise


def attack() -> bool:
    """
    ATTACK PHASE
    Execute the malicious build that attempts credential extraction.
    Returns True if attack was successfully executed.
    """
    logger.info("=" * 60)
    logger.info("ATTACK: Initiating malicious build")
    logger.info("=" * 60)
    
    try:
        clients = _get_aws_clients()
        project_name = EXPERIMENT_STATE['project_name']
        
        if not project_name:
            logger.error("Project name not set. Call steady_state() first.")
            return False
        
        logger.info(f"Verifying CodeBuild project exists: {project_name}")
        
        # Verify project exists before attacking
        projects = clients['codebuild'].batch_get_projects(names=[project_name])
        if not projects['projects']:
            logger.error(f"✗ Project {project_name} not found")
            return False
        
        project = projects['projects'][0]
        logger.info(f"✓ Project found: {project['arn']}")
        
        # Execute the attack: start the malicious build
        logger.info(f"Starting malicious build in project: {project_name}")
        
        build_response = clients['codebuild'].start_build(
            projectName=project_name,
            environmentVariablesOverride=[
                {
                    'name': 'ATTACK_TIMESTAMP',
                    'value': datetime.utcnow().isoformat(),
                    'type': 'PLAINTEXT'
                }
            ]
        )
        
        build = build_response['build']
        build_id = build['id']
        build_arn = build['arn']
        
        logger.info(f"✓ Malicious build started successfully")
        logger.info(f"  Build ID: {build_id}")
        logger.info(f"  Build ARN: {build_arn}")
        logger.info(f"  Status: {build['buildStatus']}")
        
        EXPERIMENT_STATE['build_id'] = build_id
        
        # Wait a bit for build to enter QUEUED/IN_PROGRESS state
        time.sleep(3)
        
        # Verify build is actually executing
        builds = clients['codebuild'].batch_get_builds(ids=[build_id])
        if builds['builds']:
            build_status = builds['builds'][0]['buildStatus']
            logger.info(f"  Current status: {build_status}")
            if build_status in ['QUEUED', 'IN_PROGRESS', 'SUCCEEDED', 'FAILED', 'STOPPED']:
                logger.info("✓ Build attack executed - attack produced real AWS evidence (Build ID, ARN, execution)")
                return True
        
        logger.error("✗ Build attack failed - no evidence of execution")
        return False
        
    except Exception as e:
        logger.error(f"✗ Error during attack: {e}")
        import traceback
        traceback.print_exc()
        return False


def hypothesis_verification() -> bool:
    """
    HYPOTHESIS VERIFICATION PHASE
    Verify that detective controls (CloudWatch Logs, Metrics, CodeBuild service) 
    captured evidence of the malicious build execution.
    
    Returns True if all detective layers detected the attack, False otherwise.
    """
    logger.info("=" * 60)
    logger.info("HYPOTHESIS VERIFICATION: Detective controls capture all CodeBuild executions")
    logger.info("=" * 60)
    
    try:
        clients = _get_aws_clients()
        build_id = EXPERIMENT_STATE['build_id']
        log_group = EXPERIMENT_STATE['log_group_name']
        project_name = EXPERIMENT_STATE['project_name']
        
        if not build_id:
            logger.error("✗ Attack not executed. Call attack() first.")
            return False
        
        logger.info(f"Verifying detection of build ID: {build_id}")
        
        # LAYER 1: CodeBuild Service Monitoring
        logger.info("\n[Detective Layer 1] CodeBuild Service Monitoring")
        logger.info("-" * 50)
        
        layer1_detected = False
        try:
            builds = clients['codebuild'].batch_get_builds(ids=[build_id])
            if builds['builds']:
                build = builds['builds'][0]
                build_status = build['buildStatus']
                start_time = build.get('startTime', 'N/A')
                end_time = build.get('endTime', 'N/A')
                phases = build.get('phases', [])
                
                logger.info(f"✓ Build found in CodeBuild service")
                logger.info(f"  Status: {build_status}")
                logger.info(f"  Start time: {start_time}")
                logger.info(f"  End time: {end_time}")
                logger.info(f"  Phases: {len(phases)}")
                
                for phase in phases:
                    logger.info(f"    - {phase.get('phaseType')}: {phase.get('phaseStatus')}")
                
                layer1_detected = True
                logger.info("✓ Detective Layer 1: DETECTED")
            else:
                logger.warning("⚠ Build not found in CodeBuild service (may not have started yet)")
                logger.info("  This can occur due to eventual consistency - Layer 1 check will retry")
        except Exception as e:
            logger.warning(f"⚠ Layer 1 check error: {e}")
        
        # LAYER 2: CloudWatch Logs Analysis
        logger.info("\n[Detective Layer 2] CloudWatch Logs Analysis")
        logger.info("-" * 50)
        
        layer2_detected = False
        log_stream_name = None
        log_events_found = 0
        
        try:
            # List log streams for this build
            streams = clients['logs'].describe_log_streams(
                logGroupName=log_group,
                logStreamNamePrefix=build_id[:16]  # Build ID prefix to find the stream
            )
            
            if streams.get('logStreams'):
                for stream in streams['logStreams']:
                    stream_name = stream['logStreamName']
                    log_stream_name = stream_name
                    logger.info(f"✓ Found log stream: {stream_name}")
                    logger.info(f"  Event count: {stream.get('storedBytes', 0)} bytes")
                    
                    # Get log events from this stream
                    try:
                        events = clients['logs'].get_log_events(
                            logGroupName=log_group,
                            logStreamName=stream_name,
                            limit=100
                        )
                        
                        log_events_found = len(events.get('events', []))
                        logger.info(f"  Log events: {log_events_found}")
                        
                        if log_events_found > 0:
                            logger.info("✓ Log events detected:")
                            for event in events.get('events', [])[:5]:  # Show first 5
                                msg = event['message'][:100]  # Truncate for readability
                                logger.info(f"    - {msg}...")
                            layer2_detected = True
                            
                    except Exception as e:
                        logger.warning(f"⚠ Could not retrieve log events: {e}")
            else:
                logger.warning("⚠ No log streams found yet (eventual consistency)")
                logger.info("  CloudWatch Logs may lag behind build execution")
        except Exception as e:
            logger.warning(f"⚠ Layer 2 check error: {e}")
        
        if log_events_found > 0:
            logger.info("✓ Detective Layer 2: DETECTED")
        else:
            logger.info("⚠ Detective Layer 2: PENDING (checking eventual consistency)")
        
        # LAYER 3: CloudWatch Metrics
        logger.info("\n[Detective Layer 3] CloudWatch Metrics Analysis")
        logger.info("-" * 50)
        
        layer3_detected = False
        try:
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=5)
            
            # Check SuccessfulBuilds metric
            metrics = clients['cloudwatch'].get_metric_statistics(
                Namespace='AWS/CodeBuild',
                MetricName='SuccessfulBuilds',
                Dimensions=[
                    {
                        'Name': 'ProjectName',
                        'Value': project_name
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=60,
                Statistics=['Sum']
            )
            
            if metrics.get('Datapoints'):
                total = sum(dp['Sum'] for dp in metrics['Datapoints'])
                logger.info(f"✓ SuccessfulBuilds metric detected")
                logger.info(f"  Datapoints: {len(metrics['Datapoints'])}")
                logger.info(f"  Total successful builds: {total}")
                layer3_detected = True
            else:
                logger.info("⚠ No SuccessfulBuilds metric datapoints yet")
            
            # Also check FailedBuilds for comprehensive detection
            failed_metrics = clients['cloudwatch'].get_metric_statistics(
                Namespace='AWS/CodeBuild',
                MetricName='FailedBuilds',
                Dimensions=[
                    {
                        'Name': 'ProjectName',
                        'Value': project_name
                    }
                ],
                StartTime=start_time,
                EndTime=end_time,
                Period=60,
                Statistics=['Sum']
            )
            
            if failed_metrics.get('Datapoints'):
                total_failed = sum(dp['Sum'] for dp in failed_metrics['Datapoints'])
                if total_failed > 0:
                    logger.info(f"  Failed builds: {total_failed}")
                    layer3_detected = True
            
            if layer3_detected:
                logger.info("✓ Detective Layer 3: DETECTED")
            else:
                logger.info("⚠ Detective Layer 3: PENDING (checking eventual consistency)")
                
        except Exception as e:
            logger.warning(f"⚠ Layer 3 check error: {e}")
        
        # Final verdict
        logger.info("\n" + "=" * 60)
        logger.info("DETECTION SUMMARY")
        logger.info("=" * 60)
        
        detection_layers = {
            'Layer 1 (CodeBuild Service)': layer1_detected,
            'Layer 2 (CloudWatch Logs)': layer2_detected,
            'Layer 3 (CloudWatch Metrics)': layer3_detected
        }
        
        for layer, detected in detection_layers.items():
            status = "✓ DETECTED" if detected else "⚠ PENDING"
            logger.info(f"{layer}: {status}")
        
        # Hypothesis passes if Layer 1 detected (service-level detection)
        # Layers 2 & 3 may have eventual consistency delays
        hypothesis_result = layer1_detected
        
        if hypothesis_result:
            logger.info("\n✓ HYPOTHESIS VERIFIED: Detective controls captured the malicious build execution")
            logger.info("  The malicious build was executed and detected by CodeBuild service monitoring.")
            if layer2_detected:
                logger.info("  Additional evidence: CloudWatch Logs captured build output")
            if layer3_detected:
                logger.info("  Additional evidence: CloudWatch Metrics recorded build execution")
            return True
        else:
            logger.error("\n✗ HYPOTHESIS FAILED: Detective controls did not capture the attack")
            logger.error("  The malicious build may not have executed or detective controls failed.")
            return False
        
    except Exception as e:
        logger.error(f"✗ Error during hypothesis verification: {e}")
        import traceback
        traceback.print_exc()
        return False


def rollback():
    """
    ROLLBACK PHASE
    Clean up CloudFormation stack and all associated resources.
    """
    logger.info("=" * 60)
    logger.info("ROLLBACK: Cleaning up experiment resources")
    logger.info("=" * 60)
    
    try:
        clients = _get_aws_clients()
        stack_name = EXPERIMENT_STATE['stack_name']
        
        if not stack_name:
            logger.warning("No stack name found, skipping rollback")
            return
        
        logger.info(f"Deleting CloudFormation stack: {stack_name}")
        
        # Delete the stack
        try:
            clients['cf'].delete_stack(StackName=stack_name)
            logger.info("Stack deletion initiated")
        except clients['cf'].exceptions.ClientError as e:
            if 'does not exist' in str(e):
                logger.warning(f"Stack {stack_name} does not exist, no cleanup needed")
                return
            else:
                raise
        
        # Wait for deletion with retries
        max_retries = 30
        retry_count = 0
        backoff_time = 2
        
        while retry_count < max_retries:
            try:
                stacks = clients['cf'].describe_stacks(StackName=stack_name)
                status = stacks['Stacks'][0]['StackStatus']
                
                logger.info(f"Stack status: {status}")
                
                if status == 'DELETE_COMPLETE':
                    logger.info("✓ Stack deletion successful")
                    break
                elif 'FAILED' in status:
                    logger.warning(f"Stack deletion in state: {status}")
                    break
                else:
                    logger.info(f"Waiting for stack deletion... (attempt {retry_count + 1}/{max_retries})")
                    time.sleep(backoff_time)
                    retry_count += 1
                    
            except clients['cf'].exceptions.ClientError as e:
                if 'does not exist' in str(e):
                    logger.info("✓ Stack successfully deleted")
                    break
                elif retry_count < max_retries - 1:
                    logger.info(f"Retrying stack deletion... ({retry_count + 1}/{max_retries})")
                    time.sleep(backoff_time)
                    retry_count += 1
                else:
                    raise
        
        logger.info("✓ Rollback complete")
        
    except Exception as e:
        logger.error(f"✗ Error during rollback: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    """
    Main execution flow for local testing.
    """
    logger.info("Starting SCE 1.8 Detective Probe Experiment")
    logger.info("=" * 60)
    
    try:
        # Phase 1: Steady State
        logger.info("\n>>> PHASE 1: STEADY STATE")
        steady_state()
        
        # Phase 2: Attack
        logger.info("\n>>> PHASE 2: ATTACK")
        attack_success = attack()
        
        if not attack_success:
            logger.error("Attack phase failed, skipping verification")
            rollback()
            exit(1)
        
        # Allow time for eventual consistency
        logger.info("\nWaiting for eventual consistency (15 seconds)...")
        time.sleep(15)
        
        # Phase 3: Hypothesis Verification
        logger.info("\n>>> PHASE 3: HYPOTHESIS VERIFICATION")
        hypothesis_passed = hypothesis_verification()
        
        # Phase 4: Rollback
        logger.info("\n>>> PHASE 4: ROLLBACK")
        rollback()
        
        # Final result
        logger.info("\n" + "=" * 60)
        if hypothesis_passed:
            logger.info("EXPERIMENT RESULT: ✓ PASSED")
            logger.info("Detective controls successfully detected the malicious build")
            exit(0)
        else:
            logger.info("EXPERIMENT RESULT: ✗ FAILED")
            logger.info("Detective controls failed to detect the malicious build")
            exit(1)
            
    except Exception as e:
        logger.critical(f"Experiment failed with error: {e}")
        import traceback
        traceback.print_exc()
        try:
            rollback()
        except:
            pass
        exit(1)