#!/usr/bin/env python3
"""
Security Chaos Engineering Experiment: 1.8 SCE Experiment
Probe Type: Reactive
Attack: 1.7 Start Malicious Build

This experiment validates reactive security controls by:
1. Deploying a CodeBuild project with logging enabled
2. Starting a malicious build that attempts to exfiltrate credentials
3. Verifying that CloudWatch Logs captured the build activity for forensic analysis
"""

import sys
import time
import json
import logging

# Install boto3 if not available
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "--quiet"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global variables for resource tracking
STACK_NAME = None
REGION = None
ACCOUNT_ID = None

def get_aws_clients():
    """Initialize AWS clients with current session"""
    global REGION, ACCOUNT_ID
    
    session = boto3.Session()
    REGION = session.region_name or 'us-east-1'
    
    sts = session.client('sts', region_name=REGION)
    ACCOUNT_ID = sts.get_caller_identity()['Account']
    
    return {
        'cfn': session.client('cloudformation', region_name=REGION),
        'codebuild': session.client('codebuild', region_name=REGION),
        'iam': session.client('iam', region_name=REGION),
        'logs': session.client('logs', region_name=REGION),
        'sts': sts
    }

def wait_with_backoff(check_func, max_wait=600, initial_delay=2):
    """Generic waiter with exponential backoff"""
    start = time.monotonic()
    delay = initial_delay
    
    while time.monotonic() - start < max_wait:
        try:
            if check_func():
                return True
        except Exception as e:
            logger.warning(f"Check function raised: {e}")
        
        time.sleep(delay)
        delay = min(delay * 1.5, 30)
    
    return False

def steady_state():
    """
    Deploy CloudFormation stack with CodeBuild project configured with CloudWatch Logs.
    This establishes the baseline infrastructure for reactive security monitoring.
    """
    global STACK_NAME
    
    clients = get_aws_clients()
    cfn = clients['cfn']
    
    timestamp = int(time.time())
    STACK_NAME = f"sce-experiment-{timestamp}"
    
    logger.info(f"Deploying CloudFormation stack: {STACK_NAME}")
    
    # CloudFormation template with CodeBuild project and necessary IAM roles
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 - Reactive Security Control for Malicious Build Detection",
        "Resources": {
            "CodeBuildServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
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
                    "Policies": [{
                        "PolicyName": "CodeBuildBasePolicy",
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
                    }]
                }
            },
            "MaliciousBuildProject": {
                "Type": "AWS::CodeBuild::Project",
                "Properties": {
                    "Name": f"malicious-build-{timestamp}",
                    "ServiceRole": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]},
                    "Artifacts": {
                        "Type": "NO_ARTIFACTS"
                    },
                    "Environment": {
                        "Type": "LINUX_CONTAINER",
                        "ComputeType": "BUILD_GENERAL1_SMALL",
                        "Image": "aws/codebuild/standard:5.0"
                    },
                    "Source": {
                        "Type": "NO_SOURCE",
                        "BuildSpec": json.dumps({
                            "version": "0.2",
                            "phases": {
                                "build": {
                                    "commands": [
                                        "echo 'Starting malicious build simulation'",
                                        "echo 'Attempting credential exfiltration'",
                                        "env | grep AWS || true",
                                        "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ || true",
                                        "echo 'Malicious activity logged'"
                                    ]
                                }
                            }
                        })
                    },
                    "LogsConfig": {
                        "CloudWatchLogs": {
                            "Status": "ENABLED",
                            "GroupName": f"/aws/codebuild/malicious-build-{timestamp}"
                        }
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": STACK_NAME},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                }
            },
            "BuildLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": f"/aws/codebuild/malicious-build-{timestamp}",
                    "RetentionInDays": 1
                }
            }
        },
        "Outputs": {
            "ProjectName": {
                "Value": {"Ref": "MaliciousBuildProject"},
                "Description": "CodeBuild project name"
            },
            "LogGroupName": {
                "Value": {"Ref": "BuildLogGroup"},
                "Description": "CloudWatch Logs group name"
            }
        }
    }
    
    try:
        # Check if stack already exists
        try:
            cfn.describe_stacks(StackName=STACK_NAME)
            logger.warning(f"Stack {STACK_NAME} already exists, using existing stack")
            return
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
        
        # Create stack
        cfn.create_stack(
            StackName=STACK_NAME,
            TemplateBody=json.dumps(template),
            Capabilities=['CAPABILITY_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': '1.8-SCE'},
                {'Key': 'ProbeType', 'Value': 'Reactive'},
                {'Key': 'Timestamp', 'Value': str(timestamp)}
            ]
        )
        
        logger.info(f"Stack creation initiated, waiting for completion...")
        
        # Wait for stack creation with backoff
        def check_stack_complete():
            try:
                response = cfn.describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack status: {status}")
                
                if status == 'CREATE_COMPLETE':
                    return True
                elif status in ['CREATE_FAILED', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED']:
                    raise Exception(f"Stack creation failed with status: {status}")
                return False
            except ClientError as e:
                logger.error(f"Error checking stack status: {e}")
                return False
        
        if not wait_with_backoff(check_stack_complete, max_wait=600):
            raise Exception("Stack creation timeout")
        
        logger.info(f"Stack {STACK_NAME} created successfully")
        
        # Retrieve outputs
        response = cfn.describe_stacks(StackName=STACK_NAME)
        outputs = response['Stacks'][0].get('Outputs', [])
        for output in outputs:
            logger.info(f"Output: {output['OutputKey']} = {output['OutputValue']}")
        
    except Exception as e:
        logger.error(f"Error in steady_state: {e}")
        raise

def attack() -> bool:
    """
    Execute the malicious build attack by starting a CodeBuild project
    that attempts credential exfiltration. Returns True if the build
    was successfully started and produces verifiable AWS evidence.
    """
    if not STACK_NAME:
        logger.error("STACK_NAME not set, steady_state must be called first")
        return False
    
    clients = get_aws_clients()
    cfn = clients['cfn']
    codebuild = clients['codebuild']
    
    logger.info("Executing attack: Starting malicious build")
    
    try:
        # Get project name from stack outputs
        response = cfn.describe_stacks(StackName=STACK_NAME)
        outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
        project_name = outputs.get('ProjectName')
        
        if not project_name:
            logger.error("Could not retrieve project name from stack outputs")
            return False
        
        logger.info(f"Starting build for project: {project_name}")
        
        # Start the malicious build
        build_response = codebuild.start_build(projectName=project_name)
        
        build_id = build_response['build']['id']
        build_arn = build_response['build']['arn']
        build_status = build_response['build']['buildStatus']
        
        logger.info(f"Build started successfully:")
        logger.info(f"  Build ID: {build_id}")
        logger.info(f"  Build ARN: {build_arn}")
        logger.info(f"  Initial Status: {build_status}")
        
        # Wait for build to start processing
        time.sleep(5)
        
        # Verify build is in progress or completed
        def check_build_started():
            try:
                builds = codebuild.batch_get_builds(ids=[build_id])
                if builds['builds']:
                    status = builds['builds'][0]['buildStatus']
                    logger.info(f"Build status: {status}")
                    return status in ['IN_PROGRESS', 'SUCCEEDED', 'FAILED', 'STOPPED']
                return False
            except ClientError as e:
                logger.warning(f"Error checking build status: {e}")
                return False
        
        if not wait_with_backoff(check_build_started, max_wait=120):
            logger.error("Build did not start within timeout")
            return False
        
        # Capture final build state as evidence
        builds = codebuild.batch_get_builds(ids=[build_id])
        final_status = builds['builds'][0]['buildStatus']
        
        logger.info(f"Attack executed successfully. Build final status: {final_status}")
        
        # Store build ID for hypothesis verification
        global BUILD_ID
        BUILD_ID = build_id
        
        return True
        
    except ClientError as e:
        logger.error(f"AWS API error during attack: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during attack: {e}")
        return False

def hypothesis_verification() -> bool:
    """
    Verify the reactive security control: CloudWatch Logs must contain
    evidence of the malicious build activity for forensic analysis.
    
    Returns True if logs captured the malicious activity, False otherwise.
    """
    if not STACK_NAME:
        logger.error("STACK_NAME not set")
        return False
    
    clients = get_aws_clients()
    cfn = clients['cfn']
    logs = clients['logs']
    
    logger.info("Verifying reactive security control: CloudWatch Logs capture")
    
    try:
        # Get log group name from stack outputs
        response = cfn.describe_stacks(StackName=STACK_NAME)
        outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
        log_group_name = outputs.get('LogGroupName')
        
        if not log_group_name:
            logger.error("Could not retrieve log group name from stack outputs")
            return False
        
        logger.info(f"Checking log group: {log_group_name}")
        
        # Verify log group exists
        try:
            logs.describe_log_groups(logGroupNamePrefix=log_group_name)
            logger.info(f"Log group {log_group_name} exists")
        except ClientError as e:
            logger.error(f"Log group does not exist: {e}")
            return False
        
        # Wait for logs to be written (eventual consistency)
        time.sleep(10)
        
        # List log streams in the group
        def check_log_streams():
            try:
                streams_response = logs.describe_log_streams(
                    logGroupName=log_group_name,
                    orderBy='LastEventTime',
                    descending=True,
                    limit=10
                )
                
                if not streams_response.get('logStreams'):
                    logger.info("No log streams found yet, waiting...")
                    return False
                
                logger.info(f"Found {len(streams_response['logStreams'])} log stream(s)")
                return True
                
            except ClientError as e:
                logger.warning(f"Error describing log streams: {e}")
                return False
        
        if not wait_with_backoff(check_log_streams, max_wait=180):
            logger.error("No log streams created within timeout")
            return False
        
        # Retrieve log streams
        streams_response = logs.describe_log_streams(
            logGroupName=log_group_name,
            orderBy='LastEventTime',
            descending=True,
            limit=10
        )
        
        # Search for malicious activity evidence in logs
        malicious_indicators = [
            'malicious build',
            'credential exfiltration',
            'AWS_',
            '169.254.169.254'
        ]
        
        evidence_found = False
        
        for stream in streams_response['logStreams']:
            stream_name = stream['logStreamName']
            logger.info(f"Examining log stream: {stream_name}")
            
            try:
                # Get log events
                events_response = logs.get_log_events(
                    logGroupName=log_group_name,
                    logStreamName=stream_name,
                    startFromHead=True,
                    limit=100
                )
                
                events = events_response.get('events', [])
                logger.info(f"Retrieved {len(events)} log events from stream {stream_name}")
                
                for event in events:
                    message = event.get('message', '').lower()
                    
                    # Check for malicious indicators
                    for indicator in malicious_indicators:
                        if indicator.lower() in message:
                            logger.info(f"EVIDENCE FOUND: '{indicator}' in log message")
                            logger.info(f"  Message: {event.get('message')[:200]}")
                            evidence_found = True
                            break
                    
                    if evidence_found:
                        break
                
            except ClientError as e:
                logger.warning(f"Error retrieving log events from stream {stream_name}: {e}")
                continue
            
            if evidence_found:
                break
        
        if evidence_found:
            logger.info("SUCCESS: Reactive control verified - malicious activity logged to CloudWatch")
            return True
        else:
            logger.error("FAILURE: No evidence of malicious activity found in CloudWatch Logs")
            return False
        
    except ClientError as e:
        logger.error(f"AWS API error during hypothesis verification: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during hypothesis verification: {e}")
        return False

def rollback():
    """
    Clean up all resources by deleting the CloudFormation stack.
    Always attempts cleanup even if previous phases failed.
    """
    if not STACK_NAME:
        logger.warning("No stack name set, nothing to roll back")
        return
    
    clients = get_aws_clients()
    cfn = clients['cfn']
    
    logger.info(f"Rolling back: Deleting stack {STACK_NAME}")
    
    try:
        # Check if stack exists
        try:
            cfn.describe_stacks(StackName=STACK_NAME)
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.info(f"Stack {STACK_NAME} does not exist, nothing to delete")
                return
            raise
        
        # Delete stack
        cfn.delete_stack(StackName=STACK_NAME)
        logger.info(f"Stack deletion initiated")
        
        # Wait for deletion with backoff
        def check_stack_deleted():
            try:
                response = cfn.describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack status: {status}")
                
                if status == 'DELETE_COMPLETE':
                    return True
                elif status in ['DELETE_FAILED']:
                    raise Exception(f"Stack deletion failed with status: {status}")
                return False
            except ClientError as e:
                if 'does not exist' in str(e):
                    logger.info("Stack deleted successfully")
                    return True
                logger.error(f"Error checking stack status: {e}")
                return False
        
        if not wait_with_backoff(check_stack_deleted, max_wait=600):
            logger.error("Stack deletion timeout")
            return
        
        logger.info(f"Stack {STACK_NAME} deleted successfully")
        
    except Exception as e:
        logger.error(f"Error during rollback: {e}")

def main():
    """Main execution flow with proper error handling"""
    try:
        logger.info("=== Starting SCE Experiment 1.8: Reactive Security Control ===")
        
        steady_state()
        logger.info("✓ Steady state established")
        
        attack_success = attack()
        logger.info(f"✓ Attack executed: {attack_success}")
        
        hypothesis_result = hypothesis_verification()
        logger.info(f"✓ Hypothesis verification: {hypothesis_result}")
        
        if hypothesis_result:
            logger.info("=== EXPERIMENT PASSED: Reactive control working as expected ===")
        else:
            logger.info("=== EXPERIMENT FAILED: Reactive control did not behave as expected ===")
        
    except Exception as e:
        logger.error(f"Experiment failed with error: {e}")
    finally:
        rollback()
        logger.info("=== Experiment complete ===")

if __name__ == "__main__":
    main()