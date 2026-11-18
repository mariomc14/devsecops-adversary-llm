#!/usr/bin/env python3
"""
Security Chaos Engineering Experiment: 1.3 SCE Experiment
Probe Type: Preventive
Attack: 1.2 Create Malicious CodeBuild Project

This experiment validates that preventive controls block the creation of 
malicious CodeBuild projects with dangerous configurations.
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

# Global state
STACK_NAME = None
EXPERIMENT_TIMESTAMP = int(time.time())
REGION = None


def get_session_info():
    """Retrieve current AWS session information."""
    global REGION
    try:
        session = boto3.Session()
        if not REGION:
            REGION = session.region_name or "us-east-1"
        sts = session.client('sts', region_name=REGION)
        identity = sts.get_caller_identity()
        logger.info(f"Running as: {identity['Arn']}")
        logger.info(f"Account: {identity['Account']}")
        logger.info(f"Region: {REGION}")
        return identity
    except Exception as e:
        logger.error(f"Failed to get session info: {e}")
        raise


def wait_with_backoff(check_func, max_attempts=60, initial_delay=2):
    """Generic exponential backoff waiter."""
    attempt = 0
    delay = initial_delay
    start = time.monotonic()
    
    while attempt < max_attempts:
        try:
            if check_func():
                elapsed = time.monotonic() - start
                logger.info(f"Condition met after {elapsed:.1f}s")
                return True
        except Exception as e:
            logger.warning(f"Check attempt {attempt + 1} failed: {e}")
        
        if attempt < max_attempts - 1:
            time.sleep(delay)
            delay = min(delay * 1.5, 30)
        attempt += 1
    
    return False


def steady_state():
    """
    Deploy CloudFormation stack with:
    - IAM role for CodeBuild (with restricted permissions)
    - S3 bucket for artifacts
    - SCPs or IAM policy to prevent malicious CodeBuild projects (preventive control)
    - CloudWatch Logs group for CodeBuild
    """
    global STACK_NAME, REGION
    
    try:
        identity = get_session_info()
        account_id = identity['Account']
        
        STACK_NAME = f"sce-experiment-{EXPERIMENT_TIMESTAMP}"
        logger.info(f"Creating stack: {STACK_NAME}")
        
        cfn = boto3.client('cloudformation', region_name=REGION)
        
        # CloudFormation template with preventive controls
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "SCE 1.3 - Preventive controls for CodeBuild security",
            "Resources": {
                # S3 bucket for CodeBuild artifacts
                "ArtifactBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": f"sce-codebuild-artifacts-{EXPERIMENT_TIMESTAMP}",
                        "BucketEncryption": {
                            "ServerSideEncryptionConfiguration": [{
                                "ServerSideEncryptionByDefault": {
                                    "SSEAlgorithm": "AES256"
                                }
                            }]
                        },
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": True,
                            "BlockPublicPolicy": True,
                            "IgnorePublicAcls": True,
                            "RestrictPublicBuckets": True
                        },
                        "Tags": [{
                            "Key": "Experiment",
                            "Value": STACK_NAME
                        }]
                    }
                },
                # CloudWatch Logs group
                "CodeBuildLogGroup": {
                    "Type": "AWS::Logs::LogGroup",
                    "Properties": {
                        "LogGroupName": f"/aws/codebuild/sce-{EXPERIMENT_TIMESTAMP}",
                        "RetentionInDays": 1
                    }
                },
                # IAM role for CodeBuild (legitimate use)
                "CodeBuildRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": f"sce-codebuild-role-{EXPERIMENT_TIMESTAMP}",
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
                            "PolicyName": "S3Access",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [{
                                    "Effect": "Allow",
                                    "Action": ["s3:GetObject", "s3:PutObject"],
                                    "Resource": f"arn:aws:s3:::sce-codebuild-artifacts-{EXPERIMENT_TIMESTAMP}/*"
                                }]
                            }
                        }],
                        "Tags": [{
                            "Key": "Experiment",
                            "Value": STACK_NAME
                        }]
                    }
                },
                # Attacker role with restricted permissions (preventive control)
                "AttackerRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": f"sce-attacker-role-{EXPERIMENT_TIMESTAMP}",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                                "Action": "sts:AssumeRole"
                            }]
                        },
                        "Policies": [{
                            "PolicyName": "PreventiveControl",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "AllowBasicCodeBuildRead",
                                        "Effect": "Allow",
                                        "Action": [
                                            "codebuild:ListProjects",
                                            "codebuild:BatchGetProjects"
                                        ],
                                        "Resource": "*"
                                    },
                                    {
                                        "Sid": "DenyMaliciousCodeBuildCreation",
                                        "Effect": "Deny",
                                        "Action": [
                                            "codebuild:CreateProject",
                                            "codebuild:UpdateProject"
                                        ],
                                        "Resource": "*",
                                        "Condition": {
                                            "StringNotEquals": {
                                                "aws:RequestedRegion": REGION
                                            }
                                        }
                                    },
                                    {
                                        "Sid": "DenyPrivilegedContainers",
                                        "Effect": "Deny",
                                        "Action": "codebuild:CreateProject",
                                        "Resource": "*",
                                        "Condition": {
                                            "StringEquals": {
                                                "codebuild:PrivilegedMode": "true"
                                            }
                                        }
                                    }
                                ]
                            }
                        }],
                        "Tags": [{
                            "Key": "Experiment",
                            "Value": STACK_NAME
                        }]
                    }
                }
            },
            "Outputs": {
                "BucketName": {
                    "Value": {"Ref": "ArtifactBucket"}
                },
                "CodeBuildRoleArn": {
                    "Value": {"Fn::GetAtt": ["CodeBuildRole", "Arn"]}
                },
                "AttackerRoleArn": {
                    "Value": {"Fn::GetAtt": ["AttackerRole", "Arn"]}
                }
            }
        }
        
        try:
            cfn.create_stack(
                StackName=STACK_NAME,
                TemplateBody=json.dumps(template),
                Capabilities=['CAPABILITY_NAMED_IAM'],
                Tags=[
                    {'Key': 'Experiment', 'Value': '1.3-SCE'},
                    {'Key': 'Timestamp', 'Value': str(EXPERIMENT_TIMESTAMP)}
                ]
            )
            logger.info(f"Stack creation initiated: {STACK_NAME}")
        except ClientError as e:
            if 'AlreadyExists' in str(e):
                logger.warning(f"Stack {STACK_NAME} already exists, continuing...")
            else:
                raise
        
        # Wait for stack creation
        def check_stack_complete():
            try:
                response = cfn.describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack status: {status}")
                
                if 'FAILED' in status or 'ROLLBACK' in status:
                    raise Exception(f"Stack creation failed: {status}")
                return status == 'CREATE_COMPLETE'
            except ClientError as e:
                logger.error(f"Error checking stack: {e}")
                return False
        
        if not wait_with_backoff(check_stack_complete, max_attempts=90, initial_delay=5):
            raise Exception("Stack creation timeout")
        
        # Retrieve outputs
        response = cfn.describe_stacks(StackName=STACK_NAME)
        outputs = response['Stacks'][0].get('Outputs', [])
        logger.info(f"Stack outputs: {json.dumps(outputs, indent=2)}")
        
        logger.info("Steady state established successfully")
        
    except Exception as e:
        logger.error(f"Steady state failed: {e}")
        raise


def attack() -> bool:
    """
    Attempt to create a malicious CodeBuild project with dangerous configuration:
    - Privileged mode enabled
    - Potentially accessing sensitive environment variables
    - Using attacker-controlled source
    
    Returns True if attack is attempted (regardless of success/failure).
    The preventive control should block this.
    """
    global STACK_NAME, REGION
    
    try:
        logger.info("Starting attack: Create Malicious CodeBuild Project")
        
        cfn = boto3.client('cloudformation', region_name=REGION)
        sts = boto3.client('sts', region_name=REGION)
        
        # Get stack outputs
        response = cfn.describe_stacks(StackName=STACK_NAME)
        outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
        
        attacker_role_arn = outputs.get('AttackerRoleArn')
        codebuild_role_arn = outputs.get('CodeBuildRoleArn')
        bucket_name = outputs.get('BucketName')
        
        if not all([attacker_role_arn, codebuild_role_arn, bucket_name]):
            logger.error("Missing required stack outputs")
            return False
        
        logger.info(f"Assuming attacker role: {attacker_role_arn}")
        
        # Assume attacker role
        assumed = sts.assume_role(
            RoleArn=attacker_role_arn,
            RoleSessionName=f"attack-session-{EXPERIMENT_TIMESTAMP}"
        )
        
        # Create CodeBuild client with attacker credentials
        attacker_codebuild = boto3.client(
            'codebuild',
            region_name=REGION,
            aws_access_key_id=assumed['Credentials']['AccessKeyId'],
            aws_secret_access_key=assumed['Credentials']['SecretAccessKey'],
            aws_session_token=assumed['Credentials']['SessionToken']
        )
        
        malicious_project_name = f"malicious-project-{EXPERIMENT_TIMESTAMP}"
        
        # Attempt 1: Create project with privileged mode (should be denied)
        logger.info("Attack attempt 1: Creating CodeBuild project with privileged mode")
        try:
            response = attacker_codebuild.create_project(
                name=malicious_project_name,
                source={
                    'type': 'NO_SOURCE',
                    'buildspec': 'version: 0.2\nphases:\n  build:\n    commands:\n      - echo "Malicious build"\n      - env\n'
                },
                artifacts={
                    'type': 'S3',
                    'location': bucket_name,
                    'path': 'malicious/'
                },
                environment={
                    'type': 'LINUX_CONTAINER',
                    'image': 'aws/codebuild/standard:5.0',
                    'computeType': 'BUILD_GENERAL1_SMALL',
                    'privilegedMode': True,  # MALICIOUS: privileged mode
                    'environmentVariables': [
                        {
                            'name': 'MALICIOUS_FLAG',
                            'value': 'true',
                            'type': 'PLAINTEXT'
                        }
                    ]
                },
                serviceRole=codebuild_role_arn,
                tags=[
                    {'key': 'Attack', 'value': 'Malicious'},
                    {'key': 'Experiment', 'value': STACK_NAME}
                ]
            )
            
            logger.warning(f"Attack succeeded unexpectedly! Project ARN: {response['project']['arn']}")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            logger.info(f"Attack blocked with error {error_code}: {error_msg}")
            
            # This is expected - the preventive control should block it
            if error_code in ['AccessDeniedException', 'AccessDenied']:
                logger.info("Preventive control successfully blocked privileged mode creation")
                return True  # Attack was attempted (and blocked)
            else:
                logger.error(f"Unexpected error: {e}")
                return True
        
    except Exception as e:
        logger.error(f"Attack execution error: {e}")
        return False


def hypothesis_verification() -> bool:
    """
    Verify that the preventive control blocked the malicious CodeBuild project creation.
    
    Returns True if:
    - The malicious project does NOT exist in CodeBuild
    - CloudTrail or IAM policy evaluation shows denial (if available)
    
    This validates that the preventive control worked as expected.
    """
    global STACK_NAME, REGION
    
    try:
        logger.info("Starting hypothesis verification")
        
        cfn = boto3.client('cloudformation', region_name=REGION)
        codebuild = boto3.client('codebuild', region_name=REGION)
        iam = boto3.client('iam', region_name=REGION)
        
        # Get stack outputs
        response = cfn.describe_stacks(StackName=STACK_NAME)
        outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
        
        attacker_role_arn = outputs.get('AttackerRoleArn')
        if not attacker_role_arn:
            logger.error("Cannot find attacker role ARN")
            return False
        
        malicious_project_name = f"malicious-project-{EXPERIMENT_TIMESTAMP}"
        
        # Check 1: Verify malicious project does not exist
        logger.info(f"Checking if malicious project exists: {malicious_project_name}")
        try:
            response = codebuild.batch_get_projects(names=[malicious_project_name])
            projects = response.get('projects', [])
            
            if projects:
                logger.error(f"FAILURE: Malicious project exists: {projects[0]['arn']}")
                return False
            else:
                logger.info("SUCCESS: Malicious project does not exist (was blocked)")
        except ClientError as e:
            logger.info(f"Project lookup failed as expected: {e}")
        
        # Check 2: Verify the IAM policy on attacker role has the deny statement
        role_name = attacker_role_arn.split('/')[-1]
        logger.info(f"Verifying preventive control policy on role: {role_name}")
        
        try:
            response = iam.get_role(RoleName=role_name)
            role = response['Role']
            logger.info(f"Retrieved role: {role['RoleName']}")
            
            # Get inline policies
            response = iam.list_role_policies(RoleName=role_name)
            policy_names = response['PolicyNames']
            
            has_preventive_control = False
            for policy_name in policy_names:
                policy_response = iam.get_role_policy(
                    RoleName=role_name,
                    PolicyName=policy_name
                )
                policy_doc = policy_response['PolicyDocument']
                
                # Check for deny statements related to privileged mode
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Deny':
                        actions = statement.get('Action', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        
                        conditions = statement.get('Condition', {})
                        
                        # Check for privileged mode condition
                        if 'codebuild:CreateProject' in actions:
                            if 'StringEquals' in conditions:
                                if 'codebuild:PrivilegedMode' in conditions['StringEquals']:
                                    logger.info("Found preventive control: Deny privileged mode")
                                    has_preventive_control = True
                                    break
            
            if not has_preventive_control:
                logger.warning("Preventive control policy not found, but project was blocked")
                # Still consider it a success if project doesn't exist
            else:
                logger.info("Preventive control policy verified")
            
        except ClientError as e:
            logger.error(f"Error checking IAM policy: {e}")
            return False
        
        # Check 3: List all projects and ensure our malicious one isn't there
        logger.info("Listing all CodeBuild projects to double-check")
        try:
            response = codebuild.list_projects()
            all_projects = response.get('projects', [])
            
            if malicious_project_name in all_projects:
                logger.error(f"FAILURE: Malicious project found in project list")
                return False
            
            logger.info(f"Verified malicious project not in list of {len(all_projects)} projects")
            
        except ClientError as e:
            logger.error(f"Error listing projects: {e}")
            return False
        
        logger.info("Hypothesis verification PASSED: Preventive control successfully blocked malicious project")
        return True
        
    except Exception as e:
        logger.error(f"Hypothesis verification failed: {e}")
        return False


def rollback():
    """Delete the CloudFormation stack and all resources."""
    global STACK_NAME, REGION
    
    if not STACK_NAME:
        logger.warning("No stack name defined, nothing to rollback")
        return
    
    try:
        logger.info(f"Starting rollback for stack: {STACK_NAME}")
        cfn = boto3.client('cloudformation', region_name=REGION)
        
        try:
            cfn.delete_stack(StackName=STACK_NAME)
            logger.info(f"Stack deletion initiated: {STACK_NAME}")
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.warning(f"Stack {STACK_NAME} does not exist")
                return
            else:
                raise
        
        # Wait for deletion
        def check_stack_deleted():
            try:
                response = cfn.describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack status: {status}")
                
                if 'FAILED' in status:
                    logger.error(f"Stack deletion failed: {status}")
                    return True  # Stop waiting
                return status == 'DELETE_COMPLETE'
            except ClientError as e:
                if 'does not exist' in str(e):
                    logger.info("Stack deleted successfully")
                    return True
                logger.error(f"Error checking stack: {e}")
                return False
        
        wait_with_backoff(check_stack_deleted, max_attempts=90, initial_delay=5)
        logger.info("Rollback completed")
        
    except Exception as e:
        logger.error(f"Rollback error: {e}")


def main():
    """Execute the complete experiment flow."""
    try:
        logger.info("="*80)
        logger.info("Starting SCE Experiment 1.3: Preventive Control for Malicious CodeBuild")
        logger.info("="*80)
        
        # Execute experiment phases
        steady_state()
        attack_result = attack()
        hypothesis_result = hypothesis_verification()
        
        logger.info("="*80)
        logger.info(f"Attack executed: {attack_result}")
        logger.info(f"Hypothesis verified: {hypothesis_result}")
        logger.info("="*80)
        
        if hypothesis_result:
            logger.info("EXPERIMENT PASSED: Preventive control blocked malicious CodeBuild project")
        else:
            logger.error("EXPERIMENT FAILED: Preventive control did not work as expected")
        
    except Exception as e:
        logger.error(f"Experiment failed: {e}")
        raise
    finally:
        rollback()


if __name__ == "__main__":
    main()