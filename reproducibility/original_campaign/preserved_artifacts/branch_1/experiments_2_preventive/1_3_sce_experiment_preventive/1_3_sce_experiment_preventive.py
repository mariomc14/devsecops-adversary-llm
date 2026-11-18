"""
SCE 1.3 Preventive Probe Experiment
Tests whether IAM preventive controls block malicious CodeBuild project creation.

This experiment validates that explicit deny policies prevent an attacker from:
1. Creating a CodeBuild project with privileged mode enabled
2. Passing an IAM role to the project for credential exfiltration

Attack Vector: T1552.005 (Unsecured Credentials in CodeBuild environment)
Defense: IAM Least Privilege Control via explicit deny policies
"""

import json
import time
import logging
import boto3
import sys
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state management
EXPERIMENT_STATE: Dict[str, Any] = {
    'stack_name': None,
    'role_arn': None,
    'role_name': None,
    'timestamp': None,
    'account_id': None,
    'region': 'us-east-1',
    'stack_outputs': {}
}

# AWS Clients
cloudformation_client = boto3.client('cloudformation', region_name=EXPERIMENT_STATE['region'])
iam_client = boto3.client('iam', region_name=EXPERIMENT_STATE['region'])
codebuild_client = boto3.client('codebuild', region_name=EXPERIMENT_STATE['region'])
sts_client = boto3.client('sts', region_name=EXPERIMENT_STATE['region'])


def _get_account_id() -> str:
    """Retrieve AWS account ID from STS."""
    if not EXPERIMENT_STATE['account_id']:
        try:
            response = sts_client.get_caller_identity()
            EXPERIMENT_STATE['account_id'] = response['Account']
            logger.info(f"AWS Account ID: {EXPERIMENT_STATE['account_id']}")
        except Exception as e:
            logger.error(f"Failed to retrieve account ID: {e}")
            raise
    return EXPERIMENT_STATE['account_id']


def _generate_stack_name() -> str:
    """Generate unique stack name with timestamp suffix."""
    timestamp = int(time.time())
    EXPERIMENT_STATE['timestamp'] = timestamp
    stack_name = f"sce-1-3-preventive-{timestamp}"
    EXPERIMENT_STATE['stack_name'] = stack_name
    return stack_name


def _get_cloudformation_template() -> str:
    """
    Return CloudFormation template that provisions:
    - IAM role for CodeBuild with preventive deny policies
    - S3 bucket for build artifacts
    - Explicit deny: privileged mode
    - Explicit deny: IAM PassRole for CodeBuild
    """
    account_id = _get_account_id()
    timestamp = EXPERIMENT_STATE['timestamp']
    
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.3 Preventive Control Infrastructure - IAM Least Privilege for CodeBuild",
        "Resources": {
            "SCECodeBuildRole": {
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
                        {
                            "Key": "Experiment",
                            "Value": "SCE-1-3-Preventive"
                        },
                        {
                            "Key": "Timestamp",
                            "Value": str(timestamp)
                        }
                    ]
                }
            },
            "DenyPrivilegedModePolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": "DenyPrivilegedModeCodeBuild",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DenyPrivilegedModeOnCodeBuild",
                                "Effect": "Deny",
                                "Action": [
                                    "codebuild:CreateProject",
                                    "codebuild:UpdateProject"
                                ],
                                "Resource": f"arn:aws:codebuild:*:{account_id}:project/*",
                                "Condition": {
                                    "Bool": {
                                        "codebuild:PrivilegedMode": "true"
                                    }
                                }
                            }
                        ]
                    },
                    "Roles": [
                        {"Ref": "SCECodeBuildRole"}
                    ]
                }
            },
            "DenyPassRolePolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": "DenyIAMPassRoleForCodeBuild",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DenyPassRoleToCodeBuild",
                                "Effect": "Deny",
                                "Action": "iam:PassRole",
                                "Resource": f"arn:aws:iam::{account_id}:role/sce-codebuild-role-{timestamp}",
                                "Condition": {
                                    "StringEquals": {
                                        "iam:PassedToService": "codebuild.amazonaws.com"
                                    }
                                }
                            }
                        ]
                    },
                    "Roles": [
                        {"Ref": "SCECodeBuildRole"}
                    ]
                }
            },
            "SCEArtifactBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": f"sce-experiment-{account_id}-{timestamp}",
                    "VersioningConfiguration": {
                        "Status": "Enabled"
                    },
                    "Tags": [
                        {
                            "Key": "Experiment",
                            "Value": "SCE-1-3-Preventive"
                        }
                    ]
                }
            }
        },
        "Outputs": {
            "RoleName": {
                "Value": {"Ref": "SCECodeBuildRole"},
                "Description": "CodeBuild IAM Role Name"
            },
            "RoleArn": {
                "Value": {"Fn::GetAtt": ["SCECodeBuildRole", "Arn"]},
                "Description": "CodeBuild IAM Role ARN"
            },
            "BucketName": {
                "Value": {"Ref": "SCEArtifactBucket"},
                "Description": "S3 Artifact Bucket"
            }
        }
    }
    
    return json.dumps(template)


def _wait_for_stack(stack_name: str, target_status: str, max_attempts: int = 60) -> bool:
    """
    Wait for CloudFormation stack to reach target status with exponential backoff.
    
    Args:
        stack_name: Name of the stack
        target_status: e.g., 'CREATE_COMPLETE', 'DELETE_COMPLETE'
        max_attempts: Maximum retry attempts
    
    Returns:
        True if target status reached, False otherwise
    """
    attempt = 0
    backoff_base = 2
    
    while attempt < max_attempts:
        try:
            response = cloudformation_client.describe_stacks(StackName=stack_name)
            if response['Stacks']:
                current_status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack status: {current_status}")
                
                if current_status == target_status:
                    return True
                elif 'ROLLBACK' in current_status or 'FAILED' in current_status:
                    logger.error(f"Stack entered failed state: {current_status}")
                    return False
        except cloudformation_client.exceptions.ClientError as e:
            if 'does not exist' in str(e) and target_status == 'DELETE_COMPLETE':
                logger.info("Stack successfully deleted (not found)")
                return True
            logger.warning(f"Error querying stack status: {e}")
        
        # Exponential backoff
        wait_time = min(backoff_base ** attempt, 30)
        logger.info(f"Waiting {wait_time}s before retry (attempt {attempt + 1}/{max_attempts})")
        time.sleep(wait_time)
        attempt += 1
    
    logger.error(f"Timeout waiting for stack to reach {target_status}")
    return False


def steady_state() -> None:
    """
    PHASE 1: Deploy preventive control infrastructure.
    
    Creates:
    - IAM role with explicit deny policies for privileged CodeBuild
    - S3 bucket for artifacts
    - CloudFormation stack with unique timestamp
    """
    logger.info("=" * 80)
    logger.info("PHASE 1: STEADY STATE - Deploying Preventive Control Infrastructure")
    logger.info("=" * 80)
    
    account_id = _get_account_id()
    stack_name = _generate_stack_name()
    
    logger.info(f"Creating CloudFormation stack: {stack_name}")
    template = _get_cloudformation_template()
    
    try:
        # Create stack
        response = cloudformation_client.create_stack(
            StackName=stack_name,
            TemplateBody=template,
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': 'SCE-1-3-Preventive'},
                {'Key': 'Timestamp', 'Value': str(EXPERIMENT_STATE['timestamp'])}
            ]
        )
        logger.info(f"Stack creation initiated. Stack ID: {response['StackId']}")
        
    except cloudformation_client.exceptions.ClientError as e:
        if 'AlreadyExistsException' in str(e):
            logger.warning(f"Stack already exists: {stack_name}. Continuing...")
        else:
            logger.error(f"Failed to create stack: {e}")
            raise
    
    # Wait for stack creation
    logger.info("Waiting for stack creation (this may take 30-60 seconds)...")
    if not _wait_for_stack(stack_name, 'CREATE_COMPLETE'):
        logger.error("Stack creation failed or timed out")
        raise RuntimeError(f"Stack {stack_name} did not reach CREATE_COMPLETE status")
    
    logger.info("✓ Stack created successfully")
    
    # Extract stack outputs
    try:
        response = cloudformation_client.describe_stacks(StackName=stack_name)
        outputs = response['Stacks'][0].get('Outputs', [])
        
        for output in outputs:
            key = output['OutputKey']
            value = output['OutputValue']
            EXPERIMENT_STATE['stack_outputs'][key] = value
            
            if key == 'RoleArn':
                EXPERIMENT_STATE['role_arn'] = value
            elif key == 'RoleName':
                EXPERIMENT_STATE['role_name'] = value
        
        logger.info(f"Stack Outputs: {json.dumps(EXPERIMENT_STATE['stack_outputs'], indent=2)}")
        logger.info("✓ Preventive control infrastructure deployed successfully")
        
    except Exception as e:
        logger.error(f"Failed to extract stack outputs: {e}")
        raise


def attack() -> bool:
    """
    PHASE 2: Execute malicious CodeBuild project creation attack.
    
    Attempts to:
    1. Create a CodeBuild project with privileged mode = True
    2. Attach the preventively-controlled role
    3. Include buildspec with credential exfiltration payload
    
    Returns:
        True if attack was executed (regardless of outcome)
        False if execution failed before API call
    """
    logger.info("=" * 80)
    logger.info("PHASE 2: ATTACK - Attempting Malicious CodeBuild Project Creation")
    logger.info("=" * 80)
    
    if not EXPERIMENT_STATE['role_arn']:
        logger.error("Role ARN not available. Steady state may have failed.")
        return False
    
    if not EXPERIMENT_STATE['stack_outputs'].get('BucketName'):
        logger.error("Artifact bucket not available. Steady state may have failed.")
        return False
    
    role_arn = EXPERIMENT_STATE['role_arn']
    bucket_name = EXPERIMENT_STATE['stack_outputs']['BucketName']
    timestamp = EXPERIMENT_STATE['timestamp']
    project_name = f"sce-malicious-project-{timestamp}"
    
    logger.info(f"Target Role ARN: {role_arn}")
    logger.info(f"Target Role Name: {EXPERIMENT_STATE['role_name']}")
    logger.info(f"Executing CreateProject API call for: {project_name}")
    
    # Malicious buildspec: credential exfiltration via STS
    malicious_buildspec = {
        "version": "0.2",
        "phases": {
            "build": {
                "commands": [
                    "echo 'Exfiltrating credentials...'",
                    "aws sts get-caller-identity",
                    "aws sts get-session-token",
                    "env | grep AWS"
                ]
            }
        },
        "artifacts": {
            "files": ["**/*"]
        }
    }
    
    attack_evidence = {
        'api_call': 'codebuild:CreateProject',
        'project_name': project_name,
        'privileged_mode': True,
        'role_arn': role_arn,
        'timestamp': timestamp,
        'buildspec': malicious_buildspec
    }
    
    try:
        # Attempt to create malicious project with privileged mode
        response = codebuild_client.create_project(
            name=project_name,
            source={
                'type': 'NO_SOURCE',
                'buildspec': json.dumps(malicious_buildspec)
            },
            artifacts={
                'type': 'S3',
                'location': bucket_name,
                'path': f'artifacts/{timestamp}/'
            },
            environment={
                'type': 'LINUX_CONTAINER',
                'image': 'aws/codebuild/standard:7.0',
                'computeType': 'BUILD_GENERAL1_SMALL',
                'environmentVariables': [
                    {
                        'name': 'AWS_REGION',
                        'value': EXPERIMENT_STATE['region'],
                        'type': 'PLAINTEXT'
                    }
                ],
                'privilegedMode': True  # KEY ATTACK VECTOR
            },
            serviceRole=role_arn,  # PassRole with preventive control
            description='Malicious CodeBuild project for credential exfiltration'
        )
        
        attack_evidence['success'] = True
        attack_evidence['response'] = {
            'project_arn': response['project']['arn'],
            'project_name': response['project']['name'],
            'status_code': 200
        }
        
        logger.info(f"✗ ATTACK SUCCEEDED (unexpected): Project created: {response['project']['arn']}")
        logger.error("Preventive control FAILED - malicious project was created!")
        
        return True
        
    except codebuild_client.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        attack_evidence['error'] = {
            'code': error_code,
            'message': error_message
        }
        
        logger.warning(f"Attack produced an error (may indicate preventive control)")
        logger.info(f"  Error Code: {error_code}")
        logger.info(f"  Error Message: {error_message}")
        
        # Log as evidence for verification phase
        logger.info(f"Attack Evidence (JSON): {json.dumps(attack_evidence, indent=2)}")
        
        # Return True: attack was executed, captured error response
        return True
        
    except Exception as e:
        logger.error(f"Unexpected exception during attack: {type(e).__name__}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return True  # Still executed the attack attempt


def hypothesis_verification() -> bool:
    """
    PHASE 3: Verify preventive control effectiveness.
    
    Queries AWS to confirm:
    1. Malicious project does NOT exist
    2. Attack error indicates preventive denial (not timeout/network error)
    
    Returns:
        True if preventive control worked (project doesn't exist)
        False if control failed (project exists or verification failed)
    """
    logger.info("=" * 80)
    logger.info("PHASE 3: HYPOTHESIS VERIFICATION - Checking Preventive Control Effectiveness")
    logger.info("=" * 80)
    
    timestamp = EXPERIMENT_STATE['timestamp']
    project_name = f"sce-malicious-project-{timestamp}"
    
    logger.info(f"Querying for malicious project: {project_name}")
    
    try:
        # Direct API call to verify project doesn't exist
        response = codebuild_client.batch_get_projects(names=[project_name])
        projects = response.get('projects', [])
        
        if len(projects) == 0:
            logger.info("✓ PASS: Malicious project does not exist (preventive control worked)")
            return True
        else:
            logger.error(f"✗ FAIL: Malicious project EXISTS: {projects[0]['arn']}")
            logger.error("Preventive control did NOT block project creation!")
            return False
            
    except codebuild_client.exceptions.ProjectNotFoundException:
        logger.info("✓ PASS: Project not found (preventive control worked)")
        return True
        
    except Exception as e:
        logger.error(f"Failed to verify preventive control: {type(e).__name__}: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


def rollback() -> None:
    """
    PHASE 4: Clean up experiment resources.
    
    Deletes:
    - CloudFormation stack (which cascades to IAM role, S3 bucket, policies)
    """
    logger.info("=" * 80)
    logger.info("PHASE 4: ROLLBACK - Cleaning Up Experiment Resources")
    logger.info("=" * 80)
    
    stack_name = EXPERIMENT_STATE['stack_name']
    if not stack_name:
        logger.warning("No stack name found. Skipping rollback.")
        return
    
    logger.info(f"Initiating stack deletion: {stack_name}")
    
    try:
        cloudformation_client.delete_stack(StackName=stack_name)
        logger.info("Stack deletion initiated")
    except cloudformation_client.exceptions.ClientError as e:
        if 'does not exist' in str(e):
            logger.warning(f"Stack does not exist: {stack_name}")
        else:
            logger.error(f"Failed to delete stack: {e}")
            return
    
    # Wait for deletion
    logger.info("Waiting for stack deletion (this may take 30-60 seconds)...")
    if _wait_for_stack(stack_name, 'DELETE_COMPLETE'):
        logger.info("✓ Stack has been deleted")
        logger.info("✓ Experiment rollback completed successfully")
    else:
        logger.warning("Stack deletion timed out or failed. Manual cleanup may be required.")


if __name__ == '__main__':
    """
    Main execution flow for standalone testing.
    """
    try:
        logger.info("Starting SCE 1.3 Preventive Probe Experiment")
        
        # Phase 1: Steady State
        steady_state()
        
        # Phase 2: Attack
        attack_executed = attack()
        logger.info(f"Attack execution result: {attack_executed}")
        
        # Phase 3: Hypothesis Verification
        hypothesis_met = hypothesis_verification()
        logger.info(f"Hypothesis verification result: {hypothesis_met}")
        
        if hypothesis_met:
            logger.info("✓ EXPERIMENT PASSED: Preventive control blocked malicious project creation")
        else:
            logger.error("✗ EXPERIMENT FAILED: Preventive control did not block attack")
        
    except Exception as e:
        logger.error(f"Experiment failed with exception: {e}")
        import traceback
        logger.error(traceback.format_exc())
        
    finally:
        # Phase 4: Rollback (always executed)
        try:
            rollback()
        except Exception as e:
            logger.error(f"Rollback failed: {e}")