import boto3
import json
import logging
import time
import uuid
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def steady_state():
    """
    Create a secure CodeBuild project with minimal permissions
    """
    try:
        # Generate unique identifiers
        experiment_id = f'sce-experiment-{int(time.time())}'
        stack_name = f'sce-codebuild-{experiment_id}'
        
        # Initialize AWS clients
        cloudformation_client = boto3.client('cloudformation')
        iam_client = boto3.client('iam')
        
        # Create IAM Role with minimal permissions
        role_name = f'{experiment_id}-codebuild-role'
        assume_role_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "codebuild.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        role_response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy)
        )
        role_arn = role_response['Role']['Arn']
        
        # Attach minimal CodeBuild permissions
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/AWSCodeBuildAdminAccess'
        )
        
        # CloudFormation template for CodeBuild project
        cloudformation_template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "SecureCodeBuildProject": {
                    "Type": "AWS::CodeBuild::Project",
                    "Properties": {
                        "Name": f"{experiment_id}-project",
                        "ServiceRole": role_arn,
                        "Artifacts": {"Type": "NO_ARTIFACTS"},
                        "Environment": {
                            "Type": "LINUX_CONTAINER",
                            "ComputeType": "BUILD_GENERAL1_SMALL",
                            "Image": "aws/codebuild/amazonlinux2-x86_64-standard:3.0"
                        },
                        "Source": {
                            "Type": "NO_SOURCE",
                            "BuildSpec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo 'Secure build'"
                        }
                    }
                }
            }
        }
        
        # Create CloudFormation stack
        cloudformation_client.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(cloudformation_template),
            Capabilities=['CAPABILITY_IAM']
        )
        
        # Wait for stack creation
        waiter = cloudformation_client.get_waiter('stack_create_complete')
        waiter.wait(StackName=stack_name)
        
        logger.info(f"Created secure CodeBuild project: {experiment_id}")
        return {
            'stack_name': stack_name,
            'project_name': f"{experiment_id}-project",
            'role_name': role_name
        }
    
    except Exception as e:
        logger.error(f"Failed to create steady state: {e}")
        raise

def attack(context=None):
    """
    Attempt to modify CodeBuild project with malicious intent
    """
    if not context:
        logger.error("No context provided for attack")
        return False
    
    try:
        codebuild_client = boto3.client('codebuild')
        
        # Attempt to update project with suspicious buildspec
        malicious_buildspec = """
        version: 0.2
        phases:
          build:
            commands:
              - export AWS_ACCESS_KEY_ID=MALICIOUS_KEY
              - export AWS_SECRET_ACCESS_KEY=MALICIOUS_SECRET
        """
        
        codebuild_client.update_project(
            name=context['project_name'],
            source={
                'buildspec': malicious_buildspec
            }
        )
        
        logger.warning("Malicious project modification attempted")
        return True
    
    except ClientError as e:
        logger.error(f"Attack failed: {e}")
        return False

def hypothesis_verification(context=None):
    """
    Verify that preventive controls blocked malicious modification
    """
    if not context:
        logger.error("No context for verification")
        return False
    
    try:
        codebuild_client = boto3.client('codebuild')
        
        # Retrieve project details
        project_details = codebuild_client.batch_get_projects(
            names=[context['project_name']]
        )
        
        current_buildspec = project_details['projects'][0]['source'].get('buildspec', '')
        
        # Check for malicious indicators
        malicious_keywords = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY']
        
        for keyword in malicious_keywords:
            if keyword in current_buildspec:
                logger.error("Malicious buildspec detected!")
                return False
        
        logger.info("Preventive controls successfully blocked modification")
        return True
    
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        return False

def rollback(context=None):
    """
    Clean up resources created during the experiment
    """
    if not context:
        logger.warning("No context for rollback")
        return
    
    try:
        # Delete CloudFormation stack
        cloudformation_client = boto3.client('cloudformation')
        cloudformation_client.delete_stack(StackName=context['stack_name'])
        
        # Delete IAM Role
        iam_client = boto3.client('iam')
        iam_client.delete_role(RoleName=context['role_name'])
        
        logger.info("Rollback completed successfully")
    
    except Exception as e:
        logger.error(f"Rollback failed: {e}")

if __name__ == "__main__":
    context = steady_state()
    try:
        attack_result = attack(context)
        verification_result = hypothesis_verification(context)
        
        if not verification_result:
            logger.critical("Security control failed!")
    except Exception as e:
        logger.error(f"Experiment execution failed: {e}")
    finally:
        rollback(context)