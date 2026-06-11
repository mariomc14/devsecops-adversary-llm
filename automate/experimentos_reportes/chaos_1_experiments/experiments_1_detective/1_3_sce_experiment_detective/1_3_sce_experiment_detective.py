import boto3
import time
import logging
import json
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def steady_state():
    """
    Prepare AWS resources for the experiment
    """
    try:
        # Create a CloudFormation client
        cfn_client = boto3.client('cloudformation')
        
        # Generate a unique stack name with timestamp
        stack_name = f'sce-experiment-codebuild-{int(time.time())}'
        
        # Prepare CloudFormation template
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "VulnerableIAMRole": {
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
                            "arn:aws:iam::aws:policy/AdministratorAccess"  # Overly permissive policy
                        ]
                    }
                }
            }
        }
        
        # Create the CloudFormation stack
        cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Capabilities=['CAPABILITY_IAM']
        )
        
        # Wait for stack creation
        waiter = cfn_client.get_waiter('stack_create_complete')
        waiter.wait(StackName=stack_name)
        
        logger.info(f"Stack {stack_name} created successfully")
        
        return {
            'stack_name': stack_name,
            'role_name': 'VulnerableIAMRole'
        }
    
    except ClientError as e:
        logger.error(f"Error in steady_state: {e}")
        raise

def attack(context=None):
    """
    Create a malicious CodeBuild project with overly permissive IAM role
    """
    try:
        codebuild_client = boto3.client('codebuild')
        iam_client = boto3.client('iam')
        
        # Get the IAM role ARN
        role_arn = iam_client.get_role(RoleName='VulnerableIAMRole')['Role']['Arn']
        
        # Create a malicious CodeBuild project
        project_name = f'malicious-project-{int(time.time())}'
        response = codebuild_client.create_project(
            name=project_name,
            source={
                'type': 'NO_SOURCE',
                'buildspec': '''version: 0.2
                phases:
                  build:
                    commands:
                      - echo "Malicious build step"'''
            },
            environment={
                'type': 'LINUX_CONTAINER',
                'computeType': 'BUILD_GENERAL1_SMALL',
                'image': 'aws/codebuild/amazonlinux2-x86_64-standard:3.0'
            },
            serviceRole=role_arn,
            artifacts={'type': 'NO_ARTIFACTS'}
        )
        
        logger.info(f"Malicious CodeBuild project {project_name} created")
        return True
    
    except ClientError as e:
        logger.error(f"Error in attack: {e}")
        return False

def hypothesis_verification(context=None):
    """
    Verify if the created CodeBuild project has security risks
    """
    try:
        access_analyzer_client = boto3.client('accessanalyzer')
        
        # Use Access Analyzer to check for overly permissive IAM roles
        response = access_analyzer_client.list_findings(
            filter={
                'criteria': {
                    'resourceType': ['AWS::IAM::Role']
                }
            }
        )
        
        # Check if there are any findings indicating security risks
        for finding in response.get('findings', []):
            if finding['status'] == 'ACTIVE' and finding['resourceType'] == 'AWS::IAM::Role':
                logger.warning(f"Security risk found: {finding['id']}")
                return False
        
        logger.info("No security risks detected in IAM roles")
        return True
    
    except ClientError as e:
        logger.error(f"Error in hypothesis_verification: {e}")
        return False

def rollback(context=None):
    """
    Clean up resources created during the experiment
    """
    try:
        # Delete CloudFormation stack
        cfn_client = boto3.client('cloudformation')
        stack_name = context.get('stack_name') if context else None
        
        if stack_name:
            cfn_client.delete_stack(StackName=stack_name)
            
            # Wait for stack deletion
            waiter = cfn_client.get_waiter('stack_delete_complete')
            waiter.wait(StackName=stack_name)
            
            logger.info(f"Stack {stack_name} deleted successfully")
        
    except ClientError as e:
        logger.error(f"Error in rollback: {e}")