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
    Prepare the AWS environment for the experiment by:
    1. Creating a CloudFormation stack with base IAM resources
    2. Establishing a controlled security context
    """
    try:
        # Generate unique timestamp for resource isolation
        timestamp = int(time.time())
        stack_name = f"sce-codebuild-experiment-{timestamp}"
        
        # Create CloudFormation client
        cfn_client = boto3.client('cloudformation')
        iam_client = boto3.client('iam')
        
        # Define CloudFormation template for IAM role
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "BaseServiceRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": f"CodeBuildBaseRole-{timestamp}",
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
                            "arn:aws:iam::aws:policy/AWSCodeBuildAdminAccess"
                        ]
                    }
                }
            }
        }
        
        # Create CloudFormation stack
        cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Capabilities=['CAPABILITY_NAMED_IAM']
        )
        
        # Wait for stack creation
        waiter = cfn_client.get_waiter('stack_create_complete')
        waiter.wait(StackName=stack_name)
        
        logger.info(f"Successfully created stack: {stack_name}")
        return {
            "stack_name": stack_name,
            "timestamp": timestamp
        }
    
    except ClientError as e:
        logger.error(f"Error in steady_state: {e}")
        raise

def attack(context=None):
    """
    Simulate creation of a malicious CodeBuild project
    """
    if not context:
        context = steady_state()
    
    try:
        codebuild_client = boto3.client('codebuild')
        iam_client = boto3.client('iam')
        
        # Retrieve the IAM role created in steady_state
        role_name = f"CodeBuildBaseRole-{context['timestamp']}"
        role = iam_client.get_role(RoleName=role_name)
        
        # Create a potentially malicious CodeBuild project
        project_name = f"sce-malicious-project-{context['timestamp']}"
        
        response = codebuild_client.create_project(
            name=project_name,
            description="Potentially malicious CodeBuild project",
            serviceRole=role['Role']['Arn'],
            artifacts={
                'type': 'NO_ARTIFACTS'
            },
            environment={
                'type': 'LINUX_CONTAINER',
                'computeType': 'BUILD_GENERAL1_SMALL',
                'image': 'aws/codebuild/amazonlinux2-x86_64-standard:3.0'
            },
            source={
                'type': 'NO_SOURCE',
                'buildspec': 'version: 0.2\nphases:\n  build:\n    commands:\n      - echo "Potential malicious activity"'
            }
        )
        
        logger.info(f"Created potentially malicious project: {project_name}")
        return True
    
    except ClientError as e:
        logger.error(f"Attack failed: {e}")
        return False

def hypothesis_verification(context=None):
    """
    Verify that no unauthorized CodeBuild projects exist
    """
    if not context:
        context = {"timestamp": int(time.time())}
    
    try:
        codebuild_client = boto3.client('codebuild')
        
        # List all projects and check for unauthorized ones
        projects = codebuild_client.list_projects()['projects']
        
        # Filter projects created during this experiment
        suspicious_projects = [
            proj for proj in projects 
            if f"sce-malicious-project-{context['timestamp']}" in proj
        ]
        
        if suspicious_projects:
            logger.warning(f"Unauthorized projects found: {suspicious_projects}")
            return False
        
        logger.info("No unauthorized projects detected")
        return True
    
    except ClientError as e:
        logger.error(f"Verification error: {e}")
        return False

def rollback(context=None):
    """
    Clean up resources created during the experiment
    """
    if not context:
        return
    
    try:
        # Delete CodeBuild project if it exists
        codebuild_client = boto3.client('codebuild')
        project_name = f"sce-malicious-project-{context['timestamp']}"
        
        try:
            codebuild_client.delete_project(name=project_name)
            logger.info(f"Deleted project: {project_name}")
        except codebuild_client.exceptions.ResourceNotFoundException:
            logger.info(f"Project {project_name} already deleted")
        
        # Delete CloudFormation stack
        cfn_client = boto3.client('cloudformation')
        cfn_client.delete_stack(StackName=context['stack_name'])
        
        # Wait for stack deletion
        waiter = cfn_client.get_waiter('stack_delete_complete')
        waiter.wait(StackName=context['stack_name'])
        
        logger.info(f"Successfully deleted stack: {context['stack_name']}")
    
    except ClientError as e:
        logger.error(f"Rollback error: {e}")

# Optional: If script is run directly
if __name__ == "__main__":
    context = steady_state()
    attack(context)
    hypothesis_verification(context)
    rollback(context)