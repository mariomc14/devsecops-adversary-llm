import boto3
import json
import logging
import time
from botocore.exceptions import ClientError

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def steady_state():
    """
    Set up a controlled CodeBuild environment with minimal IAM permissions
    """
    cloudformation = boto3.client('cloudformation')
    timestamp = int(time.time())
    stack_name = f'sce-codebuild-experiment-{timestamp}'

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
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
                    "Policies": [{
                        "PolicyName": "MinimalCodeBuildAccess",
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
            "CodeBuildProject": {
                "Type": "AWS::CodeBuild::Project",
                "Properties": {
                    "Name": f"sce-test-project-{timestamp}",
                    "Description": "Security Chaos Engineering Test Project",
                    "ServiceRole": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]},
                    "Artifacts": {"Type": "NO_ARTIFACTS"},
                    "Environment": {
                        "Type": "LINUX_CONTAINER",
                        "ComputeType": "BUILD_GENERAL1_SMALL",
                        "Image": "aws/codebuild/amazonlinux2-x86_64-standard:3.0"
                    },
                    "Source": {
                        "Type": "NO_SOURCE",
                        "BuildSpec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo 'No-op build'"
                    }
                }
            }
        }
    }

    try:
        cloudformation.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Capabilities=['CAPABILITY_IAM']
        )
        
        # Wait for stack creation
        waiter = cloudformation.get_waiter('stack_create_complete')
        waiter.wait(StackName=stack_name)
        
        logger.info(f"Stack {stack_name} created successfully")
        return stack_name
    except ClientError as e:
        logger.error(f"Error creating stack: {e}")
        raise

def attack(stack_name=None):
    """
    Attempt to modify CodeBuild project configuration to escalate privileges
    """
    if not stack_name:
        logger.error("No stack name provided")
        return False

    codebuild = boto3.client('codebuild')
    cloudformation = boto3.client('cloudformation')

    try:
        # Retrieve project name from CloudFormation stack outputs
        response = cloudformation.describe_stacks(StackName=stack_name)
        project_name = [res['OutputValue'] for res in response['Stacks'][0].get('Outputs', []) 
                        if res.get('OutputKey') == 'CodeBuildProjectName'][0]

        # Attempt to update project with privileged mode
        codebuild.update_project(
            name=project_name,
            environment={
                'type': 'LINUX_CONTAINER',
                'image': 'aws/codebuild/amazonlinux2-x86_64-standard:3.0',
                'computeType': 'BUILD_GENERAL1_SMALL',
                'privilegedMode': True  # Dangerous configuration
            }
        )
        
        logger.warning(f"Successfully attempted privileged mode escalation on {project_name}")
        return True

    except Exception as e:
        logger.error(f"Attack failed: {e}")
        return False

def hypothesis_verification(stack_name=None):
    """
    Verify that no unauthorized configuration changes occurred
    """
    if not stack_name:
        logger.error("No stack name provided")
        return False

    codebuild = boto3.client('codebuild')
    cloudformation = boto3.client('cloudformation')

    try:
        # Retrieve project name from CloudFormation stack outputs
        response = cloudformation.describe_stacks(StackName=stack_name)
        project_name = [res['OutputValue'] for res in response['Stacks'][0].get('Outputs', []) 
                        if res.get('OutputKey') == 'CodeBuildProjectName'][0]

        # Retrieve current project configuration
        project_details = codebuild.batch_get_projects(names=[project_name])
        project = project_details['projects'][0]

        # Check if privileged mode is disabled
        if not project['environment'].get('privilegedMode', False):
            logger.info("Hypothesis verified: No unauthorized configuration changes")
            return True
        else:
            logger.warning("Unauthorized configuration change detected!")
            return False

    except Exception as e:
        logger.error(f"Verification failed: {e}")
        return False

def rollback(stack_name=None):
    """
    Clean up resources created during the experiment
    """
    if not stack_name:
        logger.error("No stack name provided")
        return

    cloudformation = boto3.client('cloudformation')

    try:
        cloudformation.delete_stack(StackName=stack_name)
        
        # Wait for stack deletion
        waiter = cloudformation.get_waiter('stack_delete_complete')
        waiter.wait(StackName=stack_name)
        
        logger.info(f"Stack {stack_name} deleted successfully")
    except ClientError as e:
        logger.error(f"Error deleting stack: {e}")