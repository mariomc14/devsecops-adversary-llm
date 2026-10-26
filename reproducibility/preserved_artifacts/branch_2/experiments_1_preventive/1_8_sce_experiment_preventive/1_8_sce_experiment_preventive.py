import boto3
import json
import logging
import time
import uuid
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def steady_state():
    """
    Prepare the AWS environment for the security chaos experiment
    """
    # Create a unique stack name with timestamp
    stack_name = f"sce-wildcard-prevention-{int(time.time())}"
    
    # Initialize CloudFormation and IAM clients
    cfn_client = boto3.client('cloudformation')
    iam_client = boto3.client('iam')
    
    try:
        # Define a restrictive CloudFormation template
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "SCE Experiment - Prevent Wildcard Principal Injection",
            "Resources": {
                "RestrictedRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": f"sce-restricted-role-{uuid.uuid4().hex[:8]}",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Deny",
                                    "Principal": "*",
                                    "Action": "sts:AssumeRole"
                                },
                                {
                                    "Effect": "Allow",
                                    "Principal": {"AWS": f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:root"},
                                    "Action": "sts:AssumeRole"
                                }
                            ]
                        }
                    }
                }
            }
        }
        
        # Create the stack
        cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Capabilities=['CAPABILITY_IAM', 'CAPABILITY_NAMED_IAM']
        )
        
        # Wait for stack creation
        waiter = cfn_client.get_waiter('stack_create_complete')
        waiter.wait(StackName=stack_name)
        
        logger.info(f"Stack {stack_name} created successfully")
        return stack_name
    
    except ClientError as e:
        logger.error(f"Error in steady_state: {e}")
        raise

def attack(stack_name=None):
    """
    Attempt to inject a wildcard principal
    """
    if not stack_name:
        logger.error("No stack name provided for attack")
        return False
    
    try:
        iam_client = boto3.client('iam')
        
        # Retrieve the role created in steady_state
        cfn_client = boto3.client('cloudformation')
        stack_resources = cfn_client.describe_stack_resources(StackName=stack_name)
        
        # Find the role ARN
        role_resource = next(
            (res for res in stack_resources['StackResources'] 
             if res['ResourceType'] == 'AWS::IAM::Role'), 
            None
        )
        
        if not role_resource:
            logger.error("Could not find IAM role in the stack")
            return False
        
        role_name = role_resource['LogicalResourceId']
        
        # Attempt to modify role's trust policy with wildcard principal
        malicious_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRole"
                }
            ]
        }
        
        # Try to update the assume role policy
        iam_client.update_assume_role_policy(
            RoleName=role_name,
            PolicyDocument=json.dumps(malicious_policy)
        )
        
        logger.warning("Wildcard principal injection attempted")
        return True
    
    except ClientError as e:
        logger.error(f"Attack failed: {e}")
        return False

def hypothesis_verification(stack_name=None):
    """
    Verify that the wildcard principal injection was prevented
    """
    if not stack_name:
        logger.error("No stack name provided for verification")
        return False
    
    try:
        iam_client = boto3.client('iam')
        cfn_client = boto3.client('cloudformation')
        
        # Get the role details
        stack_resources = cfn_client.describe_stack_resources(StackName=stack_name)
        role_resource = next(
            (res for res in stack_resources['StackResources'] 
             if res['ResourceType'] == 'AWS::IAM::Role'), 
            None
        )
        
        if not role_resource:
            logger.error("Could not find IAM role for verification")
            return False
        
        # Get the current trust policy
        role_name = role_resource['PhysicalResourceId']
        current_policy = iam_client.get_role(RoleName=role_name)['Role']['AssumeRolePolicyDocument']
        
        # Check if any statement allows wildcard principal
        for statement in current_policy.get('Statement', []):
            if statement.get('Principal') == '*' and statement.get('Effect') == 'Allow':
                logger.error("Wildcard principal detected - SECURITY CONTROL FAILED")
                return False
        
        logger.info("Hypothesis verified: Wildcard principal injection prevented")
        return True
    
    except ClientError as e:
        logger.error(f"Verification error: {e}")
        return False

def rollback(stack_name=None):
    """
    Clean up resources created during the experiment
    """
    if not stack_name:
        logger.warning("No stack name provided for rollback")
        return
    
    try:
        cfn_client = boto3.client('cloudformation')
        
        # Delete the CloudFormation stack
        cfn_client.delete_stack(StackName=stack_name)
        
        # Wait for stack deletion
        waiter = cfn_client.get_waiter('stack_delete_complete')
        waiter.wait(StackName=stack_name)
        
        logger.info(f"Stack {stack_name} deleted successfully")
    
    except ClientError as e:
        logger.error(f"Rollback error: {e}")