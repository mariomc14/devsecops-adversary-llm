import boto3
import json
import logging
import time
import uuid
from botocore.exceptions import ClientError, WaiterError

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def steady_state():
    """
    Provision resources for the security chaos experiment
    """
    try:
        # Create unique stack name with timestamp
        stack_name = f"sce-experiment-{int(time.time())}"
        
        # Initialize CloudFormation client
        cfn_client = boto3.client('cloudformation')
        
        # Define CloudFormation template
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "SCE Experiment Security Group Setup",
            "Resources": {
                "ExperimentSecurityGroup": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "Security group for SCE experiment",
                        "GroupName": f"sce-experiment-{uuid.uuid4()}",
                        "Tags": [
                            {
                                "Key": "ExperimentName",
                                "Value": "1.8-SCE-Experiment"
                            }
                        ]
                    }
                }
            },
            "Outputs": {
                "SecurityGroupId": {
                    "Description": "ID of the created security group",
                    "Value": {"Fn::GetAtt": ["ExperimentSecurityGroup", "GroupId"]},
                    "Export": {"Name": f"{stack_name}-SecurityGroupId"}
                }
            }
        }
        
        # Create CloudFormation stack
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
            'region': cfn_client.meta.region_name
        }
    
    except ClientError as e:
        logger.error(f"Error in steady_state: {e}")
        raise

def attack(context=None):
    """
    Simulate unauthorized security group modification
    """
    try:
        if not context or 'stack_name' not in context:
            raise ValueError("Missing context for attack")
        
        ec2_client = boto3.client('ec2')
        
        # Get the security group ID from the stack
        cfn_client = boto3.client('cloudformation')
        response = cfn_client.describe_stacks(StackName=context['stack_name'])
        security_group_id = [output for output in response['Stacks'][0]['Outputs'] 
                             if output['ExportName'] == f"{context['stack_name']}-SecurityGroupId"][0]['OutputValue']
        
        # Simulate unauthorized ingress rule addition
        ec2_client.authorize_security_group_ingress(
            GroupId=security_group_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }
            ]
        )
        
        logger.warning("Unauthorized security group modification successful")
        return True
    
    except ClientError as e:
        logger.error(f"Attack error: {e}")
        return False

def hypothesis_verification(context=None):
    """
    Detect unauthorized security group modifications
    """
    try:
        if not context or 'stack_name' not in context:
            raise ValueError("Missing context for verification")
        
        # Use AWS Config to detect changes
        config_client = boto3.client('config')
        
        # Check for recent security group configuration changes
        response = config_client.describe_configuration_items(
            configurationItemStatus='OK',
            resourceType='AWS::EC2::SecurityGroup'
        )
        
        # Look for recent unauthorized changes
        for item in response.get('configurationItems', []):
            if 'configuration' in item:
                # Check for suspicious ingress rules
                if any(rule.get('fromPort') == 22 and rule.get('cidrIp') == '0.0.0.0/0' 
                       for rule in item['configuration'].get('ipPermissions', [])):
                    logger.warning("Unauthorized security group modification detected!")
                    return False
        
        logger.info("No unauthorized modifications detected")
        return True
    
    except ClientError as e:
        logger.error(f"Verification error: {e}")
        return False

def rollback(context=None):
    """
    Clean up resources created during the experiment
    """
    try:
        if not context or 'stack_name' not in context:
            logger.warning("No context provided for rollback")
            return
        
        cfn_client = boto3.client('cloudformation')
        
        # Delete the CloudFormation stack
        cfn_client.delete_stack(StackName=context['stack_name'])
        
        # Wait for stack deletion
        waiter = cfn_client.get_waiter('stack_delete_complete')
        waiter.wait(StackName=context['stack_name'])
        
        logger.info(f"Stack {context['stack_name']} deleted successfully")
    
    except ClientError as e:
        logger.error(f"Rollback error: {e}")