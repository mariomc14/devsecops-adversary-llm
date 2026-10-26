import boto3
import json
import logging
import time
import sys
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Global variables to track experiment resources
STACK_NAME = f"sce-experiment-imds-{int(time.time())}"
REGION = "us-east-1"

def steady_state():
    """
    Prepare AWS resources for the IMDS configuration experiment
    """
    try:
        # Create CloudFormation client
        cfn_client = boto3.client('cloudformation')
        ec2_client = boto3.client('ec2')
        
        # Define CloudFormation template
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "SCE Experiment for IMDS Configuration",
            "Resources": {
                "ExperimentVPC": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {
                        "CidrBlock": "10.0.0.0/16",
                        "EnableDnsHostnames": True,
                        "Tags": [{"Key": "Name", "Value": f"{STACK_NAME}-vpc"}]
                    }
                },
                "ExperimentSubnet": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "ExperimentVPC"},
                        "CidrBlock": "10.0.1.0/24",
                        "AvailabilityZone": f"{REGION}a"
                    }
                },
                "ExperimentSecurityGroup": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "Security group for SCE IMDS experiment",
                        "VpcId": {"Ref": "ExperimentVPC"}
                    }
                },
                "ExperimentInstance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": "ami-0c55b159cbfafe1f0",  # Amazon Linux 2
                        "InstanceType": "t2.micro",
                        "SubnetId": {"Ref": "ExperimentSubnet"},
                        "SecurityGroupIds": [{"Ref": "ExperimentSecurityGroup"}],
                        "MetadataOptions": {
                            "HttpTokens": "required",
                            "HttpEndpoint": "enabled"
                        }
                    }
                }
            }
        }
        
        # Create CloudFormation stack
        cfn_client.create_stack(
            StackName=STACK_NAME,
            TemplateBody=json.dumps(template),
            Capabilities=['CAPABILITY_IAM']
        )
        
        # Wait for stack creation
        waiter = cfn_client.get_waiter('stack_create_complete')
        waiter.wait(StackName=STACK_NAME)
        
        logger.info(f"Successfully created experiment stack: {STACK_NAME}")
        return True
    
    except Exception as e:
        logger.error(f"Error in steady_state: {e}")
        return False

def attack():
    """
    Simulate attack by attempting to modify IMDS configuration
    """
    try:
        ec2_client = boto3.client('ec2')
        
        # Describe instances in the stack
        response = ec2_client.describe_instances(
            Filters=[
                {'Name': 'tag:aws:cloudformation:stack-name', 'Values': [STACK_NAME]}
            ]
        )
        
        if not response['Reservations']:
            logger.error("No instances found in the experiment stack")
            return False
        
        instance_id = response['Reservations'][0]['Instances'][0]['InstanceId']
        
        # Attempt to modify IMDS configuration to weaken protection
        ec2_client.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='optional',
            HttpEndpoint='enabled'
        )
        
        logger.info(f"Successfully modified IMDS configuration for instance {instance_id}")
        return True
    
    except Exception as e:
        logger.error(f"Error in attack: {e}")
        return False

def hypothesis_verification():
    """
    Verify reactive controls after potential IMDS configuration modification
    """
    try:
        # Long-running verification (30-minute window)
        start_time = time.monotonic()
        max_wait = 1800  # 30 minutes
        
        cloudtrail_client = boto3.client('cloudtrail')
        
        while time.monotonic() - start_time < max_wait:
            # Look for CloudTrail events indicating IMDS configuration change
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'ModifyInstanceMetadataOptions'
                    }
                ],
                MaxResults=10
            )
            
            # Check if any events match our experiment
            for event in response.get('Events', []):
                event_data = json.loads(event['CloudTrailEvent'])
                if STACK_NAME in str(event_data):
                    logger.info("Detected IMDS configuration change event")
                    return True
            
            time.sleep(60)  # Check every minute
        
        logger.error("No IMDS configuration change event detected")
        return False
    
    except Exception as e:
        logger.error(f"Error in hypothesis_verification: {e}")
        return False

def rollback():
    """
    Clean up resources created during the experiment
    """
    try:
        cfn_client = boto3.client('cloudformation')
        
        # Delete the CloudFormation stack
        cfn_client.delete_stack(StackName=STACK_NAME)
        
        # Wait for stack deletion
        waiter = cfn_client.get_waiter('stack_delete_complete')
        waiter.wait(StackName=STACK_NAME)
        
        logger.info(f"Successfully deleted experiment stack: {STACK_NAME}")
        return True
    
    except cfn_client.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'ValidationError':
            logger.warning(f"Stack {STACK_NAME} already deleted or does not exist")
        else:
            logger.error(f"Error in rollback: {e}")
        return True
    except Exception as e:
        logger.error(f"Unexpected error in rollback: {e}")
        return False

# Optional: Allow direct script execution for testing
if __name__ == "__main__":
    try:
        steady_state()
        attack()
        hypothesis_verification()
    finally:
        rollback()