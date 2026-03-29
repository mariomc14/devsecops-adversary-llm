import os
import sys
import json
import time
import logging
import subprocess
from typing import Dict, Any, List

# Ensure boto3 is available
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'boto3'])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Configure logging
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('sce_experiment.log')
    ]
)
logger = logging.getLogger(__name__)

# Global configuration
REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
TIMESTAMP = str(int(time.time()))
STACK_NAME = f"sce-experiment-imds-{TIMESTAMP}"
MAX_RETRIES = 3
RETRY_DELAY = 5

def get_latest_amazon_linux_ami() -> str:
    """
    Dynamically retrieve the latest Amazon Linux 2 AMI using standard parameters
    """
    try:
        ec2_client = boto3.client('ec2', region_name=REGION)
        
        # Updated search for latest Amazon Linux 2 AMI using supported parameters
        response = ec2_client.describe_images(
            Owners=['amazon'],
            Filters=[
                {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                {'Name': 'state', 'Values': ['available']}
            ],
            MaxResults=1  # Retrieve the most recent image
        )
        
        # Return the most recent AMI ID
        if response['Images']:
            latest_ami = response['Images'][0]['ImageId']
            logger.info(f"Found latest Amazon Linux 2 AMI: {latest_ami}")
            return latest_ami
        else:
            raise ValueError("No Amazon Linux 2 AMI found")
    
    except Exception as e:
        logger.error(f"Error retrieving AMI: {e}")
        raise

def retry_decorator(max_tries=MAX_RETRIES):
    """Decorator for retrying functions with exponential backoff"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            tries = 0
            while tries < max_tries:
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    tries += 1
                    if tries == max_tries:
                        logger.error(f"Function {func.__name__} failed after {max_tries} attempts")
                        raise
                    wait_time = RETRY_DELAY * (2 ** tries)
                    logger.warning(f"Attempt {tries} failed. Retrying in {wait_time} seconds: {e}")
                    time.sleep(wait_time)
        return wrapper
    return decorator

@retry_decorator()
def steady_state() -> bool:
    """
    Prepare a secure EC2 environment with strict IMDS configuration
    """
    try:
        # Initialize AWS clients
        cfn_client = boto3.client('cloudformation', region_name=REGION)
        
        # Dynamically get latest Amazon Linux 2 AMI
        latest_ami = get_latest_amazon_linux_ami()

        # CloudFormation template for secure IMDS configuration
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "SCE IMDS Protection Experiment",
            "Resources": {
                "ExperimentSecurityGroup": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "Security group for IMDS experiment",
                        "SecurityGroupIngress": []
                    }
                },
                "ExperimentInstance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": latest_ami,  # Dynamically selected AMI
                        "InstanceType": "t2.micro",
                        "SecurityGroupIds": [{"Ref": "ExperimentSecurityGroup"}],
                        "MetadataOptions": {
                            "HttpTokens": "required",  # Enforce IMDSv2
                            "HttpEndpoint": "enabled",
                            "HttpPutResponseHopLimit": 1  # Strict hop limit
                        },
                        "Tags": [
                            {"Key": "ExperimentName", "Value": STACK_NAME},
                            {"Key": "Timestamp", "Value": TIMESTAMP}
                        ]
                    }
                }
            }
        }
        
        # Create CloudFormation stack
        cfn_client.create_stack(
            StackName=STACK_NAME,
            TemplateBody=json.dumps(template),
            Capabilities=['CAPABILITY_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': 'IMDS-Protection'},
                {'Key': 'Timestamp', 'Value': TIMESTAMP}
            ]
        )

        # Wait for stack creation with enhanced error handling
        waiter = cfn_client.get_waiter('stack_create_complete')
        try:
            waiter.wait(
                StackName=STACK_NAME,
                WaiterConfig={'Delay': 30, 'MaxAttempts': 40}
            )
        except WaiterError as e:
            # Retrieve stack events to understand failure
            stack_events = cfn_client.describe_stack_events(StackName=STACK_NAME)
            failure_events = [
                event for event in stack_events['StackEvents']
                if event.get('ResourceStatus') == 'CREATE_FAILED'
            ]
            
            if failure_events:
                for event in failure_events:
                    logger.error(f"Stack creation failed: {event.get('ResourceStatusReason', 'Unknown reason')}")
            
            raise RuntimeError(f"Stack creation failed: {e}")

        logger.info(f"Stack {STACK_NAME} created successfully")
        return True

    except Exception as e:
        logger.error(f"Error in steady_state: {e}")
        return False

@retry_decorator()
def attack() -> bool:
    """
    Simulate IMDS configuration modification attack
    """
    try:
        ec2_client = boto3.client('ec2', region_name=REGION)
        cfn_client = boto3.client('cloudformation', region_name=REGION)
        
        # Retrieve instance ID from CloudFormation stack
        stack_resources = cfn_client.describe_stack_resources(StackName=STACK_NAME)
        instance_id = next(
            (resource['PhysicalResourceId'] 
             for resource in stack_resources['StackResources'] 
             if resource['ResourceType'] == 'AWS::EC2::Instance'),
            None
        )
        
        if not instance_id:
            raise ValueError("Could not find instance ID in stack resources")

        # Attempt to modify metadata options (simulating attack)
        ec2_client.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='optional',  # Weaken IMDSv2 requirement
            HttpEndpoint='enabled',
            HttpPutResponseHopLimit=2  # Increase hop limit
        )
        
        logger.info(f"Successfully simulated IMDS modification on {instance_id}")
        return True
    
    except Exception as e:
        logger.error(f"Attack simulation error: {e}")
        return False

def hypothesis_verification() -> bool:
    """
    Verify preventive controls are effective against IMDS modification
    """
    try:
        cloudtrail_client = boto3.client('cloudtrail', region_name=REGION)
        
        # Long-running verification (30-minute window)
        start_time = time.monotonic()
        max_wait = 1800  # 30 minutes
        
        while time.monotonic() - start_time < max_wait:
            # Check CloudTrail for unauthorized modification attempts
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'ModifyInstanceMetadataOptions'
                    }
                ],
                MaxResults=10
            )
            
            # Analyze CloudTrail events for suspicious modifications
            suspicious_events = [
                event for event in response.get('Events', [])
                if 'optional' in json.loads(event['CloudTrailEvent']).get('requestParameters', {}).get('httpTokens', '')
            ]
            
            if suspicious_events:
                logger.warning("Suspicious IMDS modification detected!")
                return False
            
            time.sleep(60)  # Check every minute
        
        return True
    
    except Exception as e:
        logger.error(f"Hypothesis verification error: {e}")
        return False

@retry_decorator()
def rollback() -> bool:
    """
    Clean up all resources created during the experiment
    """
    try:
        cfn_client = boto3.client('cloudformation', region_name=REGION)
        
        # Delete CloudFormation stack
        cfn_client.delete_stack(StackName=STACK_NAME)
        
        # Wait for stack deletion
        waiter = cfn_client.get_waiter('stack_delete_complete')
        waiter.wait(
            StackName=STACK_NAME,
            WaiterConfig={'Delay': 30, 'MaxAttempts': 40}
        )
        
        logger.info(f"Stack {STACK_NAME} deleted successfully")
        return True
    
    except cfn_client.exceptions.ValidationError:
        logger.warning(f"Stack {STACK_NAME} already deleted or does not exist")
        return True
    except Exception as e:
        logger.error(f"Rollback error: {e}")
        return False