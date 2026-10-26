import os
import time
import json
import logging
import boto3
from botocore.exceptions import ClientError, WaiterError

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Global configuration
TIMESTAMP = int(time.time())
STACK_NAME = f"sce-imds-detective-{TIMESTAMP}"
REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
MAX_RETRIES = 3
RETRY_DELAY = 5

def create_unique_name(base_name):
    """Generate a unique name with timestamp."""
    return f"{base_name}-{TIMESTAMP}"

def retry_with_backoff(func, *args, **kwargs):
    """Implement retry mechanism with exponential backoff."""
    for attempt in range(MAX_RETRIES):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.warning(f"Attempt {attempt + 1} failed: {e}")
            if attempt == MAX_RETRIES - 1:
                raise
            time.sleep(RETRY_DELAY * (2 ** attempt))

def steady_state():
    """
    Prepare AWS resources for IMDS detective experiment.
    Provisions EC2 instances and CloudTrail for monitoring.
    """
    try:
        cfn_client = boto3.client('cloudformation')
        ec2_client = boto3.client('ec2')
        s3_client = boto3.client('s3')
        cloudtrail_client = boto3.client('cloudtrail')

        # Create unique S3 bucket for CloudTrail logs
        bucket_name = create_unique_name("sce-imds-logs")
        s3_client.create_bucket(Bucket=bucket_name)

        # CloudFormation template with test resources
        cfn_template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "TestVPC": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {
                        "CidrBlock": "10.0.0.0/16",
                        "EnableDnsHostnames": True,
                        "Tags": [{"Key": "Name", "Value": f"{STACK_NAME}-vpc"}]
                    }
                },
                "TestInstance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": "ami-0c55b159cbfafe1f0",  # Replace with valid AMI
                        "InstanceType": "t2.micro",
                        "Tags": [
                            {"Key": "Name", "Value": f"{STACK_NAME}-instance"},
                            {"Key": "ExperimentName", "Value": STACK_NAME}
                        ]
                    }
                }
            }
        }

        # Create CloudFormation stack
        cfn_client.create_stack(
            StackName=STACK_NAME,
            TemplateBody=json.dumps(cfn_template),
            Capabilities=['CAPABILITY_IAM']
        )

        # Wait for stack creation
        waiter = cfn_client.get_waiter('stack_create_complete')
        waiter.wait(StackName=STACK_NAME)

        # Create CloudTrail
        trail_name = create_unique_name(f"{STACK_NAME}-trail")
        cloudtrail_client.create_trail(
            Name=trail_name,
            S3BucketName=bucket_name,
            IsMultiRegionTrail=True,
            IncludeGlobalServiceEvents=True
        )
        cloudtrail_client.start_logging(Name=trail_name)

        return True
    except Exception as e:
        logger.error(f"Steady state preparation failed: {e}")
        return False

def attack():
    """
    Simulate IMDS configuration modification attack.
    Modifies instance metadata service settings.
    """
    try:
        ec2_client = boto3.client('ec2')
        
        # Find the instance created in steady_state
        response = ec2_client.describe_instances(
            Filters=[{'Name': 'tag:ExperimentName', 'Values': [STACK_NAME]}]
        )
        
        if not response['Reservations']:
            logger.error("No instances found matching experiment tag")
            return False

        instance_id = response['Reservations'][0]['Instances'][0]['InstanceId']

        # Modify IMDS configuration
        ec2_client.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='optional',
            HttpEndpoint='enabled'
        )
        
        return True
    except Exception as e:
        logger.error(f"Attack simulation failed: {e}")
        return False

def hypothesis_verification():
    """
    Verify IMDS configuration change detection.
    Uses CloudTrail to detect modification events.
    """
    try:
        cloudtrail_client = boto3.client('cloudtrail')
        start_time = time.monotonic()
        
        while time.monotonic() - start_time < 1800:  # 30-minute window
            events = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'ModifyInstanceMetadataOptions'
                    }
                ],
                MaxResults=10
            )
            
            if events.get('Events'):
                logger.info("IMDS configuration change detected!")
                return True
            
            time.sleep(60)  # Poll every minute
        
        logger.warning("No IMDS configuration change detected within 30 minutes")
        return False
    except Exception as e:
        logger.error(f"Hypothesis verification failed: {e}")
        return False

def rollback():
    """
    Clean up all resources created during the experiment.
    """
    try:
        cfn_client = boto3.client('cloudformation')
        s3_client = boto3.client('s3')
        cloudtrail_client = boto3.client('cloudtrail')

        # Delete CloudTrail
        trail_name = create_unique_name(f"{STACK_NAME}-trail")
        try:
            cloudtrail_client.delete_trail(Name=trail_name)
        except ClientError as e:
            logger.warning(f"CloudTrail deletion failed: {e}")

        # Delete S3 bucket
        bucket_name = create_unique_name("sce-imds-logs")
        try:
            s3_client.delete_bucket(Bucket=bucket_name)
        except ClientError as e:
            logger.warning(f"S3 bucket deletion failed: {e}")

        # Delete CloudFormation stack
        cfn_client.delete_stack(StackName=STACK_NAME)
        
        # Wait for stack deletion
        waiter = cfn_client.get_waiter('stack_delete_complete')
        waiter.wait(StackName=STACK_NAME)

        logger.info("Rollback completed successfully")
    except Exception as e:
        logger.error(f"Rollback failed: {e}")

# Optional: Allow direct script execution for testing
if __name__ == "__main__":
    steady_state()
    attack()
    hypothesis_verification()
    rollback()