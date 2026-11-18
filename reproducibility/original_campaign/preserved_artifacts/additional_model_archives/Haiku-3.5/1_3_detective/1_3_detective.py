import os
import sys
import json
import time
import logging
import subprocess
from typing import Dict, Any, List, Optional

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
        logging.FileHandler('sce_experiment_detective.log')
    ]
)
logger = logging.getLogger(__name__)

# Global configuration
REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
TIMESTAMP = str(int(time.time()))
STACK_NAME = f"sce-experiment-imds-detective-{TIMESTAMP}"
MAX_RETRIES = 3
RETRY_DELAY = 5

def get_latest_amazon_linux_ami() -> str:
    """
    Retrieve the latest Amazon Linux 2 AMI with comprehensive fallback strategies
    """
    try:
        ec2_client = boto3.client('ec2', region_name=REGION)
        
        # Hardcoded recent AMI IDs for different regions
        fallback_amis = {
            'us-east-1': 'ami-0cff7528ff583bf9a',    # Amazon Linux 2
            'us-east-2': 'ami-02d1e544b84bf7502',
            'us-west-1': 'ami-0f8e81a3da6e2510a',
            'us-west-2': 'ami-0df24e148fdb9f1d8',
            'eu-west-1': 'ami-04d5cc9b88example'
        }
        
        # First, try dynamic AMI discovery
        ami_patterns = [
            'amzn2-ami-hvm-*-x86_64-gp2',
            'amzn2-ami-hvm-*-x86_64-general',
            'amzn2-ami-minimal-hvm-*-x86_64-gp2'
        ]

        for pattern in ami_patterns:
            try:
                response = ec2_client.describe_images(
                    Owners=['amazon'],
                    Filters=[
                        {'Name': 'name', 'Values': [pattern]},
                        {'Name': 'state', 'Values': ['available']}
                    ]
                )

                if response['Images']:
                    # Sort images by creation date and select the most recent
                    sorted_images = sorted(
                        response['Images'], 
                        key=lambda x: x.get('CreationDate', ''), 
                        reverse=True
                    )
                    
                    latest_ami = sorted_images[0]['ImageId']
                    logger.info(f"Found AMI using pattern {pattern}: {latest_ami}")
                    return latest_ami
            
            except Exception as e:
                logger.warning(f"Failed to find AMI with pattern {pattern}: {e}")
        
        # Fallback to region-specific hardcoded AMI
        if REGION in fallback_amis:
            logger.warning(f"Using fallback AMI for {REGION}")
            return fallback_amis[REGION]
        
        # Final fallback to a known working AMI
        logger.error("Could not find a suitable Amazon Linux 2 AMI. Using a generic fallback.")
        return 'ami-0cff7528ff583bf9a'  # US East (N. Virginia) default
    
    except Exception as e:
        logger.error(f"Comprehensive AMI retrieval failed: {e}")
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
    Prepare a secure EC2 environment with CloudTrail logging
    """
    try:
        # Initialize AWS clients
        cfn_client = boto3.client('cloudformation', region_name=REGION)
        cloudtrail_client = boto3.client('cloudtrail', region_name=REGION)
        sts_client = boto3.client('sts')
        
        # Get account ID
        account_id = sts_client.get_caller_identity()['Account']
        
        # Dynamically get latest Amazon Linux 2 AMI
        latest_ami = get_latest_amazon_linux_ami()

        # Create unique resource names
        trail_name = f"sce-imds-detective-trail-{TIMESTAMP}"
        s3_bucket_name = f"sce-imds-detective-logs-{TIMESTAMP}"
        log_group_name = f"/aws/cloudtrail/{trail_name}"
        
        # CloudFormation template with enhanced logging and security
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "SCE IMDS Detection Experiment",
            "Resources": {
                "LogBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": s3_bucket_name,
                        "VersioningConfiguration": {
                            "Status": "Enabled"
                        }
                    }
                },
                "CloudTrailLogGroup": {
                    "Type": "AWS::Logs::LogGroup",
                    "Properties": {
                        "LogGroupName": log_group_name,
                        "RetentionInDays": 30
                    }
                },
                "ExperimentSecurityGroup": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "Security group for IMDS detection experiment",
                        "SecurityGroupIngress": []
                    }
                },
                "ExperimentInstance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": latest_ami,
                        "InstanceType": "t2.micro",
                        "SecurityGroupIds": [{"Ref": "ExperimentSecurityGroup"}],
                        "MetadataOptions": {
                            "HttpTokens": "required",
                            "HttpEndpoint": "enabled",
                            "HttpPutResponseHopLimit": 1
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
            Capabilities=['CAPABILITY_IAM']
        )

        # Wait for stack creation
        waiter = cfn_client.get_waiter('stack_create_complete')
        waiter.wait(
            StackName=STACK_NAME,
            WaiterConfig={'Delay': 30, 'MaxAttempts': 40}
        )

        # Retrieve log group ARN
        log_group_arn = f"arn:aws:logs:{REGION}:{account_id}:log-group:{log_group_name}:*"

        # Create CloudTrail trail
        cloudtrail_client.create_trail(
            Name=trail_name,
            S3BucketName=s3_bucket_name,
            IsMultiRegionTrail=True,
            EnableLogFileValidation=True,
            CloudWatchLogsLogGroupArn=log_group_arn
        )
        
        # Start logging
        cloudtrail_client.start_logging(Name=trail_name)

        logger.info(f"Stack {STACK_NAME} and CloudTrail trail {trail_name} created successfully")
        return True

    except Exception as e:
        logger.error(f"Error in steady_state: {e}")
        return False

# Rest of the implementation remains the same as in previous versions
# (attack(), hypothesis_verification(), and rollback() functions)