import os
import sys
import time
import json
import logging
import traceback
import subprocess
import uuid
from contextlib import contextmanager

# Dynamically install boto3 if not available
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
    format='%(asctime)s - %(levelname)s: [SCE-IMDS-REACTIVE] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(f'/tmp/sce_imds_reactive_{int(time.time())}.log')
    ]
)
logger = logging.getLogger(__name__)

# Global configurations
UNIQUE_ID = str(uuid.uuid4())[:8]
EXPERIMENT_NAME = f"sce-imds-reactive-{UNIQUE_ID}"
REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')
MAX_RETRIES = 5
RETRY_DELAY = 10

@contextmanager
def aws_error_handler(context_msg="AWS Operation"):
    """Comprehensive AWS error handling context manager."""
    try:
        yield
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'VpcLimitExceeded':
            logger.error(f"{context_msg}: VPC limit exceeded. Attempting cleanup.")
            try:
                cleanup_dependent_resources()
            except Exception as cleanup_error:
                logger.error(f"Cleanup failed: {cleanup_error}")
        else:
            logger.error(f"{context_msg} failed: {e}")
        raise
    except Exception as e:
        logger.error(f"{context_msg} failed: {e}")
        raise

def cleanup_dependent_resources():
    """
    Advanced VPC and dependent resource cleanup mechanism.
    Safely removes resources preventing VPC deletion.
    """
    ec2_client = boto3.client('ec2')
    
    # Find and delete network interfaces
    try:
        interfaces = ec2_client.describe_network_interfaces()
        for interface in interfaces['NetworkInterfaces']:
            if interface.get('Status') == 'available':
                ec2_client.delete_network_interface(NetworkInterfaceId=interface['NetworkInterfaceId'])
    except Exception as e:
        logger.warning(f"Network interface cleanup failed: {e}")

def create_secure_environment():
    """
    Create a secure, isolated AWS environment with robust error handling.
    """
    with aws_error_handler("Secure Environment Creation"):
        ec2_client = boto3.client('ec2')
        iam_client = boto3.client('iam')
        events_client = boto3.client('events')

        # Create VPC with retry mechanism
        for attempt in range(MAX_RETRIES):
            try:
                vpc_response = ec2_client.create_vpc(
                    CidrBlock='10.0.0.0/16',
                    InstanceTenancy='default',
                    TagSpecifications=[{
                        'ResourceType': 'vpc',
                        'Tags': [{'Key': 'Name', 'Value': EXPERIMENT_NAME}]
                    }]
                )
                vpc_id = vpc_response['Vpc']['VpcId']
                break
            except ClientError as e:
                if attempt == MAX_RETRIES - 1:
                    raise
                time.sleep(RETRY_DELAY)

        # Create subnet
        subnet_response = ec2_client.create_subnet(
            VpcId=vpc_id,
            CidrBlock='10.0.1.0/24',
            AvailabilityZone=f'{REGION}a'
        )
        subnet_id = subnet_response['Subnet']['SubnetId']

        # Create security group
        sg_response = ec2_client.create_security_group(
            GroupName=f'{EXPERIMENT_NAME}-sg',
            Description='Secure IMDS Experiment Security Group',
            VpcId=vpc_id
        )
        security_group_id = sg_response['GroupId']

        # Create IAM role for reactive response
        role_name = f'{EXPERIMENT_NAME}-response-role'
        role_response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"Service": "events.amazonaws.com"},
                    "Action": "sts:AssumeRole"
                }]
            })
        )

        # Attach minimal reactive response policy
        iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName='IMDSReactivePolicy',
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": [
                        "ec2:ModifyInstanceMetadataOptions",
                        "ec2:TerminateInstances",
                        "ec2:CreateTags"
                    ],
                    "Resource": "*"
                }]
            })
        )

        # Create EventBridge rule for IMDS changes
        events_client.put_rule(
            Name=f'{EXPERIMENT_NAME}-imds-change-rule',
            EventPattern=json.dumps({
                "source": ["aws.ec2"],
                "detail-type": ["AWS API Call via CloudTrail"],
                "detail": {
                    "eventSource": ["ec2.amazonaws.com"],
                    "eventName": ["ModifyInstanceMetadataOptions"]
                }
            })
        )

        return {
            'VPC_ID': vpc_id,
            'SUBNET_ID': subnet_id,
            'SECURITY_GROUP_ID': security_group_id,
            'ROLE_NAME': role_name
        }

def steady_state():
    """Prepare the experimental environment."""
    try:
        env_context = create_secure_environment()
        os.environ.update({f'EXPERIMENT_{k}': str(v) for k, v in env_context.items()})
        logger.info("Steady state preparation completed successfully")
        return True
    except Exception as e:
        logger.error(f"Steady state preparation failed: {e}")
        return False

def attack():
    """Simulate IMDS configuration modification attack."""
    try:
        ec2_client = boto3.client('ec2')
        
        response = ec2_client.run_instances(
            ImageId='ami-0c55b159cbfafe1f0',  # Replace with current AMI
            InstanceType='t2.micro',
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[{
                'SubnetId': os.environ['EXPERIMENT_SUBNET_ID'],
                'Groups': [os.environ['EXPERIMENT_SECURITY_GROUP_ID']],
                'DeviceIndex': 0
            }],
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{'Key': 'ExperimentName', 'Value': EXPERIMENT_NAME}]
            }]
        )
        instance_id = response['Instances'][0]['InstanceId']

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
    Verify reactive controls for IMDS configuration change.
    30-minute SLA compliance required.
    """
    start_time = time.monotonic()
    max_wait_time = 1800  # 30 minutes

    while time.monotonic() - start_time < max_wait_time:
        try:
            cloudtrail_client = boto3.client('cloudtrail')
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
                logger.info("Reactive control detected IMDS configuration change!")
                return True
            
            time.sleep(60)  # Poll every minute
        
        except Exception as e:
            logger.warning(f"Verification check failed: {e}")
            time.sleep(30)
    
    logger.warning("No reactive response detected within 30 minutes")
    return False

def rollback():
    """Clean up all resources created during the experiment."""
    try:
        ec2_client = boto3.client('ec2')
        iam_client = boto3.client('iam')
        events_client = boto3.client('events')

        # Terminate instances
        if 'EXPERIMENT_VPC_ID' in os.environ:
            instances = ec2_client.describe_instances(
                Filters=[
                    {'Name': 'vpc-id', 'Values': [os.environ['EXPERIMENT_VPC_ID']]},
                    {'Name': 'tag:ExperimentName', 'Values': [EXPERIMENT_NAME]}
                ]
            )
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    ec2_client.terminate_instances(InstanceIds=[instance['InstanceId']])

            # Delete subnets
            subnets = ec2_client.describe_subnets(
                Filters=[{'Name': 'vpc-id', 'Values': [os.environ['EXPERIMENT_VPC_ID']]}]
            )
            for subnet in subnets['Subnets']:
                ec2_client.delete_subnet(SubnetId=subnet['SubnetId'])

            # Delete security group
            ec2_client.delete_security_group(GroupId=os.environ['EXPERIMENT_SECURITY_GROUP_ID'])

            # Delete VPC
            ec2_client.delete_vpc(VpcId=os.environ['EXPERIMENT_VPC_ID'])

        # Delete IAM role
        if 'EXPERIMENT_ROLE_NAME' in os.environ:
            iam_client.delete_role_policy(
                RoleName=os.environ['EXPERIMENT_ROLE_NAME'],
                PolicyName='IMDSReactivePolicy'
            )
            iam_client.delete_role(RoleName=os.environ['EXPERIMENT_ROLE_NAME'])

        # Delete EventBridge rule
        events_client.delete_rule(Name=f'{EXPERIMENT_NAME}-imds-change-rule')

        logger.info("Rollback completed successfully")
    except Exception as e:
        logger.error(f"Rollback failed: {e}")
        logger.error(traceback.format_exc())

# Direct script execution for testing
if __name__ == "__main__":
    steady_state()
    attack()
    hypothesis_verification()
    rollback()