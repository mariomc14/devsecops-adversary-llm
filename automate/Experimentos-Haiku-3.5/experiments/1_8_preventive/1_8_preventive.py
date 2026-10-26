import boto3
import json
import logging
import time
import sys
import subprocess
import os
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Ensure boto3 is available
try:
    import boto3
except ImportError:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'boto3'])
    import boto3

def generate_unique_suffix():
    """Generate a unique timestamp suffix for resources."""
    return str(int(time.time()))

def create_cloudformation_client():
    """Create a CloudFormation client with error handling."""
    try:
        return boto3.client('cloudformation')
    except Exception as e:
        logger.error(f"Failed to create CloudFormation client: {e}")
        raise

def create_ec2_client():
    """Create an EC2 client with error handling."""
    try:
        return boto3.client('ec2')
    except Exception as e:
        logger.error(f"Failed to create EC2 client: {e}")
        raise

def steady_state():
    """
    Prepare AWS resources for IMDS Protection Bypass experiment.
    Creates a CloudFormation stack with a secure EC2 instance.
    """
    try:
        # Initialize AWS clients
        cfn_client = create_cloudformation_client()
        ec2_client = create_ec2_client()

        # Generate unique stack name
        suffix = generate_unique_suffix()
        stack_name = f'sce-imds-experiment-{suffix}'

        # Find latest Amazon Linux 2 AMI
        response = ec2_client.describe_images(
            Owners=['amazon'],
            Filters=[
                {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                {'Name': 'state', 'Values': ['available']}
            ]
        )
        latest_ami = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']

        # CloudFormation template for secure EC2 instance
        cfn_template = {
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
                "IMDSExperimentInstance": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": latest_ami,
                        "InstanceType": "t2.micro",
                        "SecurityGroupIds": [{"Ref": "ExperimentSecurityGroup"}],
                        "MetadataOptions": {
                            "HttpEndpoint": "enabled",
                            "HttpTokens": "required",
                            "InstanceMetadataTags": "enabled"
                        },
                        "Tags": [
                            {"Key": "SCEExperiment", "Value": stack_name},
                            {"Key": "Timestamp", "Value": suffix}
                        ]
                    }
                }
            },
            "Outputs": {
                "InstanceId": {
                    "Description": "Experiment EC2 Instance ID",
                    "Value": {"Ref": "IMDSExperimentInstance"}
                }
            }
        }

        # Create CloudFormation stack with extended timeout
        stack_response = cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(cfn_template),
            Capabilities=['CAPABILITY_IAM'],
            TimeoutInMinutes=30
        )

        # Wait for stack creation with extended timeout and detailed error handling
        waiter = cfn_client.get_waiter('stack_create_complete')
        try:
            waiter.wait(
                StackName=stack_name, 
                WaiterConfig={'Delay': 30, 'MaxAttempts': 40}
            )
        except Exception as wait_error:
            # Get detailed stack events to understand failure
            events = cfn_client.describe_stack_events(StackName=stack_name)
            for event in events['StackEvents']:
                if event['ResourceStatus'] == 'CREATE_FAILED':
                    logger.error(f"Stack creation failed: {event['ResourceStatusReason']}")
            raise

        # Store stack name in environment for other functions
        os.environ['SCE_STACK_NAME'] = stack_name
        logger.info(f"Successfully created stack {stack_name}")
        return True

    except Exception as e:
        logger.error(f"Error in steady_state: {e}")
        logger.error(traceback.format_exc())
        return False

def attack():
    """
    Simulate IMDS configuration bypass attack.
    Modify instance metadata service settings to weaken protection.
    """
    try:
        # Get stack name and retrieve instance
        stack_name = os.environ.get('SCE_STACK_NAME')
        if not stack_name:
            raise ValueError("No stack found")

        # AWS clients
        cfn_client = create_cloudformation_client()
        ec2_client = create_ec2_client()

        # Get instance ID from CloudFormation outputs
        response = cfn_client.describe_stacks(StackName=stack_name)
        instance_id = [output['OutputValue'] for output in response['Stacks'][0]['Outputs'] 
                       if output['OutputKey'] == 'InstanceId'][0]

        # Modify IMDS settings to simulate attack
        ec2_client.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='optional',  # Weaken token requirement
            HttpEndpoint='enabled',
            HttpPutResponseHopLimit=2  # Increase hop limit
        )

        logger.info(f"Successfully modified IMDS settings for instance {instance_id}")
        return True

    except Exception as e:
        logger.error(f"Error in attack: {e}")
        logger.error(traceback.format_exc())
        return False

def hypothesis_verification():
    """
    Verify that the IMDS configuration remains secure after attack attempt.
    Uses a 30-minute polling window to account for AWS eventual consistency.
    """
    try:
        # Get stack name and retrieve instance
        stack_name = os.environ.get('SCE_STACK_NAME')
        if not stack_name:
            raise ValueError("No stack found")

        # AWS clients
        cfn_client = create_cloudformation_client()
        ec2_client = create_ec2_client()

        # Get instance ID from CloudFormation outputs
        response = cfn_client.describe_stacks(StackName=stack_name)
        instance_id = [output['OutputValue'] for output in response['Stacks'][0]['Outputs'] 
                       if output['OutputKey'] == 'InstanceId'][0]

        # Start timing verification
        start_time = time.monotonic()
        max_wait_time = 1800  # 30 minutes

        while time.monotonic() - start_time < max_wait_time:
            try:
                # Retrieve current IMDS settings
                instance_details = ec2_client.describe_instances(InstanceIds=[instance_id])
                metadata_options = instance_details['Reservations'][0]['Instances'][0]['MetadataOptions']

                # Log current settings for debugging
                logger.info(f"Current IMDS Settings: {json.dumps(metadata_options, indent=2)}")

                # Check if settings remain secure
                if (metadata_options['HttpTokens'] == 'required' and 
                    metadata_options['HttpEndpoint'] == 'enabled' and
                    metadata_options.get('HttpPutResponseHopLimit', 1) == 1):
                    logger.info("IMDS settings remain secure")
                    return True

            except Exception as check_error:
                logger.warning(f"Error during verification check: {check_error}")

            time.sleep(30)  # Check every 30 seconds

        logger.error("Failed to verify IMDS security within 30 minutes")
        return False

    except Exception as e:
        logger.error(f"Error in hypothesis_verification: {e}")
        logger.error(traceback.format_exc())
        return False

def rollback():
    """
    Clean up resources created during the experiment.
    """
    try:
        # Get stack name
        stack_name = os.environ.get('SCE_STACK_NAME')
        if not stack_name:
            logger.warning("No stack name found for rollback")
            return True

        # AWS clients
        cfn_client = create_cloudformation_client()

        # Delete CloudFormation stack
        cfn_client.delete_stack(StackName=stack_name)

        # Wait for stack deletion with error handling
        try:
            waiter = cfn_client.get_waiter('stack_delete_complete')
            waiter.wait(
                StackName=stack_name, 
                WaiterConfig={'Delay': 30, 'MaxAttempts': 40}
            )
        except Exception as wait_error:
            # Get detailed stack events
            events = cfn_client.describe_stack_events(StackName=stack_name)
            for event in events['StackEvents']:
                if event['ResourceStatus'] == 'DELETE_FAILED':
                    logger.error(f"Stack deletion failed: {event['ResourceStatusReason']}")
            raise

        logger.info(f"Successfully deleted stack {stack_name}")
        return True

    except cfn_client.exceptions.StackNotFoundException:
        logger.warning(f"Stack {stack_name} already deleted")
        return True
    except Exception as e:
        logger.error(f"Error in rollback: {e}")
        logger.error(traceback.format_exc())
        return False