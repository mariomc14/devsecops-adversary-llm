#!/usr/bin/env python3
"""
Security Chaos Engineering Experiment: SCE 1.5 Preventive Probe
Validates that IAM policy denies ec2:DescribeInstances for unauthorized principals.

This experiment:
1. Creates a CloudFormation stack with a denied IAM role and EC2 instance
2. Executes the attack (attempts DescribeInstances with denied role)
3. Verifies the control (confirms 403 AccessDenied response)
4. Cleans up via CloudFormation stack deletion

No external configuration files or CLI arguments required.
AWS credentials sourced automatically from standard credential chain (~/.aws/credentials).
"""

import json
import time
import logging
import subprocess
import sys
from typing import Tuple, Dict, Any
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state for experiment
EXPERIMENT_STATE = {
    'stack_name': None,
    'denied_role_arn': None,
    'instance_id': None,
    'region': 'us-east-1',
    'cf_client': None,
    'ec2_client': None,
    'sts_client': None,
    'iam_client': None,
}


def install_boto3():
    """Install boto3 if not already available."""
    try:
        import boto3
        logger.info("boto3 already installed")
        return boto3
    except ImportError:
        logger.info("Installing boto3...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
        import boto3
        return boto3


def initialize_aws_clients():
    """Initialize AWS clients for CloudFormation, EC2, IAM, and STS."""
    try:
        boto3 = install_boto3()
        EXPERIMENT_STATE['cf_client'] = boto3.client('cloudformation', region_name=EXPERIMENT_STATE['region'])
        EXPERIMENT_STATE['ec2_client'] = boto3.client('ec2', region_name=EXPERIMENT_STATE['region'])
        EXPERIMENT_STATE['sts_client'] = boto3.client('sts', region_name=EXPERIMENT_STATE['region'])
        EXPERIMENT_STATE['iam_client'] = boto3.client('iam', region_name=EXPERIMENT_STATE['region'])
        logger.info("AWS clients initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize AWS clients: {str(e)}")
        raise


def get_account_id() -> str:
    """Retrieve AWS account ID from STS."""
    try:
        response = EXPERIMENT_STATE['sts_client'].get_caller_identity()
        account_id = response['Account']
        logger.info(f"AWS Account ID: {account_id}")
        return account_id
    except Exception as e:
        logger.error(f"Failed to retrieve account ID: {str(e)}")
        raise


def generate_stack_name() -> str:
    """Generate unique CloudFormation stack name with timestamp."""
    timestamp = int(time.time())
    stack_name = f"sce-experiment-1-5-preventive-{timestamp}"
    logger.info(f"Generated stack name: {stack_name}")
    return stack_name


def create_cloudformation_template(account_id: str) -> str:
    """
    Create CloudFormation template that defines:
    - VPC and subnet for EC2 instance
    - Security group allowing minimal ingress
    - IAM role with DENIED ec2:DescribeInstances permission
    - EC2 instance using that role
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.5 Preventive Probe - IMDS Enumeration Denial Test",
        "Resources": {
            "ExperimentVPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport": True,
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1-5-Preventive"},
                        {"Key": "Timestamp", "Value": str(int(time.time()))}
                    ]
                }
            },
            "ExperimentSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "CidrBlock": "10.0.1.0/24",
                    "AvailabilityZone": f"{EXPERIMENT_STATE['region']}a",
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1-5-Preventive"}
                    ]
                }
            },
            "ExperimentSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "Security group for SCE 1.5 experiment",
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 22,
                            "ToPort": 22,
                            "CidrIp": "10.0.0.0/16"
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1-5-Preventive"}
                    ]
                }
            },
            "DeniedInstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-1-5-denied-role-{int(time.time())}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "ec2.amazonaws.com"
                                },
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1-5-Preventive"}
                    ]
                }
            },
            "DenyDescribeInstancesPolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": "DenyDescribeInstances",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Deny",
                                "Action": "ec2:DescribeInstances",
                                "Resource": "*"
                            },
                            {
                                "Effect": "Allow",
                                "Action": [
                                    "ec2:DescribeSecurityGroups",
                                    "ec2:DescribeNetworkInterfaces"
                                ],
                                "Resource": "*"
                            }
                        ]
                    },
                    "Roles": [{"Ref": "DeniedInstanceRole"}]
                }
            },
            "DeniedInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "Roles": [{"Ref": "DeniedInstanceRole"}]
                }
            },
            "ExperimentEC2Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": "ami-0c55b159cbfafe1f0",  # Amazon Linux 2 AMI (us-east-1)
                    "InstanceType": "t2.micro",
                    "IamInstanceProfile": {"Ref": "DeniedInstanceProfile"},
                    "NetworkInterfaces": [
                        {
                            "AssociatePublicIpAddress": False,
                            "DeviceIndex": 0,
                            "GroupSet": [{"Ref": "ExperimentSecurityGroup"}],
                            "SubnetId": {"Ref": "ExperimentSubnet"}
                        }
                    ],
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1
                    },
                    "UserData": "IyEvYmluL2Jhc2gKZWNobyAnU0NFIDEuNSBQcmV2ZW50aXZlIFRlc3QgSW5zdGFuY2Un",
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1-5-Preventive"},
                        {"Key": "Timestamp", "Value": str(int(time.time()))}
                    ]
                }
            }
        },
        "Outputs": {
            "DeniedRoleArn": {
                "Value": {"Fn::GetAtt": ["DeniedInstanceRole", "Arn"]},
                "Description": "ARN of IAM role with denied DescribeInstances"
            },
            "InstanceId": {
                "Value": {"Ref": "ExperimentEC2Instance"},
                "Description": "Instance ID for testing"
            }
        }
    }
    return json.dumps(template)


def stack_exists(stack_name: str) -> bool:
    """Check if CloudFormation stack already exists."""
    try:
        response = EXPERIMENT_STATE['cf_client'].describe_stacks(StackName=stack_name)
        status = response['Stacks'][0]['StackStatus']
        logger.info(f"Stack {stack_name} exists with status: {status}")
        return status not in ['DELETE_COMPLETE', 'DELETE_IN_PROGRESS']
    except EXPERIMENT_STATE['cf_client'].exceptions.ClientError as e:
        if 'does not exist' in str(e):
            return False
        logger.warning(f"Error checking stack existence: {str(e)}")
        return False


def wait_for_stack_creation(stack_name: str, timeout: int = 600) -> bool:
    """Poll for CloudFormation stack creation completion with exponential backoff."""
    start_time = time.monotonic()
    backoff = 2
    max_backoff = 30

    while time.monotonic() - start_time < timeout:
        try:
            response = EXPERIMENT_STATE['cf_client'].describe_stacks(StackName=stack_name)
            stack = response['Stacks'][0]
            status = stack['StackStatus']

            if status == 'CREATE_COMPLETE':
                logger.info(f"Stack {stack_name} creation completed successfully")
                return True
            elif status in ['CREATE_FAILED', 'ROLLBACK_COMPLETE', 'ROLLBACK_IN_PROGRESS']:
                logger.error(f"Stack creation failed with status: {status}")
                if 'StackStatusReason' in stack:
                    logger.error(f"Reason: {stack['StackStatusReason']}")
                return False
            elif 'IN_PROGRESS' in status:
                logger.info(f"Stack creation in progress: {status}")
                time.sleep(backoff)
                backoff = min(backoff * 1.5, max_backoff)
            else:
                logger.warning(f"Unexpected stack status: {status}")
                time.sleep(backoff)
                backoff = min(backoff * 1.5, max_backoff)

        except Exception as e:
            logger.error(f"Error polling stack status: {str(e)}")
            time.sleep(backoff)
            backoff = min(backoff * 1.5, max_backoff)

    logger.error(f"Stack creation timeout after {timeout} seconds")
    return False


def get_stack_outputs(stack_name: str) -> Dict[str, str]:
    """Retrieve CloudFormation stack outputs."""
    try:
        response = EXPERIMENT_STATE['cf_client'].describe_stacks(StackName=stack_name)
        outputs = {}
        if 'Outputs' in response['Stacks'][0]:
            for output in response['Stacks'][0]['Outputs']:
                outputs[output['OutputKey']] = output['OutputValue']
        logger.info(f"Retrieved stack outputs: {list(outputs.keys())}")
        return outputs
    except Exception as e:
        logger.error(f"Failed to retrieve stack outputs: {str(e)}")
        return {}


def wait_for_iam_role_propagation(role_arn: str, timeout: int = 120) -> bool:
    """
    Wait for IAM role to propagate across AWS services.
    Poll by attempting to assume the role or describe it.
    """
    start_time = time.monotonic()
    backoff = 2
    max_backoff = 15

    while time.monotonic() - start_time < timeout:
        try:
            role_name = role_arn.split('/')[-1]
            response = EXPERIMENT_STATE['iam_client'].get_role(RoleName=role_name)
            if response['Role']['Arn'] == role_arn:
                logger.info(f"IAM role {role_name} is accessible")
                return True
        except Exception as e:
            logger.debug(f"IAM role not yet propagated: {str(e)}")
            time.sleep(backoff)
            backoff = min(backoff * 1.5, max_backoff)

    logger.error(f"IAM role propagation timeout after {timeout} seconds")
    return False


def steady_state():
    """
    Preparation block: Create CloudFormation stack with EC2 instance and denied IAM role.
    
    This function:
    1. Initializes AWS clients
    2. Generates unique stack name
    3. Creates CloudFormation template
    4. Deploys stack
    5. Extracts outputs (role ARN, instance ID)
    6. Waits for IAM propagation
    """
    try:
        logger.info("=" * 80)
        logger.info("STEADY STATE: Initializing SCE 1.5 Preventive Probe Experiment")
        logger.info("=" * 80)

        # Initialize AWS clients
        initialize_aws_clients()

        # Get account ID
        account_id = get_account_id()

        # Generate stack name
        stack_name = generate_stack_name()
        EXPERIMENT_STATE['stack_name'] = stack_name

        # Check if stack already exists
        if stack_exists(stack_name):
            logger.warning(f"Stack {stack_name} already exists; attempting to retrieve outputs")
            outputs = get_stack_outputs(stack_name)
            if outputs:
                EXPERIMENT_STATE['denied_role_arn'] = outputs.get('DeniedRoleArn')
                EXPERIMENT_STATE['instance_id'] = outputs.get('InstanceId')
                logger.info(f"Existing stack outputs retrieved successfully")
                return
        else:
            # Create CloudFormation template
            cf_template = create_cloudformation_template(account_id)
            logger.info(f"CloudFormation template created (size: {len(cf_template)} bytes)")

            # Deploy stack
            logger.info(f"Deploying CloudFormation stack: {stack_name}")
            try:
                EXPERIMENT_STATE['cf_client'].create_stack(
                    StackName=stack_name,
                    TemplateBody=cf_template,
                    Capabilities=['CAPABILITY_NAMED_IAM'],
                    Tags=[
                        {'Key': 'Experiment', 'Value': 'SCE-1-5-Preventive'},
                        {'Key': 'Timestamp', 'Value': str(int(time.time()))}
                    ]
                )
                logger.info(f"Stack creation initiated: {stack_name}")
            except Exception as e:
                logger.error(f"Failed to create stack: {str(e)}")
                raise

            # Wait for stack creation
            if not wait_for_stack_creation(stack_name):
                raise RuntimeError(f"CloudFormation stack {stack_name} creation failed")

        # Retrieve stack outputs
        outputs = get_stack_outputs(stack_name)
        EXPERIMENT_STATE['denied_role_arn'] = outputs.get('DeniedRoleArn')
        EXPERIMENT_STATE['instance_id'] = outputs.get('InstanceId')

        logger.info(f"Denied Role ARN: {EXPERIMENT_STATE['denied_role_arn']}")
        logger.info(f"Instance ID: {EXPERIMENT_STATE['instance_id']}")

        # Wait for IAM role propagation
        if not wait_for_iam_role_propagation(EXPERIMENT_STATE['denied_role_arn']):
            logger.warning("IAM role propagation timeout; proceeding anyway")

        logger.info("STEADY STATE: Complete")
        return True

    except Exception as e:
        logger.error(f"STEADY STATE FAILED: {str(e)}")
        raise


def attack() -> bool:
    """
    Execute Attack Step 1: Enumerate EC2 instances using denied role.
    
    This function:
    1. Assumes the IAM role with denied DescribeInstances permission
    2. Attempts to execute ec2:DescribeInstances
    3. Returns True if attack was executed (regardless of success/failure)
    
    Expected result: 403 Access Denied error (verified in hypothesis_verification)
    """
    try:
        logger.info("=" * 80)
        logger.info("ATTACK: Attempting to enumerate EC2 instances with denied role")
        logger.info("=" * 80)

        if not EXPERIMENT_STATE['denied_role_arn']:
            logger.error("Denied role ARN not set; steady_state() must be called first")
            return False

        # Assume the denied role to obtain temporary credentials
        logger.info(f"Assuming role: {EXPERIMENT_STATE['denied_role_arn']}")
        try:
            assume_role_response = EXPERIMENT_STATE['sts_client'].assume_role(
                RoleArn=EXPERIMENT_STATE['denied_role_arn'],
                RoleSessionName=f"sce-1-5-attack-session-{int(time.time())}"
            )
            logger.info("Role assumption successful")
        except Exception as e:
            logger.error(f"Failed to assume role: {str(e)}")
            return False

        # Extract temporary credentials from assume_role response
        credentials = assume_role_response['Credentials']
        access_key = credentials['AccessKeyId']
        secret_key = credentials['SecretAccessKey']
        session_token = credentials['SessionToken']

        logger.info(f"Temporary credentials obtained (AccessKeyId: {access_key[:10]}...)")

        # Create a new EC2 client using the temporary credentials (denied role)
        boto3 = install_boto3()
        denied_ec2_client = boto3.client(
            'ec2',
            region_name=EXPERIMENT_STATE['region'],
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token
        )

        logger.info("Executing ec2:DescribeInstances with denied role credentials...")
        try:
            response = denied_ec2_client.describe_instances()
            logger.warning("DescribeInstances succeeded unexpectedly; preventive control may be ineffective")
            logger.info(f"Response: {json.dumps(response, default=str, indent=2)[:200]}...")
            return True  # Attack executed (even though it shouldn't have succeeded)
        except denied_ec2_client.exceptions.ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            logger.info(f"ATTACK EXECUTED: DescribeInstances returned error")
            logger.info(f"  Error Code: {error_code}")
            logger.info(f"  Error Message: {error_message}")
            return True  # Attack executed; control blocked it (expected)
        except Exception as e:
            logger.error(f"Unexpected error during DescribeInstances: {str(e)}")
            return False

    except Exception as e:
        logger.error(f"ATTACK FAILED TO EXECUTE: {str(e)}")
        return False


def hypothesis_verification() -> bool:
    """
    Verify Preventive Control: IAM policy denies ec2:DescribeInstances.
    
    This function:
    1. Attempts to execute ec2:DescribeInstances using the denied role
    2. Verifies that a 403 Access Denied error is returned
    3. Confirms the preventive control is effective
    
    Returns True if control is effective, False otherwise.
    
    SLA: 30-minute polling loop for eventual consistency (AWS IAM propagation).
    """
    try:
        logger.info("=" * 80)
        logger.info("HYPOTHESIS VERIFICATION: Validating IAM Preventive Control")
        logger.info("=" * 80)

        if not EXPERIMENT_STATE['denied_role_arn']:
            logger.error("Denied role ARN not set")
            return False

        # 30-minute SLA for eventual consistency
        sla_timeout = 1800  # 30 minutes
        start_time = time.monotonic()
        backoff = 5
        max_backoff = 60
        attempt = 0

        while time.monotonic() - start_time < sla_timeout:
            attempt += 1
            elapsed = int(time.monotonic() - start_time)
            logger.info(f"Verification attempt {attempt} (elapsed: {elapsed}s / SLA: {sla_timeout}s)")

            try:
                # Assume the denied role
                assume_role_response = EXPERIMENT_STATE['sts_client'].assume_role(
                    RoleArn=EXPERIMENT_STATE['denied_role_arn'],
                    RoleSessionName=f"sce-1-5-verify-session-{int(time.time())}-{attempt}"
                )

                credentials = assume_role_response['Credentials']
                access_key = credentials['AccessKeyId']
                secret_key = credentials['SecretAccessKey']
                session_token = credentials['SessionToken']

                logger.debug(f"Temporary credentials obtained for attempt {attempt}")

                # Create EC2 client with denied role credentials
                boto3 = install_boto3()
                denied_ec2_client = boto3.client(
                    'ec2',
                    region_name=EXPERIMENT_STATE['region'],
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    aws_session_token=session_token
                )

                # Attempt DescribeInstances
                logger.debug(f"Executing ec2:DescribeInstances with denied role (attempt {attempt})...")
                try:
                    response = denied_ec2_client.describe_instances()
                    # If we reach here, the control FAILED (no denial)
                    logger.error(f"HYPOTHESIS FAILED: DescribeInstances succeeded when it should have been denied")
                    logger.error(f"Response contains {len(response.get('Reservations', []))} reservations")
                    return False

                except denied_ec2_client.exceptions.ClientError as e:
                    error_code = e.response['Error']['Code']
                    error_message = e.response['Error']['Message']

                    if error_code == 'UnauthorizedOperation' or error_code == 'AccessDenied':
                        logger.info(f"HYPOTHESIS VERIFIED (attempt {attempt}): DescribeInstances denied")
                        logger.info(f"  Error Code: {error_code}")
                        logger.info(f"  Error Message: {error_message}")
                        logger.info("  ✓ Preventive control is EFFECTIVE: IAM policy blocked ec2:DescribeInstances")
                        return True
                    else:
                        logger.warning(f"Unexpected error code: {error_code} (attempt {attempt})")
                        logger.debug(f"Error message: {error_message}")
                        # Continue polling; might be transient

            except Exception as e:
                logger.debug(f"Transient error during verification attempt {attempt}: {str(e)}")
                # Continue polling

            # Exponential backoff
            time.sleep(backoff)
            backoff = min(backoff * 1.5, max_backoff)

        # SLA expired without confirmation
        logger.error(f"HYPOTHESIS VERIFICATION TIMEOUT: SLA of {sla_timeout}s expired after {attempt} attempts")
        logger.error("Unable to confirm IAM denial within 30-minute window (AWS eventual consistency issue)")
        return False

    except Exception as e:
        logger.error(f"HYPOTHESIS VERIFICATION ERROR: {str(e)}")
        return False


def wait_for_stack_deletion(stack_name: str, timeout: int = 600) -> bool:
    """Poll for CloudFormation stack deletion completion."""
    start_time = time.monotonic()
    backoff = 2
    max_backoff = 30

    while time.monotonic() - start_time < timeout:
        try:
            response = EXPERIMENT_STATE['cf_client'].describe_stacks(StackName=stack_name)
            stack = response['Stacks'][0]
            status = stack['StackStatus']

            if status == 'DELETE_COMPLETE':
                logger.info(f"Stack {stack_name} deletion completed successfully")
                return True
            elif status == 'DELETE_IN_PROGRESS':
                logger.info(f"Stack deletion in progress: {status}")
                time.sleep(backoff)
                backoff = min(backoff * 1.5, max_backoff)
            elif 'DELETE_FAILED' in status:
                logger.error(f"Stack deletion failed: {status}")
                if 'StackStatusReason' in stack:
                    logger.error(f"Reason: {stack['StackStatusReason']}")
                return False
            else:
                logger.warning(f"Stack in unexpected status during deletion: {status}")
                time.sleep(backoff)
                backoff = min(backoff * 1.5, max_backoff)

        except EXPERIMENT_STATE['cf_client'].exceptions.ClientError as e:
            if 'does not exist' in str(e):
                logger.info(f"Stack {stack_name} does not exist (already deleted)")
                return True
            logger.error(f"Error polling stack deletion: {str(e)}")
            time.sleep(backoff)
            backoff = min(backoff * 1.5, max_backoff)
        except Exception as e:
            logger.error(f"Unexpected error during stack deletion polling: {str(e)}")
            time.sleep(backoff)
            backoff = min(backoff * 1.5, max_backoff)

    logger.error(f"Stack deletion timeout after {timeout} seconds")
    return False


def rollback():
    """
    Teardown: Delete CloudFormation stack and all provisioned resources.
    
    This function:
    1. Deletes the CloudFormation stack using the timestamped name
    2. Polls for stack deletion completion
    3. Handles stack-not-found errors gracefully
    4. Logs all errors but allows the experiment to conclude
    """
    try:
        logger.info("=" * 80)
        logger.info("ROLLBACK: Cleaning up experiment resources")
        logger.info("=" * 80)

        if not EXPERIMENT_STATE['stack_name']:
            logger.warning("No stack name set; nothing to clean up")
            return

        stack_name = EXPERIMENT_STATE['stack_name']

        # Check if stack exists before attempting deletion
        if not stack_exists(stack_name):
            logger.info(f"Stack {stack_name} does not exist; skipping deletion")
            return

        # Initiate stack deletion
        logger.info(f"Deleting CloudFormation stack: {stack_name}")
        try:
            EXPERIMENT_STATE['cf_client'].delete_stack(StackName=stack_name)
            logger.info(f"Stack deletion initiated: {stack_name}")
        except EXPERIMENT_STATE['cf_client'].exceptions.ClientError as e:
            if 'does not exist' in str(e):
                logger.info(f"Stack {stack_name} already deleted")
                return
            logger.error(f"Error initiating stack deletion: {str(e)}")
            raise

        # Poll for deletion completion
        if not wait_for_stack_deletion(stack_name):
            logger.warning(f"Stack deletion did not complete within timeout; resource cleanup may be incomplete")
            return

        logger.info("ROLLBACK: Complete")

    except Exception as e:
        logger.error(f"ROLLBACK ERROR: {str(e)}")
        logger.warning("Rollback encountered an error; manual cleanup may be required")


# ============================================================================
# MAIN EXECUTION (for debugging/standalone testing)
# ============================================================================
if __name__ == '__main__':
    try:
        logger.info("Starting SCE 1.5 Preventive Probe Experiment")
        steady_state()
        attack_result = attack()
        verification_result = hypothesis_verification()
        logger.info(f"Experiment Result: {'PASS' if verification_result else 'FAIL'}")
    except KeyboardInterrupt:
        logger.info("Experiment interrupted by user")
    except Exception as e:
        logger.error(f"Experiment failed with error: {str(e)}")
    finally:
        rollback()