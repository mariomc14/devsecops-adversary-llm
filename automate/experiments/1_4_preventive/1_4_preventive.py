"""
SCE Experiment 1.4 - Preventive Probe
Attack Node: 1.3 - Identify Target EC2 Instance (T1580 - Cloud Infrastructure Discovery)

This experiment validates that IAM least privilege policies prevent unauthorized
EC2 enumeration by blocking ec2:DescribeInstances for non-admin roles.

Hypothesis: A restricted IAM role without ec2:DescribeInstances permission
will receive AccessDenied when attempting to enumerate EC2 instances.
"""

import json
import logging
import os
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state for experiment resources
EXPERIMENT_STATE = {
    'stack_name': None,
    'region': None,
    'role_arn': None,
    'instance_id': None,
    'timestamp': None,
    'attack_result': None
}

# Constants
EXPERIMENT_TAG = 'sce-experiment-1-4-preventive'
MAX_RETRIES = 30
RETRY_DELAY = 10


def _get_boto3():
    """Import boto3, installing if necessary."""
    try:
        import boto3
        return boto3
    except ImportError:
        logger.info("Installing boto3...")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'boto3', '-q'])
        import boto3
        return boto3


def _get_cloudformation_template():
    """
    Generate CloudFormation template for the experiment.
    Creates:
    - A test EC2 instance (target for enumeration)
    - A restricted IAM role WITHOUT ec2:DescribeInstances permission
    - An IAM policy that explicitly denies ec2:DescribeInstances
    """
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE Experiment 1.4 - Preventive Probe for EC2 Discovery Prevention",
        "Parameters": {
            "ExperimentTimestamp": {
                "Type": "String",
                "Description": "Unique timestamp for this experiment run"
            }
        },
        "Resources": {
            "TestVPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport": True,
                    "Tags": [
                        {"Key": "Name", "Value": {"Fn::Sub": "sce-vpc-${ExperimentTimestamp}"}},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            "TestSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "TestVPC"},
                    "CidrBlock": "10.0.1.0/24",
                    "MapPublicIpOnLaunch": False,
                    "Tags": [
                        {"Key": "Name", "Value": {"Fn::Sub": "sce-subnet-${ExperimentTimestamp}"}},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            "TestSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE Experiment Security Group - No ingress",
                    "VpcId": {"Ref": "TestVPC"},
                    "SecurityGroupIngress": [],
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "-1",
                            "CidrIp": "127.0.0.1/32",
                            "Description": "Deny all egress"
                        }
                    ],
                    "Tags": [
                        {"Key": "Name", "Value": {"Fn::Sub": "sce-sg-${ExperimentTimestamp}"}},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            "TestEC2Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "InstanceType": "t3.micro",
                    "ImageId": {"Fn::Sub": "{{resolve:ssm:/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2}}"},
                    "SubnetId": {"Ref": "TestSubnet"},
                    "SecurityGroupIds": [{"Ref": "TestSecurityGroup"}],
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled"
                    },
                    "Tags": [
                        {"Key": "Name", "Value": {"Fn::Sub": "sce-target-instance-${ExperimentTimestamp}"}},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Environment", "Value": "sce-test"}
                    ]
                }
            },
            "RestrictedRolePolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": {"Fn::Sub": "sce-restricted-policy-${ExperimentTimestamp}"},
                    "Description": "Policy that explicitly denies EC2 DescribeInstances - SCE Experiment 1.4",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DenyEC2Enumeration",
                                "Effect": "Deny",
                                "Action": [
                                    "ec2:DescribeInstances",
                                    "ec2:DescribeInstanceStatus",
                                    "ec2:DescribeInstanceAttribute"
                                ],
                                "Resource": "*"
                            },
                            {
                                "Sid": "AllowMinimalEC2ForTest",
                                "Effect": "Allow",
                                "Action": [
                                    "ec2:DescribeRegions"
                                ],
                                "Resource": "*"
                            }
                        ]
                    }
                }
            },
            "RestrictedRole": {
                "Type": "AWS::IAM::Role",
                "DependsOn": "RestrictedRolePolicy",
                "Properties": {
                    "RoleName": {"Fn::Sub": "sce-restricted-role-${ExperimentTimestamp}"},
                    "Description": "Restricted role for SCE Experiment 1.4 - Cannot enumerate EC2 instances",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}
                                },
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringEquals": {
                                        "sts:ExternalId": {"Fn::Sub": "sce-experiment-${ExperimentTimestamp}"}
                                    }
                                }
                            }
                        ]
                    },
                    "ManagedPolicyArns": [
                        {"Ref": "RestrictedRolePolicy"}
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            }
        },
        "Outputs": {
            "RestrictedRoleArn": {
                "Description": "ARN of the restricted IAM role",
                "Value": {"Fn::GetAtt": ["RestrictedRole", "Arn"]},
                "Export": {"Name": {"Fn::Sub": "sce-restricted-role-arn-${ExperimentTimestamp}"}}
            },
            "TestInstanceId": {
                "Description": "ID of the test EC2 instance",
                "Value": {"Ref": "TestEC2Instance"},
                "Export": {"Name": {"Fn::Sub": "sce-test-instance-id-${ExperimentTimestamp}"}}
            },
            "ExternalId": {
                "Description": "External ID for role assumption",
                "Value": {"Fn::Sub": "sce-experiment-${ExperimentTimestamp}"}
            }
        }
    }


def _wait_for_stack_completion(cf_client, stack_name, target_status, timeout=600):
    """Wait for CloudFormation stack to reach target status with retries."""
    start_time = time.monotonic()
    last_status = None
    
    while time.monotonic() - start_time < timeout:
        try:
            response = cf_client.describe_stacks(StackName=stack_name)
            if response['Stacks']:
                current_status = response['Stacks'][0]['StackStatus']
                
                if current_status != last_status:
                    logger.info(f"Stack status: {current_status}")
                    last_status = current_status
                
                if current_status == target_status:
                    return True
                elif 'FAILED' in current_status or 'ROLLBACK' in current_status:
                    logger.error(f"Stack reached failed state: {current_status}")
                    # Get stack events for debugging
                    try:
                        events = cf_client.describe_stack_events(StackName=stack_name)
                        for event in events['StackEvents'][:5]:
                            if 'FAILED' in event.get('ResourceStatus', ''):
                                logger.error(f"Failed resource: {event.get('LogicalResourceId')} - {event.get('ResourceStatusReason')}")
                    except Exception as e:
                        logger.error(f"Could not retrieve stack events: {e}")
                    return False
                elif current_status in ['DELETE_COMPLETE']:
                    if target_status == 'DELETE_COMPLETE':
                        return True
                    return False
        except cf_client.exceptions.ClientError as e:
            if 'does not exist' in str(e):
                if target_status == 'DELETE_COMPLETE':
                    return True
                logger.error(f"Stack {stack_name} does not exist")
                return False
            logger.warning(f"Error checking stack status: {e}")
        
        time.sleep(RETRY_DELAY)
    
    logger.error(f"Timeout waiting for stack {stack_name} to reach {target_status}")
    return False


def _wait_for_iam_propagation(sts_client, role_arn, external_id, max_retries=12):
    """Wait for IAM role to be assumable (eventual consistency)."""
    for attempt in range(max_retries):
        try:
            response = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='sce-propagation-test',
                ExternalId=external_id,
                DurationSeconds=900
            )
            logger.info("IAM role is now assumable")
            return response['Credentials']
        except sts_client.exceptions.ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'MalformedPolicyDocument']:
                logger.info(f"Waiting for IAM propagation (attempt {attempt + 1}/{max_retries})...")
                time.sleep(10)
            else:
                raise
    
    logger.error("IAM role propagation timeout")
    return None


def steady_state():
    """
    Preparation block: Deploy CloudFormation stack with test resources.
    
    Creates:
    - Test EC2 instance (target for enumeration attempt)
    - Restricted IAM role with explicit Deny for ec2:DescribeInstances
    """
    global EXPERIMENT_STATE
    
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.4 - Preventive Probe - Steady State Setup")
    logger.info("=" * 60)
    
    boto3 = _get_boto3()
    
    # Generate unique timestamp
    timestamp = str(int(time.time()))
    stack_name = f"sce-experiment-1-4-{timestamp}"
    
    EXPERIMENT_STATE['timestamp'] = timestamp
    EXPERIMENT_STATE['stack_name'] = stack_name
    
    # Get current region
    session = boto3.Session()
    region = session.region_name or 'us-east-1'
    EXPERIMENT_STATE['region'] = region
    
    logger.info(f"Experiment timestamp: {timestamp}")
    logger.info(f"Stack name: {stack_name}")
    logger.info(f"Region: {region}")
    
    # Create CloudFormation client
    cf_client = boto3.client('cloudformation', region_name=region)
    
    # Get template
    template = _get_cloudformation_template()
    template_body = json.dumps(template)
    
    # Check if stack already exists
    try:
        cf_client.describe_stacks(StackName=stack_name)
        logger.warning(f"Stack {stack_name} already exists, will use existing resources")
    except cf_client.exceptions.ClientError as e:
        if 'does not exist' not in str(e):
            raise
        
        # Create the stack
        logger.info("Creating CloudFormation stack...")
        try:
            cf_client.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Parameters=[
                    {
                        'ParameterKey': 'ExperimentTimestamp',
                        'ParameterValue': timestamp
                    }
                ],
                Capabilities=['CAPABILITY_NAMED_IAM'],
                Tags=[
                    {'Key': 'Experiment', 'Value': EXPERIMENT_TAG},
                    {'Key': 'Timestamp', 'Value': timestamp},
                    {'Key': 'Purpose', 'Value': 'Security Chaos Engineering'}
                ],
                OnFailure='DELETE'
            )
        except cf_client.exceptions.ClientError as e:
            logger.error(f"Failed to create stack: {e}")
            raise
    
    # Wait for stack creation
    logger.info("Waiting for stack creation to complete...")
    if not _wait_for_stack_completion(cf_client, stack_name, 'CREATE_COMPLETE'):
        raise RuntimeError(f"Stack {stack_name} failed to create")
    
    # Get stack outputs
    response = cf_client.describe_stacks(StackName=stack_name)
    outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
    
    EXPERIMENT_STATE['role_arn'] = outputs.get('RestrictedRoleArn')
    EXPERIMENT_STATE['instance_id'] = outputs.get('TestInstanceId')
    EXPERIMENT_STATE['external_id'] = outputs.get('ExternalId')
    
    logger.info(f"Restricted Role ARN: {EXPERIMENT_STATE['role_arn']}")
    logger.info(f"Test Instance ID: {EXPERIMENT_STATE['instance_id']}")
    
    # Wait for IAM propagation
    logger.info("Waiting for IAM role propagation...")
    sts_client = boto3.client('sts', region_name=region)
    credentials = _wait_for_iam_propagation(
        sts_client,
        EXPERIMENT_STATE['role_arn'],
        EXPERIMENT_STATE['external_id']
    )
    
    if not credentials:
        raise RuntimeError("Failed to assume restricted role - IAM propagation issue")
    
    logger.info("Steady state established successfully")
    logger.info("=" * 60)
    
    return True


def attack():
    """
    Execute Attack Step 1.3: Identify Target EC2 Instance
    
    Simulates attacker attempting to enumerate EC2 instances using
    the restricted IAM role that lacks ec2:DescribeInstances permission.
    
    Command being tested:
    aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions]'
    
    Expected Result: AccessDenied error due to IAM policy restriction
    """
    global EXPERIMENT_STATE
    
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.4 - Executing Attack Step 1.3")
    logger.info("Attack: EC2 Instance Enumeration (T1580 - Cloud Infrastructure Discovery)")
    logger.info("=" * 60)
    
    boto3 = _get_boto3()
    
    # Assume the restricted role
    sts_client = boto3.client('sts', region_name=EXPERIMENT_STATE['region'])
    
    try:
        assume_response = sts_client.assume_role(
            RoleArn=EXPERIMENT_STATE['role_arn'],
            RoleSessionName='sce-attack-simulation',
            ExternalId=EXPERIMENT_STATE['external_id'],
            DurationSeconds=900
        )
        credentials = assume_response['Credentials']
        logger.info(f"Successfully assumed restricted role")
    except Exception as e:
        logger.error(f"Failed to assume restricted role: {e}")
        EXPERIMENT_STATE['attack_result'] = {
            'success': False,
            'error_type': 'AssumeRoleFailed',
            'error_message': str(e)
        }
        return False
    
    # Create EC2 client with restricted role credentials
    ec2_client = boto3.client(
        'ec2',
        region_name=EXPERIMENT_STATE['region'],
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    
    # Attempt the attack: ec2:DescribeInstances
    logger.info("Attempting ec2:DescribeInstances with restricted role...")
    logger.info("Command: aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions]'")
    
    attack_blocked = False
    error_code = None
    error_message = None
    
    try:
        response = ec2_client.describe_instances(
            Filters=[
                {
                    'Name': 'tag:Experiment',
                    'Values': [EXPERIMENT_TAG]
                }
            ]
        )
        
        # If we get here, the attack succeeded (preventive control failed)
        instances_found = []
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instances_found.append({
                    'InstanceId': instance['InstanceId'],
                    'MetadataOptions': instance.get('MetadataOptions', {})
                })
        
        logger.warning(f"ATTACK SUCCEEDED - Found {len(instances_found)} instances")
        logger.warning("Preventive control FAILED to block enumeration")
        
        EXPERIMENT_STATE['attack_result'] = {
            'success': True,
            'blocked': False,
            'instances_found': instances_found,
            'error_type': None,
            'error_message': None
        }
        
    except ec2_client.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_message = e.response.get('Error', {}).get('Message', str(e))
        
        if error_code in ['AccessDenied', 'UnauthorizedOperation']:
            attack_blocked = True
            logger.info(f"ATTACK BLOCKED - Received {error_code}")
            logger.info(f"Error message: {error_message}")
            logger.info("Preventive control SUCCEEDED in blocking enumeration")
        else:
            logger.error(f"Unexpected error during attack: {error_code} - {error_message}")
        
        EXPERIMENT_STATE['attack_result'] = {
            'success': False,
            'blocked': attack_blocked,
            'instances_found': [],
            'error_type': error_code,
            'error_message': error_message
        }
    
    except Exception as e:
        logger.error(f"Unexpected exception during attack: {e}")
        EXPERIMENT_STATE['attack_result'] = {
            'success': False,
            'blocked': False,
            'instances_found': [],
            'error_type': 'UnexpectedException',
            'error_message': str(e)
        }
    
    logger.info("=" * 60)
    logger.info(f"Attack Result: {'BLOCKED' if attack_blocked else 'NOT BLOCKED'}")
    logger.info("=" * 60)
    
    return True


def hypothesis_verification():
    """
    Verify the preventive countermeasure hypothesis.
    
    Hypothesis: IAM policies will prevent EC2 enumeration by returning
    AccessDenied when a restricted role attempts ec2:DescribeInstances.
    
    Verification Criteria:
    1. Attack was attempted (attack function executed)
    2. Attack was blocked (AccessDenied or UnauthorizedOperation received)
    3. No instances were enumerated
    
    Returns:
        bool: True if preventive control worked as expected, False otherwise
    """
    global EXPERIMENT_STATE
    
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.4 - Hypothesis Verification")
    logger.info("=" * 60)
    
    attack_result = EXPERIMENT_STATE.get('attack_result')
    
    if attack_result is None:
        logger.error("No attack result found - attack may not have executed")
        return False
    
    logger.info("Verification Criteria:")
    logger.info("1. Attack was blocked by IAM policy")
    logger.info("2. Error type is AccessDenied or UnauthorizedOperation")
    logger.info("3. No instances were enumerated")
    logger.info("")
    
    # Check if attack was blocked
    was_blocked = attack_result.get('blocked', False)
    error_type = attack_result.get('error_type')
    instances_found = attack_result.get('instances_found', [])
    
    logger.info(f"Attack blocked: {was_blocked}")
    logger.info(f"Error type: {error_type}")
    logger.info(f"Instances enumerated: {len(instances_found)}")
    
    # Verification logic
    verification_passed = False
    
    if was_blocked and error_type in ['AccessDenied', 'UnauthorizedOperation']:
        if len(instances_found) == 0:
            verification_passed = True
            logger.info("")
            logger.info("✓ HYPOTHESIS VERIFIED")
            logger.info("The preventive control (IAM least privilege policy) successfully")
            logger.info("blocked the EC2 enumeration attack with AccessDenied response.")
        else:
            logger.warning("")
            logger.warning("✗ HYPOTHESIS FAILED")
            logger.warning("Attack was blocked but instances were still enumerated (inconsistent state)")
    else:
        logger.warning("")
        logger.warning("✗ HYPOTHESIS FAILED")
        if not was_blocked:
            logger.warning("The preventive control did NOT block the enumeration attack.")
            logger.warning(f"Attacker successfully enumerated {len(instances_found)} instances.")
        else:
            logger.warning(f"Unexpected error type: {error_type}")
    
    logger.info("")
    logger.info("=" * 60)
    logger.info(f"Verification Result: {'PASSED' if verification_passed else 'FAILED'}")
    logger.info("=" * 60)
    
    return verification_passed


def rollback():
    """
    Complete teardown using CloudFormation.
    
    Deletes the CloudFormation stack created in steady_state(),
    which automatically removes all resources:
    - Test EC2 instance
    - Restricted IAM role
    - IAM policy
    - VPC, Subnet, Security Group
    """
    global EXPERIMENT_STATE
    
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.4 - Rollback")
    logger.info("=" * 60)
    
    stack_name = EXPERIMENT_STATE.get('stack_name')
    
    if not stack_name:
        logger.warning("No stack name found in experiment state - nothing to rollback")
        return True
    
    boto3 = _get_boto3()
    region = EXPERIMENT_STATE.get('region', 'us-east-1')
    cf_client = boto3.client('cloudformation', region_name=region)
    
    logger.info(f"Deleting CloudFormation stack: {stack_name}")
    
    try:
        # Check if stack exists
        try:
            cf_client.describe_stacks(StackName=stack_name)
        except cf_client.exceptions.ClientError as e:
            if 'does not exist' in str(e):
                logger.info(f"Stack {stack_name} does not exist - nothing to delete")
                return True
            raise
        
        # Delete the stack
        cf_client.delete_stack(StackName=stack_name)
        logger.info("Stack deletion initiated")
        
        # Wait for deletion to complete
        logger.info("Waiting for stack deletion to complete...")
        if _wait_for_stack_completion(cf_client, stack_name, 'DELETE_COMPLETE', timeout=300):
            logger.info("Stack deleted successfully")
        else:
            logger.warning("Stack deletion may not have completed - check AWS console")
            
    except cf_client.exceptions.ClientError as e:
        if 'does not exist' in str(e):
            logger.info(f"Stack {stack_name} already deleted")
        else:
            logger.error(f"Error during rollback: {e}")
            return False
    except Exception as e:
        logger.error(f"Unexpected error during rollback: {e}")
        return False
    
    logger.info("=" * 60)
    logger.info("Rollback completed")
    logger.info("=" * 60)
    
    return True


def run_experiment():
    """
    Main entry point to run the complete experiment.
    Ensures rollback is always attempted, even on failure.
    """
    logger.info("#" * 70)
    logger.info("# SCE EXPERIMENT 1.4 - PREVENTIVE PROBE")
    logger.info("# Attack: EC2 Instance Enumeration (T1580)")
    logger.info("# Control: IAM Least Privilege Policy")
    logger.info("#" * 70)
    
    try:
        # Setup
        steady_state()
        
        # Execute attack
        attack()
        
        # Verify hypothesis
        result = hypothesis_verification()
        
        return result
        
    except Exception as e:
        logger.error(f"Experiment failed with exception: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Always attempt rollback
        logger.info("")
        logger.info("Initiating rollback (cleanup)...")
        try:
            rollback()
        except Exception as e:
            logger.error(f"Rollback failed: {e}")


if __name__ == '__main__':
    success = run_experiment()
    exit(0 if success else 1)