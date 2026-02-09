#!/usr/bin/env python3
"""
SCE Experiment 1.8 - Preventive Probe
Validates that least privilege IAM policies block unauthorized EC2 reconnaissance.

Attack Node 1.3: Identify Target EC2 Instance
Command: aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions]'

Preventive Control: Least Privilege IAM Policy restricting ec2:DescribeInstances
Expected Outcome: AccessDenied error returned, no instance data leaked
"""

import json
import logging
import os
import sys
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Ensure boto3 is available
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    import subprocess
    logger.info("Installing boto3...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Global configuration
EXPERIMENT_ID = "sce-1-8-preventive"
TIMESTAMP = int(time.time())
STACK_NAME = f"{EXPERIMENT_ID}-{TIMESTAMP}"
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Store state between functions
_experiment_state = {
    "stack_name": STACK_NAME,
    "region": AWS_REGION,
    "unprivileged_credentials": None,
    "test_instance_id": None,
    "attack_result": None,
    "stack_deployed": False
}


def _get_cloudformation_template():
    """
    Generate CloudFormation template for the experiment.
    Creates:
    - A test EC2 instance with IMDSv2 enabled
    - An unprivileged IAM user with NO ec2:DescribeInstances permission
    - Access keys for the unprivileged user
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"SCE Experiment 1.8 - Preventive Probe - Least Privilege IAM Validation - {TIMESTAMP}",
        "Parameters": {
            "LatestAmiId": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
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
                        {"Key": "Name", "Value": f"sce-1-8-vpc-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_ID},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            "TestSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "TestVPC"},
                    "CidrBlock": "10.0.1.0/24",
                    "AvailabilityZone": {"Fn::Select": ["0", {"Fn::GetAZs": {"Ref": "AWS::Region"}}]},
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-1-8-subnet-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_ID}
                    ]
                }
            },
            "TestSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE Experiment 1.8 - No inbound access",
                    "VpcId": {"Ref": "TestVPC"},
                    "SecurityGroupIngress": [],
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-1-8-sg-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_ID}
                    ]
                }
            },
            "TestEC2Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": {"Ref": "LatestAmiId"},
                    "InstanceType": "t3.micro",
                    "SubnetId": {"Ref": "TestSubnet"},
                    "SecurityGroupIds": [{"Ref": "TestSecurityGroup"}],
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled"
                    },
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-1-8-target-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_ID},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            "UnprivilegedUser": {
                "Type": "AWS::IAM::User",
                "Properties": {
                    "UserName": f"sce-1-8-unprivileged-{TIMESTAMP}",
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_ID},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            "UnprivilegedUserPolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": f"sce-1-8-minimal-policy-{TIMESTAMP}",
                    "Users": [{"Ref": "UnprivilegedUser"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowOnlySTSGetCallerIdentity",
                                "Effect": "Allow",
                                "Action": [
                                    "sts:GetCallerIdentity"
                                ],
                                "Resource": "*"
                            },
                            {
                                "Sid": "ExplicitDenyEC2Describe",
                                "Effect": "Deny",
                                "Action": [
                                    "ec2:DescribeInstances",
                                    "ec2:DescribeInstanceAttribute",
                                    "ec2:DescribeInstanceStatus"
                                ],
                                "Resource": "*"
                            }
                        ]
                    }
                }
            },
            "UnprivilegedAccessKey": {
                "Type": "AWS::IAM::AccessKey",
                "DependsOn": "UnprivilegedUserPolicy",
                "Properties": {
                    "UserName": {"Ref": "UnprivilegedUser"}
                }
            }
        },
        "Outputs": {
            "TestInstanceId": {
                "Description": "ID of the test EC2 instance",
                "Value": {"Ref": "TestEC2Instance"}
            },
            "UnprivilegedAccessKeyId": {
                "Description": "Access Key ID for unprivileged user",
                "Value": {"Ref": "UnprivilegedAccessKey"}
            },
            "UnprivilegedSecretAccessKey": {
                "Description": "Secret Access Key for unprivileged user",
                "Value": {"Fn::GetAtt": ["UnprivilegedAccessKey", "SecretAccessKey"]}
            },
            "UnprivilegedUserArn": {
                "Description": "ARN of the unprivileged user",
                "Value": {"Fn::GetAtt": ["UnprivilegedUser", "Arn"]}
            }
        }
    }
    return json.dumps(template)


def _wait_with_backoff(check_func, max_attempts=30, initial_delay=2, max_delay=30):
    """
    Wait with exponential backoff until check_func returns True.
    Uses time.monotonic() for reliable timing.
    """
    start_time = time.monotonic()
    delay = initial_delay
    
    for attempt in range(max_attempts):
        try:
            if check_func():
                elapsed = time.monotonic() - start_time
                logger.info(f"Condition met after {elapsed:.1f}s ({attempt + 1} attempts)")
                return True
        except Exception as e:
            logger.warning(f"Attempt {attempt + 1}/{max_attempts} failed: {e}")
        
        if attempt < max_attempts - 1:
            logger.info(f"Waiting {delay}s before retry...")
            time.sleep(delay)
            delay = min(delay * 1.5, max_delay)
    
    elapsed = time.monotonic() - start_time
    logger.error(f"Condition not met after {elapsed:.1f}s ({max_attempts} attempts)")
    return False


def steady_state():
    """
    Preparation block: Deploy CloudFormation stack with test resources.
    
    Creates:
    - Test EC2 instance with IMDSv2 enforced
    - Unprivileged IAM user with explicit deny on ec2:DescribeInstances
    - Access keys for the unprivileged user
    
    Returns:
        bool: True if steady state established successfully
    """
    global _experiment_state
    
    logger.info("=" * 60)
    logger.info(f"SCE Experiment 1.8 - Preventive Probe - Steady State Setup")
    logger.info(f"Stack Name: {STACK_NAME}")
    logger.info(f"Region: {AWS_REGION}")
    logger.info(f"Timestamp: {TIMESTAMP}")
    logger.info("=" * 60)
    
    try:
        cfn_client = boto3.client('cloudformation', region_name=AWS_REGION)
        
        # Check if stack already exists
        try:
            existing_stacks = cfn_client.describe_stacks(StackName=STACK_NAME)
            if existing_stacks['Stacks']:
                stack_status = existing_stacks['Stacks'][0]['StackStatus']
                logger.warning(f"Stack {STACK_NAME} already exists with status: {stack_status}")
                
                if stack_status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                    logger.info("Using existing stack...")
                    _experiment_state["stack_deployed"] = True
                elif stack_status in ['CREATE_IN_PROGRESS', 'UPDATE_IN_PROGRESS']:
                    logger.info("Stack creation in progress, waiting...")
                else:
                    logger.error(f"Stack in unexpected state: {stack_status}")
                    return False
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
            logger.info("Stack does not exist, creating...")
        
        # Create stack if not already deployed
        if not _experiment_state["stack_deployed"]:
            template_body = _get_cloudformation_template()
            
            logger.info("Creating CloudFormation stack...")
            cfn_client.create_stack(
                StackName=STACK_NAME,
                TemplateBody=template_body,
                Capabilities=['CAPABILITY_NAMED_IAM'],
                Tags=[
                    {'Key': 'Experiment', 'Value': EXPERIMENT_ID},
                    {'Key': 'Timestamp', 'Value': str(TIMESTAMP)},
                    {'Key': 'Purpose', 'Value': 'SCE-Preventive-Probe-IAM-Least-Privilege'}
                ],
                OnFailure='DELETE'
            )
            
            # Wait for stack creation with backoff
            def check_stack_complete():
                response = cfn_client.describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack status: {status}")
                
                if status == 'CREATE_COMPLETE':
                    return True
                elif status in ['CREATE_FAILED', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED']:
                    raise Exception(f"Stack creation failed with status: {status}")
                return False
            
            if not _wait_with_backoff(check_stack_complete, max_attempts=60, initial_delay=10):
                logger.error("Stack creation timed out")
                return False
            
            _experiment_state["stack_deployed"] = True
        
        # Retrieve stack outputs
        logger.info("Retrieving stack outputs...")
        response = cfn_client.describe_stacks(StackName=STACK_NAME)
        outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
        
        _experiment_state["test_instance_id"] = outputs.get('TestInstanceId')
        _experiment_state["unprivileged_credentials"] = {
            'access_key_id': outputs.get('UnprivilegedAccessKeyId'),
            'secret_access_key': outputs.get('UnprivilegedSecretAccessKey'),
            'user_arn': outputs.get('UnprivilegedUserArn')
        }
        
        logger.info(f"Test Instance ID: {_experiment_state['test_instance_id']}")
        logger.info(f"Unprivileged User ARN: {_experiment_state['unprivileged_credentials']['user_arn']}")
        
        # Wait for IAM policy propagation
        logger.info("Waiting for IAM policy propagation...")
        time.sleep(10)
        
        # Verify unprivileged credentials work for allowed actions
        logger.info("Verifying unprivileged credentials...")
        test_client = boto3.client(
            'sts',
            region_name=AWS_REGION,
            aws_access_key_id=_experiment_state['unprivileged_credentials']['access_key_id'],
            aws_secret_access_key=_experiment_state['unprivileged_credentials']['secret_access_key']
        )
        
        def verify_credentials():
            try:
                identity = test_client.get_caller_identity()
                logger.info(f"Verified identity: {identity['Arn']}")
                return True
            except ClientError as e:
                logger.warning(f"Credential verification failed: {e}")
                return False
        
        if not _wait_with_backoff(verify_credentials, max_attempts=10, initial_delay=5):
            logger.error("Failed to verify unprivileged credentials")
            return False
        
        logger.info("Steady state established successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to establish steady state: {e}")
        return False


def attack():
    """
    Execute Attack Node 1.3: Identify Target EC2 Instance
    
    Attempts to run ec2:DescribeInstances with unprivileged credentials
    that have an explicit deny policy.
    
    Command simulated:
        aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions]'
    
    Returns:
        bool: True if attack was executed (regardless of success/failure)
    """
    global _experiment_state
    
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.8 - Executing Attack Node 1.3")
    logger.info("Attack: Identify Target EC2 Instance (Reconnaissance)")
    logger.info("TTP: T1580 - Cloud Infrastructure Discovery")
    logger.info("=" * 60)
    
    if not _experiment_state.get("unprivileged_credentials"):
        logger.error("No unprivileged credentials available - steady_state() must run first")
        return False
    
    try:
        # Create EC2 client with unprivileged credentials
        ec2_client = boto3.client(
            'ec2',
            region_name=AWS_REGION,
            aws_access_key_id=_experiment_state['unprivileged_credentials']['access_key_id'],
            aws_secret_access_key=_experiment_state['unprivileged_credentials']['secret_access_key']
        )
        
        logger.info("Attempting ec2:DescribeInstances with unprivileged credentials...")
        logger.info(f"Target Instance ID: {_experiment_state['test_instance_id']}")
        
        # Attempt the reconnaissance attack
        attack_start = time.monotonic()
        
        try:
            # This should fail due to explicit deny policy
            response = ec2_client.describe_instances(
                InstanceIds=[_experiment_state['test_instance_id']]
            )
            
            # If we get here, the attack succeeded (preventive control failed)
            attack_duration = time.monotonic() - attack_start
            
            instances_found = []
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_info = {
                        'InstanceId': instance.get('InstanceId'),
                        'MetadataOptions': instance.get('MetadataOptions', {})
                    }
                    instances_found.append(instance_info)
            
            _experiment_state["attack_result"] = {
                "success": True,
                "access_denied": False,
                "error_code": None,
                "error_message": None,
                "instances_leaked": instances_found,
                "duration_seconds": attack_duration
            }
            
            logger.warning("ATTACK SUCCEEDED - Preventive control FAILED!")
            logger.warning(f"Leaked instance data: {json.dumps(instances_found, indent=2)}")
            return True
            
        except ClientError as e:
            attack_duration = time.monotonic() - attack_start
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            _experiment_state["attack_result"] = {
                "success": False,
                "access_denied": error_code in ['AccessDenied', 'UnauthorizedOperation'],
                "error_code": error_code,
                "error_message": error_message,
                "instances_leaked": [],
                "duration_seconds": attack_duration
            }
            
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                logger.info(f"ATTACK BLOCKED - AccessDenied received as expected")
                logger.info(f"Error Code: {error_code}")
                logger.info(f"Error Message: {error_message}")
            else:
                logger.warning(f"Attack failed with unexpected error: {error_code}")
                logger.warning(f"Error Message: {error_message}")
            
            return True
            
    except Exception as e:
        logger.error(f"Unexpected error during attack execution: {e}")
        _experiment_state["attack_result"] = {
            "success": False,
            "access_denied": False,
            "error_code": "UnexpectedError",
            "error_message": str(e),
            "instances_leaked": [],
            "duration_seconds": 0
        }
        return False


def hypothesis_verification():
    """
    Verify the preventive countermeasure effectiveness.
    
    Hypothesis: Least privilege IAM policy with explicit deny on ec2:DescribeInstances
    will block unauthorized reconnaissance attempts.
    
    Success Criteria:
    1. Attack received AccessDenied error
    2. No instance data was leaked
    3. The explicit deny policy was enforced
    
    Returns:
        bool: True if preventive control worked as expected
    """
    global _experiment_state
    
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.8 - Hypothesis Verification")
    logger.info("Preventive Control: Least Privilege IAM Policy")
    logger.info("=" * 60)
    
    attack_result = _experiment_state.get("attack_result")
    
    if not attack_result:
        logger.error("No attack result available - attack() must run first")
        return False
    
    logger.info("Evaluating preventive control effectiveness...")
    logger.info(f"Attack Result: {json.dumps(attack_result, indent=2)}")
    
    # Verification criteria
    criteria = {
        "access_denied_received": attack_result.get("access_denied", False),
        "no_data_leaked": len(attack_result.get("instances_leaked", [])) == 0,
        "attack_blocked": not attack_result.get("success", True)
    }
    
    logger.info("Verification Criteria:")
    for criterion, passed in criteria.items():
        status = "PASS" if passed else "FAIL"
        logger.info(f"  - {criterion}: {status}")
    
    all_criteria_met = all(criteria.values())
    
    if all_criteria_met:
        logger.info("=" * 60)
        logger.info("HYPOTHESIS VERIFIED: Preventive control is EFFECTIVE")
        logger.info("The least privilege IAM policy successfully blocked")
        logger.info("unauthorized EC2 reconnaissance attempts.")
        logger.info("=" * 60)
        
        # Log compliance alignment
        logger.info("PCI-DSS Alignment:")
        logger.info("  - Req 7.1: Least privilege access enforced")
        logger.info("  - Req 7.1.2: Privilege restricted to need-to-know")
        
        return True
    else:
        logger.error("=" * 60)
        logger.error("HYPOTHESIS FAILED: Preventive control is INEFFECTIVE")
        logger.error("The least privilege IAM policy did NOT block")
        logger.error("unauthorized EC2 reconnaissance attempts.")
        logger.error("=" * 60)
        
        if attack_result.get("instances_leaked"):
            logger.error("DATA LEAK DETECTED:")
            for instance in attack_result["instances_leaked"]:
                logger.error(f"  - Instance: {instance.get('InstanceId')}")
                logger.error(f"    MetadataOptions: {instance.get('MetadataOptions')}")
        
        return False


def rollback():
    """
    Complete teardown: Delete CloudFormation stack and all resources.
    
    Safe and tolerant: handles stack not found errors gracefully.
    
    Returns:
        bool: True if rollback completed successfully
    """
    global _experiment_state
    
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.8 - Rollback")
    logger.info(f"Deleting Stack: {STACK_NAME}")
    logger.info("=" * 60)
    
    try:
        cfn_client = boto3.client('cloudformation', region_name=AWS_REGION)
        
        # Check if stack exists
        try:
            cfn_client.describe_stacks(StackName=STACK_NAME)
            stack_exists = True
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.info(f"Stack {STACK_NAME} does not exist - nothing to delete")
                stack_exists = False
            else:
                raise
        
        if stack_exists:
            logger.info(f"Initiating stack deletion: {STACK_NAME}")
            cfn_client.delete_stack(StackName=STACK_NAME)
            
            # Wait for deletion with backoff
            def check_stack_deleted():
                try:
                    response = cfn_client.describe_stacks(StackName=STACK_NAME)
                    status = response['Stacks'][0]['StackStatus']
                    logger.info(f"Stack deletion status: {status}")
                    
                    if status == 'DELETE_COMPLETE':
                        return True
                    elif status == 'DELETE_FAILED':
                        raise Exception("Stack deletion failed")
                    return False
                except ClientError as e:
                    if 'does not exist' in str(e):
                        return True
                    raise
            
            if _wait_with_backoff(check_stack_deleted, max_attempts=60, initial_delay=10):
                logger.info("Stack deletion completed successfully")
            else:
                logger.warning("Stack deletion timed out - may still be in progress")
        
        # Clear experiment state
        _experiment_state = {
            "stack_name": None,
            "region": AWS_REGION,
            "unprivileged_credentials": None,
            "test_instance_id": None,
            "attack_result": None,
            "stack_deployed": False
        }
        
        logger.info("Rollback completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error during rollback: {e}")
        return False


def run_experiment():
    """
    Main experiment runner with proper error handling and guaranteed rollback.
    """
    logger.info("#" * 60)
    logger.info("# SCE EXPERIMENT 1.8 - PREVENTIVE PROBE")
    logger.info("# Attack Node 1.3: Identify Target EC2 Instance")
    logger.info("# Control: Least Privilege IAM Policy")
    logger.info("#" * 60)
    
    experiment_success = False
    
    try:
        # Phase 1: Establish steady state
        logger.info("\n[PHASE 1] Establishing steady state...")
        if not steady_state():
            logger.error("Failed to establish steady state")
            return False
        
        # Phase 2: Execute attack
        logger.info("\n[PHASE 2] Executing attack...")
        if not attack():
            logger.error("Failed to execute attack")
            return False
        
        # Phase 3: Verify hypothesis
        logger.info("\n[PHASE 3] Verifying hypothesis...")
        experiment_success = hypothesis_verification()
        
        return experiment_success
        
    except Exception as e:
        logger.error(f"Experiment failed with exception: {e}")
        return False
        
    finally:
        # Phase 4: Always attempt rollback
        logger.info("\n[PHASE 4] Executing rollback...")
        rollback()
        
        # Final summary
        logger.info("\n" + "#" * 60)
        if experiment_success:
            logger.info("# EXPERIMENT RESULT: SUCCESS")
            logger.info("# Preventive control validated - IAM least privilege effective")
        else:
            logger.info("# EXPERIMENT RESULT: FAILURE")
            logger.info("# Preventive control validation failed")
        logger.info("#" * 60)


if __name__ == "__main__":
    success = run_experiment()
    sys.exit(0 if success else 1)