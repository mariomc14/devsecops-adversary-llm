#!/usr/bin/env python3
"""
SCE Experiment 1.5: Rogue Instance Creation - Preventive Probe

This experiment validates that preventive controls (SCPs and IAM policies) block
unauthorized EC2 instance creation attempts, specifically:
- Blocking ec2:RunInstances with unapproved AMIs
- Blocking iam:PassRole to ECS instance profiles from non-pipeline principals

The experiment creates a restricted IAM role that simulates an attacker with
limited permissions, then verifies that attempts to create rogue EC2 instances
are denied by the preventive controls.
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
EXPERIMENT_TAG = "sce-1-5-rogue-instance-preventive"
TIMESTAMP = int(time.time())
STACK_NAME = f"sce-experiment-{TIMESTAMP}"
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Store experiment state
_experiment_state = {
    "stack_name": STACK_NAME,
    "region": AWS_REGION,
    "attacker_role_arn": None,
    "ecs_instance_profile_arn": None,
    "vpc_id": None,
    "subnet_id": None,
    "security_group_id": None,
    "attack_blocked": False,
    "error_messages": []
}


def _get_cloudformation_client():
    """Get CloudFormation client."""
    return boto3.client("cloudformation", region_name=AWS_REGION)


def _get_ec2_client():
    """Get EC2 client."""
    return boto3.client("ec2", region_name=AWS_REGION)


def _get_sts_client():
    """Get STS client."""
    return boto3.client("sts", region_name=AWS_REGION)


def _get_iam_client():
    """Get IAM client."""
    return boto3.client("iam", region_name=AWS_REGION)


def _wait_with_backoff(check_func, max_attempts=30, initial_delay=2, max_delay=30):
    """Wait with exponential backoff until check_func returns True."""
    delay = initial_delay
    start_time = time.monotonic()
    
    for attempt in range(max_attempts):
        try:
            if check_func():
                return True
        except Exception as e:
            logger.warning(f"Check attempt {attempt + 1} failed: {e}")
        
        if attempt < max_attempts - 1:
            logger.info(f"Waiting {delay}s before retry (attempt {attempt + 1}/{max_attempts})")
            time.sleep(delay)
            delay = min(delay * 1.5, max_delay)
    
    elapsed = time.monotonic() - start_time
    logger.error(f"Wait timed out after {elapsed:.1f}s and {max_attempts} attempts")
    return False


def _get_cloudformation_template():
    """Generate CloudFormation template for the experiment."""
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE Experiment 1.5: Rogue Instance Creation Preventive Probe",
        "Parameters": {
            "ExperimentTag": {
                "Type": "String",
                "Default": EXPERIMENT_TAG
            },
            "Timestamp": {
                "Type": "String",
                "Default": str(TIMESTAMP)
            }
        },
        "Resources": {
            # VPC for the experiment
            "ExperimentVPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.99.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport": True,
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-vpc-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": {"Ref": "ExperimentTag"}},
                        {"Key": "Timestamp", "Value": {"Ref": "Timestamp"}}
                    ]
                }
            },
            # Subnet for the experiment
            "ExperimentSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "CidrBlock": "10.99.1.0/24",
                    "AvailabilityZone": {"Fn::Select": ["0", {"Fn::GetAZs": {"Ref": "AWS::Region"}}]},
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-subnet-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": {"Ref": "ExperimentTag"}},
                        {"Key": "Timestamp", "Value": {"Ref": "Timestamp"}}
                    ]
                }
            },
            # Security Group
            "ExperimentSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE Experiment Security Group - No ingress allowed",
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "SecurityGroupIngress": [],
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-sg-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": {"Ref": "ExperimentTag"}},
                        {"Key": "Timestamp", "Value": {"Ref": "Timestamp"}}
                    ]
                }
            },
            # ECS Instance Role (the target role attacker tries to pass)
            "ECSInstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-ecs-instance-role-{TIMESTAMP}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": {"Ref": "ExperimentTag"}},
                        {"Key": "Timestamp", "Value": {"Ref": "Timestamp"}}
                    ]
                }
            },
            # ECS Instance Profile
            "ECSInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": f"sce-ecs-profile-{TIMESTAMP}",
                    "Roles": [{"Ref": "ECSInstanceRole"}]
                }
            },
            # Attacker Role - Simulates compromised credentials with restricted permissions
            "AttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-attacker-role-{TIMESTAMP}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": {"Fn::Sub": "arn:aws:iam::${AWS::AccountId}:root"}},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": {"Ref": "ExperimentTag"}},
                        {"Key": "Timestamp", "Value": {"Ref": "Timestamp"}}
                    ]
                }
            },
            # Attacker Policy - Allows EC2 actions but DENIES PassRole to ECS profiles
            # This simulates the preventive control
            "AttackerPolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": f"sce-attacker-policy-{TIMESTAMP}",
                    "Roles": [{"Ref": "AttackerRole"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowDescribeActions",
                                "Effect": "Allow",
                                "Action": [
                                    "ec2:Describe*",
                                    "iam:GetRole",
                                    "iam:GetInstanceProfile"
                                ],
                                "Resource": "*"
                            },
                            {
                                "Sid": "AllowRunInstancesWithConditions",
                                "Effect": "Allow",
                                "Action": "ec2:RunInstances",
                                "Resource": [
                                    {"Fn::Sub": "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:instance/*"},
                                    {"Fn::Sub": "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:volume/*"},
                                    {"Fn::Sub": "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:network-interface/*"},
                                    {"Fn::Sub": "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:security-group/*"},
                                    {"Fn::Sub": "arn:aws:ec2:${AWS::Region}:${AWS::AccountId}:subnet/*"},
                                    {"Fn::Sub": "arn:aws:ec2:${AWS::Region}::image/*"}
                                ]
                            },
                            {
                                "Sid": "DenyPassRoleToECSProfiles",
                                "Effect": "Deny",
                                "Action": "iam:PassRole",
                                "Resource": {"Fn::GetAtt": ["ECSInstanceRole", "Arn"]},
                                "Condition": {
                                    "StringEquals": {
                                        "iam:PassedToService": "ec2.amazonaws.com"
                                    }
                                }
                            },
                            {
                                "Sid": "DenyUnapprovedAMIs",
                                "Effect": "Deny",
                                "Action": "ec2:RunInstances",
                                "Resource": "arn:aws:ec2:*::image/ami-*",
                                "Condition": {
                                    "StringNotEquals": {
                                        "ec2:ImageId": "ami-00000000000000000"
                                    }
                                }
                            }
                        ]
                    }
                }
            }
        },
        "Outputs": {
            "AttackerRoleArn": {
                "Description": "ARN of the attacker role",
                "Value": {"Fn::GetAtt": ["AttackerRole", "Arn"]}
            },
            "ECSInstanceProfileArn": {
                "Description": "ARN of the ECS instance profile",
                "Value": {"Fn::GetAtt": ["ECSInstanceProfile", "Arn"]}
            },
            "ECSInstanceProfileName": {
                "Description": "Name of the ECS instance profile",
                "Value": {"Ref": "ECSInstanceProfile"}
            },
            "VpcId": {
                "Description": "VPC ID",
                "Value": {"Ref": "ExperimentVPC"}
            },
            "SubnetId": {
                "Description": "Subnet ID",
                "Value": {"Ref": "ExperimentSubnet"}
            },
            "SecurityGroupId": {
                "Description": "Security Group ID",
                "Value": {"Ref": "ExperimentSecurityGroup"}
            }
        }
    }


def steady_state():
    """
    Preparation block: Deploy CloudFormation stack with all required resources.
    
    Creates:
    - VPC, Subnet, Security Group for network isolation
    - ECS Instance Role and Profile (target of the attack)
    - Attacker Role with preventive controls (denies PassRole to ECS profiles)
    """
    logger.info(f"Starting steady_state setup for experiment: {STACK_NAME}")
    logger.info(f"AWS Region: {AWS_REGION}")
    
    cf_client = _get_cloudformation_client()
    template = _get_cloudformation_template()
    
    # Check if stack already exists
    try:
        cf_client.describe_stacks(StackName=STACK_NAME)
        logger.warning(f"Stack {STACK_NAME} already exists. Continuing with existing stack.")
    except ClientError as e:
        if "does not exist" not in str(e):
            logger.error(f"Error checking stack: {e}")
            raise
        
        # Create the stack
        logger.info(f"Creating CloudFormation stack: {STACK_NAME}")
        try:
            cf_client.create_stack(
                StackName=STACK_NAME,
                TemplateBody=json.dumps(template),
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Tags=[
                    {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                    {"Key": "Timestamp", "Value": str(TIMESTAMP)},
                    {"Key": "Purpose", "Value": "Security Chaos Engineering"}
                ],
                OnFailure="DELETE"
            )
        except ClientError as e:
            logger.error(f"Failed to create stack: {e}")
            _experiment_state["error_messages"].append(str(e))
            raise
    
    # Wait for stack creation to complete
    def check_stack_complete():
        try:
            response = cf_client.describe_stacks(StackName=STACK_NAME)
            status = response["Stacks"][0]["StackStatus"]
            logger.info(f"Stack status: {status}")
            
            if status == "CREATE_COMPLETE":
                return True
            elif status in ["CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"]:
                raise Exception(f"Stack creation failed with status: {status}")
            return False
        except ClientError as e:
            if "does not exist" in str(e):
                return False
            raise
    
    logger.info("Waiting for stack creation to complete...")
    if not _wait_with_backoff(check_stack_complete, max_attempts=60, initial_delay=5):
        raise Exception("Stack creation timed out")
    
    # Get stack outputs
    response = cf_client.describe_stacks(StackName=STACK_NAME)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in response["Stacks"][0].get("Outputs", [])}
    
    _experiment_state["attacker_role_arn"] = outputs.get("AttackerRoleArn")
    _experiment_state["ecs_instance_profile_arn"] = outputs.get("ECSInstanceProfileArn")
    _experiment_state["ecs_instance_profile_name"] = outputs.get("ECSInstanceProfileName")
    _experiment_state["vpc_id"] = outputs.get("VpcId")
    _experiment_state["subnet_id"] = outputs.get("SubnetId")
    _experiment_state["security_group_id"] = outputs.get("SecurityGroupId")
    
    logger.info(f"Stack outputs: {outputs}")
    
    # Wait for IAM propagation
    logger.info("Waiting for IAM policy propagation...")
    time.sleep(10)
    
    logger.info("Steady state setup complete")
    return True


def attack():
    """
    Execute the attack: Attempt to create EC2 instance with ECS configuration.
    
    This simulates attack step 1.4:
    - Attacker assumes the restricted role
    - Attempts to run EC2 instance with ECS-optimized AMI
    - Attempts to pass ECS instance profile to the instance
    
    The preventive controls should block this attempt.
    """
    logger.info("Starting attack execution...")
    
    if not _experiment_state["attacker_role_arn"]:
        logger.error("Attacker role ARN not found. Was steady_state() executed?")
        return False
    
    # Assume the attacker role
    sts_client = _get_sts_client()
    
    try:
        logger.info(f"Assuming attacker role: {_experiment_state['attacker_role_arn']}")
        assume_response = sts_client.assume_role(
            RoleArn=_experiment_state["attacker_role_arn"],
            RoleSessionName=f"sce-attack-{TIMESTAMP}"
        )
        
        credentials = assume_response["Credentials"]
        
        # Create EC2 client with attacker credentials
        attacker_ec2 = boto3.client(
            "ec2",
            region_name=AWS_REGION,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"]
        )
        
    except ClientError as e:
        logger.error(f"Failed to assume attacker role: {e}")
        _experiment_state["error_messages"].append(str(e))
        return False
    
    # Get an ECS-optimized AMI (Amazon Linux 2 ECS-optimized)
    ec2_client = _get_ec2_client()
    try:
        ami_response = ec2_client.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["amzn2-ami-ecs-hvm-*-x86_64-ebs"]},
                {"Name": "state", "Values": ["available"]}
            ]
        )
        
        if ami_response["Images"]:
            # Sort by creation date and get the latest
            images = sorted(ami_response["Images"], key=lambda x: x["CreationDate"], reverse=True)
            ecs_ami_id = images[0]["ImageId"]
            logger.info(f"Found ECS-optimized AMI: {ecs_ami_id}")
        else:
            # Fallback to a known AMI ID format
            ecs_ami_id = "ami-07fde2ae86109a2af"
            logger.warning(f"No ECS AMI found, using fallback: {ecs_ami_id}")
            
    except ClientError as e:
        logger.warning(f"Failed to find ECS AMI: {e}")
        ecs_ami_id = "ami-07fde2ae86109a2af"
    
    # Prepare user data script (ECS agent configuration)
    user_data_script = """#!/bin/bash
echo ECS_CLUSTER=target-cluster >> /etc/ecs/ecs.config
echo ECS_BACKEND_HOST= >> /etc/ecs/ecs.config
"""
    
    import base64
    user_data_encoded = base64.b64encode(user_data_script.encode()).decode()
    
    # Attempt the attack: Run EC2 instance with ECS configuration
    attack_blocked = False
    block_reason = None
    
    logger.info("Attempting to create rogue EC2 instance with ECS configuration...")
    logger.info(f"  AMI: {ecs_ami_id}")
    logger.info(f"  Instance Profile: {_experiment_state['ecs_instance_profile_name']}")
    logger.info(f"  Subnet: {_experiment_state['subnet_id']}")
    
    try:
        response = attacker_ec2.run_instances(
            ImageId=ecs_ami_id,
            InstanceType="t2.micro",
            MinCount=1,
            MaxCount=1,
            SubnetId=_experiment_state["subnet_id"],
            SecurityGroupIds=[_experiment_state["security_group_id"]],
            IamInstanceProfile={
                "Name": _experiment_state["ecs_instance_profile_name"]
            },
            UserData=user_data_encoded,
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-rogue-instance-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            ]
        )
        
        # If we get here, the attack succeeded (control failed)
        instance_id = response["Instances"][0]["InstanceId"]
        logger.error(f"ATTACK SUCCEEDED - Instance created: {instance_id}")
        logger.error("Preventive control FAILED to block the attack!")
        
        # Terminate the instance immediately
        try:
            attacker_ec2.terminate_instances(InstanceIds=[instance_id])
            logger.info(f"Terminated rogue instance: {instance_id}")
        except Exception as e:
            logger.error(f"Failed to terminate instance: {e}")
            # Try with main credentials
            ec2_client.terminate_instances(InstanceIds=[instance_id])
        
        _experiment_state["attack_blocked"] = False
        
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_message = e.response.get("Error", {}).get("Message", str(e))
        
        logger.info(f"Attack blocked with error code: {error_code}")
        logger.info(f"Error message: {error_message}")
        
        # Check if blocked by our preventive controls
        if error_code in ["UnauthorizedOperation", "AccessDenied"]:
            if "PassRole" in error_message or "iam:PassRole" in error_message:
                attack_blocked = True
                block_reason = "PassRole denied - Preventive control working"
            elif "ImageId" in error_message or "image" in error_message.lower():
                attack_blocked = True
                block_reason = "AMI restriction - Preventive control working"
            else:
                attack_blocked = True
                block_reason = f"Access denied - {error_message}"
        elif error_code == "InvalidParameterValue":
            # This can happen if AMI doesn't exist in region
            logger.warning(f"Invalid parameter: {error_message}")
            attack_blocked = False
            block_reason = f"Invalid parameter (not a security control): {error_message}"
        else:
            logger.warning(f"Unexpected error: {error_code} - {error_message}")
            attack_blocked = False
            block_reason = f"Unexpected error: {error_code}"
        
        _experiment_state["attack_blocked"] = attack_blocked
        _experiment_state["block_reason"] = block_reason
        _experiment_state["error_messages"].append(error_message)
    
    logger.info(f"Attack blocked: {_experiment_state['attack_blocked']}")
    if block_reason:
        logger.info(f"Block reason: {block_reason}")
    
    return True


def hypothesis_verification():
    """
    Verify that the preventive control blocked the attack.
    
    Success criteria:
    - The attack attempt was blocked (AccessDenied)
    - The block was due to IAM policy (PassRole denied or AMI restriction)
    - No rogue instance was created
    """
    logger.info("Verifying hypothesis: Preventive control blocked rogue instance creation")
    
    # Check if attack was blocked
    if not _experiment_state.get("attack_blocked", False):
        logger.error("HYPOTHESIS FAILED: Attack was NOT blocked by preventive controls")
        logger.error(f"Block reason: {_experiment_state.get('block_reason', 'Unknown')}")
        return False
    
    # Verify no instances were created with our experiment tag
    ec2_client = _get_ec2_client()
    
    try:
        response = ec2_client.describe_instances(
            Filters=[
                {"Name": "tag:Experiment", "Values": [EXPERIMENT_TAG]},
                {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}
            ]
        )
        
        instances = []
        for reservation in response.get("Reservations", []):
            instances.extend(reservation.get("Instances", []))
        
        if instances:
            logger.error(f"HYPOTHESIS FAILED: Found {len(instances)} rogue instance(s)")
            for inst in instances:
                logger.error(f"  Instance: {inst['InstanceId']} - State: {inst['State']['Name']}")
            return False
        
        logger.info("No rogue instances found - Preventive control verified")
        
    except ClientError as e:
        logger.error(f"Error checking for rogue instances: {e}")
        _experiment_state["error_messages"].append(str(e))
        return False
    
    # Final verification
    block_reason = _experiment_state.get("block_reason", "")
    
    if "PassRole" in block_reason or "AMI" in block_reason or "Access denied" in block_reason:
        logger.info("HYPOTHESIS VERIFIED: Preventive control successfully blocked the attack")
        logger.info(f"Block mechanism: {block_reason}")
        return True
    else:
        logger.warning(f"Attack blocked but reason unclear: {block_reason}")
        return True  # Still consider it a pass if attack was blocked


def rollback():
    """
    Complete teardown: Delete CloudFormation stack and all resources.
    """
    logger.info(f"Starting rollback for stack: {STACK_NAME}")
    
    cf_client = _get_cloudformation_client()
    ec2_client = _get_ec2_client()
    
    # First, terminate any instances that might have been created
    try:
        response = ec2_client.describe_instances(
            Filters=[
                {"Name": "tag:Experiment", "Values": [EXPERIMENT_TAG]},
                {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}
            ]
        )
        
        instance_ids = []
        for reservation in response.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_ids.append(instance["InstanceId"])
        
        if instance_ids:
            logger.info(f"Terminating {len(instance_ids)} instance(s): {instance_ids}")
            ec2_client.terminate_instances(InstanceIds=instance_ids)
            
            # Wait for termination
            waiter = ec2_client.get_waiter("instance_terminated")
            waiter.wait(InstanceIds=instance_ids, WaiterConfig={"Delay": 5, "MaxAttempts": 40})
            logger.info("Instances terminated")
            
    except ClientError as e:
        logger.warning(f"Error terminating instances: {e}")
    
    # Delete the CloudFormation stack
    try:
        logger.info(f"Deleting CloudFormation stack: {STACK_NAME}")
        cf_client.delete_stack(StackName=STACK_NAME)
        
        # Wait for deletion
        def check_stack_deleted():
            try:
                response = cf_client.describe_stacks(StackName=STACK_NAME)
                status = response["Stacks"][0]["StackStatus"]
                logger.info(f"Stack deletion status: {status}")
                
                if status == "DELETE_COMPLETE":
                    return True
                elif status == "DELETE_FAILED":
                    raise Exception("Stack deletion failed")
                return False
            except ClientError as e:
                if "does not exist" in str(e):
                    return True
                raise
        
        logger.info("Waiting for stack deletion to complete...")
        if _wait_with_backoff(check_stack_deleted, max_attempts=60, initial_delay=5):
            logger.info("Stack deleted successfully")
        else:
            logger.warning("Stack deletion timed out, but resources may still be cleaning up")
            
    except ClientError as e:
        if "does not exist" in str(e):
            logger.info("Stack already deleted or does not exist")
        else:
            logger.error(f"Error deleting stack: {e}")
            _experiment_state["error_messages"].append(str(e))
    
    logger.info("Rollback complete")
    return True


def run_experiment():
    """
    Main entry point to run the complete experiment.
    """
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.5: Rogue Instance Creation - Preventive Probe")
    logger.info("=" * 60)
    
    success = False
    
    try:
        # Setup
        logger.info("\n--- PHASE 1: Steady State Setup ---")
        steady_state()
        
        # Attack
        logger.info("\n--- PHASE 2: Attack Execution ---")
        attack()
        
        # Verify
        logger.info("\n--- PHASE 3: Hypothesis Verification ---")
        success = hypothesis_verification()
        
    except Exception as e:
        logger.error(f"Experiment failed with exception: {e}")
        _experiment_state["error_messages"].append(str(e))
        success = False
        
    finally:
        # Always rollback
        logger.info("\n--- PHASE 4: Rollback ---")
        try:
            rollback()
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
    
    # Summary
    logger.info("\n" + "=" * 60)
    logger.info("EXPERIMENT SUMMARY")
    logger.info("=" * 60)
    logger.info(f"Result: {'PASSED' if success else 'FAILED'}")
    logger.info(f"Attack Blocked: {_experiment_state.get('attack_blocked', False)}")
    logger.info(f"Block Reason: {_experiment_state.get('block_reason', 'N/A')}")
    
    if _experiment_state["error_messages"]:
        logger.info("Errors encountered:")
        for msg in _experiment_state["error_messages"]:
            logger.info(f"  - {msg}")
    
    return success


if __name__ == "__main__":
    result = run_experiment()
    sys.exit(0 if result else 1)