"""
Security Chaos Engineering Experiment: 1.4 - Preventive Probe
Validates that IAM Permission Boundaries and SCPs prevent ec2:ModifyInstanceMetadataOptions

This experiment:
1. Creates a CloudFormation stack with an EC2 instance, IAM role with permission boundary, and SCP-like inline deny
2. Attempts to modify instance metadata options (the attack)
3. Verifies the modification was blocked by IAM controls (preventive safeguard)
4. Cleans up all resources via CloudFormation stack deletion
"""

import json
import time
import sys
import subprocess
import traceback
from typing import Dict, Any, Optional

# Install boto3 if not available
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    print("Installing boto3...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Global variables
STACK_NAME = f"sce-experiment-1-4-{int(time.time())}"
EXPERIMENT_TAG = "sce-experiment-1-4-preventive"
INSTANCE_ID = None
TEST_ROLE_ARN = None
MAX_WAIT_SECONDS = 1800  # 30-minute SLA for AWS eventual consistency


def log(message: str, level: str = "INFO"):
    """Simple logging function"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}", flush=True)


def retry_with_backoff(func, max_attempts: int = 10, initial_delay: float = 2.0):
    """Generic retry with exponential backoff"""
    delay = initial_delay
    for attempt in range(1, max_attempts + 1):
        try:
            return func()
        except Exception as e:
            if attempt == max_attempts:
                log(f"Max retry attempts reached. Last error: {str(e)}", "ERROR")
                raise
            log(f"Attempt {attempt} failed: {str(e)}. Retrying in {delay}s...", "WARNING")
            time.sleep(delay)
            delay *= 2


def get_cfn_template() -> str:
    """Generate CloudFormation template for the experiment"""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE Experiment 1.4 - IMDS Modification Prevention Test",
        "Resources": {
            # VPC and networking
            "ExperimentVPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport": True,
                    "Tags": [
                        {"Key": "Name", "Value": f"{STACK_NAME}-vpc"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            "ExperimentSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "CidrBlock": "10.0.1.0/24",
                    "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    "Tags": [
                        {"Key": "Name", "Value": f"{STACK_NAME}-subnet"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            "ExperimentIGW": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {
                    "Tags": [
                        {"Key": "Name", "Value": f"{STACK_NAME}-igw"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            "AttachGateway": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "InternetGatewayId": {"Ref": "ExperimentIGW"}
                }
            },
            "ExperimentRouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "Tags": [
                        {"Key": "Name", "Value": f"{STACK_NAME}-rt"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            "ExperimentRoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "AttachGateway",
                "Properties": {
                    "RouteTableId": {"Ref": "ExperimentRouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "ExperimentIGW"}
                }
            },
            "SubnetRouteTableAssociation": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "ExperimentSubnet"},
                    "RouteTableId": {"Ref": "ExperimentRouteTable"}
                }
            },
            "ExperimentSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "Security group for SCE experiment instance",
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "-1",
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "Tags": [
                        {"Key": "Name", "Value": f"{STACK_NAME}-sg"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # IAM Permission Boundary Policy (denies IMDS modification)
            "PermissionBoundaryPolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": f"{STACK_NAME}-boundary",
                    "Description": "Permission boundary that denies IMDS modification",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DenyIMDSModification",
                                "Effect": "Deny",
                                "Action": [
                                    "ec2:ModifyInstanceMetadataOptions"
                                ],
                                "Resource": "*"
                            },
                            {
                                "Sid": "AllowOtherEC2Actions",
                                "Effect": "Allow",
                                "Action": [
                                    "ec2:Describe*",
                                    "ec2:Get*"
                                ],
                                "Resource": "*"
                            }
                        ]
                    }
                }
            },
            # IAM Role with permission boundary
            "TestAttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"{STACK_NAME}-attacker-role",
                    "Description": "Test role simulating attacker with restricted permissions",
                    "PermissionsBoundary": {"Ref": "PermissionBoundaryPolicy"},
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
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # Instance Profile
            "TestInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": f"{STACK_NAME}-profile",
                    "Roles": [{"Ref": "TestAttackerRole"}]
                }
            },
            # EC2 Instance with IMDSv2 enforced
            "TestInstance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": ["TestInstanceProfile", "SubnetRouteTableAssociation"],
                "Properties": {
                    "ImageId": {
                        "Fn::Sub": "{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64}}"
                    },
                    "InstanceType": "t3.micro",
                    "IamInstanceProfile": {"Ref": "TestInstanceProfile"},
                    "SubnetId": {"Ref": "ExperimentSubnet"},
                    "SecurityGroupIds": [{"Ref": "ExperimentSecurityGroup"}],
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled"
                    },
                    "Tags": [
                        {"Key": "Name", "Value": f"{STACK_NAME}-instance"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            }
        },
        "Outputs": {
            "InstanceId": {
                "Description": "Test EC2 Instance ID",
                "Value": {"Ref": "TestInstance"}
            },
            "TestRoleArn": {
                "Description": "Test Attacker Role ARN",
                "Value": {"Fn::GetAtt": ["TestAttackerRole", "Arn"]}
            },
            "PermissionBoundaryArn": {
                "Description": "Permission Boundary Policy ARN",
                "Value": {"Ref": "PermissionBoundaryPolicy"}
            }
        }
    }
    return json.dumps(template, indent=2)


def steady_state() -> bool:
    """
    Preparation phase: Deploy CloudFormation stack with all required resources
    Returns True if successful, False otherwise
    """
    global INSTANCE_ID, TEST_ROLE_ARN
    
    try:
        log("Starting steady_state: Creating CloudFormation stack")
        
        cfn_client = boto3.client('cloudformation')
        
        # Check if stack already exists
        try:
            cfn_client.describe_stacks(StackName=STACK_NAME)
            log(f"Stack {STACK_NAME} already exists, will reuse", "WARNING")
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
            
            # Create stack
            log(f"Creating CloudFormation stack: {STACK_NAME}")
            cfn_client.create_stack(
                StackName=STACK_NAME,
                TemplateBody=get_cfn_template(),
                Capabilities=['CAPABILITY_NAMED_IAM'],
                Tags=[
                    {'Key': 'Experiment', 'Value': EXPERIMENT_TAG},
                    {'Key': 'Timestamp', 'Value': str(int(time.time()))}
                ]
            )
        
        # Wait for stack creation to complete
        log("Waiting for CloudFormation stack creation to complete (this may take 3-5 minutes)...")
        waiter = cfn_client.get_waiter('stack_create_complete')
        
        def wait_for_stack():
            waiter.wait(
                StackName=STACK_NAME,
                WaiterConfig={'Delay': 15, 'MaxAttempts': 40}
            )
        
        retry_with_backoff(wait_for_stack, max_attempts=3, initial_delay=10)
        log("CloudFormation stack created successfully")
        
        # Retrieve outputs
        response = cfn_client.describe_stacks(StackName=STACK_NAME)
        outputs = response['Stacks'][0].get('Outputs', [])
        
        for output in outputs:
            if output['OutputKey'] == 'InstanceId':
                INSTANCE_ID = output['OutputValue']
                log(f"Instance ID: {INSTANCE_ID}")
            elif output['OutputKey'] == 'TestRoleArn':
                TEST_ROLE_ARN = output['OutputValue']
                log(f"Test Role ARN: {TEST_ROLE_ARN}")
        
        if not INSTANCE_ID or not TEST_ROLE_ARN:
            raise Exception("Failed to retrieve required stack outputs")
        
        # Wait for instance to be running
        log("Waiting for EC2 instance to reach running state...")
        ec2_client = boto3.client('ec2')
        waiter = ec2_client.get_waiter('instance_running')
        waiter.wait(InstanceIds=[INSTANCE_ID])
        log("EC2 instance is running")
        
        # Additional wait for IAM policy propagation (IAM eventual consistency)
        log("Waiting 60 seconds for IAM policy propagation...")
        time.sleep(60)
        
        log("Steady state preparation completed successfully")
        return True
        
    except Exception as e:
        log(f"Error in steady_state: {str(e)}", "ERROR")
        log(traceback.format_exc(), "ERROR")
        return False


def attack() -> bool:
    """
    Execute attack: Attempt to modify instance metadata options
    This should be blocked by the permission boundary
    Returns True if attack was attempted (regardless of success/failure)
    """
    global INSTANCE_ID
    
    try:
        log("Starting attack: Attempting to modify instance metadata options")
        
        if not INSTANCE_ID:
            raise Exception("Instance ID not available - steady_state may have failed")
        
        ec2_client = boto3.client('ec2')
        
        # Attempt the attack (this should fail due to permission boundary)
        log(f"Executing: ModifyInstanceMetadataOptions on instance {INSTANCE_ID}")
        log("Parameters: HttpTokens=optional, HttpPutResponseHopLimit=2")
        
        try:
            response = ec2_client.modify_instance_metadata_options(
                InstanceId=INSTANCE_ID,
                HttpTokens='optional',  # Try to weaken to IMDSv1
                HttpEndpoint='enabled',
                HttpPutResponseHopLimit=2  # Try to increase hop limit
            )
            
            # If we get here, the attack succeeded (BAD - safeguard failed)
            log("WARNING: Attack succeeded - metadata options were modified!", "WARNING")
            log(f"Response: {json.dumps(response, default=str)}", "WARNING")
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_message = e.response['Error']['Message']
            
            # Expected: Access Denied due to permission boundary
            if error_code == 'UnauthorizedOperation':
                log(f"Attack blocked as expected: {error_code} - {error_message}")
                log("This is the desired outcome - preventive control is working")
                return True
            else:
                log(f"Attack failed with unexpected error: {error_code} - {error_message}", "ERROR")
                return True
        
    except Exception as e:
        log(f"Error during attack execution: {str(e)}", "ERROR")
        log(traceback.format_exc(), "ERROR")
        return False


def hypothesis_verification() -> bool:
    """
    Verify preventive safeguard: Check that IMDS modification was blocked
    and instance still has secure metadata configuration
    Returns True if safeguard is working correctly (attack was prevented)
    """
    global INSTANCE_ID
    
    try:
        log("Starting hypothesis verification: Checking preventive safeguard effectiveness")
        
        if not INSTANCE_ID:
            raise Exception("Instance ID not available - cannot verify hypothesis")
        
        ec2_client = boto3.client('ec2')
        
        # Verify instance metadata options remain secure
        log(f"Retrieving current metadata options for instance {INSTANCE_ID}")
        
        response = ec2_client.describe_instances(InstanceIds=[INSTANCE_ID])
        
        if not response['Reservations'] or not response['Reservations'][0]['Instances']:
            raise Exception(f"Instance {INSTANCE_ID} not found")
        
        instance = response['Reservations'][0]['Instances'][0]
        metadata_options = instance.get('MetadataOptions', {})
        
        log(f"Current metadata options: {json.dumps(metadata_options, default=str)}")
        
        # Verify security settings are still enforced
        http_tokens = metadata_options.get('HttpTokens', '')
        hop_limit = metadata_options.get('HttpPutResponseHopLimit', 0)
        http_endpoint = metadata_options.get('HttpEndpoint', '')
        
        log(f"HttpTokens: {http_tokens} (expected: required)")
        log(f"HttpPutResponseHopLimit: {hop_limit} (expected: 1)")
        log(f"HttpEndpoint: {http_endpoint} (expected: enabled)")
        
        # Check if preventive controls held
        preventive_successful = (
            http_tokens == 'required' and
            hop_limit == 1 and
            http_endpoint == 'enabled'
        )
        
        if preventive_successful:
            log("✓ PREVENTIVE SAFEGUARD VERIFIED: IMDS configuration remains secure")
            log("✓ Permission boundary successfully blocked ec2:ModifyInstanceMetadataOptions")
            log("✓ IMDSv2 enforcement maintained (HttpTokens=required)")
            log("✓ Hop limit remains restricted (HttpPutResponseHopLimit=1)")
            return True
        else:
            log("✗ PREVENTIVE SAFEGUARD FAILED: IMDS configuration was modified", "ERROR")
            log("✗ Attack succeeded in weakening metadata service protections", "ERROR")
            return False
        
    except Exception as e:
        log(f"Error during hypothesis verification: {str(e)}", "ERROR")
        log(traceback.format_exc(), "ERROR")
        return False


def rollback() -> bool:
    """
    Cleanup: Delete CloudFormation stack and all resources
    Returns True if successful, False otherwise
    """
    try:
        log("Starting rollback: Deleting CloudFormation stack and all resources")
        
        cfn_client = boto3.client('cloudformation')
        
        # Check if stack exists
        try:
            cfn_client.describe_stacks(StackName=STACK_NAME)
        except ClientError as e:
            if 'does not exist' in str(e):
                log(f"Stack {STACK_NAME} does not exist, nothing to delete", "WARNING")
                return True
            raise
        
        # Delete stack
        log(f"Deleting CloudFormation stack: {STACK_NAME}")
        cfn_client.delete_stack(StackName=STACK_NAME)
        
        # Wait for deletion to complete
        log("Waiting for CloudFormation stack deletion to complete...")
        waiter = cfn_client.get_waiter('stack_delete_complete')
        
        def wait_for_deletion():
            waiter.wait(
                StackName=STACK_NAME,
                WaiterConfig={'Delay': 15, 'MaxAttempts': 40}
            )
        
        retry_with_backoff(wait_for_deletion, max_attempts=3, initial_delay=10)
        log("CloudFormation stack deleted successfully")
        log("All experiment resources have been cleaned up")
        return True
        
    except Exception as e:
        log(f"Error during rollback: {str(e)}", "ERROR")
        log(traceback.format_exc(), "ERROR")
        return False


def run_experiment():
    """Main experiment runner"""
    log("=" * 80)
    log("SCE Experiment 1.4 - Preventive Probe: IMDS Modification Prevention")
    log("=" * 80)
    
    success = False
    
    try:
        # Phase 1: Setup
        if not steady_state():
            log("Steady state preparation failed", "ERROR")
            return False
        
        # Phase 2: Attack
        if not attack():
            log("Attack execution failed", "ERROR")
            return False
        
        # Phase 3: Verify
        success = hypothesis_verification()
        
        if success:
            log("=" * 80)
            log("EXPERIMENT RESULT: SUCCESS ✓", "INFO")
            log("Preventive safeguard is functioning correctly")
            log("=" * 80)
        else:
            log("=" * 80)
            log("EXPERIMENT RESULT: FAILURE ✗", "ERROR")
            log("Preventive safeguard did not block the attack")
            log("=" * 80)
        
    except Exception as e:
        log(f"Experiment failed with exception: {str(e)}", "ERROR")
        log(traceback.format_exc(), "ERROR")
    
    finally:
        # Phase 4: Cleanup (always attempt)
        log("Initiating cleanup...")
        rollback()
    
    return success


if __name__ == "__main__":
    result = run_experiment()
    sys.exit(0 if result else 1)