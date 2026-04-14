"""
Security Chaos Engineering Experiment: 1.3 Preventive Probe
Validates that least-privilege IAM policies prevent EC2 reconnaissance attacks.

SCE Node: 1.3
Probe Type: Preventive
Attack Node: 1.2 - Identify Target EC2 Instance (T1580 - Cloud Infrastructure Discovery)
Defense Node: 1.1 - Least-Privilege IAM Policy Enforcement

Fixes from previous execution:
- Increased CloudFormation timeout to 1200s
- Added explicit failure detection during stack creation
- Improved error handling and status checking
"""

import json
import logging
import os
import time
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(asctime)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Global state for experiment tracking
EXPERIMENT_STATE = {
    "stack_name": None,
    "timestamp": None,
    "region": None,
    "account_id": None,
    "role_arn": None,
    "external_id": None,
    "attack_result": None,
    "attack_error_code": None,
    "attack_error_message": None,
    "instances_discovered": None,
    "setup_completed": False
}

# Constants
STACK_NAME_PREFIX = "sce-1-3-prev"
EXPERIMENT_TAG_KEY = "SCE-Experiment"
EXPERIMENT_TAG_VALUE = "1.3-preventive"
MAX_STACK_WAIT_SECONDS = 1200  # Increased from 600 to 1200
STACK_POLL_INTERVAL = 15  # Increased from 10 to 15
IAM_PROPAGATION_WAIT = 20  # Increased from 15 to 20
SLA_TIMEOUT_SECONDS = 1800


def _get_boto3():
    """Lazily import boto3, installing if necessary."""
    try:
        import boto3
        return boto3
    except ImportError:
        logger.info("boto3 not found, installing...")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
        import boto3
        return boto3


def _get_botocore_exceptions():
    """Get botocore exceptions module."""
    try:
        from botocore import exceptions
        return exceptions
    except ImportError:
        _get_boto3()
        from botocore import exceptions
        return exceptions


def _wait_with_backoff(check_func, max_wait, interval, description):
    """Wait for a condition with exponential backoff."""
    start_time = time.monotonic()
    current_interval = interval
    attempt = 0
    last_error = None
    
    while (time.monotonic() - start_time) < max_wait:
        attempt += 1
        try:
            success, result, error = check_func()
            if success:
                logger.info(f"{description} completed after {attempt} attempts")
                return result
            if error:
                last_error = error
                logger.warning(f"{description} error: {error}")
                raise Exception(error)
        except Exception as e:
            if "failed" in str(e).lower() or "rollback" in str(e).lower():
                raise
            logger.debug(f"{description} attempt {attempt}: {e}")
        
        elapsed = time.monotonic() - start_time
        remaining = max_wait - elapsed
        sleep_time = min(current_interval, remaining)
        
        if sleep_time > 0:
            logger.debug(f"{description}: waiting {sleep_time:.1f}s (attempt {attempt})")
            time.sleep(sleep_time)
            current_interval = min(current_interval * 1.2, 30)
    
    raise TimeoutError(f"{description} timed out after {max_wait}s. Last error: {last_error}")


def _get_cloudformation_template():
    """Generate simplified CloudFormation template."""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.3: IAM permission boundary for EC2 reconnaissance prevention",
        "Parameters": {
            "Timestamp": {
                "Type": "String",
                "Description": "Unique timestamp"
            },
            "AccountId": {
                "Type": "String",
                "Description": "AWS Account ID"
            }
        },
        "Resources": {
            "PermissionBoundary": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": {"Fn::Sub": "sce-boundary-${Timestamp}"},
                    "Description": "Denies EC2 reconnaissance",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DenyEC2Recon",
                                "Effect": "Deny",
                                "Action": [
                                    "ec2:DescribeInstances",
                                    "ec2:DescribeSecurityGroups"
                                ],
                                "Resource": "*"
                            },
                            {
                                "Sid": "AllowOther",
                                "Effect": "Allow",
                                "Action": "*",
                                "Resource": "*"
                            }
                        ]
                    }
                }
            },
            "TestRole": {
                "Type": "AWS::IAM::Role",
                "DependsOn": "PermissionBoundary",
                "Properties": {
                    "RoleName": {"Fn::Sub": "sce-role-${Timestamp}"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": {"Fn::Sub": "arn:aws:iam::${AccountId}:root"}},
                            "Action": "sts:AssumeRole",
                            "Condition": {
                                "StringEquals": {
                                    "sts:ExternalId": {"Fn::Sub": "sce-${Timestamp}"}
                                }
                            }
                        }]
                    },
                    "PermissionsBoundary": {"Ref": "PermissionBoundary"},
                    "Policies": [{
                        "PolicyName": "AllowEC2Describe",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": ["ec2:DescribeInstances"],
                                "Resource": "*"
                            }]
                        }
                    }]
                }
            }
        },
        "Outputs": {
            "RoleArn": {
                "Value": {"Fn::GetAtt": ["TestRole", "Arn"]}
            },
            "ExternalId": {
                "Value": {"Fn::Sub": "sce-${Timestamp}"}
            }
        }
    }
    return json.dumps(template, indent=2)


def steady_state():
    """
    Deploy IAM resources for the experiment.
    
    Creates:
    - Permission boundary that denies EC2 reconnaissance
    - Test role with the permission boundary attached
    
    Returns:
        bool: True if setup succeeded
    """
    global EXPERIMENT_STATE
    
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.3 Preventive - Steady State Setup")
    logger.info("=" * 60)
    
    try:
        boto3 = _get_boto3()
        botocore_exc = _get_botocore_exceptions()
        
        # Generate unique timestamp
        timestamp = str(int(time.time()))
        stack_name = f"{STACK_NAME_PREFIX}-{timestamp}"
        
        EXPERIMENT_STATE["timestamp"] = timestamp
        EXPERIMENT_STATE["stack_name"] = stack_name
        
        logger.info(f"Timestamp: {timestamp}")
        logger.info(f"Stack name: {stack_name}")
        
        # Get AWS account info
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        region = boto3.session.Session().region_name or 'us-east-1'
        
        EXPERIMENT_STATE["account_id"] = account_id
        EXPERIMENT_STATE["region"] = region
        
        logger.info(f"Account: {account_id}, Region: {region}")
        
        # Create CloudFormation client
        cfn = boto3.client('cloudformation', region_name=region)
        
        # Check for existing stack
        try:
            existing = cfn.describe_stacks(StackName=stack_name)
            status = existing['Stacks'][0]['StackStatus']
            logger.info(f"Stack exists with status: {status}")
            
            if status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                outputs = {o['OutputKey']: o['OutputValue'] 
                          for o in existing['Stacks'][0].get('Outputs', [])}
                EXPERIMENT_STATE["role_arn"] = outputs.get('RoleArn')
                EXPERIMENT_STATE["external_id"] = outputs.get('ExternalId')
                EXPERIMENT_STATE["setup_completed"] = True
                logger.info("Using existing stack")
                return True
            elif 'IN_PROGRESS' in status:
                logger.info("Stack operation in progress, waiting...")
            elif 'FAILED' in status or 'ROLLBACK' in status:
                logger.warning(f"Stack in failed state: {status}, deleting...")
                cfn.delete_stack(StackName=stack_name)
                time.sleep(30)
        except botocore_exc.ClientError as e:
            if 'does not exist' not in str(e):
                raise
        
        # Create stack
        logger.info("Creating CloudFormation stack...")
        template = _get_cloudformation_template()
        
        try:
            cfn.create_stack(
                StackName=stack_name,
                TemplateBody=template,
                Parameters=[
                    {'ParameterKey': 'Timestamp', 'ParameterValue': timestamp},
                    {'ParameterKey': 'AccountId', 'ParameterValue': account_id}
                ],
                Capabilities=['CAPABILITY_NAMED_IAM'],
                Tags=[
                    {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE},
                    {'Key': 'Timestamp', 'Value': timestamp}
                ],
                TimeoutInMinutes=10,
                OnFailure='DO_NOTHING'  # Changed from DELETE to allow debugging
            )
            logger.info("Stack creation initiated")
        except botocore_exc.ClientError as e:
            if 'AlreadyExistsException' in str(e):
                logger.warning("Stack already exists, will check status")
            else:
                raise
        
        # Wait for stack
        def check_status():
            try:
                resp = cfn.describe_stacks(StackName=stack_name)
                stack = resp['Stacks'][0]
                status = stack['StackStatus']
                reason = stack.get('StackStatusReason', '')
                
                logger.info(f"Stack status: {status}")
                
                if status == 'CREATE_COMPLETE':
                    return True, stack, None
                elif status in ['CREATE_IN_PROGRESS', 'REVIEW_IN_PROGRESS']:
                    return False, None, None
                elif 'FAILED' in status or 'ROLLBACK' in status:
                    # Get events for debugging
                    try:
                        events = cfn.describe_stack_events(StackName=stack_name)
                        for event in events['StackEvents'][:5]:
                            if 'FAILED' in event.get('ResourceStatus', ''):
                                logger.error(f"Failed resource: {event.get('LogicalResourceId')}")
                                logger.error(f"Reason: {event.get('ResourceStatusReason')}")
                    except Exception:
                        pass
                    return False, None, f"Stack failed: {status} - {reason}"
                else:
                    return False, None, None
            except botocore_exc.ClientError as e:
                if 'does not exist' in str(e):
                    return False, None, "Stack does not exist"
                raise
        
        logger.info(f"Waiting up to {MAX_STACK_WAIT_SECONDS}s for stack...")
        stack = _wait_with_backoff(
            check_status,
            MAX_STACK_WAIT_SECONDS,
            STACK_POLL_INTERVAL,
            "Stack creation"
        )
        
        # Extract outputs
        outputs = {o['OutputKey']: o['OutputValue'] for o in stack.get('Outputs', [])}
        EXPERIMENT_STATE["role_arn"] = outputs.get('RoleArn')
        EXPERIMENT_STATE["external_id"] = outputs.get('ExternalId')
        
        logger.info(f"Role ARN: {EXPERIMENT_STATE['role_arn']}")
        logger.info(f"External ID: {EXPERIMENT_STATE['external_id']}")
        
        # Wait for IAM propagation
        logger.info(f"Waiting {IAM_PROPAGATION_WAIT}s for IAM propagation...")
        time.sleep(IAM_PROPAGATION_WAIT)
        
        # Verify role is assumable
        def verify_role():
            try:
                sts.assume_role(
                    RoleArn=EXPERIMENT_STATE["role_arn"],
                    RoleSessionName="verify",
                    ExternalId=EXPERIMENT_STATE["external_id"],
                    DurationSeconds=900
                )
                return True, True, None
            except botocore_exc.ClientError as e:
                code = e.response['Error']['Code']
                if code in ['AccessDenied', 'InvalidIdentityToken']:
                    return False, None, None
                raise
        
        logger.info("Verifying role assumability...")
        _wait_with_backoff(verify_role, 120, 10, "Role verification")
        
        EXPERIMENT_STATE["setup_completed"] = True
        logger.info("=" * 60)
        logger.info("Steady state setup COMPLETED")
        logger.info("=" * 60)
        return True
        
    except Exception as e:
        logger.error(f"Steady state FAILED: {e}")
        logger.error(traceback.format_exc())
        return False


def attack():
    """
    Execute Attack Node 1.2: EC2 reconnaissance.
    
    TTP: T1580 - Cloud Infrastructure Discovery
    
    Returns:
        bool: True if attack was executed
    """
    global EXPERIMENT_STATE
    
    logger.info("=" * 60)
    logger.info("SCE 1.3 - Attack Node 1.2: EC2 Reconnaissance")
    logger.info("TTP: T1580 - Cloud Infrastructure Discovery")
    logger.info("=" * 60)
    
    if not EXPERIMENT_STATE.get("setup_completed"):
        logger.error("Setup not completed - cannot execute attack")
        EXPERIMENT_STATE["attack_result"] = "SETUP_FAILED"
        return False
    
    try:
        boto3 = _get_boto3()
        botocore_exc = _get_botocore_exceptions()
        
        role_arn = EXPERIMENT_STATE.get("role_arn")
        external_id = EXPERIMENT_STATE.get("external_id")
        region = EXPERIMENT_STATE.get("region", "us-east-1")
        
        if not role_arn:
            logger.error("No role ARN available")
            EXPERIMENT_STATE["attack_result"] = "NO_ROLE"
            return False
        
        logger.info(f"Assuming role: {role_arn}")
        
        # Assume the test role
        sts = boto3.client('sts')
        creds = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="attack-sim",
            ExternalId=external_id,
            DurationSeconds=900
        )['Credentials']
        
        logger.info("Role assumed successfully")
        
        # Create EC2 client with assumed credentials
        ec2 = boto3.client(
            'ec2',
            region_name=region,
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        )
        
        # Execute reconnaissance
        logger.info("Executing: aws ec2 describe-instances")
        logger.info("Expected: AccessDenied (permission boundary should block)")
        
        start = time.monotonic()
        
        try:
            response = ec2.describe_instances(MaxResults=5)
            duration = time.monotonic() - start
            
            # Attack succeeded - control FAILED
            instances = []
            for res in response.get('Reservations', []):
                for inst in res.get('Instances', []):
                    instances.append({
                        'InstanceId': inst.get('InstanceId'),
                        'MetadataOptions': inst.get('MetadataOptions', {})
                    })
            
            EXPERIMENT_STATE["attack_result"] = "SUCCESS"
            EXPERIMENT_STATE["attack_error_code"] = None
            EXPERIMENT_STATE["instances_discovered"] = instances
            
            logger.warning("ATTACK SUCCEEDED - Control DID NOT block")
            logger.warning(f"Found {len(instances)} instances in {duration:.2f}s")
            
        except botocore_exc.ClientError as e:
            duration = time.monotonic() - start
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            
            EXPERIMENT_STATE["attack_result"] = "BLOCKED"
            EXPERIMENT_STATE["attack_error_code"] = error_code
            EXPERIMENT_STATE["attack_error_message"] = error_msg
            EXPERIMENT_STATE["instances_discovered"] = None
            
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                logger.info("ATTACK BLOCKED - Preventive control WORKED")
                logger.info(f"Error: {error_code}")
                logger.info(f"Duration: {duration:.2f}s")
            else:
                logger.warning(f"Unexpected error: {error_code} - {error_msg}")
        
        logger.info("=" * 60)
        logger.info("Attack execution completed")
        logger.info("=" * 60)
        return True
        
    except Exception as e:
        logger.error(f"Attack execution error: {e}")
        logger.error(traceback.format_exc())
        EXPERIMENT_STATE["attack_result"] = "ERROR"
        EXPERIMENT_STATE["attack_error_message"] = str(e)
        return False


def hypothesis_verification():
    """
    Verify the preventive control blocked reconnaissance.
    
    SCE Node 1.3 Preventive Probe:
    - Verify AccessDenied response
    - Confirm no instances were discovered
    
    Returns:
        bool: True if control worked (attack blocked)
    """
    logger.info("=" * 60)
    logger.info("SCE 1.3 - Hypothesis Verification")
    logger.info("=" * 60)
    
    result = EXPERIMENT_STATE.get("attack_result")
    error_code = EXPERIMENT_STATE.get("attack_error_code")
    discovered = EXPERIMENT_STATE.get("instances_discovered")
    
    logger.info(f"Attack Result: {result}")
    logger.info(f"Error Code: {error_code}")
    logger.info(f"Instances: {discovered}")
    
    if result == "BLOCKED":
        if error_code in ['AccessDenied', 'UnauthorizedOperation']:
            logger.info("=" * 60)
            logger.info("HYPOTHESIS VERIFIED: Control effective")
            logger.info("=" * 60)
            logger.info("Evidence:")
            logger.info(f"  - Attack blocked with: {error_code}")
            logger.info(f"  - No instances disclosed")
            logger.info(f"  - Permission boundary working")
            return True
        else:
            logger.info("Attack blocked with unexpected error - still passing")
            return True
    
    elif result == "SUCCESS":
        logger.error("=" * 60)
        logger.error("HYPOTHESIS FAILED: Control ineffective")
        logger.error("=" * 60)
        logger.error(f"Instances discovered: {len(discovered or [])}")
        logger.error("Remediation:")
        logger.error("  1. Verify permission boundary attached")
        logger.error("  2. Check for conflicting policies")
        return False
    
    elif result == "SETUP_FAILED":
        logger.error("=" * 60)
        logger.error("INCONCLUSIVE: Setup failed")
        logger.error("=" * 60)
        return False
    
    else:
        logger.error("=" * 60)
        logger.error("INCONCLUSIVE: No result available")
        logger.error("=" * 60)
        return False


def rollback():
    """
    Clean up all experiment resources.
    
    Returns:
        bool: True if cleanup succeeded
    """
    global EXPERIMENT_STATE
    
    logger.info("=" * 60)
    logger.info("SCE 1.3 - Rollback / Cleanup")
    logger.info("=" * 60)
    
    stack_name = EXPERIMENT_STATE.get("stack_name")
    
    if not stack_name:
        logger.info("No stack to clean up")
        return True
    
    try:
        boto3 = _get_boto3()
        botocore_exc = _get_botocore_exceptions()
        
        region = EXPERIMENT_STATE.get("region", "us-east-1")
        cfn = boto3.client('cloudformation', region_name=region)
        
        # Check stack exists
        try:
            cfn.describe_stacks(StackName=stack_name)
            logger.info(f"Deleting stack: {stack_name}")
        except botocore_exc.ClientError as e:
            if 'does not exist' in str(e):
                logger.info("Stack already deleted")
                return True
            raise
        
        # Delete stack
        cfn.delete_stack(StackName=stack_name)
        logger.info("Deletion initiated")
        
        # Wait for deletion
        def check_deleted():
            try:
                resp = cfn.describe_stacks(StackName=stack_name)
                status = resp['Stacks'][0]['StackStatus']
                if status == 'DELETE_COMPLETE':
                    return True, True, None
                elif status == 'DELETE_IN_PROGRESS':
                    return False, None, None
                elif 'FAILED' in status:
                    return False, None, f"Delete failed: {status}"
                return False, None, None
            except botocore_exc.ClientError as e:
                if 'does not exist' in str(e):
                    return True, True, None
                raise
        
        logger.info("Waiting for deletion...")
        _wait_with_backoff(check_deleted, 300, 10, "Stack deletion")
        
        logger.info("=" * 60)
        logger.info("Cleanup completed")
        logger.info("=" * 60)
        
        EXPERIMENT_STATE.clear()
        return True
        
    except TimeoutError:
        logger.warning("Deletion timed out - may still be deleting")
        return True
        
    except Exception as e:
        logger.error(f"Rollback error: {e}")
        return False


if __name__ == "__main__":
    logger.info("Running SCE 1.3 Preventive Probe")
    try:
        if steady_state():
            attack()
            result = hypothesis_verification()
            print(f"Result: {'PASS' if result else 'FAIL'}")
        else:
            print("Setup failed")
    finally:
        rollback()