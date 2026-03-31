#!/usr/bin/env python3
"""
Security Chaos Engineering Experiment: 2.3 Detective Probe (PRODUCTION READY)
Attack Node: 1.2 (Enumerate IMDS), 2.2 (Modify IMDS Configuration)
Probe Type: Detective
Goal: Validate CloudTrail detection of unauthorized IMDS modifications

Production improvements:
- Better CloudFormation diagnostics and error recovery
- Simplified resource dependencies to reduce failure surface
- Adaptive timeout and retry logic
- Enhanced pre-flight validation
- Comprehensive event logging for troubleshooting
"""

import json
import time
import sys
import subprocess
import logging
from datetime import datetime, timedelta

# Configure logging with detailed output
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(funcName)s:%(lineno)d] %(message)s'
)
logger = logging.getLogger(__name__)

# Global state
EXPERIMENT_STATE = {
    'stack_name': None,
    'timestamp': None,
    'instance_id': None,
    'role_name': None,
    'cloudtrail_bucket': None,
    'attacker_principal_arn': None,
    'steady_state_complete': False,
    'stack_created': False,
}

# Ensure boto3 is installed
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    logger.info("Installing boto3...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "boto3"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError


def _get_aws_clients():
    """Initialize AWS service clients with error handling."""
    try:
        return {
            'ec2': boto3.client('ec2'),
            'iam': boto3.client('iam'),
            'cloudformation': boto3.client('cloudformation'),
            'cloudtrail': boto3.client('cloudtrail'),
            'logs': boto3.client('logs'),
            's3': boto3.client('s3'),
            'sts': boto3.client('sts'),
        }
    except Exception as e:
        logger.error(f"Failed to initialize AWS clients: {e}", exc_info=True)
        raise


def _retry_with_backoff(func, max_retries=12, initial_backoff=2, max_backoff=60):
    """Retry function with exponential backoff."""
    retries = 0
    backoff = initial_backoff
    start_time = time.monotonic()
    
    while retries < max_retries:
        try:
            return func()
        except Exception as e:
            retries += 1
            elapsed = time.monotonic() - start_time
            
            if retries >= max_retries:
                logger.error(f"Max retries ({max_retries}) exhausted after {elapsed:.1f}s. Last error: {e}")
                raise RuntimeError(f"Failed after {max_retries} retries: {str(e)[:200]}") from e
            
            backoff = min(backoff * 2, max_backoff)
            logger.debug(f"Attempt {retries}/{max_retries} failed: {str(e)[:100]}. Retrying in {backoff}s...")
            time.sleep(backoff)
    
    raise RuntimeError("Retry loop exhausted")


def _get_stack_events_for_diagnostics(stack_name, clients, limit=10):
    """Retrieve recent CloudFormation stack events for diagnostics."""
    try:
        cf = clients['cloudformation']
        events_response = cf.describe_stack_events(StackName=stack_name)
        events = sorted(events_response['StackEvents'], 
                       key=lambda x: x['Timestamp'], reverse=True)[:limit]
        
        logger.error("Recent CloudFormation events:")
        for event in events:
            status = event.get('ResourceStatus', 'UNKNOWN')
            resource = event.get('LogicalResourceId', 'N/A')
            reason = event.get('ResourceStatusReason', '')
            timestamp = event['Timestamp'].isoformat()
            
            # Highlight failures
            if 'FAILED' in status or 'ROLLBACK' in status:
                logger.error(f"  [{timestamp}] {status}: {resource} - {reason}")
            else:
                logger.debug(f"  [{timestamp}] {status}: {resource}")
    except Exception as e:
        logger.warning(f"Could not retrieve stack events for diagnostics: {e}")


def _wait_for_cloudformation_stack(stack_name, clients, timeout=1200, check_interval=15):
    """Wait for CloudFormation stack to complete creation."""
    cf = clients['cloudformation']
    start = time.time()
    last_status = None
    
    logger.info(f"Waiting for stack {stack_name} to complete (timeout: {timeout}s, check every {check_interval}s)...")
    
    while time.time() - start < timeout:
        try:
            response = cf.describe_stacks(StackName=stack_name)
            if not response['Stacks']:
                logger.warning("Stack not found in describe_stacks response")
                time.sleep(check_interval)
                continue
            
            stack = response['Stacks'][0]
            status = stack.get('StackStatus')
            elapsed = time.time() - start
            
            if status != last_status:
                logger.info(f"[{elapsed:.0f}s] Stack status: {status}")
                last_status = status
            
            # Success
            if status == 'CREATE_COMPLETE':
                logger.info(f"✓ Stack created successfully in {elapsed:.1f}s")
                return True
            
            # Rollback/failure
            elif status in ['ROLLBACK_COMPLETE', 'CREATE_FAILED', 'ROLLBACK_IN_PROGRESS']:
                logger.error(f"✗ Stack creation failed with status: {status}")
                _get_stack_events_for_diagnostics(stack_name, clients, limit=15)
                return False
            
            # Still creating
            else:
                time.sleep(check_interval)
        
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.warning("Stack not found (may still be initializing)")
                time.sleep(check_interval)
            else:
                logger.error(f"Error checking stack status: {e}")
                time.sleep(check_interval)
    
    logger.error(f"✗ Stack creation timed out after {timeout}s")
    _get_stack_events_for_diagnostics(stack_name, clients, limit=15)
    return False


def _get_latest_ami_id(clients):
    """Get latest Amazon Linux 2 AMI ID."""
    ec2 = clients['ec2']
    try:
        response = ec2.describe_images(
            Owners=['amazon'],
            Filters=[
                {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                {'Name': 'state', 'Values': ['available']},
                {'Name': 'root-device-type', 'Values': ['ebs']},
            ]
        )
        
        if not response['Images']:
            raise RuntimeError("No Amazon Linux 2 AMI found")
        
        images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
        ami_id = images[0]['ImageId']
        logger.info(f"Using AMI: {ami_id} (created: {images[0]['CreationDate']})")
        return ami_id
    except Exception as e:
        logger.error(f"Failed to retrieve AMI: {e}", exc_info=True)
        raise


def _create_cloudformation_template(ami_id):
    """Create simplified CloudFormation template with error recovery."""
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 2.3 Detective Probe - IMDS Modification Detection (Production Ready)",
        "Parameters": {
            "InstanceType": {
                "Type": "String",
                "Default": "t3.micro",
                "Description": "EC2 instance type"
            }
        },
        "Resources": {
            # S3 bucket for CloudTrail logs
            "CloudTrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": f"sce-ct-{EXPERIMENT_STATE['timestamp']}",
                    "VersioningConfiguration": {"Status": "Enabled"},
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-2.3"},
                        {"Key": "Timestamp", "Value": str(EXPERIMENT_STATE['timestamp'])}
                    ]
                }
            },
            
            # S3 bucket policy for CloudTrail
            "CloudTrailBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "CloudTrailBucket"},
                    "PolicyText": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSCloudTrailAclCheck",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:GetBucketAcl",
                                "Resource": {"Fn::GetAtt": ["CloudTrailBucket", "Arn"]}
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {"Fn::Sub": "${CloudTrailBucket.Arn}/*"},
                                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}
                            }
                        ]
                    }
                }
            },
            
            # CloudTrail trail (simplified)
            "SCECloudTrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": "CloudTrailBucketPolicy",
                "Properties": {
                    "TrailName": f"sce-trail-{EXPERIMENT_STATE['timestamp']}",
                    "S3BucketName": {"Ref": "CloudTrailBucket"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": False,
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-2.3"},
                        {"Key": "Timestamp", "Value": str(EXPERIMENT_STATE['timestamp'])}
                    ]
                }
            },
            
            # CloudWatch Log Group
            "CloudTrailLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": f"/aws/cloudtrail/sce-{EXPERIMENT_STATE['timestamp']}",
                    "RetentionInDays": 3
                }
            },
            
            # Security Group
            "TestInstanceSG": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE test instance security group",
                    "SecurityGroupEgress": [
                        {"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-2.3"},
                        {"Key": "Timestamp", "Value": str(EXPERIMENT_STATE['timestamp'])}
                    ]
                }
            },
            
            # IAM Role for EC2 instance
            "TestInstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-test-role-{EXPERIMENT_STATE['timestamp']}",
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
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-2.3"},
                        {"Key": "Timestamp", "Value": str(EXPERIMENT_STATE['timestamp'])}
                    ]
                }
            },
            
            # Instance Profile
            "TestInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": f"sce-profile-{EXPERIMENT_STATE['timestamp']}",
                    "Roles": [{"Ref": "TestInstanceRole"}]
                }
            },
            
            # EC2 Instance
            "TestInstance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": ami_id,
                    "InstanceType": {"Ref": "InstanceType"},
                    "IamInstanceProfile": {"Ref": "TestInstanceProfile"},
                    "SecurityGroupIds": [{"Ref": "TestInstanceSG"}],
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled"
                    },
                    "TagSpecifications": [
                        {
                            "ResourceType": "instance",
                            "Tags": [
                                {"Key": "Name", "Value": f"sce-instance-{EXPERIMENT_STATE['timestamp']}"},
                                {"Key": "Experiment", "Value": "SCE-2.3"},
                                {"Key": "Timestamp", "Value": str(EXPERIMENT_STATE['timestamp'])}
                            ]
                        }
                    ]
                }
            },
            
            # IAM Role for attacker
            "AttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-attacker-{EXPERIMENT_STATE['timestamp']}",
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
                    "Policies": [
                        {
                            "PolicyName": "EC2Modify",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:DescribeInstances",
                                            "ec2:ModifyInstanceMetadataOptions"
                                        ],
                                        "Resource": "*"
                                    }
                                ]
                            }
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-2.3"},
                        {"Key": "Timestamp", "Value": str(EXPERIMENT_STATE['timestamp'])}
                    ]
                }
            }
        },
        "Outputs": {
            "TestInstanceId": {
                "Description": "Instance ID",
                "Value": {"Ref": "TestInstance"}
            },
            "CloudTrailBucket": {
                "Description": "CloudTrail bucket",
                "Value": {"Ref": "CloudTrailBucket"}
            },
            "AttackerRoleArn": {
                "Description": "Attacker role ARN",
                "Value": {"Fn::GetAtt": ["AttackerRole", "Arn"]}
            }
        }
    }
    
    return json.dumps(template)


def steady_state():
    """Prepare test infrastructure."""
    global EXPERIMENT_STATE
    
    logger.info("=" * 80)
    logger.info("PHASE 1: STEADY STATE - Infrastructure Preparation")
    logger.info("=" * 80)
    
    EXPERIMENT_STATE['timestamp'] = int(time.time())
    EXPERIMENT_STATE['stack_name'] = f"sce-experiment-{EXPERIMENT_STATE['timestamp']}"
    
    logger.info(f"Stack name: {EXPERIMENT_STATE['stack_name']}")
    logger.info(f"Timestamp: {EXPERIMENT_STATE['timestamp']}")
    
    try:
        clients = _get_aws_clients()
        ami_id = _get_latest_ami_id(clients)
        template = _create_cloudformation_template(ami_id)
        
        cf = clients['cloudformation']
        logger.info(f"Creating CloudFormation stack...")
        
        cf.create_stack(
            StackName=EXPERIMENT_STATE['stack_name'],
            TemplateBody=template,
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': 'SCE-2.3'},
                {'Key': 'Timestamp', 'Value': str(EXPERIMENT_STATE['timestamp'])}
            ]
        )
        
        EXPERIMENT_STATE['stack_created'] = True
        logger.info(f"✓ Stack creation initiated")
        
        # Wait for stack creation
        if not _wait_for_cloudformation_stack(EXPERIMENT_STATE['stack_name'], clients, timeout=1200):
            raise RuntimeError("Stack creation failed or timed out")
        
        # Get outputs
        logger.info("Retrieving stack outputs...")
        response = cf.describe_stacks(StackName=EXPERIMENT_STATE['stack_name'])
        stack = response['Stacks'][0]
        
        if stack['StackStatus'] != 'CREATE_COMPLETE':
            raise RuntimeError(f"Stack status: {stack['StackStatus']}")
        
        outputs = {o['OutputKey']: o['OutputValue'] for o in stack.get('Outputs', [])}
        
        EXPERIMENT_STATE['instance_id'] = outputs.get('TestInstanceId')
        EXPERIMENT_STATE['cloudtrail_bucket'] = outputs.get('CloudTrailBucket')
        EXPERIMENT_STATE['attacker_principal_arn'] = outputs.get('AttackerRoleArn')
        
        if not all([EXPERIMENT_STATE['instance_id'], EXPERIMENT_STATE['attacker_principal_arn']]):
            raise RuntimeError("Missing required stack outputs")
        
        logger.info(f"✓ Instance ID: {EXPERIMENT_STATE['instance_id']}")
        logger.info(f"✓ Attacker ARN: {EXPERIMENT_STATE['attacker_principal_arn']}")
        
        # Wait for eventual consistency
        logger.info("Waiting for AWS eventual consistency (120s)...")
        time.sleep(120)
        
        # Verify instance running
        ec2 = clients['ec2']
        instances = ec2.describe_instances(InstanceIds=[EXPERIMENT_STATE['instance_id']])
        state = instances['Reservations'][0]['Instances'][0]['State']['Name']
        logger.info(f"✓ Instance state: {state}")
        
        EXPERIMENT_STATE['steady_state_complete'] = True
        logger.info("✓ Steady state completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"✗ Steady state failed: {e}", exc_info=True)
        raise


def attack():
    """Execute attack steps 1.2 and 2.2."""
    global EXPERIMENT_STATE
    
    logger.info("=" * 80)
    logger.info("PHASE 2: ATTACK - Execute Steps 1.2 & 2.2")
    logger.info("=" * 80)
    
    if not EXPERIMENT_STATE['steady_state_complete']:
        raise RuntimeError("Steady state must complete first")
    
    try:
        clients = _get_aws_clients()
        sts = clients['sts']
        
        # Assume attacker role
        logger.info(f"Assuming attacker role: {EXPERIMENT_STATE['attacker_principal_arn']}")
        assumed_role = sts.assume_role(
            RoleArn=EXPERIMENT_STATE['attacker_principal_arn'],
            RoleSessionName='sce-attacker',
            DurationSeconds=3600
        )
        
        creds = assumed_role['Credentials']
        attacker_ec2 = boto3.client(
            'ec2',
            aws_access_key_id=creds['AccessKeyId'],
            aws_secret_access_key=creds['SecretAccessKey'],
            aws_session_token=creds['SessionToken']
        )
        
        # Attack 1.2: Enumerate
        logger.info("\n[Attack 1.2] Enumerate IMDS Configuration (T1526)")
        response = attacker_ec2.describe_instances(InstanceIds=[EXPERIMENT_STATE['instance_id']])
        instance = response['Reservations'][0]['Instances'][0]
        metadata = instance.get('MetadataOptions', {})
        
        baseline_tokens = metadata.get('HttpTokens')
        baseline_hop = metadata.get('HttpPutResponseHopLimit')
        logger.info(f"  Baseline: HttpTokens={baseline_tokens}, HopLimit={baseline_hop}")
        
        # Attack 2.2: Modify
        logger.info("\n[Attack 2.2] Modify IMDS Configuration (T1578.001)")
        attacker_ec2.modify_instance_metadata_options(
            InstanceId=EXPERIMENT_STATE['instance_id'],
            HttpTokens='optional',
            HttpPutResponseHopLimit=2
        )
        logger.info(f"  Modification requested")
        
        # Wait and verify
        time.sleep(30)
        response = attacker_ec2.describe_instances(InstanceIds=[EXPERIMENT_STATE['instance_id']])
        instance = response['Reservations'][0]['Instances'][0]
        metadata = instance.get('MetadataOptions', {})
        
        final_tokens = metadata.get('HttpTokens')
        final_hop = metadata.get('HttpPutResponseHopLimit')
        logger.info(f"  After modification: HttpTokens={final_tokens}, HopLimit={final_hop}")
        
        if final_tokens == 'optional' and final_hop == 2:
            logger.info(f"✓ Attack successful: IMDS weakened")
            return True
        else:
            logger.warning(f"✗ Attack may not have applied yet")
            return False
        
    except Exception as e:
        logger.error(f"✗ Attack execution failed: {e}", exc_info=True)
        raise


def hypothesis_verification():
    """Verify detective controls detected IMDS modification."""
    global EXPERIMENT_STATE
    
    logger.info("=" * 80)
    logger.info("PHASE 3: HYPOTHESIS VERIFICATION - Detective Controls")
    logger.info("=" * 80)
    
    if not EXPERIMENT_STATE['instance_id']:
        raise RuntimeError("Instance ID not available")
    
    clients = _get_aws_clients()
    
    # SLA: 30 minutes for CloudTrail event delivery
    sla_seconds = 1800
    poll_interval = 20
    start_time = time.monotonic()
    
    logger.info(f"SLA: {sla_seconds}s | Poll interval: {poll_interval}s | Instance: {EXPERIMENT_STATE['instance_id']}")
    
    cloudtrail_detected = False
    
    while time.monotonic() - start_time < sla_seconds:
        elapsed = time.monotonic() - start_time
        
        try:
            logger.info(f"\n[{elapsed:.0f}s] Checking CloudTrail for ModifyInstanceMetadataOptions...")
            
            ct = clients['cloudtrail']
            events = ct.lookup_events(
                LookupAttributes=[{'AttributeKey': 'EventName', 'Value': 'ModifyInstanceMetadataOptions'}],
                MaxResults=50,
                StartTime=datetime.utcnow() - timedelta(hours=1)
            )
            
            for event in events.get('Events', []):
                event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                request = event_data.get('requestParameters', {})
                instance_id = request.get('instanceId', '')
                
                if instance_id == EXPERIMENT_STATE['instance_id']:
                    logger.info(f"  ✓ Found ModifyInstanceMetadataOptions event!")
                    logger.info(f"    EventTime: {event['EventTime']}")
                    logger.info(f"    HttpTokens: {request.get('httpTokens')}")
                    logger.info(f"    HopLimit: {request.get('httpPutResponseHopLimit')}")
                    
                    if (request.get('httpTokens') == 'optional' and 
                        request.get('httpPutResponseHopLimit') == 2):
                        cloudtrail_detected = True
                        logger.info(f"✓ HYPOTHESIS VERIFIED: Detective detected weakening parameters")
                        logger.info(f"  Detection time: {elapsed:.1f}s (SLA: {sla_seconds}s)")
                        return True
        
        except ClientError as e:
            if 'LookupEventsRateLimitExceededException' not in str(e):
                logger.debug(f"  CloudTrail error: {e}")
        
        except Exception as e:
            logger.debug(f"  Error during check: {e}")
        
        remaining = sla_seconds - elapsed
        if remaining > poll_interval:
            logger.debug(f"  No detection yet. Retrying in {poll_interval}s...")
            time.sleep(poll_interval)
        else:
            time.sleep(min(poll_interval, remaining))
    
    # SLA expired
    logger.error(f"\n✗ HYPOTHESIS FAILED: Detective did not detect modification within {sla_seconds}s SLA")
    return False


def rollback():
    """Clean up infrastructure."""
    global EXPERIMENT_STATE
    
    logger.info("=" * 80)
    logger.info("PHASE 4: ROLLBACK - Infrastructure Cleanup")
    logger.info("=" * 80)
    
    if not EXPERIMENT_STATE['stack_name']:
        logger.warning("No stack to clean up")
        return True
    
    try:
        clients = _get_aws_clients()
        cf = clients['cloudformation']
        
        # Delete stack
        logger.info(f"Deleting CloudFormation stack: {EXPERIMENT_STATE['stack_name']}")
        try:
            cf.delete_stack(StackName=EXPERIMENT_STATE['stack_name'])
            logger.info(f"✓ Stack deletion initiated")
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.info("Stack already deleted")
                return True
            raise
        
        # Wait for deletion
        waiter = cf.get_waiter('stack_delete_complete')
        try:
            logger.info("Waiting for stack deletion...")
            waiter.wait(
                StackName=EXPERIMENT_STATE['stack_name'],
                WaiterConfig={'Delay': 15, 'MaxAttempts': 120}
            )
            logger.info(f"✓ Stack deleted successfully")
            return True
        except WaiterError as e:
            logger.error(f"Stack deletion timed out: {e}")
            return False
        
    except Exception as e:
        logger.error(f"Rollback error: {e}", exc_info=True)
        return False


# Main execution
if __name__ == '__main__':
    logger.info("SCE 2.3 Detective Probe - Standalone Runner (Production Ready)")
    
    try:
        logger.info("\nExecuting experiment workflow...")
        steady_state()
        attack()
        result = hypothesis_verification()
        
        if result:
            logger.info("\n" + "=" * 80)
            logger.info("✓✓✓ EXPERIMENT PASSED ✓✓✓")
            logger.info("=" * 80)
        else:
            logger.error("\n" + "=" * 80)
            logger.error("✗✗✗ EXPERIMENT FAILED ✗✗✗")
            logger.error("=" * 80)
    
    except Exception as e:
        logger.error(f"\n✗ Experiment error: {e}")
    
    finally:
        try:
            rollback()
        except Exception as e:
            logger.error(f"Rollback error: {e}")