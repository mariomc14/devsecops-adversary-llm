#!/usr/bin/env python3
"""
SCE Experiment 1.4 - Detective Probe
Validates CloudTrail detection of ModifyInstanceMetadataOptions API calls.

This experiment:
1. Creates an EC2 instance with IMDSv2 enforced
2. Sets up CloudTrail logging to detect IMDS modification attempts
3. Executes the attack (ModifyInstanceMetadataOptions)
4. Verifies CloudTrail captured the event within 30-minute SLA
"""

import json
import logging
import time
import os
import sys

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
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'boto3', '-q'])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Global configuration
EXPERIMENT_TAG = "sce-1-4-detective"
TIMESTAMP_SUFFIX = str(int(time.time()))
STACK_NAME = f"sce-experiment-1-4-{TIMESTAMP_SUFFIX}"
DETECTION_SLA_SECONDS = 1800  # 30-minute SLA for CloudTrail eventual consistency

# Global state storage
_experiment_state = {
    "stack_name": STACK_NAME,
    "instance_id": None,
    "trail_name": None,
    "bucket_name": None,
    "attack_timestamp": None,
    "region": None
}


def _get_boto3_client(service_name: str):
    """Get boto3 client with proper region handling."""
    session = boto3.Session()
    region = session.region_name or 'us-east-1'
    _experiment_state["region"] = region
    return boto3.client(service_name, region_name=region)


def _get_boto3_resource(service_name: str):
    """Get boto3 resource with proper region handling."""
    session = boto3.Session()
    region = session.region_name or 'us-east-1'
    _experiment_state["region"] = region
    return boto3.resource(service_name, region_name=region)


def _wait_with_backoff(check_func, max_wait_seconds: int, description: str) -> bool:
    """
    Poll with exponential backoff until check_func returns True or timeout.
    
    Args:
        check_func: Function that returns True when condition is met
        max_wait_seconds: Maximum time to wait
        description: Description for logging
    
    Returns:
        bool: True if condition met, False if timeout
    """
    start_time = time.monotonic()
    attempt = 0
    base_delay = 5
    max_delay = 60
    
    while (time.monotonic() - start_time) < max_wait_seconds:
        attempt += 1
        elapsed = int(time.monotonic() - start_time)
        
        try:
            if check_func():
                logger.info(f"{description}: SUCCESS after {elapsed}s (attempt {attempt})")
                return True
        except Exception as e:
            logger.warning(f"{description}: Attempt {attempt} failed with error: {e}")
        
        # Exponential backoff with jitter
        delay = min(base_delay * (2 ** min(attempt - 1, 5)), max_delay)
        remaining = max_wait_seconds - (time.monotonic() - start_time)
        
        if remaining > delay:
            logger.info(f"{description}: Waiting {delay}s before retry (elapsed: {elapsed}s, remaining: {int(remaining)}s)")
            time.sleep(delay)
        else:
            break
    
    logger.error(f"{description}: TIMEOUT after {max_wait_seconds}s")
    return False


def _get_cloudformation_template() -> str:
    """
    Generate CloudFormation template for the experiment.
    
    Creates:
    - VPC and subnet for EC2 instance
    - EC2 instance with IMDSv2 enforced
    - S3 bucket for CloudTrail logs
    - CloudTrail trail configured to log management events
    """
    account_id = _get_boto3_client('sts').get_caller_identity()['Account']
    region = _experiment_state.get("region", "us-east-1")
    
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"SCE Experiment 1.4 Detective Probe - CloudTrail IMDS Modification Detection - {TIMESTAMP_SUFFIX}",
        "Parameters": {
            "ExperimentTag": {
                "Type": "String",
                "Default": EXPERIMENT_TAG
            },
            "TimestampSuffix": {
                "Type": "String",
                "Default": TIMESTAMP_SUFFIX
            }
        },
        "Resources": {
            # VPC for EC2 instance
            "ExperimentVPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport": True,
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-1-4-vpc-{TIMESTAMP_SUFFIX}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": TIMESTAMP_SUFFIX}
                    ]
                }
            },
            # Subnet for EC2 instance
            "ExperimentSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "CidrBlock": "10.0.1.0/24",
                    "AvailabilityZone": {"Fn::Select": ["0", {"Fn::GetAZs": ""}]},
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-1-4-subnet-{TIMESTAMP_SUFFIX}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": TIMESTAMP_SUFFIX}
                    ]
                }
            },
            # Security Group (no inbound, minimal outbound)
            "ExperimentSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE 1.4 Experiment - Isolated security group",
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "-1",
                            "CidrIp": "127.0.0.1/32",
                            "Description": "Deny all outbound"
                        }
                    ],
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-1-4-sg-{TIMESTAMP_SUFFIX}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": TIMESTAMP_SUFFIX}
                    ]
                }
            },
            # EC2 Instance with IMDSv2 enforced (secure baseline)
            "ExperimentInstance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "InstanceType": "t3.micro",
                    "ImageId": {"Fn::Sub": "{{resolve:ssm:/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2}}"},
                    "SubnetId": {"Ref": "ExperimentSubnet"},
                    "SecurityGroupIds": [{"Ref": "ExperimentSecurityGroup"}],
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled"
                    },
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-1-4-instance-{TIMESTAMP_SUFFIX}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": TIMESTAMP_SUFFIX}
                    ]
                }
            },
            # S3 Bucket for CloudTrail logs
            "CloudTrailBucket": {
                "Type": "AWS::S3::Bucket",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "BucketName": f"sce-1-4-cloudtrail-{TIMESTAMP_SUFFIX}",
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True
                    },
                    "LifecycleConfiguration": {
                        "Rules": [
                            {
                                "Id": "DeleteAfter1Day",
                                "Status": "Enabled",
                                "ExpirationInDays": 1
                            }
                        ]
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": TIMESTAMP_SUFFIX}
                    ]
                }
            },
            # S3 Bucket Policy for CloudTrail
            "CloudTrailBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "CloudTrailBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSCloudTrailAclCheck",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:GetBucketAcl",
                                "Resource": {"Fn::Sub": "arn:aws:s3:::${CloudTrailBucket}"},
                                "Condition": {
                                    "StringEquals": {
                                        "AWS:SourceArn": {"Fn::Sub": f"arn:aws:cloudtrail:{region}:{account_id}:trail/sce-1-4-trail-{TIMESTAMP_SUFFIX}"}
                                    }
                                }
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {"Fn::Sub": f"arn:aws:s3:::${{CloudTrailBucket}}/AWSLogs/{account_id}/*"},
                                "Condition": {
                                    "StringEquals": {
                                        "s3:x-amz-acl": "bucket-owner-full-control",
                                        "AWS:SourceArn": {"Fn::Sub": f"arn:aws:cloudtrail:{region}:{account_id}:trail/sce-1-4-trail-{TIMESTAMP_SUFFIX}"}
                                    }
                                }
                            }
                        ]
                    }
                }
            },
            # CloudTrail Trail
            "ExperimentTrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": ["CloudTrailBucketPolicy"],
                "Properties": {
                    "TrailName": f"sce-1-4-trail-{TIMESTAMP_SUFFIX}",
                    "S3BucketName": {"Ref": "CloudTrailBucket"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": False,
                    "EnableLogFileValidation": True,
                    "EventSelectors": [
                        {
                            "ReadWriteType": "WriteOnly",
                            "IncludeManagementEvents": True,
                            "DataResources": []
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": TIMESTAMP_SUFFIX}
                    ]
                }
            }
        },
        "Outputs": {
            "InstanceId": {
                "Description": "EC2 Instance ID",
                "Value": {"Ref": "ExperimentInstance"},
                "Export": {"Name": f"sce-1-4-instance-id-{TIMESTAMP_SUFFIX}"}
            },
            "TrailName": {
                "Description": "CloudTrail Trail Name",
                "Value": {"Ref": "ExperimentTrail"},
                "Export": {"Name": f"sce-1-4-trail-name-{TIMESTAMP_SUFFIX}"}
            },
            "BucketName": {
                "Description": "CloudTrail S3 Bucket Name",
                "Value": {"Ref": "CloudTrailBucket"},
                "Export": {"Name": f"sce-1-4-bucket-name-{TIMESTAMP_SUFFIX}"}
            }
        }
    }
    
    return json.dumps(template)


def steady_state() -> bool:
    """
    Preparation block: Deploy CloudFormation stack with all required resources.
    
    Creates:
    - EC2 instance with IMDSv2 enforced
    - CloudTrail trail for API logging
    - S3 bucket for CloudTrail logs
    
    Returns:
        bool: True if setup successful, False otherwise
    """
    logger.info("=" * 60)
    logger.info("SCE EXPERIMENT 1.4 - DETECTIVE PROBE")
    logger.info("Validating CloudTrail detection of IMDS modification")
    logger.info("=" * 60)
    
    cfn_client = _get_boto3_client('cloudformation')
    
    try:
        # Check if stack already exists
        try:
            existing_stack = cfn_client.describe_stacks(StackName=STACK_NAME)
            stack_status = existing_stack['Stacks'][0]['StackStatus']
            
            if stack_status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                logger.warning(f"Stack {STACK_NAME} already exists with status {stack_status}. Retrieving outputs...")
                outputs = existing_stack['Stacks'][0].get('Outputs', [])
                for output in outputs:
                    if output['OutputKey'] == 'InstanceId':
                        _experiment_state['instance_id'] = output['OutputValue']
                    elif output['OutputKey'] == 'TrailName':
                        _experiment_state['trail_name'] = output['OutputValue']
                    elif output['OutputKey'] == 'BucketName':
                        _experiment_state['bucket_name'] = output['OutputValue']
                return True
            elif stack_status in ['CREATE_IN_PROGRESS', 'UPDATE_IN_PROGRESS']:
                logger.info(f"Stack {STACK_NAME} is in progress. Waiting for completion...")
            else:
                logger.warning(f"Stack {STACK_NAME} in unexpected state {stack_status}. Attempting to delete and recreate...")
                cfn_client.delete_stack(StackName=STACK_NAME)
                waiter = cfn_client.get_waiter('stack_delete_complete')
                waiter.wait(StackName=STACK_NAME, WaiterConfig={'Delay': 10, 'MaxAttempts': 60})
                
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
            logger.info(f"Stack {STACK_NAME} does not exist. Creating...")
        
        # Create the stack
        logger.info(f"Creating CloudFormation stack: {STACK_NAME}")
        template_body = _get_cloudformation_template()
        
        cfn_client.create_stack(
            StackName=STACK_NAME,
            TemplateBody=template_body,
            Capabilities=['CAPABILITY_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': EXPERIMENT_TAG},
                {'Key': 'Timestamp', 'Value': TIMESTAMP_SUFFIX},
                {'Key': 'Purpose', 'Value': 'SCE-Detective-Probe-CloudTrail-IMDS'}
            ],
            OnFailure='DELETE'
        )
        
        logger.info("Waiting for stack creation to complete...")
        
        def check_stack_complete():
            response = cfn_client.describe_stacks(StackName=STACK_NAME)
            status = response['Stacks'][0]['StackStatus']
            
            if status == 'CREATE_COMPLETE':
                return True
            elif status in ['CREATE_FAILED', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED', 'DELETE_COMPLETE']:
                raise Exception(f"Stack creation failed with status: {status}")
            
            logger.info(f"Stack status: {status}")
            return False
        
        # Wait for stack creation with 15-minute timeout
        if not _wait_with_backoff(check_stack_complete, 900, "Stack creation"):
            logger.error("Stack creation timed out")
            return False
        
        # Get stack outputs
        response = cfn_client.describe_stacks(StackName=STACK_NAME)
        outputs = response['Stacks'][0].get('Outputs', [])
        
        for output in outputs:
            if output['OutputKey'] == 'InstanceId':
                _experiment_state['instance_id'] = output['OutputValue']
                logger.info(f"EC2 Instance ID: {output['OutputValue']}")
            elif output['OutputKey'] == 'TrailName':
                _experiment_state['trail_name'] = output['OutputValue']
                logger.info(f"CloudTrail Name: {output['OutputValue']}")
            elif output['OutputKey'] == 'BucketName':
                _experiment_state['bucket_name'] = output['OutputValue']
                logger.info(f"S3 Bucket Name: {output['OutputValue']}")
        
        # Verify instance is running
        ec2_client = _get_boto3_client('ec2')
        instance_id = _experiment_state['instance_id']
        
        def check_instance_running():
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            state = response['Reservations'][0]['Instances'][0]['State']['Name']
            return state == 'running'
        
        logger.info("Waiting for EC2 instance to be in running state...")
        if not _wait_with_backoff(check_instance_running, 300, "Instance running"):
            logger.error("Instance failed to reach running state")
            return False
        
        # Verify CloudTrail is logging
        cloudtrail_client = _get_boto3_client('cloudtrail')
        trail_name = _experiment_state['trail_name']
        
        def check_trail_logging():
            response = cloudtrail_client.get_trail_status(Name=trail_name)
            return response.get('IsLogging', False)
        
        logger.info("Verifying CloudTrail is actively logging...")
        if not _wait_with_backoff(check_trail_logging, 120, "CloudTrail logging"):
            logger.error("CloudTrail failed to start logging")
            return False
        
        # Verify baseline IMDS configuration (IMDSv2 enforced)
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        metadata_options = response['Reservations'][0]['Instances'][0].get('MetadataOptions', {})
        
        http_tokens = metadata_options.get('HttpTokens', 'optional')
        hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
        
        logger.info(f"Baseline IMDS Configuration:")
        logger.info(f"  HttpTokens: {http_tokens}")
        logger.info(f"  HttpPutResponseHopLimit: {hop_limit}")
        
        if http_tokens != 'required':
            logger.warning(f"Expected HttpTokens='required', got '{http_tokens}'")
        
        logger.info("Steady state established successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to establish steady state: {e}")
        return False


def attack() -> bool:
    """
    Execute the attack: Modify IMDS options to weaken security.
    
    This simulates Attack Step 1.3 from the attack tree:
    - Set HttpTokens to 'optional' (allowing IMDSv1)
    - Increase HttpPutResponseHopLimit to 2
    
    Returns:
        bool: True if attack executed successfully, False otherwise
    """
    logger.info("=" * 60)
    logger.info("EXECUTING ATTACK: Weaken IMDS Security Configuration")
    logger.info("=" * 60)
    
    instance_id = _experiment_state.get('instance_id')
    
    if not instance_id:
        logger.error("No instance ID found. Run steady_state() first.")
        return False
    
    ec2_client = _get_boto3_client('ec2')
    
    try:
        # Record the attack timestamp for CloudTrail query
        _experiment_state['attack_timestamp'] = time.time()
        attack_time_iso = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(_experiment_state['attack_timestamp']))
        
        logger.info(f"Attack timestamp: {attack_time_iso}")
        logger.info(f"Target instance: {instance_id}")
        logger.info("Executing: aws ec2 modify-instance-metadata-options")
        logger.info("  --http-tokens optional")
        logger.info("  --http-endpoint enabled")
        logger.info("  --http-put-response-hop-limit 2")
        
        # Execute the attack
        response = ec2_client.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='optional',
            HttpEndpoint='enabled',
            HttpPutResponseHopLimit=2
        )
        
        # Verify the modification was applied
        new_state = response.get('InstanceMetadataOptions', {})
        new_http_tokens = new_state.get('HttpTokens', 'unknown')
        new_hop_limit = new_state.get('HttpPutResponseHopLimit', 'unknown')
        
        logger.info("Attack executed. New IMDS configuration:")
        logger.info(f"  HttpTokens: {new_http_tokens}")
        logger.info(f"  HttpPutResponseHopLimit: {new_hop_limit}")
        
        if new_http_tokens == 'optional' and new_hop_limit == 2:
            logger.info("IMDS security successfully weakened (attack successful)")
            return True
        else:
            logger.warning("IMDS modification may not have fully applied")
            return True  # Attack was still executed
            
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        logger.error(f"Attack failed: {error_code} - {error_msg}")
        
        # If access denied, the preventive control is working
        if error_code == 'AccessDenied':
            logger.info("Preventive control blocked the attack (expected in hardened environments)")
            return False
        
        return False
    except Exception as e:
        logger.error(f"Unexpected error during attack: {e}")
        return False


def hypothesis_verification() -> bool:
    """
    Verify that CloudTrail detected the ModifyInstanceMetadataOptions API call.
    
    This validates the Detective probe from SCE Node 1.4:
    - Query CloudTrail for ModifyInstanceMetadataOptions events
    - Verify the event was captured with correct details
    - Implement 30-minute SLA for eventual consistency
    
    Returns:
        bool: True if CloudTrail detected the event, False otherwise
    """
    logger.info("=" * 60)
    logger.info("HYPOTHESIS VERIFICATION: CloudTrail Detection")
    logger.info("=" * 60)
    
    instance_id = _experiment_state.get('instance_id')
    trail_name = _experiment_state.get('trail_name')
    attack_timestamp = _experiment_state.get('attack_timestamp')
    region = _experiment_state.get('region', 'us-east-1')
    
    if not all([instance_id, trail_name, attack_timestamp]):
        logger.error("Missing experiment state. Ensure steady_state() and attack() were executed.")
        return False
    
    cloudtrail_client = _get_boto3_client('cloudtrail')
    
    # Calculate time window for CloudTrail lookup
    # Start 1 minute before attack, end at current time
    start_time = time.gmtime(attack_timestamp - 60)
    
    logger.info(f"Searching for ModifyInstanceMetadataOptions event...")
    logger.info(f"Instance ID: {instance_id}")
    logger.info(f"Trail: {trail_name}")
    logger.info(f"SLA: {DETECTION_SLA_SECONDS} seconds (30 minutes)")
    
    def check_cloudtrail_event():
        """Check if CloudTrail has captured the ModifyInstanceMetadataOptions event."""
        try:
            # Use LookupEvents to search for the specific API call
            response = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'ModifyInstanceMetadataOptions'
                    }
                ],
                StartTime=time.strftime('%Y-%m-%dT%H:%M:%SZ', start_time),
                EndTime=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
                MaxResults=50
            )
            
            events = response.get('Events', [])
            logger.info(f"Found {len(events)} ModifyInstanceMetadataOptions events")
            
            for event in events:
                event_time = event.get('EventTime')
                cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                
                # Check if this event is for our instance
                request_params = cloud_trail_event.get('requestParameters', {})
                event_instance_id = request_params.get('instanceId', '')
                
                if event_instance_id == instance_id:
                    logger.info("=" * 40)
                    logger.info("DETECTION CONFIRMED!")
                    logger.info("=" * 40)
                    logger.info(f"Event Time: {event_time}")
                    logger.info(f"Event ID: {event.get('EventId')}")
                    logger.info(f"Event Source: {cloud_trail_event.get('eventSource')}")
                    logger.info(f"User Identity: {cloud_trail_event.get('userIdentity', {}).get('arn', 'N/A')}")
                    logger.info(f"Source IP: {cloud_trail_event.get('sourceIPAddress', 'N/A')}")
                    logger.info(f"Request Parameters:")
                    logger.info(f"  instanceId: {request_params.get('instanceId')}")
                    logger.info(f"  httpTokens: {request_params.get('httpTokens')}")
                    logger.info(f"  httpPutResponseHopLimit: {request_params.get('httpPutResponseHopLimit')}")
                    
                    return True
            
            return False
            
        except ClientError as e:
            logger.warning(f"CloudTrail lookup error: {e}")
            return False
    
    # Wait for CloudTrail event with 30-minute SLA
    if _wait_with_backoff(check_cloudtrail_event, DETECTION_SLA_SECONDS, "CloudTrail detection"):
        logger.info("=" * 60)
        logger.info("HYPOTHESIS VERIFIED: Detective control is working")
        logger.info("CloudTrail successfully detected ModifyInstanceMetadataOptions API call")
        logger.info("=" * 60)
        return True
    else:
        logger.error("=" * 60)
        logger.error("HYPOTHESIS FAILED: Detective control did not detect the event")
        logger.error(f"CloudTrail did not capture the event within {DETECTION_SLA_SECONDS}s SLA")
        logger.error("=" * 60)
        return False


def rollback() -> bool:
    """
    Complete teardown: Delete CloudFormation stack and all resources.
    
    This function:
    - Deletes the CloudFormation stack
    - Waits for deletion to complete
    - Handles errors gracefully (stack not found, etc.)
    
    Returns:
        bool: True if rollback successful, False otherwise
    """
    logger.info("=" * 60)
    logger.info("ROLLBACK: Cleaning up experiment resources")
    logger.info("=" * 60)
    
    cfn_client = _get_boto3_client('cloudformation')
    stack_name = _experiment_state.get('stack_name', STACK_NAME)
    
    try:
        # First, try to revert IMDS settings if instance still exists
        instance_id = _experiment_state.get('instance_id')
        if instance_id:
            try:
                ec2_client = _get_boto3_client('ec2')
                logger.info(f"Reverting IMDS settings on instance {instance_id}...")
                ec2_client.modify_instance_metadata_options(
                    InstanceId=instance_id,
                    HttpTokens='required',
                    HttpPutResponseHopLimit=1
                )
                logger.info("IMDS settings reverted to secure configuration")
            except Exception as e:
                logger.warning(f"Could not revert IMDS settings: {e}")
        
        # Empty the S3 bucket before stack deletion
        bucket_name = _experiment_state.get('bucket_name')
        if bucket_name:
            try:
                s3_resource = _get_boto3_resource('s3')
                bucket = s3_resource.Bucket(bucket_name)
                logger.info(f"Emptying S3 bucket {bucket_name}...")
                bucket.objects.all().delete()
                logger.info("S3 bucket emptied")
            except Exception as e:
                logger.warning(f"Could not empty S3 bucket: {e}")
        
        # Delete the CloudFormation stack
        logger.info(f"Deleting CloudFormation stack: {stack_name}")
        
        try:
            cfn_client.delete_stack(StackName=stack_name)
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.info(f"Stack {stack_name} does not exist. Nothing to delete.")
                return True
            raise
        
        # Wait for stack deletion
        def check_stack_deleted():
            try:
                response = cfn_client.describe_stacks(StackName=stack_name)
                status = response['Stacks'][0]['StackStatus']
                
                if status == 'DELETE_COMPLETE':
                    return True
                elif status == 'DELETE_FAILED':
                    logger.error(f"Stack deletion failed. Status: {status}")
                    return False
                
                logger.info(f"Stack deletion in progress. Status: {status}")
                return False
                
            except ClientError as e:
                if 'does not exist' in str(e):
                    return True
                raise
        
        if _wait_with_backoff(check_stack_deleted, 900, "Stack deletion"):
            logger.info("Stack deleted successfully")
            return True
        else:
            logger.error("Stack deletion timed out")
            return False
            
    except Exception as e:
        logger.error(f"Error during rollback: {e}")
        return False


def run_experiment():
    """
    Run the complete SCE experiment.
    
    This function orchestrates:
    1. Steady state setup
    2. Attack execution
    3. Hypothesis verification
    4. Rollback (always executed)
    """
    logger.info("=" * 60)
    logger.info("STARTING SCE EXPERIMENT 1.4 - DETECTIVE PROBE")
    logger.info("=" * 60)
    
    success = False
    
    try:
        # Step 1: Establish steady state
        if not steady_state():
            logger.error("Failed to establish steady state")
            return False
        
        # Step 2: Execute attack
        if not attack():
            logger.warning("Attack may have been blocked by preventive controls")
            # Continue to verification - we want to see if CloudTrail caught any attempt
        
        # Step 3: Verify hypothesis
        success = hypothesis_verification()
        
        return success
        
    except Exception as e:
        logger.error(f"Experiment failed with exception: {e}")
        return False
        
    finally:
        # Always attempt rollback
        logger.info("Executing rollback regardless of experiment outcome...")
        rollback()
        
        if success:
            logger.info("=" * 60)
            logger.info("EXPERIMENT RESULT: PASSED")
            logger.info("Detective control validated successfully")
            logger.info("=" * 60)
        else:
            logger.info("=" * 60)
            logger.info("EXPERIMENT RESULT: FAILED")
            logger.info("Detective control did not meet expectations")
            logger.info("=" * 60)


# For direct execution
if __name__ == "__main__":
    run_experiment()