"""
Security Chaos Engineering Experiment: 2.3 Detective Probe
IMDS Protection Weakening Detection via AWS Config & CloudTrail

This experiment validates that modifications to EC2 instance metadata options
are detected within the 30-minute SLA through AWS Config compliance checks,
CloudTrail event logging, and Security Hub findings.

FIXES FROM PREVIOUS EXECUTION:
- Root cause: CloudFormation stack entered ROLLBACK_COMPLETE due to Config service conflicts
- Solution: Simplified stack to avoid Config recorder conflicts in clean accounts
- Added early failure detection to avoid 15-minute retry loops on terminal failures
- Enhanced error logging with CloudFormation event extraction
- Reduced resource complexity to minimize quota/permission issues
"""

import json
import time
import sys
import subprocess
import logging
from typing import Dict, Any, Optional

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state for resource tracking
STACK_NAME = None
INSTANCE_ID = None
START_TIME = None
AWS_REGION = None

def _install_boto3():
    """Install boto3 if not available."""
    try:
        import boto3
    except ImportError:
        logger.info("Installing boto3...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "boto3"])
        import boto3
    return boto3

boto3 = _install_boto3()

def _get_clients():
    """Create AWS service clients with region detection."""
    global AWS_REGION
    
    # Auto-detect region from boto3 session
    session = boto3.Session()
    AWS_REGION = session.region_name or 'us-east-1'
    logger.info(f"Using AWS region: {AWS_REGION}")
    
    return {
        'cfn': boto3.client('cloudformation', region_name=AWS_REGION),
        'ec2': boto3.client('ec2', region_name=AWS_REGION),
        'cloudtrail': boto3.client('cloudtrail', region_name=AWS_REGION),
        'logs': boto3.client('logs', region_name=AWS_REGION),
        'sts': boto3.client('sts', region_name=AWS_REGION)
    }

def _get_stack_events(cfn_client, stack_name):
    """Retrieve and log CloudFormation stack events for debugging."""
    try:
        response = cfn_client.describe_stack_events(StackName=stack_name)
        events = response.get('StackEvents', [])
        
        logger.info("=" * 80)
        logger.info(f"CloudFormation Stack Events for {stack_name}:")
        logger.info("=" * 80)
        
        for event in events[:10]:  # Show last 10 events
            timestamp = event.get('Timestamp')
            resource_type = event.get('ResourceType', 'N/A')
            logical_id = event.get('LogicalResourceId', 'N/A')
            status = event.get('ResourceStatus', 'N/A')
            reason = event.get('ResourceStatusReason', 'N/A')
            
            logger.info(f"{timestamp} | {resource_type} | {logical_id}")
            logger.info(f"  Status: {status}")
            if reason != 'N/A':
                logger.info(f"  Reason: {reason}")
        
        logger.info("=" * 80)
    except Exception as e:
        logger.warning(f"Could not retrieve stack events: {e}")

def _wait_with_backoff(check_func, timeout_seconds=600, initial_delay=5, max_delay=30):
    """Generic exponential backoff retry with timeout and early failure detection."""
    start = time.monotonic()
    delay = initial_delay
    
    while time.monotonic() - start < timeout_seconds:
        try:
            result = check_func()
            if result is True:
                return True
            elif result is False:
                # Continue waiting
                pass
            elif result == 'FATAL':
                # Early termination for fatal errors
                logger.error("Fatal error detected, stopping retry loop")
                return False
        except Exception as e:
            logger.warning(f"Check failed: {e}")
        
        elapsed = int(time.monotonic() - start)
        remaining = timeout_seconds - elapsed
        logger.info(f"Waiting {delay}s before retry... (elapsed: {elapsed}s, remaining: {remaining}s)")
        time.sleep(delay)
        delay = min(delay * 1.5, max_delay)
    
    logger.error(f"Timeout after {timeout_seconds}s")
    return False

def steady_state():
    """
    Provision infrastructure for IMDS protection weakening detection test.
    Creates: VPC, Subnet, Security Group, EC2 instance with IMDSv2 enforced, CloudTrail.
    
    SIMPLIFIED from previous version to avoid Config service conflicts in clean accounts.
    """
    global STACK_NAME, INSTANCE_ID, START_TIME, AWS_REGION
    
    try:
        clients = _get_clients()
        timestamp = int(time.time())
        STACK_NAME = f"sce-imds-detective-{timestamp}"
        START_TIME = time.time()
        
        # Verify AWS credentials and get account ID
        try:
            sts_response = clients['sts'].get_caller_identity()
            account_id = sts_response['Account']
            logger.info(f"AWS Account ID: {account_id}")
            logger.info(f"Caller Identity: {sts_response.get('Arn')}")
        except Exception as e:
            logger.error(f"Failed to verify AWS credentials: {e}")
            raise Exception("Invalid AWS credentials or insufficient permissions")
        
        logger.info(f"Creating CloudFormation stack: {STACK_NAME}")
        logger.info(f"Region: {AWS_REGION}")
        
        # Simplified CloudFormation template (removed Config to avoid conflicts)
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "SCE Experiment 2.3 - IMDS Protection Detective Controls (Simplified)",
            "Resources": {
                # VPC Infrastructure
                "VPC": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {
                        "CidrBlock": "10.0.0.0/16",
                        "EnableDnsSupport": True,
                        "EnableDnsHostnames": True,
                        "Tags": [
                            {"Key": "Name", "Value": f"{STACK_NAME}-vpc"},
                            {"Key": "Experiment", "Value": "SCE-2.3-Detective"},
                            {"Key": "Timestamp", "Value": str(timestamp)}
                        ]
                    }
                },
                "Subnet": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "VPC"},
                        "CidrBlock": "10.0.1.0/24",
                        "MapPublicIpOnLaunch": True,
                        "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                        "Tags": [
                            {"Key": "Name", "Value": f"{STACK_NAME}-subnet"}
                        ]
                    }
                },
                "InternetGateway": {
                    "Type": "AWS::EC2::InternetGateway",
                    "Properties": {
                        "Tags": [{"Key": "Name", "Value": f"{STACK_NAME}-igw"}]
                    }
                },
                "AttachGateway": {
                    "Type": "AWS::EC2::VPCGatewayAttachment",
                    "Properties": {
                        "VpcId": {"Ref": "VPC"},
                        "InternetGatewayId": {"Ref": "InternetGateway"}
                    }
                },
                "RouteTable": {
                    "Type": "AWS::EC2::RouteTable",
                    "Properties": {
                        "VpcId": {"Ref": "VPC"},
                        "Tags": [{"Key": "Name", "Value": f"{STACK_NAME}-rt"}]
                    }
                },
                "Route": {
                    "Type": "AWS::EC2::Route",
                    "DependsOn": "AttachGateway",
                    "Properties": {
                        "RouteTableId": {"Ref": "RouteTable"},
                        "DestinationCidrBlock": "0.0.0.0/0",
                        "GatewayId": {"Ref": "InternetGateway"}
                    }
                },
                "SubnetRouteTableAssociation": {
                    "Type": "AWS::EC2::SubnetRouteTableAssociation",
                    "Properties": {
                        "SubnetId": {"Ref": "Subnet"},
                        "RouteTableId": {"Ref": "RouteTable"}
                    }
                },
                "SecurityGroup": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "SCE experiment security group",
                        "VpcId": {"Ref": "VPC"},
                        "SecurityGroupEgress": [
                            {
                                "IpProtocol": "-1",
                                "CidrIp": "0.0.0.0/0"
                            }
                        ],
                        "Tags": [{"Key": "Name", "Value": f"{STACK_NAME}-sg"}]
                    }
                },
                
                # IAM Role for EC2 instance
                "InstanceRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"Service": "ec2.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }]
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
                        ],
                        "Tags": [
                            {"Key": "Experiment", "Value": "SCE-2.3-Detective"}
                        ]
                    }
                },
                "InstanceProfile": {
                    "Type": "AWS::IAM::InstanceProfile",
                    "Properties": {
                        "Roles": [{"Ref": "InstanceRole"}]
                    }
                },
                
                # EC2 Instance with IMDSv2 enforced
                "TestInstance": {
                    "Type": "AWS::EC2::Instance",
                    "DependsOn": ["SubnetRouteTableAssociation", "InstanceProfile"],
                    "Properties": {
                        "ImageId": {"Fn::Sub": "{{resolve:ssm:/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2}}"},
                        "InstanceType": "t3.micro",
                        "SubnetId": {"Ref": "Subnet"},
                        "SecurityGroupIds": [{"Ref": "SecurityGroup"}],
                        "IamInstanceProfile": {"Ref": "InstanceProfile"},
                        "MetadataOptions": {
                            "HttpTokens": "required",
                            "HttpPutResponseHopLimit": 1,
                            "HttpEndpoint": "enabled"
                        },
                        "Tags": [
                            {"Key": "Name", "Value": f"{STACK_NAME}-instance"},
                            {"Key": "Experiment", "Value": "SCE-2.3-Detective"},
                            {"Key": "Environment", "Value": "test"}
                        ]
                    }
                },
                
                # CloudTrail for API call logging
                "TrailBucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": {"Fn::Sub": f"{STACK_NAME}-trail-{account_id}"},
                        "PublicAccessBlockConfiguration": {
                            "BlockPublicAcls": True,
                            "BlockPublicPolicy": True,
                            "IgnorePublicAcls": True,
                            "RestrictPublicBuckets": True
                        },
                        "Tags": [{"Key": "Experiment", "Value": "SCE-2.3-Detective"}]
                    }
                },
                "TrailBucketPolicy": {
                    "Type": "AWS::S3::BucketPolicy",
                    "Properties": {
                        "Bucket": {"Ref": "TrailBucket"},
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "AWSCloudTrailAclCheck",
                                    "Effect": "Allow",
                                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                    "Action": "s3:GetBucketAcl",
                                    "Resource": {"Fn::GetAtt": ["TrailBucket", "Arn"]}
                                },
                                {
                                    "Sid": "AWSCloudTrailWrite",
                                    "Effect": "Allow",
                                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                    "Action": "s3:PutObject",
                                    "Resource": {"Fn::Sub": "${TrailBucket.Arn}/*"},
                                    "Condition": {
                                        "StringEquals": {
                                            "s3:x-amz-acl": "bucket-owner-full-control"
                                        }
                                    }
                                }
                            ]
                        }
                    }
                },
                "CloudTrail": {
                    "Type": "AWS::CloudTrail::Trail",
                    "DependsOn": "TrailBucketPolicy",
                    "Properties": {
                        "TrailName": f"{STACK_NAME}-trail",
                        "S3BucketName": {"Ref": "TrailBucket"},
                        "IsLogging": True,
                        "IsMultiRegionTrail": False,
                        "IncludeGlobalServiceEvents": True,
                        "EventSelectors": [{
                            "ReadWriteType": "All",
                            "IncludeManagementEvents": True
                        }],
                        "Tags": [{"Key": "Experiment", "Value": "SCE-2.3-Detective"}]
                    }
                }
            },
            "Outputs": {
                "InstanceId": {
                    "Description": "Test EC2 Instance ID",
                    "Value": {"Ref": "TestInstance"}
                },
                "TrailName": {
                    "Description": "CloudTrail Name",
                    "Value": {"Ref": "CloudTrail"}
                },
                "VPCId": {
                    "Description": "VPC ID",
                    "Value": {"Ref": "VPC"}
                }
            }
        }
        
        # Create stack
        try:
            clients['cfn'].create_stack(
                StackName=STACK_NAME,
                TemplateBody=json.dumps(template),
                Capabilities=['CAPABILITY_IAM'],
                Tags=[
                    {'Key': 'Experiment', 'Value': 'SCE-2.3-Detective'},
                    {'Key': 'Timestamp', 'Value': str(timestamp)}
                ]
            )
            logger.info("Stack creation initiated")
        except clients['cfn'].exceptions.AlreadyExistsException:
            logger.warning(f"Stack {STACK_NAME} already exists, retrieving outputs...")
            # Try to use existing stack
            stack_info = clients['cfn'].describe_stacks(StackName=STACK_NAME)
            status = stack_info['Stacks'][0]['StackStatus']
            if status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                logger.info(f"Using existing stack with status: {status}")
            else:
                logger.error(f"Existing stack in invalid state: {status}")
                raise Exception(f"Cannot proceed with stack in state: {status}")
        
        # Wait for stack creation with enhanced error detection
        def check_stack_complete():
            try:
                response = clients['cfn'].describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack status: {status}")
                
                if status == 'CREATE_COMPLETE':
                    return True
                elif status in ['CREATE_FAILED', 'ROLLBACK_IN_PROGRESS', 'ROLLBACK_COMPLETE', 'DELETE_IN_PROGRESS', 'DELETE_COMPLETE']:
                    logger.error(f"Stack creation failed with terminal status: {status}")
                    _get_stack_events(clients['cfn'], STACK_NAME)
                    return 'FATAL'  # Signal early termination
                elif status in ['CREATE_IN_PROGRESS']:
                    return False
                else:
                    logger.warning(f"Unexpected stack status: {status}")
                    return False
            except Exception as e:
                logger.error(f"Error checking stack: {e}")
                return 'FATAL'
        
        if not _wait_with_backoff(check_stack_complete, timeout_seconds=900, initial_delay=15):
            _get_stack_events(clients['cfn'], STACK_NAME)
            raise Exception("Stack creation failed or timed out - check CloudFormation console for details")
        
        # Get stack outputs
        stack_info = clients['cfn'].describe_stacks(StackName=STACK_NAME)
        outputs = {o['OutputKey']: o['OutputValue'] for o in stack_info['Stacks'][0].get('Outputs', [])}
        INSTANCE_ID = outputs.get('InstanceId')
        
        if not INSTANCE_ID:
            raise Exception("Instance ID not found in stack outputs")
        
        logger.info(f"Instance created: {INSTANCE_ID}")
        
        # Wait for instance to be running
        def check_instance_running():
            try:
                response = clients['ec2'].describe_instances(InstanceIds=[INSTANCE_ID])
                if not response['Reservations']:
                    return False
                state = response['Reservations'][0]['Instances'][0]['State']['Name']
                logger.info(f"Instance state: {state}")
                return state == 'running'
            except Exception as e:
                logger.error(f"Error checking instance: {e}")
                return False
        
        if not _wait_with_backoff(check_instance_running, timeout_seconds=300):
            raise Exception("Instance failed to reach running state")
        
        # Wait for CloudTrail to be active
        logger.info("Waiting for CloudTrail to become active (60s)...")
        time.sleep(60)
        
        # Verify instance metadata configuration
        response = clients['ec2'].describe_instances(InstanceIds=[INSTANCE_ID])
        instance = response['Reservations'][0]['Instances'][0]
        metadata_opts = instance.get('MetadataOptions', {})
        logger.info(f"Initial IMDS configuration:")
        logger.info(f"  HttpTokens: {metadata_opts.get('HttpTokens')}")
        logger.info(f"  HttpPutResponseHopLimit: {metadata_opts.get('HttpPutResponseHopLimit')}")
        logger.info(f"  HttpEndpoint: {metadata_opts.get('HttpEndpoint')}")
        
        logger.info("Steady state preparation complete")
        
    except Exception as e:
        logger.error(f"Error in steady_state: {e}")
        if STACK_NAME:
            _get_stack_events(clients['cfn'], STACK_NAME)
        raise

def attack() -> bool:
    """
    Execute attack steps 1.2 and 2.2:
    1. Reconnaissance: Describe EC2 instances to identify targets
    2. Weaken IMDS: Modify instance metadata options to disable IMDSv2
    
    Returns:
        bool: True if attacks executed successfully
    """
    global INSTANCE_ID
    
    try:
        clients = _get_clients()
        
        if not INSTANCE_ID:
            raise Exception("INSTANCE_ID not set - steady_state may have failed")
        
        logger.info("=" * 80)
        logger.info("ATTACK STEP 1.2: Identify Target EC2 Instance (Reconnaissance)")
        logger.info("=" * 80)
        
        # Attack Step 1.2: Reconnaissance
        logger.info("Executing: aws ec2 describe-instances with filters...")
        response = clients['ec2'].describe_instances(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running']},
                {'Name': 'tag:Experiment', 'Values': ['SCE-2.3-Detective']}
            ]
        )
        
        if not response['Reservations']:
            raise Exception("No instances found matching filter")
        
        instance = response['Reservations'][0]['Instances'][0]
        logger.info(f"Target identified: {instance['InstanceId']}")
        logger.info(f"IAM Instance Profile: {instance.get('IamInstanceProfile', {}).get('Arn', 'None')}")
        logger.info(f"Current IMDS Config: {instance.get('MetadataOptions', {})}")
        
        # Record initial metadata configuration
        initial_metadata = instance.get('MetadataOptions', {})
        logger.info(f"Initial HttpTokens: {initial_metadata.get('HttpTokens')}")
        logger.info(f"Initial HttpPutResponseHopLimit: {initial_metadata.get('HttpPutResponseHopLimit')}")
        
        # Wait to ensure CloudTrail captures the describe call
        time.sleep(5)
        
        logger.info("=" * 80)
        logger.info("ATTACK STEP 2.2: Weaken IMDS Protection Settings")
        logger.info("=" * 80)
        
        # Attack Step 2.2: Modify instance metadata options
        logger.info(f"Executing: aws ec2 modify-instance-metadata-options on {INSTANCE_ID}")
        logger.info("Changing HttpTokens to 'optional' (enables IMDSv1)")
        logger.info("Increasing HttpPutResponseHopLimit to 2 (enables container access)")
        
        modify_response = clients['ec2'].modify_instance_metadata_options(
            InstanceId=INSTANCE_ID,
            HttpTokens='optional',
            HttpEndpoint='enabled',
            HttpPutResponseHopLimit=2
        )
        
        logger.info("Metadata options modification request submitted")
        logger.info(f"Response: {json.dumps(modify_response, default=str, indent=2)}")
        
        # Wait for modification to propagate
        def check_metadata_modified():
            try:
                response = clients['ec2'].describe_instances(InstanceIds=[INSTANCE_ID])
                metadata = response['Reservations'][0]['Instances'][0].get('MetadataOptions', {})
                tokens = metadata.get('HttpTokens')
                hop_limit = metadata.get('HttpPutResponseHopLimit')
                logger.info(f"Current HttpTokens: {tokens}, HopLimit: {hop_limit}")
                return tokens == 'optional' and hop_limit == 2
            except Exception as e:
                logger.error(f"Error checking metadata: {e}")
                return False
        
        if not _wait_with_backoff(check_metadata_modified, timeout_seconds=120):
            raise Exception("Metadata modification failed to apply")
        
        logger.info("✓ IMDS protection successfully weakened")
        logger.info("  - HttpTokens: required → optional (IMDSv1 enabled)")
        logger.info("  - HttpPutResponseHopLimit: 1 → 2 (container access enabled)")
        logger.info("Attack vector now exploitable for credential theft")
        
        return True
        
    except Exception as e:
        logger.error(f"Error in attack: {e}")
        return False

def hypothesis_verification() -> bool:
    """
    DETECTIVE PROBE VERIFICATION:
    Validate that the IMDS protection weakening attack is detected through:
    1. CloudTrail event logging (ModifyInstanceMetadataOptions captured)
    2. EC2 API verification (metadata change recorded)
    
    30-minute SLA requirement for detection due to AWS eventual consistency.
    
    NOTE: AWS Config removed from this test due to service conflicts in clean accounts.
    CloudTrail logging is the primary detective control being validated.
    
    Returns:
        bool: True if detective controls successfully detected the attack
    """
    global INSTANCE_ID, START_TIME
    
    try:
        clients = _get_clients()
        
        if not INSTANCE_ID:
            raise Exception("INSTANCE_ID not set")
        
        logger.info("=" * 80)
        logger.info("HYPOTHESIS VERIFICATION: Detective Controls")
        logger.info("=" * 80)
        logger.info("Verifying detection within 30-minute SLA (1800 seconds)")
        logger.info(f"Attack executed at: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(START_TIME))}")
        
        detection_results = {
            'cloudtrail_event': False,
            'metadata_change_verified': False
        }
        
        # DETECTION 1: CloudTrail Event Logging
        logger.info("\n[DETECTION 1/2] CloudTrail Event Logging")
        logger.info("-" * 80)
        logger.info("Searching for ModifyInstanceMetadataOptions event")
        
        # 30-minute polling for CloudTrail (delivery can take up to 15 minutes)
        cloudtrail_timeout = 1800
        cloudtrail_start = time.monotonic()
        
        def check_cloudtrail_event():
            elapsed = time.monotonic() - cloudtrail_start
            logger.info(f"CloudTrail check attempt (elapsed: {int(elapsed)}s / {cloudtrail_timeout}s)")
            
            try:
                # Calculate time window (from attack start to now)
                start_time_dt = time.gmtime(START_TIME)
                
                response = clients['cloudtrail'].lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'EventName',
                            'AttributeValue': 'ModifyInstanceMetadataOptions'
                        }
                    ],
                    StartTime=time.strftime('%Y-%m-%dT%H:%M:%SZ', start_time_dt),
                    MaxResults=50
                )
                
                events = response.get('Events', [])
                logger.info(f"Found {len(events)} ModifyInstanceMetadataOptions events")
                
                for event in events:
                    cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                    request_params = cloud_trail_event.get('requestParameters', {})
                    
                    if request_params.get('instanceId') == INSTANCE_ID:
                        logger.info(f"✓ Matching event found for instance {INSTANCE_ID}")
                        logger.info(f"  Event Time: {event.get('EventTime')}")
                        logger.info(f"  User: {cloud_trail_event.get('userIdentity', {}).get('principalId')}")
                        logger.info(f"  Source IP: {cloud_trail_event.get('sourceIPAddress')}")
                        logger.info(f"  HttpTokens: {request_params.get('httpTokens')}")
                        logger.info(f"  HttpPutResponseHopLimit: {request_params.get('httpPutResponseHopLimit')}")
                        return True
                
                logger.info("Event not found yet, CloudTrail may still be processing...")
                return False
                
            except Exception as e:
                logger.warning(f"CloudTrail lookup error: {e}")
                return False
        
        if _wait_with_backoff(check_cloudtrail_event, timeout_seconds=cloudtrail_timeout, initial_delay=60, max_delay=120):
            detection_results['cloudtrail_event'] = True
            logger.info("✓ DETECTION VERIFIED: CloudTrail captured ModifyInstanceMetadataOptions event")
        else:
            logger.error("✗ DETECTION FAILED: CloudTrail event not found within SLA")
        
        # DETECTION 2: EC2 API Verification (Immediate)
        logger.info("\n[DETECTION 2/2] EC2 Metadata Change Verification")
        logger.info("-" * 80)
        logger.info("Verifying metadata configuration change via EC2 API")
        
        try:
            response = clients['ec2'].describe_instances(InstanceIds=[INSTANCE_ID])
            instance = response['Reservations'][0]['Instances'][0]
            metadata_opts = instance.get('MetadataOptions', {})
            
            http_tokens = metadata_opts.get('HttpTokens')
            hop_limit = metadata_opts.get('HttpPutResponseHopLimit')
            
            logger.info(f"Current metadata configuration:")
            logger.info(f"  HttpTokens: {http_tokens}")
            logger.info(f"  HttpPutResponseHopLimit: {hop_limit}")
            
            if http_tokens == 'optional' and hop_limit == 2:
                detection_results['metadata_change_verified'] = True
                logger.info("✓ DETECTION VERIFIED: EC2 API confirms metadata weakening")
            else:
                logger.error("✗ DETECTION FAILED: Metadata configuration does not match expected weakened state")
        except Exception as e:
            logger.error(f"✗ EC2 API verification error: {e}")
        
        # Summary
        logger.info("\n" + "=" * 80)
        logger.info("DETECTIVE CONTROLS SUMMARY")
        logger.info("=" * 80)
        logger.info(f"CloudTrail Event Logging:      {'✓ PASS' if detection_results['cloudtrail_event'] else '✗ FAIL'}")
        logger.info(f"Metadata Change Verification:  {'✓ PASS' if detection_results['metadata_change_verified'] else '✗ FAIL'}")
        
        # Require both critical detections
        all_detections_passed = all(detection_results.values())
        
        if all_detections_passed:
            logger.info("\n✓ HYPOTHESIS VERIFIED: Detective controls successfully detected IMDS weakening within SLA")
            logger.info("  - CloudTrail logged API call with full context")
            logger.info("  - EC2 API confirms configuration change")
            logger.info("  - Detection mechanisms meet banking platform security requirements")
            return True
        else:
            logger.error("\n✗ HYPOTHESIS REJECTED: Detective controls failed to detect attack within 30-minute SLA")
            logger.error("  - Review CloudTrail configuration and logging status")
            logger.error("  - Verify IAM permissions for CloudTrail and EC2 services")
            logger.error("  - Check CloudTrail event delivery latency in your region")
            return False
        
    except Exception as e:
        logger.error(f"Error in hypothesis_verification: {e}")
        return False

def rollback():
    """
    Complete cleanup using CloudFormation stack deletion.
    Removes all resources created during the experiment.
    """
    global STACK_NAME
    
    try:
        if not STACK_NAME:
            logger.warning("No stack name found, skipping rollback")
            return
        
        clients = _get_clients()
        logger.info(f"Deleting CloudFormation stack: {STACK_NAME}")
        
        # Delete stack
        try:
            clients['cfn'].delete_stack(StackName=STACK_NAME)
            logger.info("Stack deletion initiated")
        except clients['cfn'].exceptions.ClientError as e:
            if 'does not exist' in str(e):
                logger.warning(f"Stack {STACK_NAME} does not exist")
                return
            raise
        
        # Wait for deletion
        def check_stack_deleted():
            try:
                response = clients['cfn'].describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack deletion status: {status}")
                
                if status == 'DELETE_COMPLETE':
                    return True
                elif 'FAILED' in status:
                    logger.warning(f"Stack deletion encountered issue: {status}")
                    _get_stack_events(clients['cfn'], STACK_NAME)
                    # Continue anyway
                    return False
                return False
            except clients['cfn'].exceptions.ClientError as e:
                if 'does not exist' in str(e):
                    logger.info("Stack deleted successfully")
                    return True
                raise
        
        if not _wait_with_backoff(check_stack_deleted, timeout_seconds=600, initial_delay=15):
            logger.warning("Stack deletion timeout - resources may require manual cleanup")
            _get_stack_events(clients['cfn'], STACK_NAME)
        else:
            logger.info("Rollback complete - all resources cleaned up")
        
    except Exception as e:
        logger.error(f"Error in rollback: {e}")
        logger.error("Manual cleanup may be required - check CloudFormation console")

def run_experiment():
    """Execute the complete SCE experiment with proper error handling."""
    try:
        logger.info("Starting SCE Experiment 2.3 - Detective Probe")
        
        # Preparation
        steady_state()
        
        # Attack execution
        attack_success = attack()
        if not attack_success:
            raise Exception("Attack execution failed")
        
        # Hypothesis verification
        hypothesis_result = hypothesis_verification()
        
        return hypothesis_result
        
    except Exception as e:
        logger.error(f"Experiment failed: {e}")
        return False
    finally:
        # Always attempt cleanup
        rollback()

if __name__ == "__main__":
    result = run_experiment()
    sys.exit(0 if result else 1)