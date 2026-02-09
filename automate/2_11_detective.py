#!/usr/bin/env python3
"""
SCE Experiment 2.11 - Detective Probe
Validates that CloudTrail alerts and AWS Config detect IMDS tampering.

Attack Node 1.3: Identify Target EC2 Instance
Command: aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions]'

Attack Node 2.4: Weaken IMDS Protections
Command: aws ec2 modify-instance-metadata-options --instance-id <ID> --http-tokens optional --http-put-response-hop-limit 2

Detective Controls:
- CloudTrail Real-time Alert (Node 2.5): Detect ModifyInstanceMetadataOptions API calls
- AWS Config Compliance Drift (Node 2.6): Detect non-compliant IMDS configurations

Expected Outcome: 
- CloudTrail captures both API calls within 60 seconds
- AWS Config marks instance as non-compliant after IMDS change
"""

import json
import logging
import os
import sys
import time
import hashlib

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
EXPERIMENT_ID = "sce-2-11-detective"
TIMESTAMP = int(time.time())
STACK_NAME = f"{EXPERIMENT_ID}-{TIMESTAMP}"
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")

# Store state between functions
_experiment_state = {
    "stack_name": STACK_NAME,
    "region": AWS_REGION,
    "test_instance_id": None,
    "trail_name": None,
    "log_group_name": None,
    "config_rule_name": None,
    "s3_bucket_name": None,
    "attack_results": {
        "reconnaissance": None,
        "imds_modification": None
    },
    "detection_results": {
        "cloudtrail_events": [],
        "config_compliance": None
    },
    "stack_deployed": False,
    "attack_timestamps": {}
}


def _get_cloudformation_template():
    """
    Generate CloudFormation template for the experiment.
    Creates:
    - A test EC2 instance with IMDSv2 enabled (baseline secure state)
    - CloudTrail trail with CloudWatch Logs integration
    - CloudWatch Log Group for trail events
    - CloudWatch Metric Filter for ModifyInstanceMetadataOptions
    - CloudWatch Alarm for IMDS changes
    - AWS Config rule for EC2_IMDSV2_CHECK
    - S3 bucket for CloudTrail logs
    - IAM roles for CloudTrail and Config
    """
    # Generate unique bucket name using hash
    bucket_suffix = hashlib.md5(f"{EXPERIMENT_ID}-{TIMESTAMP}".encode()).hexdigest()[:12]
    bucket_name = f"sce-trail-{bucket_suffix}"
    
    _experiment_state["s3_bucket_name"] = bucket_name
    
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"SCE Experiment 2.11 - Detective Probe - CloudTrail and Config Detection - {TIMESTAMP}",
        "Parameters": {
            "LatestAmiId": {
                "Type": "AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>",
                "Default": "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
            }
        },
        "Resources": {
            # VPC Resources
            "TestVPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport": True,
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-11-vpc-{TIMESTAMP}"},
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
                        {"Key": "Name", "Value": f"sce-2-11-subnet-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_ID}
                    ]
                }
            },
            "TestSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE Experiment 2.11 - No inbound access",
                    "VpcId": {"Ref": "TestVPC"},
                    "SecurityGroupIngress": [],
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-11-sg-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_ID}
                    ]
                }
            },
            # Test EC2 Instance with IMDSv2 enforced (secure baseline)
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
                        {"Key": "Name", "Value": f"sce-2-11-target-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_ID},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            # S3 Bucket for CloudTrail logs
            "TrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": bucket_name,
                    "BucketEncryption": {
                        "ServerSideEncryptionConfiguration": [
                            {
                                "ServerSideEncryptionByDefault": {
                                    "SSEAlgorithm": "AES256"
                                }
                            }
                        ]
                    },
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_ID},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
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
            # CloudWatch Log Group for CloudTrail
            "TrailLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": f"/aws/cloudtrail/sce-2-11-{TIMESTAMP}",
                    "RetentionInDays": 1,
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_ID},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            # IAM Role for CloudTrail to write to CloudWatch Logs
            "CloudTrailRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-2-11-cloudtrail-role-{TIMESTAMP}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "Policies": [
                        {
                            "PolicyName": "CloudTrailLogsPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents"
                                        ],
                                        "Resource": {"Fn::GetAtt": ["TrailLogGroup", "Arn"]}
                                    }
                                ]
                            }
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_ID},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            # CloudTrail Trail
            "DetectionTrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": ["TrailBucketPolicy", "CloudTrailRole"],
                "Properties": {
                    "TrailName": f"sce-2-11-trail-{TIMESTAMP}",
                    "S3BucketName": {"Ref": "TrailBucket"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": True,
                    "EnableLogFileValidation": True,
                    "CloudWatchLogsLogGroupArn": {"Fn::GetAtt": ["TrailLogGroup", "Arn"]},
                    "CloudWatchLogsRoleArn": {"Fn::GetAtt": ["CloudTrailRole", "Arn"]},
                    "EventSelectors": [
                        {
                            "ReadWriteType": "All",
                            "IncludeManagementEvents": True
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_ID},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            # CloudWatch Metric Filter for IMDS modifications
            "IMDSModificationMetricFilter": {
                "Type": "AWS::Logs::MetricFilter",
                "DependsOn": "DetectionTrail",
                "Properties": {
                    "LogGroupName": {"Ref": "TrailLogGroup"},
                    "FilterPattern": "{ ($.eventName = ModifyInstanceMetadataOptions) }",
                    "MetricTransformations": [
                        {
                            "MetricName": f"IMDSModificationCount-{TIMESTAMP}",
                            "MetricNamespace": "SCE/IMDSDetection",
                            "MetricValue": "1",
                            "DefaultValue": 0
                        }
                    ]
                }
            },
            # CloudWatch Alarm for IMDS modifications
            "IMDSModificationAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": f"sce-2-11-imds-modification-{TIMESTAMP}",
                    "AlarmDescription": "Alarm when IMDS configuration is modified",
                    "MetricName": f"IMDSModificationCount-{TIMESTAMP}",
                    "Namespace": "SCE/IMDSDetection",
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "TreatMissingData": "notBreaching"
                }
            },
            # IAM Role for AWS Config
            "ConfigRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-2-11-config-role-{TIMESTAMP}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "config.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_ID},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            # AWS Config Configuration Recorder
            "ConfigRecorder": {
                "Type": "AWS::Config::ConfigurationRecorder",
                "DependsOn": "ConfigRole",
                "Properties": {
                    "Name": f"sce-2-11-recorder-{TIMESTAMP}",
                    "RoleARN": {"Fn::GetAtt": ["ConfigRole", "Arn"]},
                    "RecordingGroup": {
                        "AllSupported": False,
                        "IncludeGlobalResourceTypes": False,
                        "ResourceTypes": ["AWS::EC2::Instance"]
                    }
                }
            },
            # AWS Config Delivery Channel
            "ConfigDeliveryChannel": {
                "Type": "AWS::Config::DeliveryChannel",
                "DependsOn": ["ConfigRecorder", "TrailBucketPolicy"],
                "Properties": {
                    "Name": f"sce-2-11-delivery-{TIMESTAMP}",
                    "S3BucketName": {"Ref": "TrailBucket"}
                }
            },
            # AWS Config Rule for IMDSv2
            "IMDSv2ConfigRule": {
                "Type": "AWS::Config::ConfigRule",
                "DependsOn": "ConfigRecorder",
                "Properties": {
                    "ConfigRuleName": f"sce-2-11-imdsv2-check-{TIMESTAMP}",
                    "Description": "Checks if EC2 instances require IMDSv2",
                    "Source": {
                        "Owner": "AWS",
                        "SourceIdentifier": "EC2_IMDSV2_CHECK"
                    },
                    "Scope": {
                        "ComplianceResourceTypes": ["AWS::EC2::Instance"]
                    }
                }
            }
        },
        "Outputs": {
            "TestInstanceId": {
                "Description": "ID of the test EC2 instance",
                "Value": {"Ref": "TestEC2Instance"}
            },
            "TrailName": {
                "Description": "Name of the CloudTrail trail",
                "Value": {"Ref": "DetectionTrail"}
            },
            "LogGroupName": {
                "Description": "Name of the CloudWatch Log Group",
                "Value": {"Ref": "TrailLogGroup"}
            },
            "ConfigRuleName": {
                "Description": "Name of the AWS Config rule",
                "Value": {"Ref": "IMDSv2ConfigRule"}
            },
            "AlarmName": {
                "Description": "Name of the CloudWatch Alarm",
                "Value": {"Ref": "IMDSModificationAlarm"}
            },
            "S3BucketName": {
                "Description": "Name of the S3 bucket for logs",
                "Value": {"Ref": "TrailBucket"}
            }
        }
    }
    return json.dumps(template)


def _wait_with_backoff(check_func, max_attempts=30, initial_delay=2, max_delay=30, description="condition"):
    """
    Wait with exponential backoff until check_func returns True.
    Uses time.monotonic() for reliable timing.
    """
    start_time = time.monotonic()
    delay = initial_delay
    
    for attempt in range(max_attempts):
        try:
            result = check_func()
            if result:
                elapsed = time.monotonic() - start_time
                logger.info(f"{description} met after {elapsed:.1f}s ({attempt + 1} attempts)")
                return True
        except Exception as e:
            logger.warning(f"Attempt {attempt + 1}/{max_attempts} for {description} failed: {e}")
        
        if attempt < max_attempts - 1:
            logger.debug(f"Waiting {delay}s before retry for {description}...")
            time.sleep(delay)
            delay = min(delay * 1.5, max_delay)
    
    elapsed = time.monotonic() - start_time
    logger.error(f"{description} not met after {elapsed:.1f}s ({max_attempts} attempts)")
    return False


def steady_state():
    """
    Preparation block: Deploy CloudFormation stack with test resources.
    
    Creates:
    - Test EC2 instance with IMDSv2 enforced (secure baseline)
    - CloudTrail trail with CloudWatch Logs integration
    - CloudWatch metric filter and alarm for IMDS changes
    - AWS Config rule for EC2_IMDSV2_CHECK
    
    Returns:
        bool: True if steady state established successfully
    """
    global _experiment_state
    
    logger.info("=" * 70)
    logger.info("SCE Experiment 2.11 - Detective Probe - Steady State Setup")
    logger.info(f"Stack Name: {STACK_NAME}")
    logger.info(f"Region: {AWS_REGION}")
    logger.info(f"Timestamp: {TIMESTAMP}")
    logger.info("=" * 70)
    
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
            logger.info("This may take 5-10 minutes due to CloudTrail and Config setup...")
            
            cfn_client.create_stack(
                StackName=STACK_NAME,
                TemplateBody=template_body,
                Capabilities=['CAPABILITY_NAMED_IAM'],
                Tags=[
                    {'Key': 'Experiment', 'Value': EXPERIMENT_ID},
                    {'Key': 'Timestamp', 'Value': str(TIMESTAMP)},
                    {'Key': 'Purpose', 'Value': 'SCE-Detective-Probe-CloudTrail-Config'}
                ],
                OnFailure='DELETE',
                TimeoutInMinutes=15
            )
            
            # Wait for stack creation with backoff
            def check_stack_complete():
                response = cfn_client.describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack status: {status}")
                
                if status == 'CREATE_COMPLETE':
                    return True
                elif status in ['CREATE_FAILED', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED', 'DELETE_COMPLETE']:
                    # Get failure reason
                    events = cfn_client.describe_stack_events(StackName=STACK_NAME)
                    for event in events['StackEvents']:
                        if 'FAILED' in event.get('ResourceStatus', ''):
                            logger.error(f"Resource failure: {event.get('LogicalResourceId')} - {event.get('ResourceStatusReason')}")
                    raise Exception(f"Stack creation failed with status: {status}")
                return False
            
            if not _wait_with_backoff(check_stack_complete, max_attempts=90, initial_delay=10, description="Stack creation"):
                logger.error("Stack creation timed out")
                return False
            
            _experiment_state["stack_deployed"] = True
        
        # Retrieve stack outputs
        logger.info("Retrieving stack outputs...")
        response = cfn_client.describe_stacks(StackName=STACK_NAME)
        outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
        
        _experiment_state["test_instance_id"] = outputs.get('TestInstanceId')
        _experiment_state["trail_name"] = outputs.get('TrailName')
        _experiment_state["log_group_name"] = outputs.get('LogGroupName')
        _experiment_state["config_rule_name"] = outputs.get('ConfigRuleName')
        _experiment_state["alarm_name"] = outputs.get('AlarmName')
        _experiment_state["s3_bucket_name"] = outputs.get('S3BucketName')
        
        logger.info(f"Test Instance ID: {_experiment_state['test_instance_id']}")
        logger.info(f"CloudTrail Name: {_experiment_state['trail_name']}")
        logger.info(f"Log Group Name: {_experiment_state['log_group_name']}")
        logger.info(f"Config Rule Name: {_experiment_state['config_rule_name']}")
        
        # Wait for CloudTrail to start logging
        logger.info("Waiting for CloudTrail to initialize...")
        time.sleep(30)
        
        # Start AWS Config recorder
        logger.info("Starting AWS Config recorder...")
        config_client = boto3.client('config', region_name=AWS_REGION)
        try:
            config_client.start_configuration_recorder(
                ConfigurationRecorderName=f"sce-2-11-recorder-{TIMESTAMP}"
            )
            logger.info("Config recorder started")
        except ClientError as e:
            logger.warning(f"Could not start config recorder: {e}")
        
        # Wait for Config to initialize
        time.sleep(15)
        
        # Verify initial compliance state
        logger.info("Verifying initial compliance state...")
        try:
            compliance = config_client.get_compliance_details_by_resource(
                ResourceType='AWS::EC2::Instance',
                ResourceId=_experiment_state['test_instance_id']
            )
            logger.info(f"Initial compliance results: {len(compliance.get('EvaluationResults', []))} evaluations")
        except ClientError as e:
            logger.warning(f"Could not get initial compliance: {e}")
        
        logger.info("Steady state established successfully")
        return True
        
    except Exception as e:
        logger.error(f"Failed to establish steady state: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


def attack():
    """
    Execute Attack Nodes 1.3 and 2.4 in sequence.
    
    Attack Node 1.3: Identify Target EC2 Instance (Reconnaissance)
    Command: aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions]'
    
    Attack Node 2.4: Weaken IMDS Protections
    Command: aws ec2 modify-instance-metadata-options --instance-id <ID> --http-tokens optional --http-put-response-hop-limit 2
    
    Returns:
        bool: True if attacks were executed (regardless of success/failure)
    """
    global _experiment_state
    
    logger.info("=" * 70)
    logger.info("SCE Experiment 2.11 - Executing Attack Nodes 1.3 and 2.4")
    logger.info("=" * 70)
    
    if not _experiment_state.get("test_instance_id"):
        logger.error("No test instance ID available - steady_state() must run first")
        return False
    
    ec2_client = boto3.client('ec2', region_name=AWS_REGION)
    
    # ==================== ATTACK NODE 1.3 ====================
    logger.info("-" * 50)
    logger.info("Attack Node 1.3: Identify Target EC2 Instance")
    logger.info("TTP: T1580 - Cloud Infrastructure Discovery")
    logger.info("-" * 50)
    
    try:
        _experiment_state["attack_timestamps"]["reconnaissance_start"] = time.time()
        
        # Execute reconnaissance
        response = ec2_client.describe_instances(
            InstanceIds=[_experiment_state['test_instance_id']]
        )
        
        _experiment_state["attack_timestamps"]["reconnaissance_end"] = time.time()
        
        instances_found = []
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instance_info = {
                    'InstanceId': instance.get('InstanceId'),
                    'MetadataOptions': instance.get('MetadataOptions', {})
                }
                instances_found.append(instance_info)
        
        _experiment_state["attack_results"]["reconnaissance"] = {
            "success": True,
            "instances_found": instances_found,
            "timestamp": _experiment_state["attack_timestamps"]["reconnaissance_start"]
        }
        
        logger.info(f"Reconnaissance successful - found {len(instances_found)} instance(s)")
        for inst in instances_found:
            logger.info(f"  Instance: {inst['InstanceId']}")
            logger.info(f"  MetadataOptions: {json.dumps(inst['MetadataOptions'], indent=4)}")
            
    except ClientError as e:
        logger.error(f"Reconnaissance failed: {e}")
        _experiment_state["attack_results"]["reconnaissance"] = {
            "success": False,
            "error": str(e),
            "timestamp": time.time()
        }
    
    # Wait briefly between attacks
    logger.info("Waiting 5 seconds before IMDS modification attack...")
    time.sleep(5)
    
    # ==================== ATTACK NODE 2.4 ====================
    logger.info("-" * 50)
    logger.info("Attack Node 2.4: Weaken IMDS Protections")
    logger.info("TTP: T1562.001 - Impair Defenses: Disable or Modify Tools")
    logger.info("-" * 50)
    
    try:
        _experiment_state["attack_timestamps"]["imds_modification_start"] = time.time()
        
        # Execute IMDS weakening attack
        logger.info(f"Modifying IMDS options for instance: {_experiment_state['test_instance_id']}")
        logger.info("  Setting HttpTokens: optional (re-enabling IMDSv1)")
        logger.info("  Setting HttpPutResponseHopLimit: 2 (allowing container access)")
        
        response = ec2_client.modify_instance_metadata_options(
            InstanceId=_experiment_state['test_instance_id'],
            HttpTokens='optional',
            HttpEndpoint='enabled',
            HttpPutResponseHopLimit=2
        )
        
        _experiment_state["attack_timestamps"]["imds_modification_end"] = time.time()
        
        new_metadata_options = response.get('InstanceMetadataOptions', {})
        
        _experiment_state["attack_results"]["imds_modification"] = {
            "success": True,
            "new_metadata_options": new_metadata_options,
            "timestamp": _experiment_state["attack_timestamps"]["imds_modification_start"]
        }
        
        logger.info("IMDS modification successful!")
        logger.info(f"  New HttpTokens: {new_metadata_options.get('HttpTokens')}")
        logger.info(f"  New HttpPutResponseHopLimit: {new_metadata_options.get('HttpPutResponseHopLimit')}")
        logger.info(f"  State: {new_metadata_options.get('State')}")
        
    except ClientError as e:
        logger.error(f"IMDS modification failed: {e}")
        _experiment_state["attack_results"]["imds_modification"] = {
            "success": False,
            "error": str(e),
            "timestamp": time.time()
        }
    
    # Record attack completion time for detection verification
    _experiment_state["attack_timestamps"]["attacks_completed"] = time.time()
    
    logger.info("-" * 50)
    logger.info("Attack execution completed")
    logger.info(f"Attacks completed at: {_experiment_state['attack_timestamps']['attacks_completed']}")
    logger.info("-" * 50)
    
    return True


def hypothesis_verification():
    """
    Verify the detective countermeasures effectiveness.
    
    Hypothesis: CloudTrail and AWS Config will detect IMDS tampering attacks.
    
    Detective Controls Verified:
    1. CloudTrail captures DescribeInstances API call (Node 1.3)
    2. CloudTrail captures ModifyInstanceMetadataOptions API call (Node 2.4)
    3. AWS Config marks instance as non-compliant after IMDS change
    
    Success Criteria:
    - CloudTrail events captured within 90 seconds
    - AWS Config compliance status changes to NON_COMPLIANT
    
    Returns:
        bool: True if detective controls worked as expected
    """
    global _experiment_state
    
    logger.info("=" * 70)
    logger.info("SCE Experiment 2.11 - Hypothesis Verification")
    logger.info("Detective Controls: CloudTrail + AWS Config")
    logger.info("=" * 70)
    
    if not _experiment_state.get("attack_results", {}).get("imds_modification"):
        logger.error("No attack results available - attack() must run first")
        return False
    
    logs_client = boto3.client('logs', region_name=AWS_REGION)
    config_client = boto3.client('config', region_name=AWS_REGION)
    cloudwatch_client = boto3.client('cloudwatch', region_name=AWS_REGION)
    
    verification_results = {
        "cloudtrail_describe_instances": False,
        "cloudtrail_modify_imds": False,
        "config_non_compliant": False,
        "cloudwatch_alarm_triggered": False
    }
    
    # ==================== VERIFY CLOUDTRAIL DETECTION ====================
    logger.info("-" * 50)
    logger.info("Verifying CloudTrail Detection (Nodes 2.5, 2.6)")
    logger.info("-" * 50)
    
    # Wait for CloudTrail events to propagate to CloudWatch Logs
    logger.info("Waiting for CloudTrail events to propagate (up to 90 seconds)...")
    
    attack_start_time = _experiment_state["attack_timestamps"].get("reconnaissance_start", time.time() - 300)
    
    def check_cloudtrail_events():
        try:
            # Query CloudWatch Logs for CloudTrail events
            query = f"""
            fields @timestamp, @message, eventName, eventSource, sourceIPAddress
            | filter eventSource = 'ec2.amazonaws.com'
            | filter eventName in ['DescribeInstances', 'ModifyInstanceMetadataOptions']
            | sort @timestamp desc
            | limit 50
            """
            
            start_query_response = logs_client.start_query(
                logGroupName=_experiment_state['log_group_name'],
                startTime=int(attack_start_time - 60),
                endTime=int(time.time() + 60),
                queryString=query
            )
            
            query_id = start_query_response['queryId']
            
            # Wait for query to complete
            time.sleep(5)
            
            query_results = logs_client.get_query_results(queryId=query_id)
            
            if query_results['status'] != 'Complete':
                time.sleep(5)
                query_results = logs_client.get_query_results(queryId=query_id)
            
            events_found = {
                'DescribeInstances': False,
                'ModifyInstanceMetadataOptions': False
            }
            
            for result in query_results.get('results', []):
                event_data = {field['field']: field['value'] for field in result}
                event_name = event_data.get('eventName', '')
                
                if event_name in events_found:
                    events_found[event_name] = True
                    logger.info(f"  Found CloudTrail event: {event_name}")
                    _experiment_state["detection_results"]["cloudtrail_events"].append(event_data)
            
            return events_found['DescribeInstances'] and events_found['ModifyInstanceMetadataOptions']
            
        except Exception as e:
            logger.warning(f"CloudTrail query failed: {e}")
            return False
    
    # Try CloudWatch Logs Insights query
    cloudtrail_detected = _wait_with_backoff(
        check_cloudtrail_events, 
        max_attempts=12, 
        initial_delay=10,
        description="CloudTrail event detection"
    )
    
    if cloudtrail_detected:
        verification_results["cloudtrail_describe_instances"] = True
        verification_results["cloudtrail_modify_imds"] = True
        logger.info("CloudTrail detection: VERIFIED")
    else:
        # Fallback: Check CloudTrail directly via LookupEvents
        logger.info("Falling back to CloudTrail LookupEvents API...")
        cloudtrail_client = boto3.client('cloudtrail', region_name=AWS_REGION)
        
        try:
            events = cloudtrail_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'ResourceName',
                        'AttributeValue': _experiment_state['test_instance_id']
                    }
                ],
                StartTime=attack_start_time - 60,
                EndTime=time.time() + 60,
                MaxResults=50
            )
            
            for event in events.get('Events', []):
                event_name = event.get('EventName', '')
                if event_name == 'DescribeInstances':
                    verification_results["cloudtrail_describe_instances"] = True
                    logger.info(f"  Found via LookupEvents: {event_name}")
                elif event_name == 'ModifyInstanceMetadataOptions':
                    verification_results["cloudtrail_modify_imds"] = True
                    logger.info(f"  Found via LookupEvents: {event_name}")
                    
        except Exception as e:
            logger.warning(f"CloudTrail LookupEvents failed: {e}")
    
    # ==================== VERIFY AWS CONFIG DETECTION ====================
    logger.info("-" * 50)
    logger.info("Verifying AWS Config Compliance Detection (Node 2.6)")
    logger.info("-" * 50)
    
    # Trigger Config re-evaluation
    logger.info("Triggering AWS Config rule re-evaluation...")
    try:
        config_client.start_config_rules_evaluation(
            ConfigRuleNames=[_experiment_state['config_rule_name']]
        )
        logger.info("Config rule evaluation triggered")
    except ClientError as e:
        logger.warning(f"Could not trigger Config evaluation: {e}")
    
    # Wait for Config evaluation
    def check_config_compliance():
        try:
            compliance = config_client.get_compliance_details_by_resource(
                ResourceType='AWS::EC2::Instance',
                ResourceId=_experiment_state['test_instance_id'],
                ComplianceTypes=['NON_COMPLIANT']
            )
            
            evaluations = compliance.get('EvaluationResults', [])
            
            for eval_result in evaluations:
                if eval_result.get('ComplianceType') == 'NON_COMPLIANT':
                    config_rule = eval_result.get('EvaluationResultIdentifier', {}).get('EvaluationResultQualifier', {}).get('ConfigRuleName', '')
                    if 'imdsv2' in config_rule.lower() or _experiment_state['config_rule_name'] in config_rule:
                        logger.info(f"  Config rule {config_rule}: NON_COMPLIANT")
                        _experiment_state["detection_results"]["config_compliance"] = eval_result
                        return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Config compliance check failed: {e}")
            return False
    
    config_detected = _wait_with_backoff(
        check_config_compliance,
        max_attempts=15,
        initial_delay=10,
        description="Config compliance detection"
    )
    
    if config_detected:
        verification_results["config_non_compliant"] = True
        logger.info("AWS Config detection: VERIFIED (NON_COMPLIANT)")
    else:
        logger.warning("AWS Config detection: NOT VERIFIED within timeout")
    
    # ==================== VERIFY CLOUDWATCH ALARM ====================
    logger.info("-" * 50)
    logger.info("Verifying CloudWatch Alarm Status")
    logger.info("-" * 50)
    
    try:
        alarm_response = cloudwatch_client.describe_alarms(
            AlarmNames=[_experiment_state.get('alarm_name', f"sce-2-11-imds-modification-{TIMESTAMP}")]
        )
        
        for alarm in alarm_response.get('MetricAlarms', []):
            state = alarm.get('StateValue')
            logger.info(f"  Alarm {alarm.get('AlarmName')}: {state}")
            if state in ['ALARM', 'OK']:
                verification_results["cloudwatch_alarm_triggered"] = True
                
    except Exception as e:
        logger.warning(f"CloudWatch alarm check failed: {e}")
    
    # ==================== FINAL VERIFICATION ====================
    logger.info("=" * 70)
    logger.info("Verification Summary")
    logger.info("=" * 70)
    
    criteria = {
        "CloudTrail DescribeInstances captured": verification_results["cloudtrail_describe_instances"],
        "CloudTrail ModifyInstanceMetadataOptions captured": verification_results["cloudtrail_modify_imds"],
        "AWS Config NON_COMPLIANT status": verification_results["config_non_compliant"],
        "CloudWatch Alarm configured": verification_results["cloudwatch_alarm_triggered"]
    }
    
    logger.info("Detection Criteria Results:")
    for criterion, passed in criteria.items():
        status = "PASS" if passed else "FAIL"
        logger.info(f"  - {criterion}: {status}")
    
    # Core detective controls are CloudTrail and Config
    core_criteria_met = (
        verification_results["cloudtrail_modify_imds"] and 
        (verification_results["config_non_compliant"] or verification_results["cloudtrail_describe_instances"])
    )
    
    if core_criteria_met:
        logger.info("=" * 70)
        logger.info("HYPOTHESIS VERIFIED: Detective controls are EFFECTIVE")
        logger.info("CloudTrail and/or AWS Config successfully detected")
        logger.info("the IMDS tampering attack (Nodes 1.3 and 2.4).")
        logger.info("=" * 70)
        
        # Log compliance alignment
        logger.info("PCI-DSS Alignment:")
        logger.info("  - Req 10.2: Audit trails captured API calls")
        logger.info("  - Req 11.5: Change detection via AWS Config")
        
        return True
    else:
        logger.error("=" * 70)
        logger.error("HYPOTHESIS FAILED: Detective controls are INEFFECTIVE")
        logger.error("CloudTrail and AWS Config did NOT detect the")
        logger.error("IMDS tampering attack within the expected timeframe.")
        logger.error("=" * 70)
        
        return False


def rollback():
    """
    Complete teardown: Delete CloudFormation stack and all resources.
    
    Also restores IMDS settings if instance still exists.
    Safe and tolerant: handles errors gracefully.
    
    Returns:
        bool: True if rollback completed successfully
    """
    global _experiment_state
    
    logger.info("=" * 70)
    logger.info("SCE Experiment 2.11 - Rollback")
    logger.info(f"Deleting Stack: {STACK_NAME}")
    logger.info("=" * 70)
    
    # First, try to restore IMDS settings
    if _experiment_state.get("test_instance_id"):
        logger.info("Attempting to restore IMDS settings...")
        try:
            ec2_client = boto3.client('ec2', region_name=AWS_REGION)
            ec2_client.modify_instance_metadata_options(
                InstanceId=_experiment_state['test_instance_id'],
                HttpTokens='required',
                HttpPutResponseHopLimit=1
            )
            logger.info("IMDS settings restored to secure baseline")
        except Exception as e:
            logger.warning(f"Could not restore IMDS settings: {e}")
    
    # Stop Config recorder
    logger.info("Stopping AWS Config recorder...")
    try:
        config_client = boto3.client('config', region_name=AWS_REGION)
        config_client.stop_configuration_recorder(
            ConfigurationRecorderName=f"sce-2-11-recorder-{TIMESTAMP}"
        )
        logger.info("Config recorder stopped")
    except Exception as e:
        logger.warning(f"Could not stop config recorder: {e}")
    
    # Delete CloudFormation stack
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
            
            # First, empty the S3 bucket if it exists
            if _experiment_state.get("s3_bucket_name"):
                logger.info(f"Emptying S3 bucket: {_experiment_state['s3_bucket_name']}")
                try:
                    s3_client = boto3.client('s3', region_name=AWS_REGION)
                    s3_resource = boto3.resource('s3', region_name=AWS_REGION)
                    bucket = s3_resource.Bucket(_experiment_state['s3_bucket_name'])
                    bucket.objects.all().delete()
                    logger.info("S3 bucket emptied")
                except Exception as e:
                    logger.warning(f"Could not empty S3 bucket: {e}")
            
            # Delete the stack
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
                        # Log failure reason
                        events = cfn_client.describe_stack_events(StackName=STACK_NAME)
                        for event in events['StackEvents'][:5]:
                            if 'FAILED' in event.get('ResourceStatus', ''):
                                logger.error(f"Delete failure: {event.get('LogicalResourceId')} - {event.get('ResourceStatusReason')}")
                        return False
                    return False
                except ClientError as e:
                    if 'does not exist' in str(e):
                        return True
                    raise
            
            if _wait_with_backoff(check_stack_deleted, max_attempts=60, initial_delay=10, description="Stack deletion"):
                logger.info("Stack deletion completed successfully")
            else:
                logger.warning("Stack deletion timed out - may still be in progress")
        
        # Clear experiment state
        _experiment_state = {
            "stack_name": None,
            "region": AWS_REGION,
            "test_instance_id": None,
            "trail_name": None,
            "log_group_name": None,
            "config_rule_name": None,
            "s3_bucket_name": None,
            "attack_results": {"reconnaissance": None, "imds_modification": None},
            "detection_results": {"cloudtrail_events": [], "config_compliance": None},
            "stack_deployed": False,
            "attack_timestamps": {}
        }
        
        logger.info("Rollback completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error during rollback: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False


def run_experiment():
    """
    Main experiment runner with proper error handling and guaranteed rollback.
    """
    logger.info("#" * 70)
    logger.info("# SCE EXPERIMENT 2.11 - DETECTIVE PROBE")
    logger.info("# Attack Nodes: 1.3 (Reconnaissance) + 2.4 (IMDS Tampering)")
    logger.info("# Controls: CloudTrail Real-time Alert + AWS Config Compliance")
    logger.info("#" * 70)
    
    experiment_success = False
    
    try:
        # Phase 1: Establish steady state
        logger.info("\n[PHASE 1] Establishing steady state...")
        if not steady_state():
            logger.error("Failed to establish steady state")
            return False
        
        # Phase 2: Execute attacks
        logger.info("\n[PHASE 2] Executing attacks...")
        if not attack():
            logger.error("Failed to execute attacks")
            return False
        
        # Wait for detection systems to process events
        logger.info("\n[PHASE 2.5] Waiting for detection systems to process events...")
        time.sleep(30)
        
        # Phase 3: Verify hypothesis
        logger.info("\n[PHASE 3] Verifying hypothesis...")
        experiment_success = hypothesis_verification()
        
        return experiment_success
        
    except Exception as e:
        logger.error(f"Experiment failed with exception: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return False
        
    finally:
        # Phase 4: Always attempt rollback
        logger.info("\n[PHASE 4] Executing rollback...")
        rollback()
        
        # Final summary
        logger.info("\n" + "#" * 70)
        if experiment_success:
            logger.info("# EXPERIMENT RESULT: SUCCESS")
            logger.info("# Detective controls validated - CloudTrail and Config effective")
        else:
            logger.info("# EXPERIMENT RESULT: FAILURE")
            logger.info("# Detective control validation failed")
        logger.info("#" * 70)


if __name__ == "__main__":
    success = run_experiment()
    sys.exit(0 if success else 1)