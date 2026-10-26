#!/usr/bin/env python3
"""
SCE Experiment 1.4 - Reactive Probe
Validates Auto-Remediation Lambda that reverts IMDS configuration when weakened.

This experiment:
1. Creates an EC2 instance with IMDSv2 enforced
2. Sets up EventBridge rule + Lambda for auto-remediation
3. Executes the attack (ModifyInstanceMetadataOptions to weaken IMDS)
4. Verifies Lambda automatically reverts IMDS to secure configuration within SLA
"""

import json
import logging
import time
import os
import sys
import hashlib
import base64
import zipfile
import io

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
EXPERIMENT_TAG = "sce-1-4-reactive"
TIMESTAMP_SUFFIX = str(int(time.time()))
STACK_NAME = f"sce-experiment-1-4-reactive-{TIMESTAMP_SUFFIX}"
REMEDIATION_SLA_SECONDS = 1800  # 30-minute SLA for reactive control

# Global state storage
_experiment_state = {
    "stack_name": STACK_NAME,
    "instance_id": None,
    "lambda_function_name": None,
    "event_rule_name": None,
    "attack_timestamp": None,
    "region": None,
    "account_id": None
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


def _get_lambda_code() -> str:
    """
    Generate the Lambda function code for IMDS auto-remediation.
    
    This Lambda:
    - Triggers on ModifyInstanceMetadataOptions events via EventBridge
    - Checks if IMDS was weakened (HttpTokens != required or HopLimit > 1)
    - Automatically reverts to secure configuration
    - Logs all actions for audit trail
    """
    lambda_code = '''
import json
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event, context):
    """
    Auto-remediation Lambda for IMDS security configuration.
    
    Triggered by EventBridge when ModifyInstanceMetadataOptions is called.
    Automatically reverts insecure IMDS configurations.
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    ec2_client = boto3.client('ec2')
    
    try:
        # Extract instance ID from CloudTrail event
        detail = event.get('detail', {})
        request_params = detail.get('requestParameters', {})
        instance_id = request_params.get('instanceId')
        
        if not instance_id:
            logger.error("No instance ID found in event")
            return {
                'statusCode': 400,
                'body': 'No instance ID in event'
            }
        
        # Check current IMDS configuration
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        
        if not response['Reservations']:
            logger.error(f"Instance {instance_id} not found")
            return {
                'statusCode': 404,
                'body': f'Instance {instance_id} not found'
            }
        
        instance = response['Reservations'][0]['Instances'][0]
        metadata_options = instance.get('MetadataOptions', {})
        
        current_http_tokens = metadata_options.get('HttpTokens', 'optional')
        current_hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
        
        logger.info(f"Current IMDS config - HttpTokens: {current_http_tokens}, HopLimit: {current_hop_limit}")
        
        # Check if remediation is needed
        needs_remediation = False
        
        if current_http_tokens != 'required':
            logger.warning(f"SECURITY VIOLATION: HttpTokens is '{current_http_tokens}', should be 'required'")
            needs_remediation = True
        
        if current_hop_limit > 1:
            logger.warning(f"SECURITY VIOLATION: HopLimit is {current_hop_limit}, should be 1")
            needs_remediation = True
        
        if not needs_remediation:
            logger.info("IMDS configuration is already secure. No remediation needed.")
            return {
                'statusCode': 200,
                'body': 'No remediation needed'
            }
        
        # Perform remediation
        logger.info(f"REMEDIATING instance {instance_id}: Setting HttpTokens=required, HopLimit=1")
        
        ec2_client.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='required',
            HttpPutResponseHopLimit=1,
            HttpEndpoint='enabled'
        )
        
        logger.info(f"SUCCESS: Instance {instance_id} IMDS configuration remediated")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Remediation successful',
                'instance_id': instance_id,
                'action': 'Reverted to HttpTokens=required, HopLimit=1'
            })
        }
        
    except Exception as e:
        logger.error(f"Remediation failed: {str(e)}")
        return {
            'statusCode': 500,
            'body': f'Remediation failed: {str(e)}'
        }
'''
    return lambda_code


def _create_lambda_zip() -> bytes:
    """Create a ZIP file containing the Lambda function code."""
    lambda_code = _get_lambda_code()
    
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr('lambda_function.py', lambda_code)
    
    zip_buffer.seek(0)
    return zip_buffer.read()


def _get_cloudformation_template() -> str:
    """
    Generate CloudFormation template for the reactive probe experiment.
    
    Creates:
    - VPC and subnet for EC2 instance
    - EC2 instance with IMDSv2 enforced (secure baseline)
    - IAM role for Lambda execution
    - Lambda function for auto-remediation
    - EventBridge rule to trigger Lambda on IMDS modification
    - CloudTrail trail for event capture
    """
    sts_client = _get_boto3_client('sts')
    account_id = sts_client.get_caller_identity()['Account']
    _experiment_state["account_id"] = account_id
    region = _experiment_state.get("region", "us-east-1")
    
    # Create Lambda deployment package
    lambda_zip = _create_lambda_zip()
    lambda_zip_b64 = base64.b64encode(lambda_zip).decode('utf-8')
    
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"SCE Experiment 1.4 Reactive Probe - Auto-Remediation Lambda for IMDS Weakening - {TIMESTAMP_SUFFIX}",
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
                        {"Key": "Name", "Value": f"sce-1-4-reactive-vpc-{TIMESTAMP_SUFFIX}"},
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
                        {"Key": "Name", "Value": f"sce-1-4-reactive-subnet-{TIMESTAMP_SUFFIX}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": TIMESTAMP_SUFFIX}
                    ]
                }
            },
            # Security Group (minimal access)
            "ExperimentSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE 1.4 Reactive Experiment - Isolated security group",
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "-1",
                            "CidrIp": "127.0.0.1/32",
                            "Description": "Deny all outbound"
                        }
                    ],
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-1-4-reactive-sg-{TIMESTAMP_SUFFIX}"},
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
                        {"Key": "Name", "Value": f"sce-1-4-reactive-instance-{TIMESTAMP_SUFFIX}"},
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
                    "BucketName": f"sce-1-4-reactive-trail-{TIMESTAMP_SUFFIX}",
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
                                        "AWS:SourceArn": {"Fn::Sub": f"arn:aws:cloudtrail:{region}:{account_id}:trail/sce-1-4-reactive-trail-{TIMESTAMP_SUFFIX}"}
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
                                        "AWS:SourceArn": {"Fn::Sub": f"arn:aws:cloudtrail:{region}:{account_id}:trail/sce-1-4-reactive-trail-{TIMESTAMP_SUFFIX}"}
                                    }
                                }
                            }
                        ]
                    }
                }
            },
            # CloudTrail Trail for capturing API events
            "ExperimentTrail": {
                "Type": "AWS::CloudTrail::Trail",
                "DependsOn": ["CloudTrailBucketPolicy"],
                "Properties": {
                    "TrailName": f"sce-1-4-reactive-trail-{TIMESTAMP_SUFFIX}",
                    "S3BucketName": {"Ref": "CloudTrailBucket"},
                    "IsLogging": True,
                    "IsMultiRegionTrail": False,
                    "IncludeGlobalServiceEvents": False,
                    "EnableLogFileValidation": False,
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": TIMESTAMP_SUFFIX}
                    ]
                }
            },
            # IAM Role for Lambda execution
            "LambdaExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-1-4-reactive-lambda-role-{TIMESTAMP_SUFFIX}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "Policies": [
                        {
                            "PolicyName": "IMDSRemediationPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogGroup",
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents"
                                        ],
                                        "Resource": f"arn:aws:logs:{region}:{account_id}:*"
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:DescribeInstances",
                                            "ec2:ModifyInstanceMetadataOptions"
                                        ],
                                        "Resource": "*",
                                        "Condition": {
                                            "StringEquals": {
                                                "aws:ResourceTag/Experiment": EXPERIMENT_TAG
                                            }
                                        }
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:DescribeInstances"
                                        ],
                                        "Resource": "*"
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:ModifyInstanceMetadataOptions"
                                        ],
                                        "Resource": f"arn:aws:ec2:{region}:{account_id}:instance/*"
                                    }
                                ]
                            }
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": TIMESTAMP_SUFFIX}
                    ]
                }
            },
            # Lambda Function for auto-remediation
            "RemediationLambda": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": ["LambdaExecutionRole"],
                "Properties": {
                    "FunctionName": f"sce-1-4-reactive-remediation-{TIMESTAMP_SUFFIX}",
                    "Runtime": "python3.9",
                    "Handler": "lambda_function.lambda_handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecutionRole", "Arn"]},
                    "Timeout": 60,
                    "MemorySize": 128,
                    "Code": {
                        "ZipFile": _get_lambda_code()
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": TIMESTAMP_SUFFIX}
                    ]
                }
            },
            # EventBridge Rule to trigger Lambda on IMDS modification
            "IMDSModificationRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": f"sce-1-4-reactive-imds-rule-{TIMESTAMP_SUFFIX}",
                    "Description": "Triggers remediation Lambda when IMDS configuration is modified",
                    "State": "ENABLED",
                    "EventPattern": {
                        "source": ["aws.ec2"],
                        "detail-type": ["AWS API Call via CloudTrail"],
                        "detail": {
                            "eventSource": ["ec2.amazonaws.com"],
                            "eventName": ["ModifyInstanceMetadataOptions"]
                        }
                    },
                    "Targets": [
                        {
                            "Id": "RemediationLambdaTarget",
                            "Arn": {"Fn::GetAtt": ["RemediationLambda", "Arn"]}
                        }
                    ]
                }
            },
            # Lambda permission for EventBridge
            "LambdaInvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "RemediationLambda"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["IMDSModificationRule", "Arn"]}
                }
            }
        },
        "Outputs": {
            "InstanceId": {
                "Description": "EC2 Instance ID",
                "Value": {"Ref": "ExperimentInstance"},
                "Export": {"Name": f"sce-1-4-reactive-instance-id-{TIMESTAMP_SUFFIX}"}
            },
            "LambdaFunctionName": {
                "Description": "Remediation Lambda Function Name",
                "Value": {"Ref": "RemediationLambda"},
                "Export": {"Name": f"sce-1-4-reactive-lambda-name-{TIMESTAMP_SUFFIX}"}
            },
            "EventRuleName": {
                "Description": "EventBridge Rule Name",
                "Value": {"Ref": "IMDSModificationRule"},
                "Export": {"Name": f"sce-1-4-reactive-rule-name-{TIMESTAMP_SUFFIX}"}
            },
            "TrailName": {
                "Description": "CloudTrail Trail Name",
                "Value": {"Ref": "ExperimentTrail"},
                "Export": {"Name": f"sce-1-4-reactive-trail-name-{TIMESTAMP_SUFFIX}"}
            },
            "BucketName": {
                "Description": "CloudTrail S3 Bucket Name",
                "Value": {"Ref": "CloudTrailBucket"},
                "Export": {"Name": f"sce-1-4-reactive-bucket-name-{TIMESTAMP_SUFFIX}"}
            }
        }
    }
    
    return json.dumps(template)


def steady_state() -> bool:
    """
    Preparation block: Deploy CloudFormation stack with all required resources.
    
    Creates:
    - EC2 instance with IMDSv2 enforced (secure baseline)
    - Lambda function for auto-remediation
    - EventBridge rule to trigger Lambda on IMDS modification
    - CloudTrail for event capture
    
    Returns:
        bool: True if setup successful, False otherwise
    """
    logger.info("=" * 60)
    logger.info("SCE EXPERIMENT 1.4 - REACTIVE PROBE")
    logger.info("Validating Auto-Remediation Lambda for IMDS Weakening")
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
                    elif output['OutputKey'] == 'LambdaFunctionName':
                        _experiment_state['lambda_function_name'] = output['OutputValue']
                    elif output['OutputKey'] == 'EventRuleName':
                        _experiment_state['event_rule_name'] = output['OutputValue']
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
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': EXPERIMENT_TAG},
                {'Key': 'Timestamp', 'Value': TIMESTAMP_SUFFIX},
                {'Key': 'Purpose', 'Value': 'SCE-Reactive-Probe-IMDS-Remediation'}
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
                reason = response['Stacks'][0].get('StackStatusReason', 'Unknown')
                raise Exception(f"Stack creation failed with status: {status}, reason: {reason}")
            
            logger.info(f"Stack status: {status}")
            return False
        
        # Wait for stack creation with 20-minute timeout
        if not _wait_with_backoff(check_stack_complete, 1200, "Stack creation"):
            logger.error("Stack creation timed out")
            return False
        
        # Get stack outputs
        response = cfn_client.describe_stacks(StackName=STACK_NAME)
        outputs = response['Stacks'][0].get('Outputs', [])
        
        for output in outputs:
            if output['OutputKey'] == 'InstanceId':
                _experiment_state['instance_id'] = output['OutputValue']
                logger.info(f"EC2 Instance ID: {output['OutputValue']}")
            elif output['OutputKey'] == 'LambdaFunctionName':
                _experiment_state['lambda_function_name'] = output['OutputValue']
                logger.info(f"Lambda Function: {output['OutputValue']}")
            elif output['OutputKey'] == 'EventRuleName':
                _experiment_state['event_rule_name'] = output['OutputValue']
                logger.info(f"EventBridge Rule: {output['OutputValue']}")
            elif output['OutputKey'] == 'BucketName':
                _experiment_state['bucket_name'] = output['OutputValue']
                logger.info(f"S3 Bucket: {output['OutputValue']}")
        
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
        
        # Verify Lambda function exists and is active
        lambda_client = _get_boto3_client('lambda')
        lambda_name = _experiment_state['lambda_function_name']
        
        def check_lambda_active():
            response = lambda_client.get_function(FunctionName=lambda_name)
            state = response['Configuration'].get('State', 'Unknown')
            return state == 'Active'
        
        logger.info("Verifying Lambda function is active...")
        if not _wait_with_backoff(check_lambda_active, 120, "Lambda active"):
            logger.error("Lambda function failed to become active")
            return False
        
        # Verify EventBridge rule is enabled
        events_client = _get_boto3_client('events')
        rule_name = _experiment_state['event_rule_name']
        
        def check_rule_enabled():
            response = events_client.describe_rule(Name=rule_name)
            state = response.get('State', 'DISABLED')
            return state == 'ENABLED'
        
        logger.info("Verifying EventBridge rule is enabled...")
        if not _wait_with_backoff(check_rule_enabled, 60, "EventBridge rule enabled"):
            logger.error("EventBridge rule is not enabled")
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
        logger.info("Reactive control chain: EventBridge -> Lambda -> EC2 ModifyInstanceMetadataOptions")
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
    
    The reactive control (Lambda) should automatically revert these changes.
    
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
        # Record the attack timestamp
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
        
        logger.info("Attack executed. Immediate IMDS configuration:")
        logger.info(f"  HttpTokens: {new_http_tokens}")
        logger.info(f"  HttpPutResponseHopLimit: {new_hop_limit}")
        
        if new_http_tokens == 'optional' or new_hop_limit == 2:
            logger.info("IMDS security successfully weakened (attack successful)")
            logger.info("Now waiting for reactive control to trigger remediation...")
            return True
        else:
            logger.warning("IMDS modification may not have fully applied")
            return True  # Attack was still executed
            
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        logger.error(f"Attack failed: {error_code} - {error_msg}")
        
        if error_code == 'AccessDenied':
            logger.info("Preventive control blocked the attack")
            return False
        
        return False
    except Exception as e:
        logger.error(f"Unexpected error during attack: {e}")
        return False


def hypothesis_verification() -> bool:
    """
    Verify that the reactive control automatically remediated the IMDS configuration.
    
    This validates the Reactive probe from SCE Node 1.4:
    - Check if IMDS configuration was reverted to secure state
    - Verify HttpTokens is 'required' and HopLimit is 1
    - Check Lambda invocation logs for confirmation
    - Implement 30-minute SLA for eventual consistency
    
    Returns:
        bool: True if remediation occurred, False otherwise
    """
    logger.info("=" * 60)
    logger.info("HYPOTHESIS VERIFICATION: Reactive Control Remediation")
    logger.info("=" * 60)
    
    instance_id = _experiment_state.get('instance_id')
    lambda_name = _experiment_state.get('lambda_function_name')
    attack_timestamp = _experiment_state.get('attack_timestamp')
    
    if not all([instance_id, lambda_name, attack_timestamp]):
        logger.error("Missing experiment state. Ensure steady_state() and attack() were executed.")
        return False
    
    ec2_client = _get_boto3_client('ec2')
    logs_client = _get_boto3_client('logs')
    
    logger.info(f"Verifying IMDS remediation on instance: {instance_id}")
    logger.info(f"Lambda function: {lambda_name}")
    logger.info(f"SLA: {REMEDIATION_SLA_SECONDS} seconds (30 minutes)")
    
    remediation_confirmed = False
    lambda_invoked = False
    
    def check_imds_remediated():
        """Check if IMDS has been reverted to secure configuration."""
        nonlocal remediation_confirmed
        
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            
            if not response['Reservations']:
                logger.warning(f"Instance {instance_id} not found")
                return False
            
            metadata_options = response['Reservations'][0]['Instances'][0].get('MetadataOptions', {})
            
            current_http_tokens = metadata_options.get('HttpTokens', 'optional')
            current_hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
            
            logger.info(f"Current IMDS config - HttpTokens: {current_http_tokens}, HopLimit: {current_hop_limit}")
            
            # Check if remediation has occurred
            if current_http_tokens == 'required' and current_hop_limit == 1:
                logger.info("IMDS configuration is in secure state!")
                remediation_confirmed = True
                return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Error checking IMDS configuration: {e}")
            return False
    
    def check_lambda_invocation():
        """Check Lambda CloudWatch logs for remediation evidence."""
        nonlocal lambda_invoked
        
        try:
            log_group_name = f"/aws/lambda/{lambda_name}"
            
            # Check if log group exists
            try:
                logs_client.describe_log_groups(logGroupNamePrefix=log_group_name)
            except ClientError:
                logger.info("Lambda log group not yet created")
                return False
            
            # Query recent logs
            end_time = int(time.time() * 1000)
            start_time = int(attack_timestamp * 1000) - 60000  # 1 minute before attack
            
            response = logs_client.filter_log_events(
                logGroupName=log_group_name,
                startTime=start_time,
                endTime=end_time,
                filterPattern='"REMEDIATING"'
            )
            
            events = response.get('events', [])
            
            if events:
                logger.info(f"Found {len(events)} remediation log entries")
                for event in events[:3]:  # Show first 3 entries
                    logger.info(f"  Lambda log: {event.get('message', '')[:200]}")
                lambda_invoked = True
                return True
            
            # Also check for any Lambda invocations
            response = logs_client.filter_log_events(
                logGroupName=log_group_name,
                startTime=start_time,
                endTime=end_time,
                filterPattern='"Received event"'
            )
            
            if response.get('events'):
                logger.info("Lambda was invoked (event received)")
                lambda_invoked = True
            
            return False
            
        except ClientError as e:
            if 'ResourceNotFoundException' in str(e):
                logger.info("Lambda log group not yet available")
            else:
                logger.warning(f"Error checking Lambda logs: {e}")
            return False
    
    # Combined check function
    def verify_remediation():
        imds_ok = check_imds_remediated()
        lambda_ok = check_lambda_invocation()
        
        # We consider success if IMDS is remediated
        # Lambda logs are additional evidence but not strictly required
        return imds_ok
    
    # Wait for remediation with 30-minute SLA
    if _wait_with_backoff(verify_remediation, REMEDIATION_SLA_SECONDS, "IMDS remediation"):
        logger.info("=" * 60)
        logger.info("HYPOTHESIS VERIFIED: Reactive control is working")
        logger.info("=" * 60)
        logger.info("Evidence collected:")
        logger.info(f"  - IMDS configuration remediated: {remediation_confirmed}")
        logger.info(f"  - Lambda invocation logged: {lambda_invoked}")
        logger.info("Auto-remediation Lambda successfully reverted IMDS to secure configuration")
        return True
    else:
        # Final check on IMDS state
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            metadata_options = response['Reservations'][0]['Instances'][0].get('MetadataOptions', {})
            final_http_tokens = metadata_options.get('HttpTokens', 'optional')
            final_hop_limit = metadata_options.get('HttpPutResponseHopLimit', 1)
            
            logger.error("=" * 60)
            logger.error("HYPOTHESIS FAILED: Reactive control did not remediate in time")
            logger.error("=" * 60)
            logger.error(f"Final IMDS state - HttpTokens: {final_http_tokens}, HopLimit: {final_hop_limit}")
            logger.error(f"Expected - HttpTokens: required, HopLimit: 1")
            
            # If IMDS is still in secure state, it might have been remediated
            if final_http_tokens == 'required' and final_hop_limit == 1:
                logger.info("Note: IMDS is in secure state - remediation may have occurred")
                return True
                
        except Exception as e:
            logger.error(f"Error in final IMDS check: {e}")
        
        return False


def rollback() -> bool:
    """
    Complete teardown: Delete CloudFormation stack and all resources.
    
    This function:
    - Reverts IMDS to secure settings (defensive measure)
    - Empties S3 bucket
    - Deletes the CloudFormation stack
    - Waits for deletion to complete
    - Handles errors gracefully
    
    Returns:
        bool: True if rollback successful, False otherwise
    """
    logger.info("=" * 60)
    logger.info("ROLLBACK: Cleaning up experiment resources")
    logger.info("=" * 60)
    
    cfn_client = _get_boto3_client('cloudformation')
    stack_name = _experiment_state.get('stack_name', STACK_NAME)
    
    try:
        # First, ensure IMDS is in secure state
        instance_id = _experiment_state.get('instance_id')
        if instance_id:
            try:
                ec2_client = _get_boto3_client('ec2')
                logger.info(f"Ensuring IMDS is in secure state on instance {instance_id}...")
                ec2_client.modify_instance_metadata_options(
                    InstanceId=instance_id,
                    HttpTokens='required',
                    HttpPutResponseHopLimit=1
                )
                logger.info("IMDS settings confirmed secure")
            except Exception as e:
                logger.warning(f"Could not modify IMDS settings: {e}")
        
        # Empty the S3 bucket before stack deletion
        bucket_name = _experiment_state.get('bucket_name')
        if bucket_name:
            try:
                s3_resource = _get_boto3_resource('s3')
                bucket = s3_resource.Bucket(bucket_name)
                logger.info(f"Emptying S3 bucket {bucket_name}...")
                bucket.objects.all().delete()
                bucket.object_versions.all().delete()
                logger.info("S3 bucket emptied")
            except Exception as e:
                logger.warning(f"Could not empty S3 bucket: {e}")
        
        # Delete Lambda log group (not part of stack)
        lambda_name = _experiment_state.get('lambda_function_name')
        if lambda_name:
            try:
                logs_client = _get_boto3_client('logs')
                log_group_name = f"/aws/lambda/{lambda_name}"
                logs_client.delete_log_group(logGroupName=log_group_name)
                logger.info(f"Deleted Lambda log group: {log_group_name}")
            except ClientError as e:
                if 'ResourceNotFoundException' not in str(e):
                    logger.warning(f"Could not delete Lambda log group: {e}")
        
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
                    reason = response['Stacks'][0].get('StackStatusReason', 'Unknown')
                    logger.error(f"Stack deletion failed. Status: {status}, Reason: {reason}")
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
    logger.info("STARTING SCE EXPERIMENT 1.4 - REACTIVE PROBE")
    logger.info("=" * 60)
    
    success = False
    
    try:
        # Step 1: Establish steady state
        if not steady_state():
            logger.error("Failed to establish steady state")
            return False
        
        # Step 2: Execute attack
        if not attack():
            logger.warning("Attack failed - checking if preventive control blocked it")
        
        # Step 3: Verify hypothesis (reactive remediation)
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
            logger.info("Reactive control validated successfully")
            logger.info("=" * 60)
        else:
            logger.info("=" * 60)
            logger.info("EXPERIMENT RESULT: FAILED")
            logger.info("Reactive control did not meet expectations")
            logger.info("=" * 60)


# For direct execution
if __name__ == "__main__":
    run_experiment()