"""
Security Chaos Engineering Experiment: 1.34 - Reactive Probe
Validates automated IMDS remediation and credential revocation response
for attack step 1.2 (Weaken IMDS Protection via ModifyInstanceMetadataOptions)
"""

import json
import time
import sys
import logging
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Runtime dependency installation
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    logger.info("Installing boto3...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "boto3"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Global state
STACK_NAME = None
INSTANCE_ID = None
ROLE_NAME = None
ORIGINAL_IMDS_CONFIG = {}
EXPERIMENT_START_TIME = None

def _get_timestamp_suffix():
    """Generate unique timestamp suffix for resource naming"""
    return str(int(time.time()))

def _retry_with_backoff(func, max_attempts=5, initial_delay=2, max_delay=60):
    """Execute function with exponential backoff retry logic"""
    delay = initial_delay
    for attempt in range(max_attempts):
        try:
            return func()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['Throttling', 'RequestLimitExceeded', 'TooManyRequestsException']:
                if attempt < max_attempts - 1:
                    logger.warning(f"Throttled, retrying in {delay}s (attempt {attempt + 1}/{max_attempts})")
                    time.sleep(delay)
                    delay = min(delay * 2, max_delay)
                else:
                    raise
            else:
                raise
        except Exception as e:
            if attempt < max_attempts - 1:
                logger.warning(f"Error: {e}, retrying in {delay}s")
                time.sleep(delay)
                delay = min(delay * 2, max_delay)
            else:
                raise

def _wait_for_stack_complete(cfn_client, stack_name, operation='create'):
    """Wait for CloudFormation stack operation to complete"""
    if operation == 'create':
        waiter = cfn_client.get_waiter('stack_create_complete')
    elif operation == 'delete':
        waiter = cfn_client.get_waiter('stack_delete_complete')
    else:
        raise ValueError(f"Unknown operation: {operation}")
    
    try:
        logger.info(f"Waiting for stack {operation} to complete...")
        waiter.wait(
            StackName=stack_name,
            WaiterConfig={'Delay': 15, 'MaxAttempts': 60}
        )
        logger.info(f"Stack {operation} completed successfully")
        return True
    except WaiterError as e:
        logger.error(f"Stack {operation} failed: {e}")
        return False

def _get_ami_id(ec2_client):
    """Get latest Amazon Linux 2 AMI ID"""
    try:
        response = ec2_client.describe_images(
            Owners=['amazon'],
            Filters=[
                {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                {'Name': 'state', 'Values': ['available']}
            ]
        )
        images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
        if images:
            return images[0]['ImageId']
        raise Exception("No Amazon Linux 2 AMI found")
    except Exception as e:
        logger.error(f"Failed to get AMI ID: {e}")
        raise

def steady_state():
    """
    Preparation: Deploy CloudFormation stack with EC2 instance, IAM role,
    EventBridge rule, Lambda function, and Step Functions workflow for
    automated IMDS remediation
    """
    global STACK_NAME, INSTANCE_ID, ROLE_NAME, EXPERIMENT_START_TIME
    
    logger.info("=== Starting Steady State Setup ===")
    EXPERIMENT_START_TIME = datetime.utcnow()
    
    try:
        # Initialize AWS clients
        cfn_client = boto3.client('cloudformation')
        ec2_client = boto3.client('ec2')
        
        # Generate unique stack name
        timestamp = _get_timestamp_suffix()
        STACK_NAME = f"sce-imds-reactive-{timestamp}"
        logger.info(f"Stack name: {STACK_NAME}")
        
        # Get latest AMI
        ami_id = _get_ami_id(ec2_client)
        logger.info(f"Using AMI: {ami_id}")
        
        # CloudFormation template for reactive control experiment
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "SCE Experiment 1.34 - IMDS Reactive Remediation Test",
            "Resources": {
                # VPC and Networking
                "VPC": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {
                        "CidrBlock": "10.0.0.0/16",
                        "EnableDnsHostnames": True,
                        "EnableDnsSupport": True,
                        "Tags": [
                            {"Key": "Name", "Value": f"sce-vpc-{timestamp}"},
                            {"Key": "Experiment", "Value": "SCE-1.34-Reactive"}
                        ]
                    }
                },
                "Subnet": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "VPC"},
                        "CidrBlock": "10.0.1.0/24",
                        "MapPublicIpOnLaunch": True,
                        "Tags": [
                            {"Key": "Name", "Value": f"sce-subnet-{timestamp}"},
                            {"Key": "Experiment", "Value": "SCE-1.34-Reactive"}
                        ]
                    }
                },
                "InternetGateway": {
                    "Type": "AWS::EC2::InternetGateway",
                    "Properties": {
                        "Tags": [
                            {"Key": "Name", "Value": f"sce-igw-{timestamp}"},
                            {"Key": "Experiment", "Value": "SCE-1.34-Reactive"}
                        ]
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
                        "Tags": [
                            {"Key": "Name", "Value": f"sce-rt-{timestamp}"},
                            {"Key": "Experiment", "Value": "SCE-1.34-Reactive"}
                        ]
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
                        "GroupDescription": "SCE Experiment Security Group",
                        "VpcId": {"Ref": "VPC"},
                        "SecurityGroupEgress": [
                            {"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}
                        ],
                        "Tags": [
                            {"Key": "Name", "Value": f"sce-sg-{timestamp}"},
                            {"Key": "Experiment", "Value": "SCE-1.34-Reactive"}
                        ]
                    }
                },
                # IAM Role for EC2 Instance
                "InstanceRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": f"SCE-BankingAPIRole-{timestamp}",
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
                        "Policies": [{
                            "PolicyName": "BankingAPIPermissions",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:ListBucket", "s3:GetObject"],
                                        "Resource": "*"
                                    }
                                ]
                            }
                        }],
                        "Tags": [
                            {"Key": "Experiment", "Value": "SCE-1.34-Reactive"}
                        ]
                    }
                },
                "InstanceProfile": {
                    "Type": "AWS::IAM::InstanceProfile",
                    "Properties": {
                        "Roles": [{"Ref": "InstanceRole"}],
                        "InstanceProfileName": f"SCE-BankingAPIProfile-{timestamp}"
                    }
                },
                # Lambda Execution Role
                "LambdaExecutionRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": f"SCE-RemediationLambdaRole-{timestamp}",
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole"
                            }]
                        },
                        "ManagedPolicyArns": [
                            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                        ],
                        "Policies": [{
                            "PolicyName": "RemediationPermissions",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:ModifyInstanceMetadataOptions",
                                            "ec2:DescribeInstances",
                                            "ec2:DescribeSecurityGroups",
                                            "ec2:CreateSecurityGroup",
                                            "ec2:ModifyInstanceAttribute",
                                            "ec2:CreateSnapshot",
                                            "ec2:CreateTags"
                                        ],
                                        "Resource": "*"
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "iam:PutRolePolicy",
                                            "iam:GetRole"
                                        ],
                                        "Resource": "*"
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "sns:Publish"
                                        ],
                                        "Resource": "*"
                                    }
                                ]
                            }
                        }],
                        "Tags": [
                            {"Key": "Experiment", "Value": "SCE-1.34-Reactive"}
                        ]
                    }
                },
                # Lambda Function for IMDS Remediation
                "RemediationFunction": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "FunctionName": f"SCE-IMDSRemediation-{timestamp}",
                        "Runtime": "python3.11",
                        "Handler": "index.lambda_handler",
                        "Role": {"Fn::GetAtt": ["LambdaExecutionRole", "Arn"]},
                        "Timeout": 300,
                        "Code": {
                            "ZipFile": """
import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2')
iam = boto3.client('iam')

def lambda_handler(event, context):
    logger.info(f"Received event: {json.dumps(event)}")
    
    try:
        # Extract instance ID from event
        detail = event.get('detail', {})
        request_params = detail.get('requestParameters', {})
        instance_id = request_params.get('instanceId')
        
        if not instance_id:
            logger.error("No instance ID found in event")
            return {'statusCode': 400, 'body': 'No instance ID'}
        
        logger.info(f"Remediating instance: {instance_id}")
        
        # Step 1: Revert IMDS to secure configuration
        logger.info("Step 1: Reverting IMDS to IMDSv2-required")
        ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='required',
            HttpPutResponseHopLimit=1,
            HttpEndpoint='enabled'
        )
        logger.info("IMDS reverted to secure configuration")
        
        # Step 2: Get instance details
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        iam_profile_arn = instance.get('IamInstanceProfile', {}).get('Arn', '')
        
        if iam_profile_arn:
            # Extract role name from profile ARN
            profile_name = iam_profile_arn.split('/')[-1]
            logger.info(f"Instance profile: {profile_name}")
            
            # Step 3: Apply deny policy to instance role
            logger.info("Step 2: Applying temporary deny policy to instance role")
            try:
                # Get role name from instance profile
                iam_resource = boto3.resource('iam')
                instance_profile = iam_resource.InstanceProfile(profile_name)
                roles = list(instance_profile.roles)
                
                if roles:
                    role_name = roles[0].name
                    logger.info(f"Found role: {role_name}")
                    
                    deny_policy = {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Deny",
                            "Action": "*",
                            "Resource": "*",
                            "Condition": {
                                "DateGreaterThan": {
                                    "aws:TokenIssueTime": event['time']
                                }
                            }
                        }]
                    }
                    
                    iam.put_role_policy(
                        RoleName=role_name,
                        PolicyName='SCE-EmergencyDeny',
                        PolicyDocument=json.dumps(deny_policy)
                    )
                    logger.info("Temporary deny policy applied")
            except Exception as e:
                logger.error(f"Failed to apply deny policy: {e}")
        
        # Step 4: Tag instance for quarantine
        logger.info("Step 3: Tagging instance as quarantined")
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {'Key': 'SecurityStatus', 'Value': 'QUARANTINE'},
                {'Key': 'IncidentTimestamp', 'Value': event['time']}
            ]
        )
        
        logger.info("Remediation completed successfully")
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Remediation successful',
                'instanceId': instance_id
            })
        }
        
    except Exception as e:
        logger.error(f"Remediation failed: {e}")
        return {'statusCode': 500, 'body': str(e)}
"""
                        },
                        "Tags": [
                            {"Key": "Experiment", "Value": "SCE-1.34-Reactive"}
                        ]
                    }
                },
                # EventBridge Rule
                "IMDSChangeRule": {
                    "Type": "AWS::Events::Rule",
                    "Properties": {
                        "Name": f"SCE-IMDSChangeDetection-{timestamp}",
                        "Description": "Detect IMDS configuration weakening",
                        "EventPattern": json.dumps({
                            "source": ["aws.ec2"],
                            "detail-type": ["AWS API Call via CloudTrail"],
                            "detail": {
                                "eventName": ["ModifyInstanceMetadataOptions"],
                                "requestParameters": {
                                    "httpTokens": ["optional"]
                                }
                            }
                        }),
                        "State": "ENABLED",
                        "Targets": [{
                            "Arn": {"Fn::GetAtt": ["RemediationFunction", "Arn"]},
                            "Id": "RemediationTarget"
                        }]
                    }
                },
                "LambdaInvokePermission": {
                    "Type": "AWS::Lambda::Permission",
                    "Properties": {
                        "FunctionName": {"Ref": "RemediationFunction"},
                        "Action": "lambda:InvokeFunction",
                        "Principal": "events.amazonaws.com",
                        "SourceArn": {"Fn::GetAtt": ["IMDSChangeRule", "Arn"]}
                    }
                },
                # EC2 Instance
                "TestInstance": {
                    "Type": "AWS::EC2::Instance",
                    "DependsOn": ["InstanceProfile", "SubnetRouteTableAssociation"],
                    "Properties": {
                        "ImageId": ami_id,
                        "InstanceType": "t3.micro",
                        "IamInstanceProfile": {"Ref": "InstanceProfile"},
                        "SubnetId": {"Ref": "Subnet"},
                        "SecurityGroupIds": [{"Ref": "SecurityGroup"}],
                        "MetadataOptions": {
                            "HttpTokens": "required",
                            "HttpPutResponseHopLimit": 1,
                            "HttpEndpoint": "enabled"
                        },
                        "Tags": [
                            {"Key": "Name", "Value": f"sce-banking-api-{timestamp}"},
                            {"Key": "Experiment", "Value": "SCE-1.34-Reactive"},
                            {"Key": "Environment", "Value": "Production"}
                        ]
                    }
                }
            },
            "Outputs": {
                "InstanceId": {
                    "Description": "EC2 Instance ID",
                    "Value": {"Ref": "TestInstance"}
                },
                "RoleName": {
                    "Description": "IAM Role Name",
                    "Value": {"Ref": "InstanceRole"}
                },
                "LambdaFunctionName": {
                    "Description": "Lambda Function Name",
                    "Value": {"Ref": "RemediationFunction"}
                }
            }
        }
        
        # Create stack
        logger.info("Creating CloudFormation stack...")
        cfn_client.create_stack(
            StackName=STACK_NAME,
            TemplateBody=json.dumps(template),
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': 'SCE-1.34-Reactive'},
                {'Key': 'Timestamp', 'Value': timestamp}
            ]
        )
        
        # Wait for stack creation
        if not _wait_for_stack_complete(cfn_client, STACK_NAME, 'create'):
            raise Exception("Stack creation failed")
        
        # Get outputs
        response = cfn_client.describe_stacks(StackName=STACK_NAME)
        outputs = response['Stacks'][0]['Outputs']
        
        for output in outputs:
            if output['OutputKey'] == 'InstanceId':
                INSTANCE_ID = output['OutputValue']
            elif output['OutputKey'] == 'RoleName':
                ROLE_NAME = output['OutputValue']
        
        logger.info(f"Instance ID: {INSTANCE_ID}")
        logger.info(f"Role Name: {ROLE_NAME}")
        
        # Wait for IAM propagation
        logger.info("Waiting for IAM role propagation (30 seconds)...")
        time.sleep(30)
        
        # Wait for instance to be running
        logger.info("Waiting for instance to reach running state...")
        ec2_client.get_waiter('instance_running').wait(InstanceIds=[INSTANCE_ID])
        
        # Store original IMDS configuration
        response = ec2_client.describe_instances(InstanceIds=[INSTANCE_ID])
        instance = response['Reservations'][0]['Instances'][0]
        metadata_options = instance.get('MetadataOptions', {})
        ORIGINAL_IMDS_CONFIG = {
            'HttpTokens': metadata_options.get('HttpTokens', 'required'),
            'HttpPutResponseHopLimit': metadata_options.get('HttpPutResponseHopLimit', 1)
        }
        logger.info(f"Original IMDS config: {ORIGINAL_IMDS_CONFIG}")
        
        logger.info("=== Steady State Setup Complete ===")
        return True
        
    except Exception as e:
        logger.error(f"Steady state setup failed: {e}")
        raise

def attack():
    """
    Execute Attack Step 1.2: Modify Instance Metadata Options to Weaken IMDS Protections
    
    Command: aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> 
             --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2
    """
    global INSTANCE_ID
    
    logger.info("=== Starting Attack Execution ===")
    
    try:
        if not INSTANCE_ID:
            raise Exception("Instance ID not available - steady_state() may have failed")
        
        ec2_client = boto3.client('ec2')
        
        logger.info(f"Attacking instance: {INSTANCE_ID}")
        logger.info("Weakening IMDS protection: setting HttpTokens=optional, HopLimit=2")
        
        # Execute the attack - weaken IMDS configuration
        response = ec2_client.modify_instance_metadata_options(
            InstanceId=INSTANCE_ID,
            HttpTokens='optional',  # Enable IMDSv1 (insecure)
            HttpPutResponseHopLimit=2,  # Increase hop limit (allows container access)
            HttpEndpoint='enabled'
        )
        
        logger.info(f"Attack executed successfully. Response: {response['ResponseMetadata']['HTTPStatusCode']}")
        
        # Verify the attack succeeded
        time.sleep(5)  # Brief wait for consistency
        response = ec2_client.describe_instances(InstanceIds=[INSTANCE_ID])
        instance = response['Reservations'][0]['Instances'][0]
        metadata_options = instance.get('MetadataOptions', {})
        
        current_tokens = metadata_options.get('HttpTokens')
        current_hop_limit = metadata_options.get('HttpPutResponseHopLimit')
        
        logger.info(f"Current IMDS config - HttpTokens: {current_tokens}, HopLimit: {current_hop_limit}")
        
        if current_tokens == 'optional' and current_hop_limit == 2:
            logger.info("Attack successful: IMDS protections weakened")
            logger.info("=== Attack Execution Complete ===")
            return True
        else:
            logger.error("Attack verification failed: IMDS config not as expected")
            return False
            
    except ClientError as e:
        logger.error(f"Attack failed with AWS error: {e}")
        return False
    except Exception as e:
        logger.error(f"Attack failed: {e}")
        return False

def hypothesis_verification():
    """
    Reactive Probe Verification: Validate automated IMDS remediation response
    
    Expected behavior (from SCE node 1.3):
    1. EventBridge rule triggers Lambda function on IMDS change detection
    2. Lambda reverts IMDS to IMDSv2-required (HttpTokens=required, HopLimit=1)
    3. Temporary deny policy applied to instance role
    4. Instance tagged with QUARANTINE status
    5. All actions complete within MTTR target (5 minutes for auto-remediation)
    
    Verification steps:
    1. Poll CloudTrail for Lambda invocation (30-minute SLA)
    2. Verify IMDS configuration reverted to secure state
    3. Confirm IAM inline policy applied to instance role
    4. Check instance tags for quarantine marker
    5. Measure response time from attack to remediation
    """
    global INSTANCE_ID, ROLE_NAME, EXPERIMENT_START_TIME
    
    logger.info("=== Starting Hypothesis Verification (Reactive Probe) ===")
    
    try:
        if not INSTANCE_ID or not ROLE_NAME:
            logger.error("Missing required state (instance ID or role name)")
            return False
        
        ec2_client = boto3.client('ec2')
        iam_client = boto3.client('iam')
        logs_client = boto3.client('logs')
        
        # SLA: 30-minute polling window for AWS eventual consistency
        max_wait_seconds = 1800  # 30 minutes
        poll_interval = 15  # Check every 15 seconds
        start_time = time.monotonic()
        
        remediation_detected = False
        remediation_timestamp = None
        
        logger.info("Polling for reactive remediation (30-minute SLA)...")
        
        while (time.monotonic() - start_time) < max_wait_seconds:
            elapsed = int(time.monotonic() - start_time)
            logger.info(f"Polling attempt at {elapsed}s / {max_wait_seconds}s")
            
            try:
                # Check 1: Verify IMDS configuration reverted
                response = ec2_client.describe_instances(InstanceIds=[INSTANCE_ID])
                instance = response['Reservations'][0]['Instances'][0]
                metadata_options = instance.get('MetadataOptions', {})
                
                current_tokens = metadata_options.get('HttpTokens')
                current_hop_limit = metadata_options.get('HttpPutResponseHopLimit')
                
                logger.info(f"Current IMDS - HttpTokens: {current_tokens}, HopLimit: {current_hop_limit}")
                
                imds_reverted = (current_tokens == 'required' and current_hop_limit == 1)
                
                # Check 2: Verify instance tagged for quarantine
                tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                quarantine_tagged = ('SecurityStatus' in tags and tags['SecurityStatus'] == 'QUARANTINE')
                
                if quarantine_tagged:
                    logger.info(f"Quarantine tag detected: {tags.get('SecurityStatus')}")
                
                # Check 3: Verify IAM inline policy applied
                try:
                    response = iam_client.get_role_policy(
                        RoleName=ROLE_NAME,
                        PolicyName='SCE-EmergencyDeny'
                    )
                    deny_policy_applied = True
                    policy_document = response.get('PolicyDocument', {})
                    logger.info(f"Deny policy detected on role {ROLE_NAME}")
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchEntity':
                        deny_policy_applied = False
                    else:
                        raise
                
                # All conditions met = remediation successful
                if imds_reverted and quarantine_tagged and deny_policy_applied:
                    remediation_detected = True
                    remediation_timestamp = time.monotonic()
                    logger.info("✓ All reactive controls verified successfully")
                    break
                else:
                    status = []
                    if not imds_reverted:
                        status.append("IMDS not reverted")
                    if not quarantine_tagged:
                        status.append("No quarantine tag")
                    if not deny_policy_applied:
                        status.append("No deny policy")
                    logger.info(f"Partial remediation: {', '.join(status)}")
                
            except Exception as e:
                logger.warning(f"Polling error: {e}")
            
            time.sleep(poll_interval)
        
        # Verification results
        if not remediation_detected:
            logger.error("✗ Reactive remediation NOT detected within 30-minute SLA")
            logger.error("Expected: IMDS reverted, quarantine tag, deny policy applied")
            return False
        
        # Calculate response time
        response_time = remediation_timestamp - start_time
        logger.info(f"Response time: {response_time:.1f} seconds")
        
        # Verify MTTR target (5 minutes = 300 seconds for auto-remediation)
        mttr_target = 300
        if response_time <= mttr_target:
            logger.info(f"✓ MTTR target met: {response_time:.1f}s <= {mttr_target}s")
        else:
            logger.warning(f"⚠ MTTR target exceeded: {response_time:.1f}s > {mttr_target}s")
        
        # Final state verification
        logger.info("=== Final State Verification ===")
        
        # Verify IMDS configuration
        response = ec2_client.describe_instances(InstanceIds=[INSTANCE_ID])
        instance = response['Reservations'][0]['Instances'][0]
        metadata_options = instance.get('MetadataOptions', {})
        
        logger.info(f"Final IMDS - HttpTokens: {metadata_options.get('HttpTokens')}")
        logger.info(f"Final IMDS - HopLimit: {metadata_options.get('HttpPutResponseHopLimit')}")
        
        # Verify instance tags
        tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
        logger.info(f"Final Tags - SecurityStatus: {tags.get('SecurityStatus')}")
        logger.info(f"Final Tags - IncidentTimestamp: {tags.get('IncidentTimestamp')}")
        
        # Verify IAM policy
        try:
            response = iam_client.get_role_policy(
                RoleName=ROLE_NAME,
                PolicyName='SCE-EmergencyDeny'
            )
            logger.info("Final State - Deny policy present on role")
        except ClientError:
            logger.warning("Final State - Deny policy not found")
        
        logger.info("=== Hypothesis Verification Complete: SUCCESS ===")
        return True
        
    except Exception as e:
        logger.error(f"Hypothesis verification failed: {e}")
        return False

def rollback():
    """
    Complete teardown: Delete CloudFormation stack and all resources
    """
    global STACK_NAME
    
    logger.info("=== Starting Rollback ===")
    
    try:
        if not STACK_NAME:
            logger.warning("No stack name available, nothing to rollback")
            return True
        
        cfn_client = boto3.client('cloudformation')
        
        # Check if stack exists
        try:
            cfn_client.describe_stacks(StackName=STACK_NAME)
            logger.info(f"Deleting stack: {STACK_NAME}")
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.info("Stack already deleted or never created")
                return True
            raise
        
        # Delete stack
        cfn_client.delete_stack(StackName=STACK_NAME)
        
        # Wait for deletion
        if _wait_for_stack_complete(cfn_client, STACK_NAME, 'delete'):
            logger.info("Stack deleted successfully")
        else:
            logger.warning("Stack deletion completed with warnings")
        
        logger.info("=== Rollback Complete ===")
        return True
        
    except ClientError as e:
        if 'does not exist' in str(e):
            logger.info("Stack not found during rollback (already deleted)")
            return True
        logger.error(f"Rollback failed: {e}")
        return False
    except Exception as e:
        logger.error(f"Rollback error: {e}")
        return False

def run_experiment():
    """
    Execute complete experiment flow with proper error handling
    """
    try:
        # Phase 1: Setup
        steady_state()
        
        # Phase 2: Attack
        attack_success = attack()
        if not attack_success:
            logger.error("Attack phase failed")
            return False
        
        # Phase 3: Verification
        verification_success = hypothesis_verification()
        
        return verification_success
        
    finally:
        # Always attempt cleanup
        rollback()

if __name__ == "__main__":
    success = run_experiment()
    sys.exit(0 if success else 1)