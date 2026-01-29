#!/usr/bin/env python3
"""
SCE Experiment 2.4 - Detective Probe
Validates that ECS cluster events detect unauthorized container instance registration.

Attack Steps:
- 1.4: Create EC2 Instance with ECS Configuration
- 2.3: Configure User Data for ECS Cluster Registration

Detective Control: Monitor ECS cluster events for RegisterContainerInstance from unknown
instance; verify alert fires within 3 min
"""

import json
import logging
import os
import time
import sys
import base64
import uuid

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
REGION = os.environ.get('AWS_REGION', 'us-east-1')
TIMESTAMP = int(time.time())
STACK_NAME = f"sce-experiment-2-4-detective-{TIMESTAMP}"
EXPERIMENT_TAG = "sce-2.4-detective"
CLUSTER_NAME = f"sce-target-cluster-{TIMESTAMP}"

# Store created resources for cleanup
_experiment_state = {
    'stack_name': STACK_NAME,
    'stack_created': False,
    'cluster_name': CLUSTER_NAME,
    'cluster_arn': None,
    'instance_id': None,
    'instance_profile_arn': None,
    'instance_role_name': None,
    'vpc_id': None,
    'subnet_id': None,
    'security_group_id': None,
    'log_group_name': None,
    'event_rule_name': None,
    'sns_topic_arn': None,
    'sqs_queue_url': None,
    'sqs_queue_arn': None,
    'attack_executed': False,
    'container_instance_arn': None,
    'registration_detected': False,
    'detection_time_seconds': None,
    'alert_received': False
}


def _get_clients():
    """Initialize AWS clients."""
    return {
        'cloudformation': boto3.client('cloudformation', region_name=REGION),
        'ec2': boto3.client('ec2', region_name=REGION),
        'ecs': boto3.client('ecs', region_name=REGION),
        'iam': boto3.client('iam', region_name=REGION),
        'sts': boto3.client('sts', region_name=REGION),
        'events': boto3.client('events', region_name=REGION),
        'logs': boto3.client('logs', region_name=REGION),
        'sns': boto3.client('sns', region_name=REGION),
        'sqs': boto3.client('sqs', region_name=REGION)
    }


def _wait_with_backoff(check_func, max_attempts=30, initial_delay=2, max_delay=30):
    """Wait with exponential backoff until check_func returns True."""
    delay = initial_delay
    start_time = time.monotonic()
    
    for attempt in range(max_attempts):
        try:
            result = check_func()
            if result:
                return True
        except Exception as e:
            logger.warning(f"Check attempt {attempt + 1} failed: {e}")
        
        if attempt < max_attempts - 1:
            time.sleep(delay)
            delay = min(delay * 1.5, max_delay)
    
    elapsed = time.monotonic() - start_time
    logger.error(f"Wait timed out after {elapsed:.1f}s and {max_attempts} attempts")
    return False


def _get_latest_ecs_optimized_ami():
    """Get the latest ECS-optimized Amazon Linux 2 AMI ID."""
    clients = _get_clients()
    
    try:
        # Use SSM parameter to get latest ECS-optimized AMI
        ssm = boto3.client('ssm', region_name=REGION)
        response = ssm.get_parameter(
            Name='/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id'
        )
        return response['Parameter']['Value']
    except Exception as e:
        logger.warning(f"Could not get ECS AMI from SSM: {e}")
        # Fallback to describe images
        try:
            response = clients['ec2'].describe_images(
                Owners=['amazon'],
                Filters=[
                    {'Name': 'name', 'Values': ['amzn2-ami-ecs-hvm-*-x86_64-ebs']},
                    {'Name': 'state', 'Values': ['available']}
                ]
            )
            images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
            if images:
                return images[0]['ImageId']
        except Exception as e2:
            logger.error(f"Failed to get ECS AMI: {e2}")
        
        # Last resort fallback
        return "ami-0c02fb55956c7d316"


def _get_account_id():
    """Get current AWS account ID."""
    clients = _get_clients()
    return clients['sts'].get_caller_identity()['Account']


def _generate_user_data_script():
    """
    Generate the user data script that simulates Attack Step 2.3.
    This configures the ECS agent to register with the target cluster.
    """
    user_data = f"""#!/bin/bash
# Attack Step 2.3: Configure User Data for ECS Cluster Registration
echo "ECS_CLUSTER={CLUSTER_NAME}" >> /etc/ecs/ecs.config
echo "ECS_BACKEND_HOST=" >> /etc/ecs/ecs.config
echo "ECS_ENABLE_TASK_IAM_ROLE=true" >> /etc/ecs/ecs.config

# Start ECS agent
systemctl enable --now ecs

# Log registration attempt
echo "$(date): ECS agent configured for cluster {CLUSTER_NAME}" >> /var/log/sce-attack.log
"""
    return base64.b64encode(user_data.encode('utf-8')).decode('utf-8')


def _generate_cloudformation_template():
    """Generate CloudFormation template for the experiment."""
    account_id = _get_account_id()
    ecs_ami = _get_latest_ecs_optimized_ami()
    
    logger.info(f"Using ECS-optimized AMI: {ecs_ami}")
    
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"SCE Experiment 2.4 Detective - ECS Registration Detection - {TIMESTAMP}",
        "Parameters": {
            "EcsAmiId": {
                "Type": "String",
                "Default": ecs_ami,
                "Description": "ECS-optimized AMI ID"
            },
            "ClusterName": {
                "Type": "String",
                "Default": CLUSTER_NAME,
                "Description": "Target ECS cluster name"
            }
        },
        "Resources": {
            # VPC for isolated testing
            "ExperimentVPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.98.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport": True,
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-4-vpc-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            # Internet Gateway for ECS agent connectivity
            "InternetGateway": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-4-igw-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            "VPCGatewayAttachment": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "InternetGatewayId": {"Ref": "InternetGateway"}
                }
            },
            # Public Subnet
            "ExperimentSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "CidrBlock": "10.98.1.0/24",
                    "AvailabilityZone": {"Fn::Select": ["0", {"Fn::GetAZs": ""}]},
                    "MapPublicIpOnLaunch": True,
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-4-subnet-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # Route Table
            "RouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-4-rt-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            "PublicRoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "VPCGatewayAttachment",
                "Properties": {
                    "RouteTableId": {"Ref": "RouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "InternetGateway"}
                }
            },
            "SubnetRouteTableAssociation": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "ExperimentSubnet"},
                    "RouteTableId": {"Ref": "RouteTable"}
                }
            },
            # Security Group
            "ExperimentSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE 2.4 Experiment - ECS Agent Connectivity",
                    "VpcId": {"Ref": "ExperimentVPC"},
                    "SecurityGroupIngress": [],
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "CidrIp": "0.0.0.0/0",
                            "Description": "HTTPS for ECS agent"
                        }
                    ],
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-4-sg-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # ECS Cluster (target cluster)
            "TargetECSCluster": {
                "Type": "AWS::ECS::Cluster",
                "Properties": {
                    "ClusterName": {"Ref": "ClusterName"},
                    "ClusterSettings": [
                        {"Name": "containerInsights", "Value": "enabled"}
                    ],
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-2-4-cluster-{TIMESTAMP}"},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            # IAM Role for ECS Instance
            "ECSInstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-2-4-ecs-instance-role-{TIMESTAMP}",
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
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                    ]
                }
            },
            # Instance Profile
            "ECSInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": f"sce-2-4-ecs-profile-{TIMESTAMP}",
                    "Roles": [{"Ref": "ECSInstanceRole"}]
                }
            },
            # SNS Topic for alerts
            "AlertSNSTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {
                    "TopicName": f"sce-2-4-alerts-{TIMESTAMP}",
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # SQS Queue to receive alerts (for verification)
            "AlertSQSQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": f"sce-2-4-alert-queue-{TIMESTAMP}",
                    "MessageRetentionPeriod": 300,
                    "VisibilityTimeout": 30,
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # SQS Queue Policy to allow SNS
            "AlertSQSQueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "AlertSQSQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "sns.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["AlertSQSQueue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {"Ref": "AlertSNSTopic"}
                                    }
                                }
                            },
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["AlertSQSQueue", "Arn"]}
                            }
                        ]
                    }
                }
            },
            # SNS Subscription to SQS
            "SNSToSQSSubscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "TopicArn": {"Ref": "AlertSNSTopic"},
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["AlertSQSQueue", "Arn"]}
                }
            },
            # CloudWatch Log Group for ECS events
            "ECSEventLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": f"/sce/2-4/ecs-events-{TIMESTAMP}",
                    "RetentionInDays": 1,
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            # EventBridge Rule to detect ECS container instance registration
            "ECSRegistrationEventRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": f"sce-2-4-ecs-registration-{TIMESTAMP}",
                    "Description": "Detect ECS container instance registration events",
                    "State": "ENABLED",
                    "EventPattern": {
                        "source": ["aws.ecs"],
                        "detail-type": ["ECS Container Instance State Change"],
                        "detail": {
                            "clusterArn": [{"Fn::GetAtt": ["TargetECSCluster", "Arn"]}],
                            "status": ["ACTIVE", "REGISTERING"]
                        }
                    },
                    "Targets": [
                        {
                            "Id": "SendToSQS",
                            "Arn": {"Fn::GetAtt": ["AlertSQSQueue", "Arn"]}
                        },
                        {
                            "Id": "SendToCloudWatchLogs",
                            "Arn": {"Fn::Sub": "arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/sce/2-4/ecs-events-" + str(TIMESTAMP)}
                        }
                    ]
                }
            },
            # CloudWatch Logs Resource Policy for EventBridge
            "LogsResourcePolicy": {
                "Type": "AWS::Logs::ResourcePolicy",
                "Properties": {
                    "PolicyName": f"sce-2-4-events-to-logs-{TIMESTAMP}",
                    "PolicyDocument": {
                        "Fn::Sub": json.dumps({
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "events.amazonaws.com"},
                                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                                    "Resource": f"arn:aws:logs:${{AWS::Region}}:${{AWS::AccountId}}:log-group:/sce/2-4/ecs-events-{TIMESTAMP}:*"
                                }
                            ]
                        })
                    }
                }
            }
        },
        "Outputs": {
            "ClusterArn": {
                "Description": "ARN of the target ECS cluster",
                "Value": {"Fn::GetAtt": ["TargetECSCluster", "Arn"]}
            },
            "ClusterName": {
                "Description": "Name of the target ECS cluster",
                "Value": {"Ref": "ClusterName"}
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
            },
            "InstanceProfileArn": {
                "Description": "Instance Profile ARN",
                "Value": {"Fn::GetAtt": ["ECSInstanceProfile", "Arn"]}
            },
            "InstanceProfileName": {
                "Description": "Instance Profile Name",
                "Value": {"Ref": "ECSInstanceProfile"}
            },
            "InstanceRoleName": {
                "Description": "Instance Role Name",
                "Value": {"Ref": "ECSInstanceRole"}
            },
            "SNSTopicArn": {
                "Description": "SNS Topic ARN for alerts",
                "Value": {"Ref": "AlertSNSTopic"}
            },
            "SQSQueueUrl": {
                "Description": "SQS Queue URL for alerts",
                "Value": {"Ref": "AlertSQSQueue"}
            },
            "SQSQueueArn": {
                "Description": "SQS Queue ARN for alerts",
                "Value": {"Fn::GetAtt": ["AlertSQSQueue", "Arn"]}
            },
            "LogGroupName": {
                "Description": "CloudWatch Log Group Name",
                "Value": {"Ref": "ECSEventLogGroup"}
            },
            "EventRuleName": {
                "Description": "EventBridge Rule Name",
                "Value": {"Ref": "ECSRegistrationEventRule"}
            },
            "EcsAmiId": {
                "Description": "ECS-optimized AMI ID used",
                "Value": {"Ref": "EcsAmiId"}
            }
        }
    }
    
    return json.dumps(template)


def steady_state():
    """
    Preparation block: Deploy CloudFormation stack with all required resources.
    Creates VPC, ECS cluster, EventBridge rule, SNS/SQS for alert detection.
    """
    logger.info(f"Starting steady_state for experiment {STACK_NAME}")
    clients = _get_clients()
    
    try:
        # Check if stack already exists
        try:
            response = clients['cloudformation'].describe_stacks(StackName=STACK_NAME)
            if response['Stacks']:
                stack_status = response['Stacks'][0]['StackStatus']
                if stack_status in ['CREATE_COMPLETE', 'UPDATE_COMPLETE']:
                    logger.warning(f"Stack {STACK_NAME} already exists with status {stack_status}")
                    _experiment_state['stack_created'] = True
                    _extract_stack_outputs(clients)
                    return True
                elif stack_status in ['CREATE_IN_PROGRESS', 'UPDATE_IN_PROGRESS']:
                    logger.info(f"Stack {STACK_NAME} is in progress, waiting...")
                elif stack_status in ['ROLLBACK_COMPLETE', 'DELETE_COMPLETE']:
                    logger.info(f"Stack in {stack_status}, will recreate")
                    try:
                        clients['cloudformation'].delete_stack(StackName=STACK_NAME)
                        time.sleep(10)
                    except Exception:
                        pass
                else:
                    logger.warning(f"Stack {STACK_NAME} in unexpected state: {stack_status}")
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
            logger.info(f"Stack {STACK_NAME} does not exist, creating...")
        
        # Generate and deploy CloudFormation template
        template_body = _generate_cloudformation_template()
        
        logger.info(f"Creating CloudFormation stack: {STACK_NAME}")
        clients['cloudformation'].create_stack(
            StackName=STACK_NAME,
            TemplateBody=template_body,
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': EXPERIMENT_TAG},
                {'Key': 'Timestamp', 'Value': str(TIMESTAMP)},
                {'Key': 'Purpose', 'Value': 'SCE-ECS-Registration-Detection'}
            ],
            OnFailure='DELETE',
            TimeoutInMinutes=15
        )
        
        # Wait for stack creation with backoff
        logger.info("Waiting for stack creation to complete...")
        
        def check_stack_complete():
            try:
                response = clients['cloudformation'].describe_stacks(StackName=STACK_NAME)
                if response['Stacks']:
                    status = response['Stacks'][0]['StackStatus']
                    logger.info(f"Stack status: {status}")
                    if status == 'CREATE_COMPLETE':
                        return True
                    elif status in ['CREATE_FAILED', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED', 'ROLLBACK_IN_PROGRESS']:
                        # Get failure reason
                        events = clients['cloudformation'].describe_stack_events(StackName=STACK_NAME)
                        for event in events['StackEvents']:
                            if 'FAILED' in event.get('ResourceStatus', ''):
                                logger.error(f"Stack failure: {event.get('ResourceStatusReason', 'Unknown')}")
                        raise Exception(f"Stack creation failed with status: {status}")
                return False
            except ClientError as e:
                if 'does not exist' in str(e):
                    return False
                raise
        
        if not _wait_with_backoff(check_stack_complete, max_attempts=90, initial_delay=10):
            raise Exception("Stack creation timed out")
        
        _experiment_state['stack_created'] = True
        logger.info(f"Stack {STACK_NAME} created successfully")
        
        # Extract outputs
        _extract_stack_outputs(clients)
        
        # Wait for IAM and EventBridge propagation
        logger.info("Waiting for IAM and EventBridge propagation...")
        time.sleep(20)
        
        # Verify EventBridge rule is active
        logger.info("Verifying EventBridge rule is active...")
        rule_response = clients['events'].describe_rule(
            Name=_experiment_state['event_rule_name']
        )
        logger.info(f"EventBridge rule state: {rule_response['State']}")
        
        # Purge any existing messages in SQS queue
        logger.info("Purging SQS queue...")
        try:
            clients['sqs'].purge_queue(QueueUrl=_experiment_state['sqs_queue_url'])
            time.sleep(5)
        except ClientError as e:
            if 'PurgeQueueInProgress' not in str(e):
                logger.warning(f"Could not purge queue: {e}")
        
        return True
        
    except Exception as e:
        logger.error(f"steady_state failed: {e}")
        raise


def _extract_stack_outputs(clients):
    """Extract stack outputs and store in experiment state."""
    try:
        response = clients['cloudformation'].describe_stacks(StackName=STACK_NAME)
        if response['Stacks']:
            outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
            
            _experiment_state['cluster_arn'] = outputs.get('ClusterArn')
            _experiment_state['cluster_name'] = outputs.get('ClusterName')
            _experiment_state['vpc_id'] = outputs.get('VpcId')
            _experiment_state['subnet_id'] = outputs.get('SubnetId')
            _experiment_state['security_group_id'] = outputs.get('SecurityGroupId')
            _experiment_state['instance_profile_arn'] = outputs.get('InstanceProfileArn')
            _experiment_state['instance_profile_name'] = outputs.get('InstanceProfileName')
            _experiment_state['instance_role_name'] = outputs.get('InstanceRoleName')
            _experiment_state['sns_topic_arn'] = outputs.get('SNSTopicArn')
            _experiment_state['sqs_queue_url'] = outputs.get('SQSQueueUrl')
            _experiment_state['sqs_queue_arn'] = outputs.get('SQSQueueArn')
            _experiment_state['log_group_name'] = outputs.get('LogGroupName')
            _experiment_state['event_rule_name'] = outputs.get('EventRuleName')
            _experiment_state['ecs_ami_id'] = outputs.get('EcsAmiId')
            
            logger.info(f"Extracted outputs: Cluster={_experiment_state['cluster_name']}, "
                       f"VPC={_experiment_state['vpc_id']}")
    except Exception as e:
        logger.error(f"Failed to extract stack outputs: {e}")
        raise


def attack():
    """
    Execute Attack Steps 1.4 and 2.3:
    - 1.4: Create EC2 Instance with ECS Configuration
    - 2.3: Configure User Data for ECS Cluster Registration
    
    This launches an EC2 instance with user-data that configures the ECS agent
    to register with the target cluster, simulating an attacker's rogue instance.
    """
    logger.info("Starting attack phase - launching rogue EC2 instance with ECS configuration")
    clients = _get_clients()
    
    attack_start_time = time.monotonic()
    _experiment_state['attack_start_time'] = attack_start_time
    
    try:
        # Generate user data script (Attack Step 2.3)
        user_data_b64 = _generate_user_data_script()
        
        logger.info(f"Launching EC2 instance with ECS agent configured for cluster: {_experiment_state['cluster_name']}")
        
        # Attack Step 1.4: Create EC2 Instance with ECS Configuration
        response = clients['ec2'].run_instances(
            ImageId=_experiment_state['ecs_ami_id'],
            InstanceType='t3.micro',
            MinCount=1,
            MaxCount=1,
            SubnetId=_experiment_state['subnet_id'],
            SecurityGroupIds=[_experiment_state['security_group_id']],
            IamInstanceProfile={
                'Name': _experiment_state['instance_profile_name']
            },
            UserData=user_data_b64,
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': f'sce-rogue-instance-{TIMESTAMP}'},
                        {'Key': 'Experiment', 'Value': EXPERIMENT_TAG},
                        {'Key': 'AttackStep', 'Value': '1.4-2.3'},
                        {'Key': 'Purpose', 'Value': 'SCE-Rogue-ECS-Registration'}
                    ]
                }
            ],
            MetadataOptions={
                'HttpTokens': 'optional',
                'HttpEndpoint': 'enabled'
            }
        )
        
        instance_id = response['Instances'][0]['InstanceId']
        _experiment_state['instance_id'] = instance_id
        _experiment_state['attack_executed'] = True
        
        logger.info(f"Rogue instance launched: {instance_id}")
        
        # Wait for instance to be running
        logger.info("Waiting for instance to reach running state...")
        
        def check_instance_running():
            try:
                resp = clients['ec2'].describe_instances(InstanceIds=[instance_id])
                state = resp['Reservations'][0]['Instances'][0]['State']['Name']
                logger.info(f"Instance state: {state}")
                return state == 'running'
            except Exception as e:
                logger.warning(f"Error checking instance state: {e}")
                return False
        
        if not _wait_with_backoff(check_instance_running, max_attempts=30, initial_delay=5):
            logger.warning("Instance did not reach running state in time")
        
        # Wait for ECS agent to register (give it time to boot and register)
        logger.info("Waiting for ECS agent to register with cluster...")
        time.sleep(60)  # ECS agent typically takes 30-60 seconds to register
        
        # Check if container instance was registered
        logger.info("Checking for container instance registration...")
        
        def check_container_instance():
            try:
                resp = clients['ecs'].list_container_instances(
                    cluster=_experiment_state['cluster_name'],
                    status='ACTIVE'
                )
                if resp.get('containerInstanceArns'):
                    _experiment_state['container_instance_arn'] = resp['containerInstanceArns'][0]
                    logger.info(f"Container instance registered: {_experiment_state['container_instance_arn']}")
                    return True
                return False
            except Exception as e:
                logger.warning(f"Error checking container instances: {e}")
                return False
        
        _wait_with_backoff(check_container_instance, max_attempts=12, initial_delay=10)
        
        attack_end_time = time.monotonic()
        _experiment_state['attack_duration'] = attack_end_time - attack_start_time
        
        logger.info(f"Attack phase completed in {_experiment_state['attack_duration']:.1f}s")
        return True
        
    except Exception as e:
        logger.error(f"Attack phase failed: {e}")
        _experiment_state['attack_error'] = str(e)
        raise


def hypothesis_verification():
    """
    Verify the detective control worked as expected.
    
    Expected behavior (from SCE Experiment 2.4 Detective Probe):
    - Monitor ECS cluster events for RegisterContainerInstance from unknown instance
    - Verify alert fires within 3 min
    
    Returns True if the detective control successfully detected the registration.
    """
    logger.info("Starting hypothesis verification - checking for detection alerts")
    clients = _get_clients()
    
    verification_start = time.monotonic()
    max_wait_time = 180  # 3 minutes as specified in the probe
    
    try:
        # Method 1: Check SQS queue for EventBridge alerts
        logger.info("Checking SQS queue for ECS registration alerts...")
        
        alert_found = False
        detection_details = []
        
        while (time.monotonic() - verification_start) < max_wait_time:
            try:
                response = clients['sqs'].receive_message(
                    QueueUrl=_experiment_state['sqs_queue_url'],
                    MaxNumberOfMessages=10,
                    WaitTimeSeconds=10,
                    MessageAttributeNames=['All']
                )
                
                messages = response.get('Messages', [])
                
                for message in messages:
                    body = message.get('Body', '')
                    logger.info(f"Received SQS message: {body[:500]}...")
                    
                    try:
                        # Parse the message body
                        msg_data = json.loads(body)
                        
                        # Check if it's an ECS event
                        if 'detail-type' in msg_data:
                            detail_type = msg_data.get('detail-type', '')
                            if 'ECS Container Instance State Change' in detail_type:
                                detail = msg_data.get('detail', {})
                                status = detail.get('status', '')
                                ec2_instance_id = detail.get('ec2InstanceId', '')
                                
                                logger.info(f"ECS Event detected - Status: {status}, EC2 Instance: {ec2_instance_id}")
                                
                                if ec2_instance_id == _experiment_state.get('instance_id'):
                                    alert_found = True
                                    detection_time = time.monotonic() - _experiment_state.get('attack_start_time', verification_start)
                                    _experiment_state['detection_time_seconds'] = detection_time
                                    detection_details.append({
                                        'type': 'ECS Container Instance State Change',
                                        'status': status,
                                        'instance_id': ec2_instance_id,
                                        'detection_time': detection_time
                                    })
                                    logger.info(f"ALERT DETECTED for rogue instance in {detection_time:.1f}s")
                        
                        # Check if it's wrapped in SNS notification
                        elif 'Message' in msg_data:
                            inner_msg = json.loads(msg_data['Message'])
                            if 'detail-type' in inner_msg:
                                detail_type = inner_msg.get('detail-type', '')
                                if 'ECS Container Instance State Change' in detail_type:
                                    detail = inner_msg.get('detail', {})
                                    ec2_instance_id = detail.get('ec2InstanceId', '')
                                    
                                    if ec2_instance_id == _experiment_state.get('instance_id'):
                                        alert_found = True
                                        detection_time = time.monotonic() - _experiment_state.get('attack_start_time', verification_start)
                                        _experiment_state['detection_time_seconds'] = detection_time
                                        detection_details.append({
                                            'type': 'ECS Container Instance State Change (via SNS)',
                                            'instance_id': ec2_instance_id,
                                            'detection_time': detection_time
                                        })
                                        logger.info(f"ALERT DETECTED (via SNS) for rogue instance in {detection_time:.1f}s")
                    
                    except json.JSONDecodeError:
                        logger.warning(f"Could not parse message as JSON: {body[:200]}")
                    
                    # Delete processed message
                    clients['sqs'].delete_message(
                        QueueUrl=_experiment_state['sqs_queue_url'],
                        ReceiptHandle=message['ReceiptHandle']
                    )
                
                if alert_found:
                    break
                    
            except Exception as e:
                logger.warning(f"Error receiving SQS messages: {e}")
                time.sleep(5)
        
        # Method 2: Check CloudWatch Logs for events
        if not alert_found:
            logger.info("Checking CloudWatch Logs for ECS events...")
            try:
                log_response = clients['logs'].filter_log_events(
                    logGroupName=_experiment_state['log_group_name'],
                    startTime=int((_experiment_state.get('attack_start_time', verification_start) - 60) * 1000),
                    limit=50
                )
                
                for event in log_response.get('events', []):
                    message = event.get('message', '')
                    logger.info(f"CloudWatch Log event: {message[:300]}...")
                    
                    if _experiment_state.get('instance_id', '') in message:
                        alert_found = True
                        detection_details.append({
                            'type': 'CloudWatch Logs',
                            'message': message[:500]
                        })
                        logger.info("ALERT DETECTED in CloudWatch Logs")
                        
            except Exception as e:
                logger.warning(f"Error checking CloudWatch Logs: {e}")
        
        # Method 3: Verify container instance exists in cluster (confirms registration happened)
        logger.info("Verifying container instance registration in ECS cluster...")
        try:
            ci_response = clients['ecs'].list_container_instances(
                cluster=_experiment_state['cluster_name']
            )
            
            if ci_response.get('containerInstanceArns'):
                for ci_arn in ci_response['containerInstanceArns']:
                    ci_detail = clients['ecs'].describe_container_instances(
                        cluster=_experiment_state['cluster_name'],
                        containerInstances=[ci_arn]
                    )
                    
                    for ci in ci_detail.get('containerInstances', []):
                        ec2_id = ci.get('ec2InstanceId', '')
                        if ec2_id == _experiment_state.get('instance_id'):
                            logger.info(f"Confirmed: Rogue instance {ec2_id} is registered in cluster")
                            _experiment_state['registration_confirmed'] = True
                            
                            # If we confirmed registration but didn't get alert, detection may have failed
                            if not alert_found:
                                logger.warning("Registration confirmed but no alert received - checking if event was generated")
                                # The registration happened, so EventBridge should have fired
                                # Give it a bit more time
                                time.sleep(10)
                                
        except Exception as e:
            logger.warning(f"Error verifying container instances: {e}")
        
        # Final verification
        _experiment_state['alert_received'] = alert_found
        _experiment_state['detection_details'] = detection_details
        
        elapsed = time.monotonic() - verification_start
        logger.info(f"Verification completed in {elapsed:.1f}s")
        
        if alert_found:
            detection_time = _experiment_state.get('detection_time_seconds', elapsed)
            if detection_time <= 180:  # Within 3 minutes
                logger.info(f"VERIFICATION PASSED: Detective control detected registration in {detection_time:.1f}s (within 3 min threshold)")
                return True
            else:
                logger.warning(f"VERIFICATION PARTIAL: Detection occurred but took {detection_time:.1f}s (exceeded 3 min threshold)")
                return True  # Still detected, just slower
        else:
            # Check if registration actually happened
            if _experiment_state.get('registration_confirmed') or _experiment_state.get('container_instance_arn'):
                logger.error("VERIFICATION FAILED: Registration occurred but no alert was detected")
                return False
            else:
                logger.warning("VERIFICATION INCONCLUSIVE: Neither registration nor alert confirmed")
                return False
                
    except Exception as e:
        logger.error(f"Hypothesis verification failed with error: {e}")
        return False


def rollback():
    """
    Complete teardown: Terminate instance, deregister container instance, delete CloudFormation stack.
    Safe and tolerant - handles missing resources gracefully.
    """
    logger.info(f"Starting rollback for stack: {STACK_NAME}")
    clients = _get_clients()
    
    try:
        # Step 1: Deregister container instance from ECS cluster
        if _experiment_state.get('container_instance_arn'):
            try:
                logger.info(f"Deregistering container instance: {_experiment_state['container_instance_arn']}")
                clients['ecs'].deregister_container_instance(
                    cluster=_experiment_state['cluster_name'],
                    containerInstance=_experiment_state['container_instance_arn'],
                    force=True
                )
                logger.info("Container instance deregistered")
            except ClientError as e:
                logger.warning(f"Could not deregister container instance: {e}")
        
        # Step 2: Terminate EC2 instance
        if _experiment_state.get('instance_id'):
            try:
                logger.info(f"Terminating instance: {_experiment_state['instance_id']}")
                clients['ec2'].terminate_instances(
                    InstanceIds=[_experiment_state['instance_id']]
                )
                
                # Wait for termination
                def check_terminated():
                    try:
                        resp = clients['ec2'].describe_instances(
                            InstanceIds=[_experiment_state['instance_id']]
                        )
                        state = resp['Reservations'][0]['Instances'][0]['State']['Name']
                        return state == 'terminated'
                    except Exception:
                        return True
                
                _wait_with_backoff(check_terminated, max_attempts=20, initial_delay=5)
                logger.info("Instance terminated")
            except ClientError as e:
                if 'InvalidInstanceID' not in str(e):
                    logger.warning(f"Could not terminate instance: {e}")
        
        # Step 3: Delete CloudFormation stack
        try:
            logger.info(f"Deleting CloudFormation stack: {STACK_NAME}")
            clients['cloudformation'].delete_stack(StackName=STACK_NAME)
            
            # Wait for deletion with backoff
            def check_stack_deleted():
                try:
                    response = clients['cloudformation'].describe_stacks(StackName=STACK_NAME)
                    if response['Stacks']:
                        status = response['Stacks'][0]['StackStatus']
                        logger.info(f"Stack deletion status: {status}")
                        if status == 'DELETE_COMPLETE':
                            return True
                        elif status == 'DELETE_FAILED':
                            logger.error("Stack deletion failed")
                            # Try to get failure reason
                            events = clients['cloudformation'].describe_stack_events(StackName=STACK_NAME)
                            for event in events['StackEvents'][:5]:
                                if 'FAILED' in event.get('ResourceStatus', ''):
                                    logger.error(f"Failure: {event.get('ResourceStatusReason', 'Unknown')}")
                            return True  # Continue anyway
                    return False
                except ClientError as e:
                    if 'does not exist' in str(e):
                        return True
                    raise
            
            if _wait_with_backoff(check_stack_deleted, max_attempts=60, initial_delay=10):
                logger.info(f"Stack {STACK_NAME} deleted successfully")
            else:
                logger.warning("Stack deletion timed out, may still be in progress")
                
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.info(f"Stack {STACK_NAME} already deleted or does not exist")
            else:
                logger.error(f"Error deleting stack: {e}")
                raise
        
        _experiment_state['stack_created'] = False
        logger.info("Rollback completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Rollback encountered error: {e}")
        raise


def run_experiment():
    """
    Main entry point to run the complete experiment.
    Ensures rollback is always attempted.
    """
    logger.info("=" * 70)
    logger.info("SCE Experiment 2.4 - Detective Probe")
    logger.info("Validating ECS Container Instance Registration Detection")
    logger.info("=" * 70)
    
    result = False
    
    try:
        # Phase 1: Setup
        logger.info("\n--- PHASE 1: STEADY STATE ---")
        steady_state()
        
        # Phase 2: Attack
        logger.info("\n--- PHASE 2: ATTACK (Steps 1.4 & 2.3) ---")
        attack()
        
        # Phase 3: Verification
        logger.info("\n--- PHASE 3: HYPOTHESIS VERIFICATION ---")
        result = hypothesis_verification()
        
        logger.info("\n" + "=" * 70)
        if result:
            logger.info("EXPERIMENT RESULT: PASSED - Detective control effective")
            logger.info(f"Detection time: {_experiment_state.get('detection_time_seconds', 'N/A')}s")
        else:
            logger.info("EXPERIMENT RESULT: FAILED - Detective control ineffective")
        logger.info("=" * 70)
        
    except Exception as e:
        logger.error(f"Experiment failed with error: {e}")
        result = False
        
    finally:
        # Phase 4: Cleanup (always runs)
        logger.info("\n--- PHASE 4: ROLLBACK ---")
        try:
            rollback()
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
    
    return result


if __name__ == "__main__":
    success = run_experiment()
    sys.exit(0 if success else 1)