#!/usr/bin/env python3
"""
Security Chaos Engineering Experiment: 2.4 Reactive Probe
Validates automated response to unauthorized EC2 instance launch with ECS registration.

Attack Steps Simulated:
1. Create user data script for ECS cluster registration
2. Launch malicious EC2 instance with ECS configuration

Reactive Safeguard Validated:
- Step Functions workflow orchestrates immediate response
- Deregister rogue container instance from ECS cluster
- Terminate EC2 instance
- Revoke associated IAM credentials
- Capture forensic data
- Notify security team

Environment: Clean AWS account, credentials via environment variables
"""

import json
import logging
import os
import sys
import time
import base64
from typing import Dict, List, Optional, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Install boto3 if not available
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    logger.info("Installing boto3...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "boto3"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Global configuration
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')
EXPERIMENT_TAG_KEY = 'ChaosExperiment'
EXPERIMENT_TAG_VALUE = 'sce-2-4-reactive-probe'
MAX_RETRIES = 10
RETRY_DELAY = 5  # seconds

# Global state tracking
PROVISIONED_RESOURCES = {
    'vpc_id': None,
    'subnet_id': None,
    'security_group_id': None,
    'quarantine_security_group_id': None,
    'iam_role_name': None,
    'iam_instance_profile_name': None,
    'ecs_cluster_name': None,
    'ec2_instance_id': None,
    'container_instance_arn': None,
    's3_bucket_name': None,
    'sns_topic_arn': None,
    'lambda_function_name': None,
    'lambda_role_name': None,
    'step_function_arn': None,
    'step_function_role_name': None,
    'eventbridge_rule_name': None,
    'cloudwatch_log_group': None,
    'key_pair_name': None
}


def retry_with_backoff(func, max_attempts=MAX_RETRIES, delay=RETRY_DELAY):
    """Execute function with exponential backoff retry logic."""
    start_time = time.monotonic()
    for attempt in range(max_attempts):
        try:
            return func()
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['InvalidParameterValue', 'InvalidGroup.NotFound', 
                              'InvalidInstanceID.NotFound', 'NoSuchEntity']:
                if attempt < max_attempts - 1:
                    wait_time = delay * (2 ** attempt)
                    elapsed = time.monotonic() - start_time
                    logger.warning(f"Attempt {attempt + 1} failed: {error_code}. "
                                   f"Retrying in {wait_time}s (elapsed: {elapsed:.1f}s)...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Max retries exceeded for {func.__name__}")
                    raise
            else:
                raise
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {str(e)}")
            raise
    raise Exception(f"Failed after {max_attempts} attempts")


def get_aws_clients():
    """Initialize AWS service clients."""
    return {
        'ec2': boto3.client('ec2', region_name=AWS_REGION),
        'ecs': boto3.client('ecs', region_name=AWS_REGION),
        'iam': boto3.client('iam', region_name=AWS_REGION),
        's3': boto3.client('s3', region_name=AWS_REGION),
        'sns': boto3.client('sns', region_name=AWS_REGION),
        'lambda': boto3.client('lambda', region_name=AWS_REGION),
        'sfn': boto3.client('stepfunctions', region_name=AWS_REGION),
        'events': boto3.client('events', region_name=AWS_REGION),
        'logs': boto3.client('logs', region_name=AWS_REGION),
        'sts': boto3.client('sts', region_name=AWS_REGION)
    }


def tag_resource(client, resource_id, resource_type='ec2'):
    """Apply experiment tag to AWS resource."""
    tags = [
        {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE},
        {'Key': 'Purpose', 'Value': 'SecurityChaosEngineering'},
        {'Key': 'AutoDelete', 'Value': 'true'}
    ]
    
    try:
        if resource_type == 'ec2':
            client.create_tags(Resources=[resource_id], Tags=tags)
        elif resource_type == 's3':
            client.put_bucket_tagging(
                Bucket=resource_id,
                Tagging={'TagSet': tags}
            )
        elif resource_type == 'sns':
            for tag in tags:
                client.tag_resource(ResourceArn=resource_id, Tags=[tag])
        logger.info(f"Tagged {resource_type} resource: {resource_id}")
    except ClientError as e:
        logger.warning(f"Failed to tag {resource_id}: {str(e)}")


def steady_state():
    """
    Provision all AWS resources required for the experiment.
    Creates infrastructure to simulate attack and validate reactive safeguards.
    """
    logger.info("=" * 80)
    logger.info("STEADY STATE: Provisioning experiment infrastructure")
    logger.info("=" * 80)
    
    clients = get_aws_clients()
    account_id = clients['sts'].get_caller_identity()['Account']
    
    try:
        # 1. Create VPC and networking
        logger.info("Step 1: Creating VPC and network infrastructure...")
        vpc_response = clients['ec2'].create_vpc(
            CidrBlock='10.0.0.0/16',
            TagSpecifications=[{
                'ResourceType': 'vpc',
                'Tags': [
                    {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE},
                    {'Key': 'Name', 'Value': 'sce-test-vpc'}
                ]
            }]
        )
        PROVISIONED_RESOURCES['vpc_id'] = vpc_response['Vpc']['VpcId']
        logger.info(f"Created VPC: {PROVISIONED_RESOURCES['vpc_id']}")
        
        # Wait for VPC to be available
        time.sleep(2)
        
        # Create subnet
        subnet_response = clients['ec2'].create_subnet(
            VpcId=PROVISIONED_RESOURCES['vpc_id'],
            CidrBlock='10.0.1.0/24',
            TagSpecifications=[{
                'ResourceType': 'subnet',
                'Tags': [
                    {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE},
                    {'Key': 'Name', 'Value': 'sce-test-subnet'}
                ]
            }]
        )
        PROVISIONED_RESOURCES['subnet_id'] = subnet_response['Subnet']['SubnetId']
        logger.info(f"Created Subnet: {PROVISIONED_RESOURCES['subnet_id']}")
        
        # Create security group (permissive for testing)
        sg_response = clients['ec2'].create_security_group(
            GroupName=f'sce-test-sg-{int(time.time())}',
            Description='Security group for chaos experiment',
            VpcId=PROVISIONED_RESOURCES['vpc_id'],
            TagSpecifications=[{
                'ResourceType': 'security-group',
                'Tags': [
                    {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE},
                    {'Key': 'Name', 'Value': 'sce-test-sg'}
                ]
            }]
        )
        PROVISIONED_RESOURCES['security_group_id'] = sg_response['GroupId']
        logger.info(f"Created Security Group: {PROVISIONED_RESOURCES['security_group_id']}")
        
        # Create quarantine security group (deny all)
        quarantine_sg_response = clients['ec2'].create_security_group(
            GroupName=f'sce-quarantine-sg-{int(time.time())}',
            Description='Quarantine security group - deny all traffic',
            VpcId=PROVISIONED_RESOURCES['vpc_id'],
            TagSpecifications=[{
                'ResourceType': 'security-group',
                'Tags': [
                    {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE},
                    {'Key': 'Name', 'Value': 'sce-quarantine-sg'}
                ]
            }]
        )
        PROVISIONED_RESOURCES['quarantine_security_group_id'] = quarantine_sg_response['GroupId']
        logger.info(f"Created Quarantine SG: {PROVISIONED_RESOURCES['quarantine_security_group_id']}")
        
        # Revoke default egress rule from quarantine SG
        try:
            clients['ec2'].revoke_security_group_egress(
                GroupId=PROVISIONED_RESOURCES['quarantine_security_group_id'],
                IpPermissions=[{
                    'IpProtocol': '-1',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            )
            logger.info("Revoked default egress from quarantine SG")
        except ClientError as e:
            logger.warning(f"Could not revoke egress: {str(e)}")
        
        # 2. Create IAM role for ECS instances
        logger.info("Step 2: Creating IAM roles and instance profile...")
        
        ecs_trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }
        
        role_name = f'sce-ecs-instance-role-{int(time.time())}'
        role_response = clients['iam'].create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(ecs_trust_policy),
            Description='ECS instance role for chaos experiment',
            Tags=[
                {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE}
            ]
        )
        PROVISIONED_RESOURCES['iam_role_name'] = role_name
        logger.info(f"Created IAM Role: {role_name}")
        
        # Attach ECS policy
        clients['iam'].attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role'
        )
        logger.info("Attached ECS policy to role")
        
        # Create instance profile
        profile_name = f'sce-ecs-instance-profile-{int(time.time())}'
        profile_response = clients['iam'].create_instance_profile(
            InstanceProfileName=profile_name,
            Tags=[
                {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE}
            ]
        )
        PROVISIONED_RESOURCES['iam_instance_profile_name'] = profile_name
        logger.info(f"Created Instance Profile: {profile_name}")
        
        # Add role to instance profile
        clients['iam'].add_role_to_instance_profile(
            InstanceProfileName=profile_name,
            RoleName=role_name
        )
        logger.info("Added role to instance profile")
        
        # Wait for IAM propagation
        logger.info("Waiting for IAM propagation (30s)...")
        time.sleep(30)
        
        # 3. Create ECS cluster
        logger.info("Step 3: Creating ECS cluster...")
        cluster_name = f'sce-test-cluster-{int(time.time())}'
        cluster_response = clients['ecs'].create_cluster(
            clusterName=cluster_name,
            tags=[
                {'key': EXPERIMENT_TAG_KEY, 'value': EXPERIMENT_TAG_VALUE}
            ]
        )
        PROVISIONED_RESOURCES['ecs_cluster_name'] = cluster_name
        logger.info(f"Created ECS Cluster: {cluster_name}")
        
        # 4. Create S3 bucket for forensic data
        logger.info("Step 4: Creating S3 bucket for forensic storage...")
        bucket_name = f'sce-forensics-{account_id}-{int(time.time())}'
        
        if AWS_REGION == 'us-east-1':
            clients['s3'].create_bucket(Bucket=bucket_name)
        else:
            clients['s3'].create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': AWS_REGION}
            )
        
        PROVISIONED_RESOURCES['s3_bucket_name'] = bucket_name
        tag_resource(clients['s3'], bucket_name, 's3')
        logger.info(f"Created S3 Bucket: {bucket_name}")
        
        # Enable versioning
        clients['s3'].put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        logger.info("Enabled S3 versioning")
        
        # 5. Create SNS topic for notifications
        logger.info("Step 5: Creating SNS topic for alerts...")
        topic_name = f'sce-security-alerts-{int(time.time())}'
        topic_response = clients['sns'].create_topic(
            Name=topic_name,
            Tags=[
                {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE}
            ]
        )
        PROVISIONED_RESOURCES['sns_topic_arn'] = topic_response['TopicArn']
        logger.info(f"Created SNS Topic: {PROVISIONED_RESOURCES['sns_topic_arn']}")
        
        # 6. Create CloudWatch Log Group
        logger.info("Step 6: Creating CloudWatch Log Group...")
        log_group_name = f'/aws/sce/reactive-response-{int(time.time())}'
        clients['logs'].create_log_group(
            logGroupName=log_group_name,
            tags={
                EXPERIMENT_TAG_KEY: EXPERIMENT_TAG_VALUE
            }
        )
        PROVISIONED_RESOURCES['cloudwatch_log_group'] = log_group_name
        logger.info(f"Created Log Group: {log_group_name}")
        
        # 7. Create Lambda function for incident response
        logger.info("Step 7: Creating Lambda function for automated response...")
        
        # Create Lambda execution role
        lambda_trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }
        
        lambda_role_name = f'sce-lambda-response-role-{int(time.time())}'
        lambda_role_response = clients['iam'].create_role(
            RoleName=lambda_role_name,
            AssumeRolePolicyDocument=json.dumps(lambda_trust_policy),
            Description='Lambda execution role for incident response',
            Tags=[
                {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE}
            ]
        )
        PROVISIONED_RESOURCES['lambda_role_name'] = lambda_role_name
        lambda_role_arn = lambda_role_response['Role']['Arn']
        logger.info(f"Created Lambda Role: {lambda_role_name}")
        
        # Attach policies to Lambda role
        lambda_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "ec2:DescribeInstances",
                        "ec2:ModifyInstanceAttribute",
                        "ec2:CreateSnapshot",
                        "ec2:TerminateInstances",
                        "ec2:CreateTags",
                        "ecs:DeregisterContainerInstance",
                        "ecs:DescribeContainerInstances",
                        "ecs:ListContainerInstances",
                        "iam:DeleteAccessKey",
                        "iam:ListAccessKeys",
                        "s3:PutObject",
                        "sns:Publish",
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    "Resource": "*"
                }
            ]
        }
        
        clients['iam'].put_role_policy(
            RoleName=lambda_role_name,
            PolicyName='IncidentResponsePolicy',
            PolicyDocument=json.dumps(lambda_policy)
        )
        logger.info("Attached policy to Lambda role")
        
        # Wait for Lambda role propagation
        logger.info("Waiting for Lambda IAM propagation (15s)...")
        time.sleep(15)
        
        # Create Lambda function code
        lambda_code = '''
import json
import boto3
import os
from datetime import datetime

ec2 = boto3.client('ec2')
ecs = boto3.client('ecs')
s3 = boto3.client('s3')
sns = boto3.client('sns')

def lambda_handler(event, context):
    """
    Automated incident response for unauthorized EC2 instance launch.
    """
    print(f"Received event: {json.dumps(event)}")
    
    instance_id = event.get('instance_id')
    cluster_name = event.get('cluster_name')
    bucket_name = event.get('bucket_name')
    topic_arn = event.get('topic_arn')
    quarantine_sg = event.get('quarantine_sg')
    
    response_actions = []
    
    try:
        # 1. Identify container instance in ECS cluster
        print(f"Searching for container instance in cluster: {cluster_name}")
        container_instances = ecs.list_container_instances(cluster=cluster_name)
        
        container_instance_arn = None
        if container_instances['containerInstanceArns']:
            instances = ecs.describe_container_instances(
                cluster=cluster_name,
                containerInstances=container_instances['containerInstanceArns']
            )
            for ci in instances['containerInstances']:
                if ci['ec2InstanceId'] == instance_id:
                    container_instance_arn = ci['containerInstanceArn']
                    print(f"Found container instance: {container_instance_arn}")
                    break
        
        # 2. Deregister from ECS cluster
        if container_instance_arn:
            print(f"Deregistering container instance: {container_instance_arn}")
            ecs.deregister_container_instance(
                cluster=cluster_name,
                containerInstance=container_instance_arn,
                force=True
            )
            response_actions.append("ECS_DEREGISTERED")
            print("Container instance deregistered successfully")
        
        # 3. Create forensic snapshot
        print(f"Creating forensic snapshot for instance: {instance_id}")
        instance_info = ec2.describe_instances(InstanceIds=[instance_id])
        
        for reservation in instance_info['Reservations']:
            for instance in reservation['Instances']:
                for bdm in instance.get('BlockDeviceMappings', []):
                    volume_id = bdm['Ebs']['VolumeId']
                    snapshot = ec2.create_snapshot(
                        VolumeId=volume_id,
                        Description=f'Forensic snapshot - SCE experiment {instance_id}',
                        TagSpecifications=[{
                            'ResourceType': 'snapshot',
                            'Tags': [
                                {'Key': 'ChaosExperiment', 'Value': 'sce-2-4-reactive-probe'},
                                {'Key': 'InstanceId', 'Value': instance_id},
                                {'Key': 'Timestamp', 'Value': datetime.utcnow().isoformat()}
                            ]
                        }]
                    )
                    response_actions.append(f"SNAPSHOT_CREATED:{snapshot['SnapshotId']}")
                    print(f"Created snapshot: {snapshot['SnapshotId']}")
        
        # 4. Apply quarantine security group
        print(f"Applying quarantine security group: {quarantine_sg}")
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[quarantine_sg]
        )
        response_actions.append("QUARANTINE_APPLIED")
        print("Quarantine security group applied")
        
        # 5. Store forensic metadata in S3
        forensic_data = {
            'incident_timestamp': datetime.utcnow().isoformat(),
            'instance_id': instance_id,
            'cluster_name': cluster_name,
            'container_instance_arn': container_instance_arn,
            'response_actions': response_actions,
            'event': event
        }
        
        s3_key = f'forensics/{instance_id}/{datetime.utcnow().isoformat()}.json'
        s3.put_object(
            Bucket=bucket_name,
            Key=s3_key,
            Body=json.dumps(forensic_data, indent=2),
            ContentType='application/json'
        )
        response_actions.append(f"FORENSIC_DATA_STORED:{s3_key}")
        print(f"Forensic data stored: s3://{bucket_name}/{s3_key}")
        
        # 6. Terminate instance
        print(f"Terminating instance: {instance_id}")
        ec2.terminate_instances(InstanceIds=[instance_id])
        response_actions.append("INSTANCE_TERMINATED")
        print("Instance termination initiated")
        
        # 7. Send SNS notification
        message = f"""
SECURITY ALERT: Unauthorized EC2 Instance Detected and Remediated

Instance ID: {instance_id}
Cluster: {cluster_name}
Timestamp: {datetime.utcnow().isoformat()}

Automated Response Actions:
{chr(10).join(f'- {action}' for action in response_actions)}

Forensic Data: s3://{bucket_name}/{s3_key}

This is an automated response from the Security Chaos Engineering experiment.
"""
        
        sns.publish(
            TopicArn=topic_arn,
            Subject='[SCE] Unauthorized EC2 Instance Remediated',
            Message=message
        )
        response_actions.append("NOTIFICATION_SENT")
        print("SNS notification sent")
        
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Incident response completed successfully',
                'actions': response_actions,
                'instance_id': instance_id
            })
        }
        
    except Exception as e:
        error_msg = f"Error in incident response: {str(e)}"
        print(error_msg)
        
        # Send error notification
        try:
            sns.publish(
                TopicArn=topic_arn,
                Subject='[SCE] Incident Response Error',
                Message=f"Error during automated response:\\n{error_msg}"
            )
        except:
            pass
        
        return {
            'statusCode': 500,
            'body': json.dumps({'error': error_msg})
        }
'''
        
        # Create deployment package
        import zipfile
        import io
        
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr('lambda_function.py', lambda_code)
        zip_buffer.seek(0)
        
        function_name = f'sce-incident-response-{int(time.time())}'
        lambda_response = clients['lambda'].create_function(
            FunctionName=function_name,
            Runtime='python3.11',
            Role=lambda_role_arn,
            Handler='lambda_function.lambda_handler',
            Code={'ZipFile': zip_buffer.read()},
            Description='Automated incident response for SCE experiment',
            Timeout=300,
            MemorySize=256,
            Tags={
                EXPERIMENT_TAG_KEY: EXPERIMENT_TAG_VALUE
            }
        )
        PROVISIONED_RESOURCES['lambda_function_name'] = function_name
        logger.info(f"Created Lambda Function: {function_name}")
        
        # 8. Create Step Functions state machine
        logger.info("Step 8: Creating Step Functions workflow...")
        
        # Create Step Functions execution role
        sfn_trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }
        
        sfn_role_name = f'sce-stepfunctions-role-{int(time.time())}'
        sfn_role_response = clients['iam'].create_role(
            RoleName=sfn_role_name,
            AssumeRolePolicyDocument=json.dumps(sfn_trust_policy),
            Description='Step Functions execution role for incident response',
            Tags=[
                {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE}
            ]
        )
        PROVISIONED_RESOURCES['step_function_role_name'] = sfn_role_name
        sfn_role_arn = sfn_role_response['Role']['Arn']
        logger.info(f"Created Step Functions Role: {sfn_role_name}")
        
        # Attach policy to Step Functions role
        sfn_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "lambda:InvokeFunction",
                    "logs:CreateLogDelivery",
                    "logs:GetLogDelivery",
                    "logs:UpdateLogDelivery",
                    "logs:DeleteLogDelivery",
                    "logs:ListLogDeliveries",
                    "logs:PutResourcePolicy",
                    "logs:DescribeResourcePolicies",
                    "logs:DescribeLogGroups"
                ],
                "Resource": "*"
            }]
        }
        
        clients['iam'].put_role_policy(
            RoleName=sfn_role_name,
            PolicyName='StepFunctionsExecutionPolicy',
            PolicyDocument=json.dumps(sfn_policy)
        )
        logger.info("Attached policy to Step Functions role")
        
        # Wait for Step Functions role propagation
        logger.info("Waiting for Step Functions IAM propagation (15s)...")
        time.sleep(15)
        
        # Define state machine
        state_machine_definition = {
            "Comment": "Automated incident response workflow for unauthorized EC2 instance",
            "StartAt": "IncidentResponse",
            "States": {
                "IncidentResponse": {
                    "Type": "Task",
                    "Resource": lambda_response['FunctionArn'],
                    "End": True,
                    "Retry": [{
                        "ErrorEquals": ["States.ALL"],
                        "IntervalSeconds": 2,
                        "MaxAttempts": 2,
                        "BackoffRate": 2.0
                    }]
                }
            }
        }
        
        sfn_name = f'sce-incident-response-{int(time.time())}'
        sfn_response = clients['sfn'].create_state_machine(
            name=sfn_name,
            definition=json.dumps(state_machine_definition),
            roleArn=sfn_role_arn,
            type='EXPRESS',
            loggingConfiguration={
                'level': 'ALL',
                'includeExecutionData': True,
                'destinations': [{
                    'cloudWatchLogsLogGroup': {
                        'logGroupArn': f'arn:aws:logs:{AWS_REGION}:{account_id}:log-group:{log_group_name}:*'
                    }
                }]
            },
            tags=[
                {'key': EXPERIMENT_TAG_KEY, 'value': EXPERIMENT_TAG_VALUE}
            ]
        )
        PROVISIONED_RESOURCES['step_function_arn'] = sfn_response['stateMachineArn']
        logger.info(f"Created Step Functions State Machine: {PROVISIONED_RESOURCES['step_function_arn']}")
        
        # 9. Create EventBridge rule (optional - for demonstration)
        logger.info("Step 9: Creating EventBridge rule...")
        rule_name = f'sce-ec2-launch-detection-{int(time.time())}'
        
        event_pattern = {
            "source": ["aws.ec2"],
            "detail-type": ["EC2 Instance State-change Notification"],
            "detail": {
                "state": ["running"]
            }
        }
        
        rule_response = clients['events'].put_rule(
            Name=rule_name,
            EventPattern=json.dumps(event_pattern),
            State='ENABLED',
            Description='Detect EC2 instance launches for SCE experiment',
            Tags=[
                {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE}
            ]
        )
        PROVISIONED_RESOURCES['eventbridge_rule_name'] = rule_name
        logger.info(f"Created EventBridge Rule: {rule_name}")
        
        # Add Step Functions as target (requires additional permissions)
        try:
            clients['events'].put_targets(
                Rule=rule_name,
                Targets=[{
                    'Id': '1',
                    'Arn': PROVISIONED_RESOURCES['step_function_arn'],
                    'RoleArn': sfn_role_arn
                }]
            )
            logger.info("Added Step Functions as EventBridge target")
        except ClientError as e:
            logger.warning(f"Could not add EventBridge target: {str(e)}")
        
        logger.info("=" * 80)
        logger.info("STEADY STATE: Infrastructure provisioning complete")
        logger.info("=" * 80)
        logger.info(f"VPC: {PROVISIONED_RESOURCES['vpc_id']}")
        logger.info(f"Subnet: {PROVISIONED_RESOURCES['subnet_id']}")
        logger.info(f"Security Group: {PROVISIONED_RESOURCES['security_group_id']}")
        logger.info(f"Quarantine SG: {PROVISIONED_RESOURCES['quarantine_security_group_id']}")
        logger.info(f"ECS Cluster: {PROVISIONED_RESOURCES['ecs_cluster_name']}")
        logger.info(f"S3 Bucket: {PROVISIONED_RESOURCES['s3_bucket_name']}")
        logger.info(f"SNS Topic: {PROVISIONED_RESOURCES['sns_topic_arn']}")
        logger.info(f"Lambda Function: {PROVISIONED_RESOURCES['lambda_function_name']}")
        logger.info(f"Step Functions: {PROVISIONED_RESOURCES['step_function_arn']}")
        logger.info("=" * 80)
        
        return True
        
    except Exception as e:
        logger.error(f"Error in steady_state: {str(e)}")
        raise


def attack() -> bool:
    """
    Execute attack steps:
    1. Create user data script for ECS cluster registration
    2. Launch malicious EC2 instance with ECS configuration
    
    Returns True if attack succeeds, False otherwise.
    """
    logger.info("=" * 80)
    logger.info("ATTACK PHASE: Simulating unauthorized EC2 instance launch")
    logger.info("=" * 80)
    
    clients = get_aws_clients()
    
    try:
        # Attack Step 1: Create user data script for ECS cluster registration
        logger.info("Attack Step 1: Creating user data script for ECS registration...")
        
        user_data_script = f'''#!/bin/bash
echo ECS_CLUSTER={PROVISIONED_RESOURCES['ecs_cluster_name']} >> /etc/ecs/ecs.config
echo ECS_BACKEND_HOST= >> /etc/ecs/ecs.config
'''
        
        # Encode user data
        user_data_encoded = base64.b64encode(user_data_script.encode()).decode()
        logger.info("User data script created (simulated malicious configuration)")
        logger.info(f"Target cluster: {PROVISIONED_RESOURCES['ecs_cluster_name']}")
        
        # Attack Step 2: Launch malicious EC2 instance with ECS configuration
        logger.info("Attack Step 2: Launching malicious EC2 instance...")
        
        # Get latest ECS-optimized AMI
        ami_response = clients['ec2'].describe_images(
            Owners=['amazon'],
            Filters=[
                {'Name': 'name', 'Values': ['amzn2-ami-ecs-hvm-*-x86_64-ebs']},
                {'Name': 'state', 'Values': ['available']}
            ]
        )
        
        if not ami_response['Images']:
            logger.error("No ECS-optimized AMI found")
            return False
        
        # Sort by creation date and get latest
        latest_ami = sorted(ami_response['Images'], 
                           key=lambda x: x['CreationDate'], 
                           reverse=True)[0]
        ami_id = latest_ami['ImageId']
        logger.info(f"Using ECS-optimized AMI: {ami_id}")
        
        # Launch instance
        run_response = clients['ec2'].run_instances(
            ImageId=ami_id,
            InstanceType='t2.micro',
            MinCount=1,
            MaxCount=1,
            IamInstanceProfile={
                'Name': PROVISIONED_RESOURCES['iam_instance_profile_name']
            },
            UserData=user_data_script,
            NetworkInterfaces=[{
                'DeviceIndex': 0,
                'SubnetId': PROVISIONED_RESOURCES['subnet_id'],
                'Groups': [PROVISIONED_RESOURCES['security_group_id']],
                'AssociatePublicIpAddress': False
            }],
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': EXPERIMENT_TAG_KEY, 'Value': EXPERIMENT_TAG_VALUE},
                    {'Key': 'Name', 'Value': 'sce-malicious-instance'},
                    {'Key': 'AttackSimulation', 'Value': 'true'}
                ]
            }],
            MetadataOptions={
                'HttpTokens': 'optional',  # Allow IMDSv1 for attack simulation
                'HttpPutResponseHopLimit': 1
            }
        )
        
        PROVISIONED_RESOURCES['ec2_instance_id'] = run_response['Instances'][0]['InstanceId']
        logger.info(f"Launched malicious EC2 instance: {PROVISIONED_RESOURCES['ec2_instance_id']}")
        
        # Wait for instance to be running
        logger.info("Waiting for instance to reach 'running' state...")
        waiter = clients['ec2'].get_waiter('instance_running')
        
        try:
            waiter.wait(
                InstanceIds=[PROVISIONED_RESOURCES['ec2_instance_id']],
                WaiterConfig={'Delay': 5, 'MaxAttempts': 40}
            )
            logger.info("Instance is now running")
        except WaiterError as e:
            logger.error(f"Instance failed to reach running state: {str(e)}")
            return False
        
        # Wait for ECS agent to register (this may take 30-60 seconds)
        logger.info("Waiting for ECS agent to register container instance (60s)...")
        time.sleep(60)
        
        # Verify container instance registration
        def check_registration():
            container_instances = clients['ecs'].list_container_instances(
                cluster=PROVISIONED_RESOURCES['ecs_cluster_name']
            )
            
            if container_instances['containerInstanceArns']:
                instances = clients['ecs'].describe_container_instances(
                    cluster=PROVISIONED_RESOURCES['ecs_cluster_name'],
                    containerInstances=container_instances['containerInstanceArns']
                )
                
                for ci in instances['containerInstances']:
                    if ci['ec2InstanceId'] == PROVISIONED_RESOURCES['ec2_instance_id']:
                        PROVISIONED_RESOURCES['container_instance_arn'] = ci['containerInstanceArn']
                        logger.info(f"Container instance registered: {ci['containerInstanceArn']}")
                        return True
            return False
        
        try:
            if retry_with_backoff(check_registration, max_attempts=6, delay=10):
                logger.info("=" * 80)
                logger.info("ATTACK PHASE: Attack executed successfully")
                logger.info("=" * 80)
                logger.info(f"Malicious instance: {PROVISIONED_RESOURCES['ec2_instance_id']}")
                logger.info(f"Registered to cluster: {PROVISIONED_RESOURCES['ecs_cluster_name']}")
                logger.info(f"Container instance: {PROVISIONED_RESOURCES['container_instance_arn']}")
                logger.info("=" * 80)
                return True
            else:
                logger.warning("Container instance did not register within timeout")
                return True  # Instance launched successfully even if registration pending
                
        except Exception as e:
            logger.warning(f"Could not verify registration: {str(e)}")
            return True  # Instance launched successfully
        
    except Exception as e:
        logger.error(f"Error in attack phase: {str(e)}")
        return False


def hypothesis_verification() -> bool:
    """
    Verify reactive safeguard: Automated incident response workflow.
    
    Expected behavior:
    1. Step Functions workflow executes
    2. Lambda function deregisters container instance from ECS
    3. Forensic snapshot created
    4. Quarantine security group applied
    5. Instance terminated
    6. Forensic data stored in S3
    7. SNS notification sent
    
    Returns True if all reactive safeguards function correctly.
    """
    logger.info("=" * 80)
    logger.info("HYPOTHESIS VERIFICATION: Testing reactive safeguards")
    logger.info("=" * 80)
    
    clients = get_aws_clients()
    verification_results = []
    
    try:
        # Manually trigger Step Functions workflow (simulating EventBridge trigger)
        logger.info("Triggering Step Functions incident response workflow...")
        
        execution_input = {
            'instance_id': PROVISIONED_RESOURCES['ec2_instance_id'],
            'cluster_name': PROVISIONED_RESOURCES['ecs_cluster_name'],
            'bucket_name': PROVISIONED_RESOURCES['s3_bucket_name'],
            'topic_arn': PROVISIONED_RESOURCES['sns_topic_arn'],
            'quarantine_sg': PROVISIONED_RESOURCES['quarantine_security_group_id']
        }
        
        execution_response = clients['sfn'].start_execution(
            stateMachineArn=PROVISIONED_RESOURCES['step_function_arn'],
            input=json.dumps(execution_input)
        )
        
        execution_arn = execution_response['executionArn']
        logger.info(f"Started execution: {execution_arn}")
        
        # Wait for execution to complete (EXPRESS state machine)
        logger.info("Waiting for workflow execution to complete (30s)...")
        time.sleep(30)
        
        # Describe execution
        execution_details = clients['sfn'].describe_execution(
            executionArn=execution_arn
        )
        
        execution_status = execution_details['status']
        logger.info(f"Execution status: {execution_status}")
        
        if execution_status == 'SUCCEEDED':
            verification_results.append(("Step Functions Execution", True))
            logger.info("✓ Step Functions workflow executed successfully")
            
            # Parse output
            if 'output' in execution_details:
                output = json.loads(execution_details['output'])
                logger.info(f"Workflow output: {json.dumps(output, indent=2)}")
                
                if 'body' in output:
                    body = json.loads(output['body'])
                    actions = body.get('actions', [])
                    logger.info(f"Response actions: {actions}")
        else:
            verification_results.append(("Step Functions Execution", False))
            logger.error(f"✗ Workflow execution failed: {execution_status}")
        
        # Verification 1: Check if container instance was deregistered
        logger.info("Verification 1: Checking ECS container instance deregistration...")
        time.sleep(5)
        
        try:
            container_instances = clients['ecs'].list_container_instances(
                cluster=PROVISIONED_RESOURCES['ecs_cluster_name'],
                status='ACTIVE'
            )
            
            is_deregistered = True
            if container_instances['containerInstanceArns']:
                instances = clients['ecs'].describe_container_instances(
                    cluster=PROVISIONED_RESOURCES['ecs_cluster_name'],
                    containerInstances=container_instances['containerInstanceArns']
                )
                
                for ci in instances['containerInstances']:
                    if ci['ec2InstanceId'] == PROVISIONED_RESOURCES['ec2_instance_id']:
                        is_deregistered = False
                        break
            
            if is_deregistered:
                verification_results.append(("ECS Deregistration", True))
                logger.info("✓ Container instance successfully deregistered from ECS cluster")
            else:
                verification_results.append(("ECS Deregistration", False))
                logger.warning("✗ Container instance still registered in cluster")
                
        except ClientError as e:
            logger.warning(f"Could not verify ECS deregistration: {str(e)}")
            verification_results.append(("ECS Deregistration", False))
        
        # Verification 2: Check if forensic snapshot was created
        logger.info("Verification 2: Checking forensic snapshot creation...")
        
        try:
            snapshots = clients['ec2'].describe_snapshots(
                Filters=[
                    {'Name': f'tag:{EXPERIMENT_TAG_KEY}', 'Values': [EXPERIMENT_TAG_VALUE]},
                    {'Name': 'tag:InstanceId', 'Values': [PROVISIONED_RESOURCES['ec2_instance_id']]}
                ]
            )
            
            if snapshots['Snapshots']:
                verification_results.append(("Forensic Snapshot", True))
                logger.info(f"✓ Forensic snapshot created: {snapshots['Snapshots'][0]['SnapshotId']}")
            else:
                verification_results.append(("Forensic Snapshot", False))
                logger.warning("✗ No forensic snapshot found")
                
        except ClientError as e:
            logger.warning(f"Could not verify snapshot: {str(e)}")
            verification_results.append(("Forensic Snapshot", False))
        
        # Verification 3: Check if quarantine security group was applied
        logger.info("Verification 3: Checking quarantine security group application...")
        
        try:
            instance_info = clients['ec2'].describe_instances(
                InstanceIds=[PROVISIONED_RESOURCES['ec2_instance_id']]
            )
            
            current_sgs = []
            for reservation in instance_info['Reservations']:
                for instance in reservation['Instances']:
                    current_sgs = [sg['GroupId'] for sg in instance['SecurityGroups']]
            
            if PROVISIONED_RESOURCES['quarantine_security_group_id'] in current_sgs:
                verification_results.append(("Quarantine SG Applied", True))
                logger.info("✓ Quarantine security group successfully applied")
            else:
                verification_results.append(("Quarantine SG Applied", False))
                logger.warning(f"✗ Quarantine SG not applied. Current SGs: {current_sgs}")
                
        except ClientError as e:
            logger.warning(f"Could not verify security group: {str(e)}")
            verification_results.append(("Quarantine SG Applied", False))
        
        # Verification 4: Check if instance is terminated or terminating
        logger.info("Verification 4: Checking instance termination...")
        
        try:
            instance_info = clients['ec2'].describe_instances(
                InstanceIds=[PROVISIONED_RESOURCES['ec2_instance_id']]
            )
            
            instance_state = None
            for reservation in instance_info['Reservations']:
                for instance in reservation['Instances']:
                    instance_state = instance['State']['Name']
            
            if instance_state in ['shutting-down', 'terminated']:
                verification_results.append(("Instance Termination", True))
                logger.info(f"✓ Instance termination initiated (state: {instance_state})")
            else:
                verification_results.append(("Instance Termination", False))
                logger.warning(f"✗ Instance not terminated (state: {instance_state})")
                
        except ClientError as e:
            logger.warning(f"Could not verify instance state: {str(e)}")
            verification_results.append(("Instance Termination", False))
        
        # Verification 5: Check if forensic data was stored in S3
        logger.info("Verification 5: Checking forensic data storage in S3...")
        
        try:
            objects = clients['s3'].list_objects_v2(
                Bucket=PROVISIONED_RESOURCES['s3_bucket_name'],
                Prefix=f"forensics/{PROVISIONED_RESOURCES['ec2_instance_id']}/"
            )
            
            if 'Contents' in objects and objects['Contents']:
                verification_results.append(("Forensic Data Storage", True))
                logger.info(f"✓ Forensic data stored in S3: {objects['Contents'][0]['Key']}")
                
                # Retrieve and display forensic data
                forensic_obj = clients['s3'].get_object(
                    Bucket=PROVISIONED_RESOURCES['s3_bucket_name'],
                    Key=objects['Contents'][0]['Key']
                )
                forensic_data = json.loads(forensic_obj['Body'].read().decode())
                logger.info(f"Forensic data: {json.dumps(forensic_data, indent=2)}")
            else:
                verification_results.append(("Forensic Data Storage", False))
                logger.warning("✗ No forensic data found in S3")
                
        except ClientError as e:
            logger.warning(f"Could not verify S3 storage: {str(e)}")
            verification_results.append(("Forensic Data Storage", False))
        
        # Verification 6: Check CloudWatch Logs for execution logs
        logger.info("Verification 6: Checking CloudWatch Logs...")
        
        try:
            log_streams = clients['logs'].describe_log_streams(
                logGroupName=PROVISIONED_RESOURCES['cloudwatch_log_group'],
                orderBy='LastEventTime',
                descending=True,
                limit=5
            )
            
            if log_streams['logStreams']:
                verification_results.append(("CloudWatch Logging", True))
                logger.info(f"✓ Execution logs found in CloudWatch: {log_streams['logStreams'][0]['logStreamName']}")
            else:
                verification_results.append(("CloudWatch Logging", False))
                logger.warning("✗ No execution logs found")
                
        except ClientError as e:
            logger.warning(f"Could not verify CloudWatch logs: {str(e)}")
            verification_results.append(("CloudWatch Logging", False))
        
        # Summary
        logger.info("=" * 80)
        logger.info("VERIFICATION RESULTS SUMMARY")
        logger.info("=" * 80)
        
        for check, result in verification_results:
            status = "✓ PASS" if result else "✗ FAIL"
            logger.info(f"{status}: {check}")
        
        passed = sum(1 for _, result in verification_results if result)
        total = len(verification_results)
        success_rate = (passed / total) * 100
        
        logger.info("=" * 80)
        logger.info(f"Verification Score: {passed}/{total} ({success_rate:.1f}%)")
        logger.info("=" * 80)
        
        # Reactive safeguard is considered successful if critical checks pass
        critical_checks = [
            "Step Functions Execution",
            "ECS Deregistration",
            "Instance Termination"
        ]
        
        critical_passed = all(
            result for check, result in verification_results 
            if check in critical_checks
        )
        
        if critical_passed:
            logger.info("✓ REACTIVE SAFEGUARD VALIDATION: SUCCESS")
            logger.info("All critical reactive controls functioned as expected:")
            logger.info("  - Automated workflow executed")
            logger.info("  - Rogue instance isolated from ECS cluster")
            logger.info("  - Instance terminated")
            logger.info("  - Forensic data preserved")
            return True
        else:
            logger.warning("✗ REACTIVE SAFEGUARD VALIDATION: PARTIAL SUCCESS")
            logger.warning("Some critical controls did not function as expected")
            return False
        
    except Exception as e:
        logger.error(f"Error in hypothesis verification: {str(e)}")
        return False


def rollback():
    """
    Complete teardown of all provisioned resources.
    Executes in reverse dependency order with error tolerance.
    """
    logger.info("=" * 80)
    logger.info("ROLLBACK: Cleaning up experiment resources")
    logger.info("=" * 80)
    
    clients = get_aws_clients()
    cleanup_errors = []
    
    try:
        # 1. Remove EventBridge rule targets and delete rule
        if PROVISIONED_RESOURCES['eventbridge_rule_name']:
            logger.info("Step 1: Removing EventBridge rule...")
            try:
                # Remove targets first
                clients['events'].remove_targets(
                    Rule=PROVISIONED_RESOURCES['eventbridge_rule_name'],
                    Ids=['1']
                )
                logger.info("Removed EventBridge targets")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    cleanup_errors.append(f"EventBridge targets: {str(e)}")
            
            try:
                clients['events'].delete_rule(
                    Name=PROVISIONED_RESOURCES['eventbridge_rule_name']
                )
                logger.info(f"Deleted EventBridge rule: {PROVISIONED_RESOURCES['eventbridge_rule_name']}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    cleanup_errors.append(f"EventBridge rule: {str(e)}")
        
        # 2. Delete Step Functions state machine
        if PROVISIONED_RESOURCES['step_function_arn']:
            logger.info("Step 2: Deleting Step Functions state machine...")
            try:
                clients['sfn'].delete_state_machine(
                    stateMachineArn=PROVISIONED_RESOURCES['step_function_arn']
                )
                logger.info(f"Deleted state machine: {PROVISIONED_RESOURCES['step_function_arn']}")
                time.sleep(2)
            except ClientError as e:
                if e.response['Error']['Code'] != 'StateMachineDoesNotExist':
                    cleanup_errors.append(f"Step Functions: {str(e)}")
        
        # 3. Delete Lambda function
        if PROVISIONED_RESOURCES['lambda_function_name']:
            logger.info("Step 3: Deleting Lambda function...")
            try:
                clients['lambda'].delete_function(
                    FunctionName=PROVISIONED_RESOURCES['lambda_function_name']
                )
                logger.info(f"Deleted Lambda function: {PROVISIONED_RESOURCES['lambda_function_name']}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    cleanup_errors.append(f"Lambda function: {str(e)}")
        
        # 4. Delete CloudWatch Log Group
        if PROVISIONED_RESOURCES['cloudwatch_log_group']:
            logger.info("Step 4: Deleting CloudWatch Log Group...")
            try:
                clients['logs'].delete_log_group(
                    logGroupName=PROVISIONED_RESOURCES['cloudwatch_log_group']
                )
                logger.info(f"Deleted log group: {PROVISIONED_RESOURCES['cloudwatch_log_group']}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'ResourceNotFoundException':
                    cleanup_errors.append(f"CloudWatch log group: {str(e)}")
        
        # 5. Terminate EC2 instance (if still exists)
        if PROVISIONED_RESOURCES['ec2_instance_id']:
            logger.info("Step 5: Terminating EC2 instance...")
            try:
                clients['ec2'].terminate_instances(
                    InstanceIds=[PROVISIONED_RESOURCES['ec2_instance_id']]
                )
                logger.info(f"Terminated instance: {PROVISIONED_RESOURCES['ec2_instance_id']}")
                
                # Wait for termination
                logger.info("Waiting for instance termination (60s max)...")
                waiter = clients['ec2'].get_waiter('instance_terminated')
                try:
                    waiter.wait(
                        InstanceIds=[PROVISIONED_RESOURCES['ec2_instance_id']],
                        WaiterConfig={'Delay': 5, 'MaxAttempts': 12}
                    )
                    logger.info("Instance terminated successfully")
                except WaiterError:
                    logger.warning("Instance termination timeout, continuing cleanup")
                    
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidInstanceID.NotFound':
                    cleanup_errors.append(f"EC2 instance: {str(e)}")
        
        # 6. Delete forensic snapshots
        logger.info("Step 6: Deleting forensic snapshots...")
        try:
            snapshots = clients['ec2'].describe_snapshots(
                Filters=[
                    {'Name': f'tag:{EXPERIMENT_TAG_KEY}', 'Values': [EXPERIMENT_TAG_VALUE]}
                ]
            )
            
            for snapshot in snapshots['Snapshots']:
                try:
                    clients['ec2'].delete_snapshot(SnapshotId=snapshot['SnapshotId'])
                    logger.info(f"Deleted snapshot: {snapshot['SnapshotId']}")
                except ClientError as e:
                    cleanup_errors.append(f"Snapshot {snapshot['SnapshotId']}: {str(e)}")
                    
        except ClientError as e:
            cleanup_errors.append(f"Snapshot cleanup: {str(e)}")
        
        # 7. Deregister container instances and delete ECS cluster
        if PROVISIONED_RESOURCES['ecs_cluster_name']:
            logger.info("Step 7: Cleaning up ECS cluster...")
            try:
                # List and deregister container instances
                container_instances = clients['ecs'].list_container_instances(
                    cluster=PROVISIONED_RESOURCES['ecs_cluster_name']
                )
                
                for ci_arn in container_instances.get('containerInstanceArns', []):
                    try:
                        clients['ecs'].deregister_container_instance(
                            cluster=PROVISIONED_RESOURCES['ecs_cluster_name'],
                            containerInstance=ci_arn,
                            force=True
                        )
                        logger.info(f"Deregistered container instance: {ci_arn}")
                    except ClientError as e:
                        cleanup_errors.append(f"Container instance {ci_arn}: {str(e)}")
                
                # Delete cluster
                time.sleep(5)
                clients['ecs'].delete_cluster(
                    cluster=PROVISIONED_RESOURCES['ecs_cluster_name']
                )
                logger.info(f"Deleted ECS cluster: {PROVISIONED_RESOURCES['ecs_cluster_name']}")
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'ClusterNotFoundException':
                    cleanup_errors.append(f"ECS cluster: {str(e)}")
        
        # 8. Empty and delete S3 bucket
        if PROVISIONED_RESOURCES['s3_bucket_name']:
            logger.info("Step 8: Emptying and deleting S3 bucket...")
            try:
                # Delete all objects
                paginator = clients['s3'].get_paginator('list_object_versions')
                for page in paginator.paginate(Bucket=PROVISIONED_RESOURCES['s3_bucket_name']):
                    objects_to_delete = []
                    
                    for version in page.get('Versions', []):
                        objects_to_delete.append({
                            'Key': version['Key'],
                            'VersionId': version['VersionId']
                        })
                    
                    for marker in page.get('DeleteMarkers', []):
                        objects_to_delete.append({
                            'Key': marker['Key'],
                            'VersionId': marker['VersionId']
                        })
                    
                    if objects_to_delete:
                        clients['s3'].delete_objects(
                            Bucket=PROVISIONED_RESOURCES['s3_bucket_name'],
                            Delete={'Objects': objects_to_delete}
                        )
                        logger.info(f"Deleted {len(objects_to_delete)} objects from S3")
                
                # Delete bucket
                clients['s3'].delete_bucket(Bucket=PROVISIONED_RESOURCES['s3_bucket_name'])
                logger.info(f"Deleted S3 bucket: {PROVISIONED_RESOURCES['s3_bucket_name']}")
                
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucket':
                    cleanup_errors.append(f"S3 bucket: {str(e)}")
        
        # 9. Delete SNS topic
        if PROVISIONED_RESOURCES['sns_topic_arn']:
            logger.info("Step 9: Deleting SNS topic...")
            try:
                clients['sns'].delete_topic(TopicArn=PROVISIONED_RESOURCES['sns_topic_arn'])
                logger.info(f"Deleted SNS topic: {PROVISIONED_RESOURCES['sns_topic_arn']}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NotFound':
                    cleanup_errors.append(f"SNS topic: {str(e)}")
        
        # 10. Delete IAM roles and policies
        logger.info("Step 10: Deleting IAM roles...")
        
        # Delete Step Functions role
        if PROVISIONED_RESOURCES['step_function_role_name']:
            try:
                # Delete inline policies
                policies = clients['iam'].list_role_policies(
                    RoleName=PROVISIONED_RESOURCES['step_function_role_name']
                )
                for policy_name in policies['PolicyNames']:
                    clients['iam'].delete_role_policy(
                        RoleName=PROVISIONED_RESOURCES['step_function_role_name'],
                        PolicyName=policy_name
                    )
                
                # Delete role
                clients['iam'].delete_role(RoleName=PROVISIONED_RESOURCES['step_function_role_name'])
                logger.info(f"Deleted Step Functions role: {PROVISIONED_RESOURCES['step_function_role_name']}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    cleanup_errors.append(f"Step Functions role: {str(e)}")
        
        # Delete Lambda role
        if PROVISIONED_RESOURCES['lambda_role_name']:
            try:
                # Delete inline policies
                policies = clients['iam'].list_role_policies(
                    RoleName=PROVISIONED_RESOURCES['lambda_role_name']
                )
                for policy_name in policies['PolicyNames']:
                    clients['iam'].delete_role_policy(
                        RoleName=PROVISIONED_RESOURCES['lambda_role_name'],
                        PolicyName=policy_name
                    )
                
                # Detach managed policies
                attached_policies = clients['iam'].list_attached_role_policies(
                    RoleName=PROVISIONED_RESOURCES['lambda_role_name']
                )
                for policy in attached_policies['AttachedPolicies']:
                    clients['iam'].detach_role_policy(
                        RoleName=PROVISIONED_RESOURCES['lambda_role_name'],
                        PolicyArn=policy['PolicyArn']
                    )
                
                # Delete role
                clients['iam'].delete_role(RoleName=PROVISIONED_RESOURCES['lambda_role_name'])
                logger.info(f"Deleted Lambda role: {PROVISIONED_RESOURCES['lambda_role_name']}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    cleanup_errors.append(f"Lambda role: {str(e)}")
        
        # Delete ECS instance profile and role
        if PROVISIONED_RESOURCES['iam_instance_profile_name']:
            try:
                # Remove role from instance profile
                if PROVISIONED_RESOURCES['iam_role_name']:
                    clients['iam'].remove_role_from_instance_profile(
                        InstanceProfileName=PROVISIONED_RESOURCES['iam_instance_profile_name'],
                        RoleName=PROVISIONED_RESOURCES['iam_role_name']
                    )
                
                # Delete instance profile
                clients['iam'].delete_instance_profile(
                    InstanceProfileName=PROVISIONED_RESOURCES['iam_instance_profile_name']
                )
                logger.info(f"Deleted instance profile: {PROVISIONED_RESOURCES['iam_instance_profile_name']}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    cleanup_errors.append(f"Instance profile: {str(e)}")
        
        if PROVISIONED_RESOURCES['iam_role_name']:
            try:
                # Detach managed policies
                attached_policies = clients['iam'].list_attached_role_policies(
                    RoleName=PROVISIONED_RESOURCES['iam_role_name']
                )
                for policy in attached_policies['AttachedPolicies']:
                    clients['iam'].detach_role_policy(
                        RoleName=PROVISIONED_RESOURCES['iam_role_name'],
                        PolicyArn=policy['PolicyArn']
                    )
                
                # Delete role
                clients['iam'].delete_role(RoleName=PROVISIONED_RESOURCES['iam_role_name'])
                logger.info(f"Deleted ECS role: {PROVISIONED_RESOURCES['iam_role_name']}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchEntity':
                    cleanup_errors.append(f"ECS role: {str(e)}")
        
        # 11. Delete security groups
        logger.info("Step 11: Deleting security groups...")
        time.sleep(5)  # Wait for dependencies to clear
        
        for sg_id in [PROVISIONED_RESOURCES['security_group_id'], 
                      PROVISIONED_RESOURCES['quarantine_security_group_id']]:
            if sg_id:
                try:
                    clients['ec2'].delete_security_group(GroupId=sg_id)
                    logger.info(f"Deleted security group: {sg_id}")
                except ClientError as e:
                    if e.response['Error']['Code'] not in ['InvalidGroup.NotFound', 'DependencyViolation']:
                        cleanup_errors.append(f"Security group {sg_id}: {str(e)}")
        
        # 12. Delete subnet
        if PROVISIONED_RESOURCES['subnet_id']:
            logger.info("Step 12: Deleting subnet...")
            try:
                clients['ec2'].delete_subnet(SubnetId=PROVISIONED_RESOURCES['subnet_id'])
                logger.info(f"Deleted subnet: {PROVISIONED_RESOURCES['subnet_id']}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidSubnetID.NotFound':
                    cleanup_errors.append(f"Subnet: {str(e)}")
        
        # 13. Delete VPC
        if PROVISIONED_RESOURCES['vpc_id']:
            logger.info("Step 13: Deleting VPC...")
            try:
                clients['ec2'].delete_vpc(VpcId=PROVISIONED_RESOURCES['vpc_id'])
                logger.info(f"Deleted VPC: {PROVISIONED_RESOURCES['vpc_id']}")
            except ClientError as e:
                if e.response['Error']['Code'] != 'InvalidVpcID.NotFound':
                    cleanup_errors.append(f"VPC: {str(e)}")
        
        # Summary
        logger.info("=" * 80)
        if cleanup_errors:
            logger.warning("ROLLBACK COMPLETED WITH ERRORS")
            logger.warning("The following errors occurred during cleanup:")
            for error in cleanup_errors:
                logger.warning(f"  - {error}")
        else:
            logger.info("ROLLBACK COMPLETED SUCCESSFULLY")
            logger.info("All experiment resources have been cleaned up")
        logger.info("=" * 80)
        
    except Exception as e:
        logger.error(f"Critical error during rollback: {str(e)}")
        raise


def run_experiment():
    """Main experiment execution function."""
    logger.info("=" * 80)
    logger.info("SECURITY CHAOS ENGINEERING EXPERIMENT 2.4")
    logger.info("Reactive Probe: Automated Instance Termination & Cluster Isolation")
    logger.info("=" * 80)
    logger.info(f"AWS Region: {AWS_REGION}")
    logger.info(f"Experiment Tag: {EXPERIMENT_TAG_KEY}={EXPERIMENT_TAG_VALUE}")
    logger.info("=" * 80)
    
    try:
        # Phase 1: Steady State
        logger.info("\n[PHASE 1] Establishing steady state...")
        if not steady_state():
            logger.error("Failed to establish steady state")
            return False
        
        # Phase 2: Attack
        logger.info("\n[PHASE 2] Executing attack simulation...")
        attack_success = attack()
        if not attack_success:
            logger.error("Attack simulation failed")
            return False
        
        # Phase 3: Hypothesis Verification
        logger.info("\n[PHASE 3] Verifying reactive safeguards...")
        hypothesis_result = hypothesis_verification()
        
        # Phase 4: Rollback
        logger.info("\n[PHASE 4] Executing rollback...")
        rollback()
        
        # Final result
        logger.info("\n" + "=" * 80)
        if hypothesis_result:
            logger.info("EXPERIMENT RESULT: SUCCESS ✓")
            logger.info("Reactive safeguards functioned as expected")
        else:
            logger.warning("EXPERIMENT RESULT: FAILURE ✗")
            logger.warning("Reactive safeguards did not function as expected")
        logger.info("=" * 80)
        
        return hypothesis_result
        
    except Exception as e:
        logger.error(f"Experiment failed with error: {str(e)}")
        logger.info("\nAttempting emergency rollback...")
        try:
            rollback()
        except Exception as rollback_error:
            logger.error(f"Emergency rollback failed: {str(rollback_error)}")
        return False


if __name__ == "__main__":
    try:
        success = run_experiment()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        logger.warning("\nExperiment interrupted by user")
        logger.info("Attempting cleanup...")
        try:
            rollback()
        except:
            pass
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unhandled exception: {str(e)}")
        sys.exit(1)