#!/usr/bin/env python3
"""
SCE 1.8: Encrypted CodeBuild Artifact Control (Preventive Probe)

This experiment validates that preventive controls effectively block
credential exfiltration via unencrypted S3 uploads from malicious
CodeBuild projects.

Attack: Node 1.7 - Start Malicious Build with credential extraction payload
Defense: Preventive encryption enforcement and bucket policies
Probe: Verify that unencrypted artifacts cannot be uploaded
"""

import json
import time
import logging
import boto3
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# AWS Clients
s3_client = boto3.client('s3', region_name='us-east-1')
codebuild_client = boto3.client('codebuild', region_name='us-east-1')
iam_client = boto3.client('iam', region_name='us-east-1')
cloudformation_client = boto3.client('cloudformation', region_name='us-east-1')
sts_client = boto3.client('sts', region_name='us-east-1')

# Global state
STACK_NAME = None
ARTIFACT_BUCKET = None
CODEBUILD_PROJECT = None
IAM_ROLE_ARN = None


def get_account_id():
    """Retrieve AWS account ID from STS."""
    try:
        response = sts_client.get_caller_identity()
        return response['Account']
    except ClientError as e:
        logger.error(f"Failed to get account ID: {e}")
        raise


def generate_stack_name():
    """Generate unique stack name with timestamp."""
    timestamp = int(time.time())
    return f"sce-1-8-experiment-{timestamp}"


def deploy_cloudformation_stack():
    """Deploy CloudFormation stack with S3 bucket, CodeBuild project, and IAM role."""
    global STACK_NAME, ARTIFACT_BUCKET, CODEBUILD_PROJECT, IAM_ROLE_ARN
    
    STACK_NAME = generate_stack_name()
    ARTIFACT_BUCKET = f"sce-artifact-bucket-{int(time.time())}"
    CODEBUILD_PROJECT = f"sce-codebuild-project-{int(time.time())}"
    
    account_id = get_account_id()
    
    # CloudFormation template with preventive controls
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8: CodeBuild Artifact Encryption Control",
        "Resources": {
            "SCECodeBuildRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "codebuild.amazonaws.com"
                                },
                                "Action": "sts:AssumeRole"
                            }
                        ]
                    },
                    "Policies": [
                        {
                            "PolicyName": "SCECodeBuildPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "s3:PutObject",
                                            "s3:GetObject"
                                        ],
                                        "Resource": f"arn:aws:s3:::{ARTIFACT_BUCKET}/*"
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogGroup",
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents"
                                        ],
                                        "Resource": "*"
                                    }
                                ]
                            }
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1-8"},
                        {"Key": "Timestamp", "Value": str(int(time.time()))}
                    ]
                }
            },
            "SCEArtifactBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": ARTIFACT_BUCKET,
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
                        {"Key": "Experiment", "Value": "SCE-1-8"},
                        {"Key": "Timestamp", "Value": str(int(time.time()))}
                    ]
                }
            },
            "SCEBucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "SCEArtifactBucket"},
                    "PolicyText": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DenyUnencryptedObjectUpload",
                                "Effect": "Deny",
                                "Principal": "*",
                                "Action": "s3:PutObject",
                                "Resource": f"arn:aws:s3:::{ARTIFACT_BUCKET}/*",
                                "Condition": {
                                    "StringNotEquals": {
                                        "s3:x-amz-server-side-encryption": "AES256"
                                    }
                                }
                            },
                            {
                                "Sid": "DenyIncorrectKmsKey",
                                "Effect": "Deny",
                                "Principal": "*",
                                "Action": "s3:PutObject",
                                "Resource": f"arn:aws:s3:::{ARTIFACT_BUCKET}/*",
                                "Condition": {
                                    "StringNotEquals": {
                                        "s3:x-amz-server-side-encryption-aws-kms-key-id": f"arn:aws:kms:us-east-1:{account_id}:alias/aws/s3"
                                    }
                                }
                            }
                        ]
                    }
                }
            },
            "SCECodeBuildProject": {
                "Type": "AWS::CodeBuild::Project",
                "Properties": {
                    "Name": CODEBUILD_PROJECT,
                    "ServiceRole": {"Fn::GetAtt": ["SCECodeBuildRole", "Arn"]},
                    "Artifacts": {
                        "Type": "S3",
                        "Location": ARTIFACT_BUCKET,
                        "EncryptionDisabled": False
                    },
                    "Environment": {
                        "Type": "LINUX_CONTAINER",
                        "ComputeType": "BUILD_GENERAL1_SMALL",
                        "Image": "aws/codebuild/standard:5.0",
                        "EnvironmentVariables": [
                            {
                                "Name": "AWS_DEFAULT_REGION",
                                "Value": "us-east-1",
                                "Type": "PLAINTEXT"
                            }
                        ]
                    },
                    "Source": {
                        "Type": "NO_SOURCE",
                        "BuildSpec": """
version: 0.2
phases:
  build:
    commands:
      - echo "Attempting to exfiltrate credentials..."
      - aws configure set region us-east-1
      - echo "AWS_ACCESS_KEY_ID=$(echo $AWS_ACCESS_KEY_ID)" > /tmp/creds.txt
      - echo "AWS_SECRET_ACCESS_KEY=$(echo $AWS_SECRET_ACCESS_KEY)" >> /tmp/creds.txt
      - echo "Uploading exfiltrated credentials to S3..."
      - aws s3 cp /tmp/creds.txt s3://%s/exfiltrated-credentials.txt || echo "Upload failed (expected - preventive control active)"
artifacts:
  files:
    - /tmp/creds.txt
  name: CredentialArtifact
  discard-paths: yes
""" % ARTIFACT_BUCKET
                    },
                    "LogsConfig": {
                        "CloudWatchLogs": {
                            "Status": "ENABLED",
                            "GroupName": f"/aws/codebuild/{CODEBUILD_PROJECT}"
                        }
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1-8"},
                        {"Key": "Timestamp", "Value": str(int(time.time()))}
                    ]
                }
            }
        },
        "Outputs": {
            "BucketName": {
                "Value": {"Ref": "SCEArtifactBucket"},
                "Description": "S3 artifact bucket"
            },
            "CodeBuildProject": {
                "Value": {"Ref": "SCECodeBuildProject"},
                "Description": "CodeBuild project name"
            },
            "RoleArn": {
                "Value": {"Fn::GetAtt": ["SCECodeBuildRole", "Arn"]},
                "Description": "CodeBuild IAM role ARN"
            }
        }
    }
    
    try:
        logger.info(f"Creating CloudFormation stack: {STACK_NAME}")
        response = cloudformation_client.create_stack(
            StackName=STACK_NAME,
            TemplateBody=json.dumps(template),
            Capabilities=['CAPABILITY_NAMED_IAM']
        )
        stack_id = response['StackId']
        logger.info(f"Stack creation initiated: {stack_id}")
        
        # Wait for stack creation with retries
        wait_for_stack_creation(STACK_NAME)
        
        # Extract outputs
        stacks = cloudformation_client.describe_stacks(StackName=STACK_NAME)
        outputs = stacks['Stacks'][0].get('Outputs', [])
        for output in outputs:
            if output['OutputKey'] == 'BucketName':
                ARTIFACT_BUCKET = output['OutputValue']
            elif output['OutputKey'] == 'CodeBuildProject':
                CODEBUILD_PROJECT = output['OutputValue']
            elif output['OutputKey'] == 'RoleArn':
                IAM_ROLE_ARN = output['OutputValue']
        
        logger.info(f"Stack deployment successful")
        logger.info(f"  Artifact Bucket: {ARTIFACT_BUCKET}")
        logger.info(f"  CodeBuild Project: {CODEBUILD_PROJECT}")
        logger.info(f"  IAM Role ARN: {IAM_ROLE_ARN}")
        
        return True
        
    except ClientError as e:
        logger.error(f"Failed to create stack: {e}")
        return False


def wait_for_stack_creation(stack_name, max_attempts=30):
    """Wait for CloudFormation stack to reach CREATE_COMPLETE."""
    for attempt in range(max_attempts):
        try:
            response = cloudformation_client.describe_stacks(StackName=stack_name)
            status = response['Stacks'][0]['StackStatus']
            
            if status == 'CREATE_COMPLETE':
                logger.info(f"Stack creation complete")
                return True
            elif 'FAILED' in status or 'ROLLBACK' in status:
                logger.error(f"Stack creation failed with status: {status}")
                return False
            else:
                logger.info(f"Stack status: {status} (attempt {attempt + 1}/{max_attempts})")
                time.sleep(2)
        except ClientError as e:
            logger.error(f"Error checking stack status: {e}")
            time.sleep(2)
    
    logger.error("Stack creation timeout")
    return False


def steady_state():
    """Deploy preventive controls: S3 encryption and CodeBuild project."""
    logger.info("=== STEADY STATE: Deploying preventive controls ===")
    
    try:
        # Check if stack already exists
        try:
            cloudformation_client.describe_stacks(StackName=STACK_NAME or generate_stack_name())
            logger.warning("Stack already exists, skipping deployment")
            return
        except ClientError:
            pass  # Stack doesn't exist, proceed with creation
        
        if not deploy_cloudformation_stack():
            raise Exception("CloudFormation stack deployment failed")
        
        # Verify bucket encryption is active
        logger.info("Verifying S3 encryption configuration...")
        encryption = s3_client.get_bucket_encryption(Bucket=ARTIFACT_BUCKET)
        if encryption:
            logger.info(f"✓ Bucket encryption enabled: {encryption['ServerSideEncryptionConfiguration']}")
        
        # Verify bucket policy exists
        logger.info("Verifying bucket policy...")
        try:
            policy = s3_client.get_bucket_policy(Bucket=ARTIFACT_BUCKET)
            logger.info(f"✓ Bucket policy active")
        except ClientError as e:
            logger.warning(f"Bucket policy not yet retrievable: {e}")
        
        # Verify CodeBuild encryption setting
        logger.info("Verifying CodeBuild encryption...")
        project = codebuild_client.batch_get_projects(names=[CODEBUILD_PROJECT])
        if project['projects']:
            artifacts = project['projects'][0].get('artifacts', {})
            encryption_disabled = artifacts.get('encryptionDisabled', True)
            logger.info(f"✓ CodeBuild EncryptionDisabled: {encryption_disabled}")
        
        logger.info("✓ Steady state deployment complete")
        
    except Exception as e:
        logger.error(f"Steady state failed: {e}")
        raise


def attack() -> bool:
    """Execute malicious CodeBuild build to attempt credential exfiltration."""
    logger.info("=== ATTACK: Triggering malicious CodeBuild execution ===")
    
    try:
        if not CODEBUILD_PROJECT:
            logger.error("CodeBuild project not initialized")
            return False
        
        logger.info(f"Starting build on project: {CODEBUILD_PROJECT}")
        
        # Trigger the build
        response = codebuild_client.start_build(projectName=CODEBUILD_PROJECT)
        build_id = response['build']['id']
        build_arn = response['build']['arn']
        
        logger.info(f"✓ Build started successfully")
        logger.info(f"  Build ID: {build_id}")
        logger.info(f"  Build ARN: {build_arn}")
        
        # Wait for build completion
        logger.info("Waiting for build execution...")
        if wait_for_build_completion(build_id):
            logger.info("✓ Build execution completed")
            
            # Query build logs to verify attack was attempted
            query_build_logs(build_id)
            
            return True
        else:
            logger.error("Build execution timeout or failure")
            return False
            
    except ClientError as e:
        logger.error(f"Failed to start build: {e}")
        return False


def wait_for_build_completion(build_id, max_attempts=30):
    """Wait for CodeBuild to complete execution."""
    for attempt in range(max_attempts):
        try:
            response = codebuild_client.batch_get_builds(ids=[build_id])
            build = response['builds'][0]
            status = build['buildStatus']
            
            if status in ['SUCCEEDED', 'FAILED', 'FAULT', 'TIMED_OUT', 'STOPPED']:
                logger.info(f"Build status: {status}")
                return True
            else:
                logger.info(f"Build in progress (status: {status}) - attempt {attempt + 1}/{max_attempts}")
                time.sleep(2)
        except ClientError as e:
            logger.error(f"Error checking build status: {e}")
            time.sleep(2)
    
    logger.error("Build execution timeout")
    return False


def query_build_logs(build_id):
    """Query CloudWatch logs for build execution details."""
    try:
        response = codebuild_client.batch_get_builds(ids=[build_id])
        build = response['builds'][0]
        
        logger.info(f"Build phase statuses:")
        for phase in build.get('phases', []):
            phase_type = phase.get('phaseType')
            phase_status = phase.get('phaseStatus')
            logger.info(f"  {phase_type}: {phase_status}")
        
        if build.get('logsConfig', {}).get('cloudWatchLogs'):
            logger.info(f"CloudWatch logs available at: /aws/codebuild/{CODEBUILD_PROJECT}")
    except Exception as e:
        logger.warning(f"Could not retrieve build logs: {e}")


def hypothesis_verification() -> bool:
    """
    Verify that preventive controls blocked credential exfiltration.
    
    This probe checks:
    1. S3 default encryption is enabled
    2. S3 bucket policy denies unencrypted uploads
    3. CodeBuild artifact encryption is enforced
    4. S3 public access blocking is enabled
    5. Bucket contains only encrypted objects (no exfiltrated credentials)
    """
    logger.info("=== PROBE: Verifying preventive control effectiveness ===")
    
    checks = {}
    
    try:
        # Check 1: S3 Default Encryption
        logger.info("Check 1: Verifying S3 default encryption...")
        try:
            encryption = s3_client.get_bucket_encryption(Bucket=ARTIFACT_BUCKET)
            rules = encryption['ServerSideEncryptionConfiguration']['Rules']
            default_algo = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
            checks['encryption'] = default_algo == 'AES256'
            logger.info(f"  {'✓' if checks['encryption'] else '✗'} S3 default encryption: {default_algo}")
        except ClientError as e:
            checks['encryption'] = False
            logger.warning(f"  ✗ Failed to retrieve bucket encryption: {e}")
        
        # Check 2: S3 Bucket Policy Denial
        logger.info("Check 2: Verifying S3 bucket policy (deny unencrypted uploads)...")
        try:
            policy_response = s3_client.get_bucket_policy(Bucket=ARTIFACT_BUCKET)
            policy = json.loads(policy_response['Policy'])
            
            # Verify deny statements for unencrypted uploads
            deny_found = False
            for statement in policy.get('Statement', []):
                if statement.get('Effect') == 'Deny':
                    actions = statement.get('Action', [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if 's3:PutObject' in actions:
                        deny_found = True
                        logger.info(f"  ✓ Deny policy found for unencrypted PutObject")
                        break
            
            checks['policy'] = deny_found
            if not deny_found:
                logger.warning(f"  ✗ No deny policy found for unencrypted uploads")
        except ClientError as e:
            checks['policy'] = False
            logger.warning(f"  ✗ Failed to retrieve bucket policy: {e}")
        
        # Check 3: CodeBuild Encryption Setting
        logger.info("Check 3: Verifying CodeBuild project encryption setting...")
        try:
            project = codebuild_client.batch_get_projects(names=[CODEBUILD_PROJECT])
            if project['projects']:
                artifacts = project['projects'][0].get('artifacts', {})
                encryption_disabled = artifacts.get('encryptionDisabled', True)
                checks['codebuild'] = not encryption_disabled
                logger.info(f"  {'✓' if checks['codebuild'] else '✗'} CodeBuild encryption enabled: {not encryption_disabled}")
            else:
                checks['codebuild'] = False
                logger.warning(f"  ✗ CodeBuild project not found")
        except ClientError as e:
            checks['codebuild'] = False
            logger.warning(f"  ✗ Failed to retrieve CodeBuild project: {e}")
        
        # Check 4: Public Access Blocking
        logger.info("Check 4: Verifying S3 public access blocking...")
        try:
            pab = s3_client.get_public_access_block(Bucket=ARTIFACT_BUCKET)
            config = pab['PublicAccessBlockConfiguration']
            all_blocked = all([
                config.get('BlockPublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('IgnorePublicAcls', False),
                config.get('RestrictPublicBuckets', False)
            ])
            checks['public_access'] = all_blocked
            logger.info(f"  {'✓' if all_blocked else '✗'} All public access blocking enabled")
        except ClientError as e:
            checks['public_access'] = False
            logger.warning(f"  ✗ Failed to retrieve public access blocking: {e}")
        
        # Check 5: Verify Only Encrypted Objects in Bucket
        logger.info("Check 5: Verifying bucket contains only encrypted objects...")
        try:
            objects = s3_client.list_objects_v2(Bucket=ARTIFACT_BUCKET)
            
            if 'Contents' not in objects or len(objects['Contents']) == 0:
                # No objects = attack was blocked
                checks['encrypted_objects_only'] = True
                logger.info(f"  ✓ Bucket is empty (attack blocked successfully)")
            else:
                # Check encryption on all objects
                all_encrypted = True
                for obj in objects['Contents']:
                    key = obj['Key']
                    head = s3_client.head_object(Bucket=ARTIFACT_BUCKET, Key=key)
                    
                    # Verify encryption metadata
                    sse = head.get('ServerSideEncryption')
                    if sse != 'AES256':
                        logger.warning(f"  ✗ Unencrypted object found: {key} (SSE: {sse})")
                        all_encrypted = False
                    else:
                        logger.info(f"  ✓ Object encrypted: {key}")
                
                checks['encrypted_objects_only'] = all_encrypted
        except ClientError as e:
            checks['encrypted_objects_only'] = False
            logger.warning(f"  ✗ Failed to verify bucket objects: {e}")
        
        # Final verdict
        all_passed = all(checks.values())
        
        logger.info("\n=== PROBE RESULTS ===")
        logger.info(f"Check 1 (S3 Encryption):            {'✓ PASS' if checks.get('encryption') else '✗ FAIL'}")
        logger.info(f"Check 2 (Preventive Policy):       {'✓ PASS' if checks.get('policy') else '✗ FAIL'}")
        logger.info(f"Check 3 (CodeBuild Encryption):    {'✓ PASS' if checks.get('codebuild') else '✗ FAIL'}")
        logger.info(f"Check 4 (Public Access Blocking):  {'✓ PASS' if checks.get('public_access') else '✗ FAIL'}")
        logger.info(f"Check 5 (Encrypted Objects Only):  {'✓ PASS' if checks.get('encrypted_objects_only') else '✗ FAIL'}")
        logger.info(f"\nOverall: {'✓ PREVENTIVE CONTROL EFFECTIVE' if all_passed else '✗ CONTROL BYPASSED'}")
        
        return all_passed
        
    except Exception as e:
        logger.error(f"Hypothesis verification failed: {e}")
        return False


def rollback():
    """Delete CloudFormation stack and all resources."""
    logger.info("=== ROLLBACK: Cleaning up experiment resources ===")
    
    if not STACK_NAME:
        logger.warning("Stack name not initialized, skipping rollback")
        return
    
    try:
        # Check if stack exists
        try:
            cloudformation_client.describe_stacks(StackName=STACK_NAME)
        except ClientError:
            logger.info("Stack does not exist, skipping deletion")
            return
        
        logger.info(f"Deleting stack: {STACK_NAME}")
        cloudformation_client.delete_stack(StackName=STACK_NAME)
        
        # Wait for deletion
        wait_for_stack_deletion(STACK_NAME)
        logger.info("✓ Rollback complete")
        
    except Exception as e:
        logger.error(f"Rollback failed: {e}")


def wait_for_stack_deletion(stack_name, max_attempts=30):
    """Wait for CloudFormation stack deletion to complete."""
    for attempt in range(max_attempts):
        try:
            response = cloudformation_client.describe_stacks(StackName=stack_name)
            status = response['Stacks'][0]['StackStatus']
            
            if 'DELETE_COMPLETE' in status:
                logger.info("Stack deletion complete")
                return True
            elif 'DELETE_FAILED' in status:
                logger.error(f"Stack deletion failed with status: {status}")
                return False
            else:
                logger.info(f"Stack deletion in progress (status: {status}) - attempt {attempt + 1}/{max_attempts}")
                time.sleep(2)
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.info("Stack deleted successfully")
                return True
            logger.error(f"Error checking stack status: {e}")
            time.sleep(2)
    
    logger.error("Stack deletion timeout")
    return False


if __name__ == '__main__':
    """Main execution flow for standalone testing."""
    try:
        logger.info("Starting SCE 1.8 experiment...")
        
        # Deploy preventive controls
        steady_state()
        
        # Execute attack
        attack_result = attack()
        logger.info(f"Attack execution: {'SUCCESS' if attack_result else 'FAILED'}")
        
        # Verify controls
        probe_result = hypothesis_verification()
        logger.info(f"Probe result: {'PASS' if probe_result else 'FAIL'}")
        
        # Cleanup
        rollback()
        
        logger.info(f"Experiment completed with overall result: {'PASS' if probe_result else 'FAIL'}")
        
    except Exception as e:
        logger.error(f"Experiment failed: {e}")
        rollback()
        raise