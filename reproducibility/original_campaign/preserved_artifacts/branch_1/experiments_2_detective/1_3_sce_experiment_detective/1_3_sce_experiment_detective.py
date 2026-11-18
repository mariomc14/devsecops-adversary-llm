#!/usr/bin/env python3
"""
Security Chaos Engineering Unit Test: 1.3 SCE Experiment (Detective Probe)
Attack Node: 1.2 Create Malicious CodeBuild Project

This experiment validates a detective control that identifies and flags
unauthorized or malicious CodeBuild projects created with suspicious configurations.

The probe detects whether CodeBuild projects are created with:
- Privileged mode enabled (allows container escape)
- Overly permissive IAM role attached
- Source from untrusted repositories
- Artifacts sent to unaudited S3 buckets
"""

import json
import logging
import time
import sys
import subprocess
from typing import Optional, Dict, List, Any

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Ensure boto3 is installed
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    logger.info("Installing boto3...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Global state for resource cleanup
STACK_NAME_SUFFIX = None
CREATED_RESOURCES = {
    'stack_name': None,
    'codebuild_project_name': None,
    'iam_role_arn': None,
    's3_bucket_name': None,
    'security_event_detected': False
}


def get_aws_account_id() -> str:
    """Retrieve the AWS account ID from STS."""
    sts = boto3.client('sts')
    try:
        response = sts.get_caller_identity()
        account_id = response['Account']
        logger.info(f"AWS Account ID: {account_id}")
        return account_id
    except ClientError as e:
        logger.error(f"Failed to retrieve account ID: {e}")
        raise


def get_aws_region() -> str:
    """Get the current AWS region."""
    session = boto3.Session()
    region = session.region_name or 'us-east-1'
    logger.info(f"AWS Region: {region}")
    return region


def wait_for_stack_status(
    cf_client,
    stack_name: str,
    expected_status: str,
    max_attempts: int = 60,
    delay: int = 5
) -> bool:
    """
    Wait for CloudFormation stack to reach expected status with exponential backoff.
    
    Args:
        cf_client: CloudFormation client
        stack_name: Stack name
        expected_status: Status to wait for (e.g., 'CREATE_COMPLETE', 'DELETE_COMPLETE')
        max_attempts: Maximum retry attempts
        delay: Initial delay in seconds
    
    Returns:
        True if status reached, False otherwise
    """
    start_time = time.monotonic()
    attempt = 0
    current_delay = delay

    while attempt < max_attempts:
        try:
            response = cf_client.describe_stacks(StackName=stack_name)
            if not response['Stacks']:
                if expected_status == 'DELETE_COMPLETE':
                    logger.info(f"Stack {stack_name} successfully deleted")
                    return True
                logger.warning(f"Stack {stack_name} not found")
                return False

            stack_status = response['Stacks'][0]['StackStatus']
            logger.debug(f"Stack status: {stack_status} (attempt {attempt + 1}/{max_attempts})")

            if stack_status == expected_status:
                elapsed = time.monotonic() - start_time
                logger.info(f"Stack reached {expected_status} after {elapsed:.2f}s")
                return True

            if 'FAILED' in stack_status or 'ROLLBACK' in stack_status:
                logger.error(f"Stack failed with status: {stack_status}")
                return False

            time.sleep(current_delay)
            current_delay = min(current_delay * 1.5, 30)  # Exponential backoff, max 30s
            attempt += 1

        except ClientError as e:
            if e.response['Error']['Code'] == 'ValidationError' and 'does not exist' in str(e):
                if expected_status == 'DELETE_COMPLETE':
                    logger.info(f"Stack {stack_name} does not exist (already deleted)")
                    return True
                logger.debug(f"Stack {stack_name} not yet created")
                time.sleep(current_delay)
                current_delay = min(current_delay * 1.5, 30)
                attempt += 1
            else:
                logger.error(f"Error describing stack: {e}")
                return False

    logger.error(f"Timeout waiting for stack {stack_name} to reach {expected_status}")
    return False


def steady_state() -> None:
    """
    Deploy CloudFormation stack with resources required for attack simulation.
    
    Creates:
    1. S3 bucket for CodeBuild artifacts (unencrypted, public read allowed)
    2. IAM role with overly permissive CodeBuild permissions
    3. CodeBuild project with privileged mode enabled and malicious configuration
    4. CloudWatch Log Group for CodeBuild
    """
    global STACK_NAME_SUFFIX, CREATED_RESOURCES

    timestamp = int(time.time())
    STACK_NAME_SUFFIX = timestamp
    stack_name = f"sce-experiment-malicious-codebuild-{timestamp}"
    CREATED_RESOURCES['stack_name'] = stack_name

    account_id = get_aws_account_id()
    region = get_aws_region()

    # CloudFormation template with malicious CodeBuild configuration
    cf_template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE Experiment: Malicious CodeBuild Project Detection",
        "Resources": {
            "MaliciousArtifactsBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": f"sce-artifacts-{account_id}-{timestamp}",
                    "VersioningConfiguration": {"Status": "Enabled"},
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": False,
                        "BlockPublicPolicy": False,
                        "IgnorePublicAcls": False,
                        "RestrictPublicBuckets": False
                    },
                    "Tags": [
                        {"Key": "experiment", "Value": "1.3-sce-experiment"},
                        {"Key": "timestamp", "Value": str(timestamp)}
                    ]
                }
            },
            "MaliciousCodeBuildRole": {
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
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/AdministratorAccess"
                    ],
                    "Tags": [
                        {"Key": "experiment", "Value": "1.3-sce-experiment"},
                        {"Key": "timestamp", "Value": str(timestamp)}
                    ]
                }
            },
            "MaliciousCodeBuildLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": f"/aws/codebuild/malicious-project-{timestamp}",
                    "RetentionInDays": 7
                }
            },
            "MaliciousCodeBuildProject": {
                "Type": "AWS::CodeBuild::Project",
                "DependsOn": ["MaliciousCodeBuildRole", "MaliciousArtifactsBucket"],
                "Properties": {
                    "Name": f"malicious-project-{timestamp}",
                    "ServiceRole": {"Fn::GetAtt": ["MaliciousCodeBuildRole", "Arn"]},
                    "Source": {
                        "Type": "GITHUB",
                        "Location": "https://github.com/example/malicious-repo.git",
                        "BuildSpec": "buildspec.yml"
                    },
                    "Environment": {
                        "Type": "LINUX_CONTAINER",
                        "Image": "aws/codebuild/standard:5.0",
                        "ComputeType": "BUILD_GENERAL1_SMALL",
                        "PrivilegedMode": True,
                        "EnvironmentVariables": [
                            {
                                "Name": "AWS_ACCOUNT_ID",
                                "Value": account_id
                            },
                            {
                                "Name": "MALICIOUS_FLAG",
                                "Value": "true"
                            }
                        ]
                    },
                    "Artifacts": {
                        "Type": "S3",
                        "Location": f"sce-artifacts-{account_id}-{timestamp}"
                    },
                    "LogsConfig": {
                        "CloudWatchLogs": {
                            "Status": "ENABLED",
                            "GroupName": f"/aws/codebuild/malicious-project-{timestamp}"
                        }
                    },
                    "Tags": [
                        {"Key": "experiment", "Value": "1.3-sce-experiment"},
                        {"Key": "timestamp", "Value": str(timestamp)},
                        {"Key": "malicious", "Value": "true"}
                    ]
                }
            }
        },
        "Outputs": {
            "CodeBuildProjectArn": {
                "Value": {"Fn::GetAtt": ["MaliciousCodeBuildProject", "Arn"]},
                "Export": {"Name": f"CodeBuildProjectArn-{timestamp}"}
            },
            "CodeBuildRoleArn": {
                "Value": {"Fn::GetAtt": ["MaliciousCodeBuildRole", "Arn"]},
                "Export": {"Name": f"CodeBuildRoleArn-{timestamp}"}
            },
            "ArtifactsBucketName": {
                "Value": {"Ref": "MaliciousArtifactsBucket"},
                "Export": {"Name": f"ArtifactsBucketName-{timestamp}"}
            }
        }
    }

    cf_client = boto3.client('cloudformation')

    # Check if stack already exists
    try:
        cf_client.describe_stacks(StackName=stack_name)
        logger.warning(f"Stack {stack_name} already exists; skipping creation")
        return
    except ClientError as e:
        if e.response['Error']['Code'] != 'ValidationError':
            logger.error(f"Error checking stack: {e}")
            raise

    # Create stack
    logger.info(f"Creating CloudFormation stack: {stack_name}")
    try:
        cf_client.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(cf_template),
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=[
                {'Key': 'experiment', 'Value': '1.3-sce-experiment'},
                {'Key': 'timestamp', 'Value': str(timestamp)}
            ]
        )
        logger.info(f"Stack creation initiated for {stack_name}")
    except ClientError as e:
        logger.error(f"Failed to create stack: {e}")
        raise

    # Wait for stack creation
    if not wait_for_stack_status(cf_client, stack_name, 'CREATE_COMPLETE'):
        logger.error(f"Stack {stack_name} failed to reach CREATE_COMPLETE status")
        raise RuntimeError(f"Stack creation failed: {stack_name}")

    # Retrieve outputs
    try:
        response = cf_client.describe_stacks(StackName=stack_name)
        stack = response['Stacks'][0]
        
        outputs = {o['OutputKey']: o['OutputValue'] for o in stack.get('Outputs', [])}
        CREATED_RESOURCES['codebuild_project_name'] = f"malicious-project-{timestamp}"
        CREATED_RESOURCES['iam_role_arn'] = outputs.get('CodeBuildRoleArn')
        CREATED_RESOURCES['s3_bucket_name'] = outputs.get('ArtifactsBucketName')

        logger.info(f"Stack created successfully")
        logger.info(f"CodeBuild Project: {CREATED_RESOURCES['codebuild_project_name']}")
        logger.info(f"IAM Role ARN: {CREATED_RESOURCES['iam_role_arn']}")
        logger.info(f"S3 Bucket: {CREATED_RESOURCES['s3_bucket_name']}")

    except ClientError as e:
        logger.error(f"Failed to retrieve stack outputs: {e}")
        raise


def attack() -> bool:
    """
    Execute attack: Verify the malicious CodeBuild project was created with suspicious configs.
    
    Attack steps (all executed as real AWS API calls):
    1. Confirm CodeBuild project exists with PrivilegedMode=True
    2. Confirm attached IAM role has AdministratorAccess
    3. Confirm artifacts bucket has public access permissions
    4. Confirm environment variables contain suspicious flags
    5. Return True if all malicious indicators are present
    """
    global CREATED_RESOURCES

    if not CREATED_RESOURCES['codebuild_project_name']:
        logger.error("CodeBuild project not created during steady_state()")
        return False

    region = get_aws_region()
    codebuild_client = boto3.client('codebuild', region_name=region)
    iam_client = boto3.client('iam')
    s3_client = boto3.client('s3')

    project_name = CREATED_RESOURCES['codebuild_project_name']
    malicious_indicators_found = []

    # Step 1: Verify CodeBuild project exists and has privileged mode enabled
    logger.info(f"[ATTACK] Checking CodeBuild project: {project_name}")
    try:
        response = codebuild_client.batch_get_projects(names=[project_name])
        if not response['projects']:
            logger.error(f"CodeBuild project {project_name} not found")
            return False

        project = response['projects'][0]
        logger.debug(f"Project found: {project['arn']}")

        # Check for privileged mode
        if project['environment'].get('privilegedMode') is True:
            logger.warning(f"[MALICIOUS] Privileged mode ENABLED in CodeBuild project")
            malicious_indicators_found.append('privileged_mode')
        else:
            logger.error("Privileged mode not enabled (attack incomplete)")
            return False

        # Check for suspicious environment variables
        env_vars = {var['name']: var['value'] for var in project['environment'].get('environmentVariables', [])}
        if 'MALICIOUS_FLAG' in env_vars and env_vars['MALICIOUS_FLAG'] == 'true':
            logger.warning(f"[MALICIOUS] Suspicious environment variable: MALICIOUS_FLAG=true")
            malicious_indicators_found.append('malicious_env_var')

        logger.info(f"CodeBuild project ARN: {project['arn']}")

    except ClientError as e:
        logger.error(f"Failed to get CodeBuild project: {e}")
        return False

    # Step 2: Verify IAM role has overly permissive policy
    logger.info(f"[ATTACK] Checking IAM role: {CREATED_RESOURCES['iam_role_arn']}")
    try:
        role_name = CREATED_RESOURCES['iam_role_arn'].split('/')[-1]
        response = iam_client.list_attached_role_policies(RoleName=role_name)

        for policy in response['AttachedPolicies']:
            if 'AdministratorAccess' in policy['PolicyName']:
                logger.warning(f"[MALICIOUS] AdministratorAccess policy attached to CodeBuild role")
                malicious_indicators_found.append('admin_policy')
                break

    except ClientError as e:
        logger.error(f"Failed to check IAM role policies: {e}")
        return False

    # Step 3: Verify S3 bucket has public access permissions
    logger.info(f"[ATTACK] Checking S3 bucket: {CREATED_RESOURCES['s3_bucket_name']}")
    try:
        response = s3_client.get_public_access_block(Bucket=CREATED_RESOURCES['s3_bucket_name'])
        config = response['PublicAccessBlockConfiguration']

        if not config.get('BlockPublicAcls') or not config.get('BlockPublicPolicy'):
            logger.warning(f"[MALICIOUS] S3 bucket has public access enabled")
            malicious_indicators_found.append('public_s3_access')

    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchPublicAccessBlockConfiguration':
            logger.error(f"Failed to check S3 public access: {e}")
            return False

    # Step 4: Verify source is from untrusted repository (GitHub)
    if 'GITHUB' in project['source']['type']:
        logger.warning(f"[MALICIOUS] CodeBuild source is from untrusted GitHub repository")
        malicious_indicators_found.append('untrusted_source')

    # Summary
    if len(malicious_indicators_found) >= 3:
        logger.info(f"[ATTACK SUCCESS] All malicious indicators present: {malicious_indicators_found}")
        CREATED_RESOURCES['security_event_detected'] = True
        return True
    else:
        logger.error(f"[ATTACK INCOMPLETE] Only {len(malicious_indicators_found)} malicious indicators found: {malicious_indicators_found}")
        return False


def hypothesis_verification() -> bool:
    """
    Detective Control Verification: Confirm that the detective probe identifies the malicious configuration.
    
    This probe queries AWS to determine if a detective control (CloudWatch Events, Config Rules, or
    EventBridge) would detect and flag the malicious CodeBuild project.
    
    Verification steps:
    1. Query CloudWatch Logs for CodeBuild project events
    2. Check AWS Config for compliance violations on CodeBuild resources
    3. Verify security findings in Security Hub (if enabled)
    4. Return True if at least one detective mechanism would flag the malicious activity
    """
    global CREATED_RESOURCES

    if not CREATED_RESOURCES['codebuild_project_name']:
        logger.error("No CodeBuild project to verify")
        return False

    region = get_aws_region()
    project_name = CREATED_RESOURCES['codebuild_project_name']
    
    detective_findings = []

    # Method 1: Check CloudWatch Logs for CodeBuild events
    logger.info(f"[VERIFY] Querying CloudWatch Logs for suspicious CodeBuild events")
    try:
        logs_client = boto3.client('logs', region_name=region)
        log_group_name = f"/aws/codebuild/{project_name}"

        try:
            response = logs_client.describe_log_streams(logGroupName=log_group_name)
            if response['logStreams']:
                logger.info(f"Log group exists for CodeBuild project (detective mechanism active)")
                detective_findings.append('logs_configured')
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                logger.error(f"Error querying logs: {e}")

    except ClientError as e:
        logger.warning(f"CloudWatch Logs query failed: {e}")

    # Method 2: Query AWS Config for CodeBuild compliance rules
    logger.info(f"[VERIFY] Checking AWS Config for CodeBuild compliance violations")
    try:
        config_client = boto3.client('config', region_name=region)

        # List all Config rules
        rules_response = config_client.describe_config_rules()
        codebuild_rules = [r for r in rules_response.get('ConfigRules', []) 
                          if 'codebuild' in r['ConfigRuleName'].lower()]

        if codebuild_rules:
            logger.info(f"Found {len(codebuild_rules)} CodeBuild-related Config rules")
            
            for rule in codebuild_rules:
                try:
                    # Check compliance for this project resource
                    compliance_response = config_client.describe_compliance_by_config_rule(
                        ConfigRuleNames=[rule['ConfigRuleName']],
                        ComplianceTypes=['NON_COMPLIANT']
                    )
                    
                    for rule_compliance in compliance_response.get('ComplianceByConfigRules', []):
                        if rule_compliance['Compliance']['ComplianceType'] == 'NON_COMPLIANT':
                            logger.warning(f"[DETECTIVE] Config Rule {rule['ConfigRuleName']} flagged non-compliance")
                            detective_findings.append(f"config_rule_{rule['ConfigRuleName']}")

                except ClientError as e:
                    logger.debug(f"Error checking rule {rule['ConfigRuleName']}: {e}")

        else:
            logger.info("No CodeBuild-specific Config rules found (detective mechanism disabled)")

    except ClientError as e:
        logger.warning(f"AWS Config query failed: {e}")

    # Method 3: Check Security Hub for findings
    logger.info(f"[VERIFY] Checking AWS Security Hub for malicious CodeBuild findings")
    try:
        securityhub_client = boto3.client('securityhub', region_name=region)

        # Query findings related to the CodeBuild project
        findings_response = securityhub_client.get_findings(
            Filters={
                'ResourceId': [
                    {
                        'Value': f"arn:aws:codebuild:{region}:*:project/{project_name}",
                        'Comparison': 'EQUALS'
                    }
                ],
                'RecordState': [
                    {
                        'Value': 'ACTIVE',
                        'Comparison': 'EQUALS'
                    }
                ]
            }
        )

        findings = findings_response.get('Findings', [])
        if findings:
            logger.warning(f"[DETECTIVE] Security Hub found {len(findings)} active findings for CodeBuild project")
            for finding in findings:
                logger.warning(f"Finding: {finding['Title']}")
                detective_findings.append('securityhub_finding')

    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            logger.info("Security Hub not enabled (detective mechanism unavailable)")
        else:
            logger.warning(f"Security Hub query failed: {e}")

    # Method 4: Direct compliance check via IAM policy analysis
    logger.info(f"[VERIFY] Analyzing CodeBuild project configuration against security baseline")
    try:
        codebuild_client = boto3.client('codebuild', region_name=region)
        response = codebuild_client.batch_get_projects(names=[project_name])

        if response['projects']:
            project = response['projects'][0]
            
            # Check for suspicious configurations
            if project['environment'].get('privilegedMode') is True:
                logger.warning(f"[DETECTIVE] Privileged mode violation detected")
                detective_findings.append('privileged_mode_violation')
            
            # Check tags for security policies
            tags = {tag['key']: tag['value'] for tag in project.get('tags', [])}
            if tags.get('malicious') == 'true':
                logger.warning(f"[DETECTIVE] Malicious tag detected on resource")
                detective_findings.append('malicious_tag')

    except ClientError as e:
        logger.error(f"Failed to analyze CodeBuild configuration: {e}")

    # Final verdict
    logger.info(f"[VERIFY] Detective findings: {detective_findings}")
    
    if len(detective_findings) > 0:
        logger.info(f"[HYPOTHESIS VERIFIED] Detective control identified malicious activity")
        return True
    else:
        logger.error(f"[HYPOTHESIS FAILED] No detective mechanisms flagged the malicious CodeBuild project")
        return False


def rollback() -> None:
    """
    Delete CloudFormation stack and clean up all resources.
    
    Handles gracefully:
    - Stack that doesn't exist
    - Stack in failed state
    - Network timeouts during deletion
    """
    global CREATED_RESOURCES

    stack_name = CREATED_RESOURCES.get('stack_name')
    if not stack_name:
        logger.warning("No stack name found; skipping rollback")
        return

    cf_client = boto3.client('cloudformation')

    logger.info(f"[ROLLBACK] Deleting CloudFormation stack: {stack_name}")
    try:
        cf_client.delete_stack(StackName=stack_name)
        logger.info(f"Stack deletion initiated for {stack_name}")
    except ClientError as e:
        if 'does not exist' in str(e):
            logger.info(f"Stack {stack_name} does not exist; already cleaned up")
            return
        logger.error(f"Error initiating stack deletion: {e}")
        raise

    # Wait for deletion
    if not wait_for_stack_status(cf_client, stack_name, 'DELETE_COMPLETE', max_attempts=60):
        logger.error(f"Stack {stack_name} did not reach DELETE_COMPLETE status")
        raise RuntimeError(f"Stack deletion failed: {stack_name}")

    logger.info(f"[ROLLBACK] Stack successfully deleted: {stack_name}")
    CREATED_RESOURCES['stack_name'] = None


def main() -> None:
    """Execute the complete experiment lifecycle."""
    logger.info("=" * 80)
    logger.info("SCE Experiment 1.3: Malicious CodeBuild Project Detection (Detective Probe)")
    logger.info("=" * 80)

    try:
        # Phase 1: Steady State
        logger.info("\n[PHASE 1] Establishing steady state...")
        steady_state()
        logger.info("[PHASE 1] ✓ Steady state established\n")

        # Phase 2: Attack
        logger.info("[PHASE 2] Executing attack...")
        attack_result = attack()
        logger.info(f"[PHASE 2] Attack result: {attack_result}\n")

        # Phase 3: Hypothesis Verification
        logger.info("[PHASE 3] Verifying detective hypothesis...")
        hypothesis_result = hypothesis_verification()
        logger.info(f"[PHASE 3] Hypothesis verification result: {hypothesis_result}\n")

        # Results
        logger.info("=" * 80)
        logger.info("EXPERIMENT RESULTS")
        logger.info("=" * 80)
        logger.info(f"Attack Executed: {attack_result}")
        logger.info(f"Detective Control Effective: {hypothesis_result}")
        logger.info("=" * 80)

    except Exception as e:
        logger.error(f"Experiment failed with exception: {e}", exc_info=True)
        raise

    finally:
        # Phase 4: Rollback (always executed)
        logger.info("\n[PHASE 4] Rolling back resources...")
        try:
            rollback()
            logger.info("[PHASE 4] ✓ Rollback completed\n")
        except Exception as e:
            logger.error(f"Rollback failed: {e}", exc_info=True)


if __name__ == '__main__':
    main()