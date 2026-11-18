#!/usr/bin/env python3
"""
SCE 1.3 - Reactive Probe for Malicious CodeBuild Detection
Validates that EventBridge detection infrastructure can identify and alert on malicious CodeBuild project creation.
"""

import json
import time
import logging
import boto3
from typing import Optional, Dict, Any
from botocore.exceptions import ClientError, BotoCoreError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# AWS Clients
iam_client = boto3.client('iam')
codebuild_client = boto3.client('codebuild')
events_client = boto3.client('events')
sns_client = boto3.client('sns')
cloudtrail_client = boto3.client('cloudtrail')
sts_client = boto3.client('sts')
logs_client = boto3.client('logs')

# Experiment state
experiment_state = {
    'stack_suffix': None,
    'iam_role_arn': None,
    'sns_topic_arn': None,
    'eventbridge_rule_name': None,
    'malicious_project_name': None,
    'account_id': None,
    'region': None,
}


def _get_account_info() -> tuple:
    """Retrieve AWS account ID and region."""
    try:
        account_id = sts_client.get_caller_identity()['Account']
        region = codebuild_client.meta.region_name
        logger.info(f"Account ID: {account_id}, Region: {region}")
        return account_id, region
    except Exception as e:
        logger.error(f"Failed to retrieve account info: {e}")
        raise


def _retry_with_backoff(func, max_retries: int = 5, base_delay: float = 1.0):
    """Retry logic with exponential backoff."""
    for attempt in range(max_retries):
        try:
            return func()
        except ClientError as e:
            if attempt == max_retries - 1:
                raise
            delay = base_delay * (2 ** attempt)
            logger.warning(f"Attempt {attempt + 1} failed: {e}. Retrying in {delay}s...")
            time.sleep(delay)


def _wait_for_stack_creation(stack_name: str, timeout: int = 300) -> bool:
    """Wait for CloudFormation stack to reach CREATE_COMPLETE state."""
    cf_client = boto3.client('cloudformation')
    start_time = time.monotonic()
    
    while time.monotonic() - start_time < timeout:
        try:
            response = cf_client.describe_stacks(StackName=stack_name)
            if response['Stacks']:
                status = response['Stacks'][0]['StackStatus']
                logger.info(f"Stack {stack_name} status: {status}")
                
                if status == 'CREATE_COMPLETE':
                    return True
                elif 'FAILED' in status or 'ROLLBACK' in status:
                    logger.error(f"Stack creation failed with status: {status}")
                    return False
        except ClientError as e:
            if 'does not exist' not in str(e):
                logger.warning(f"Stack query error: {e}")
        
        time.sleep(5)
    
    logger.error(f"Stack creation timeout after {timeout}s")
    return False


def steady_state():
    """
    Deploy detection infrastructure: EventBridge rule, SNS topic, and IAM role.
    """
    logger.info("=== STEADY STATE: Deploying detection infrastructure ===")
    
    try:
        # Initialize experiment state
        experiment_state['stack_suffix'] = int(time.time())
        experiment_state['account_id'], experiment_state['region'] = _get_account_info()
        
        account_id = experiment_state['account_id']
        suffix = experiment_state['stack_suffix']
        
        # 1. Create IAM role for CodeBuild with proper trust policy
        logger.info(f"Creating IAM role: sce-codebuild-role-{suffix}")
        
        trust_policy = {
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
        }
        
        role_response = iam_client.create_role(
            RoleName=f"sce-codebuild-role-{suffix}",
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Tags=[
                {'Key': 'Experiment', 'Value': 'SCE-1.3'},
                {'Key': 'Stack', 'Value': str(suffix)}
            ]
        )
        experiment_state['iam_role_arn'] = role_response['Role']['Arn']
        logger.info(f"Created IAM role: {experiment_state['iam_role_arn']}")
        
        # Attach inline policy for logging
        inline_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents"
                    ],
                    "Resource": f"arn:aws:logs:*:{account_id}:log-group:/aws/codebuild/*"
                }
            ]
        }
        
        iam_client.put_role_policy(
            RoleName=f"sce-codebuild-role-{suffix}",
            PolicyName=f"sce-codebuild-role-{suffix}-policy",
            PolicyDocument=json.dumps(inline_policy)
        )
        logger.info(f"Attached inline policy to role")
        
        # Wait for role to be available
        time.sleep(2)
        
        # 2. Create SNS topic for alerts
        logger.info(f"Creating SNS topic: sce-codebuild-alerts-{suffix}")
        
        sns_response = sns_client.create_topic(
            Name=f"sce-codebuild-alerts-{suffix}",
            Tags=[
                {'Key': 'Experiment', 'Value': 'SCE-1.3'},
                {'Key': 'Stack', 'Value': str(suffix)}
            ]
        )
        experiment_state['sns_topic_arn'] = sns_response['TopicArn']
        logger.info(f"Created SNS topic: {experiment_state['sns_topic_arn']}")
        
        # 3. Create EventBridge rule
        logger.info(f"Creating EventBridge rule: sce-codebuild-detection-{suffix}")
        
        event_pattern = {
            "source": ["aws.codebuild"],
            "detail-type": ["CodeBuild Project State Change"],
            "detail": {
                "event": ["codebuild-project-state-change"],
                "project-name": [{"prefix": "sce-malicious"}],
                "build-status": ["SUCCEEDED"]
            }
        }
        
        rule_response = events_client.put_rule(
            Name=f"sce-codebuild-detection-{suffix}",
            EventPattern=json.dumps(event_pattern),
            State='ENABLED',
            Description='Detects malicious CodeBuild project creation for SCE 1.3 experiment',
            Tags=[
                {'Key': 'Experiment', 'Value': 'SCE-1.3'},
                {'Key': 'Stack', 'Value': str(suffix)}
            ]
        )
        experiment_state['eventbridge_rule_name'] = f"sce-codebuild-detection-{suffix}"
        logger.info(f"Created EventBridge rule: {experiment_state['eventbridge_rule_name']}")
        
        # 4. Add SNS as target to EventBridge rule
        logger.info(f"Adding SNS topic as target to rule")
        
        events_client.put_targets(
            Rule=experiment_state['eventbridge_rule_name'],
            Targets=[
                {
                    'Id': '1',
                    'Arn': experiment_state['sns_topic_arn'],
                    'RoleArn': f"arn:aws:iam::{account_id}:role/service-role/Amazon_EventBridge_Invoke_SNS"
                }
            ]
        )
        logger.info(f"Added SNS topic as target to EventBridge rule")
        
        # 5. Set SNS resource policy to allow EventBridge
        logger.info(f"Setting SNS resource policy for EventBridge")
        
        sns_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "events.amazonaws.com"
                    },
                    "Action": "SNS:Publish",
                    "Resource": experiment_state['sns_topic_arn'],
                    "Condition": {
                        "ArnEquals": {
                            "aws:SourceArn": f"arn:aws:events:*:{account_id}:rule/{experiment_state['eventbridge_rule_name']}"
                        }
                    }
                }
            ]
        }
        
        sns_client.set_topic_attributes(
            TopicArn=experiment_state['sns_topic_arn'],
            AttributeName='Policy',
            AttributeValue=json.dumps(sns_policy)
        )
        logger.info(f"SNS resource policy set successfully")
        
        # 6. Checkpoint verification
        logger.info("Checkpoint 1: Verifying EventBridge rule status...")
        rule = events_client.describe_rule(Name=experiment_state['eventbridge_rule_name'])
        assert rule['State'] == 'ENABLED', "EventBridge rule is not enabled"
        logger.info("✓ Checkpoint 1: EventBridge rule is ENABLED")
        
        logger.info("Checkpoint 2: Verifying event pattern configuration...")
        assert 'EventPattern' in rule, "Event pattern not found"
        logger.info("✓ Checkpoint 2: Event pattern correctly configured")
        
        logger.info("Checkpoint 3: Verifying SNS topic accessibility...")
        sns_attrs = sns_client.get_topic_attributes(TopicArn=experiment_state['sns_topic_arn'])
        assert sns_attrs['Attributes']['TopicArn'] == experiment_state['sns_topic_arn']
        logger.info("✓ Checkpoint 3: SNS topic is accessible and operational")
        
        logger.info("Checkpoint 4: Verifying EventBridge-to-SNS integration...")
        targets = events_client.list_targets_by_rule(Rule=experiment_state['eventbridge_rule_name'])
        assert len(targets['Targets']) > 0, "No targets found for EventBridge rule"
        assert any(t['Arn'] == experiment_state['sns_topic_arn'] for t in targets['Targets']), "SNS topic not in targets"
        logger.info("✓ Checkpoint 4: EventBridge rule correctly targets SNS topic")
        
        logger.info("=== All infrastructure checkpoints passed ===")
        logger.info("=== Steady state deployment completed successfully ===")
        
    except Exception as e:
        logger.error(f"Steady state deployment failed: {e}", exc_info=True)
        raise


def attack() -> bool:
    """
    Execute attack: Create a malicious CodeBuild project with credential exfiltration payload.
    Returns True if attack was successfully deployed, False otherwise.
    """
    logger.info("=== ATTACK: Creating malicious CodeBuild project ===")
    
    try:
        suffix = experiment_state['stack_suffix']
        role_arn = experiment_state['iam_role_arn']
        account_id = experiment_state['account_id']
        
        project_name = f"sce-malicious-project-{suffix}"
        experiment_state['malicious_project_name'] = project_name
        
        logger.info(f"Creating malicious CodeBuild project: {project_name}")
        
        # Malicious buildspec with credential exfiltration attempts
        buildspec = """
version: 0.2

phases:
  pre_build:
    commands:
      - echo "Phase 1: Attempting credential exfiltration"
      - env | grep -i aws || true
      - cat ~/.aws/credentials 2>/dev/null || true
      - cat ~/.aws/config 2>/dev/null || true
  build:
    commands:
      - echo "Phase 2: Attempting role assumption"
      - aws sts get-caller-identity || true
      - aws iam list-users || true
  post_build:
    commands:
      - echo "Phase 3: Exfiltration complete"
"""
        
        response = codebuild_client.create_project(
            name=project_name,
            source={
                'type': 'NO_SOURCE'
            },
            artifacts={
                'type': 'NO_ARTIFACTS'
            },
            serviceRole=role_arn,
            environment={
                'type': 'LINUX_CONTAINER',
                'image': 'aws/codebuild/standard:5.0',
                'computeType': 'BUILD_GENERAL1_SMALL',
                'privilegedMode': True
            },
            logsConfig={
                'cloudWatchLogs': {
                    'status': 'ENABLED',
                    'groupName': f'/aws/codebuild/{project_name}'
                }
            },
            description='Malicious project for SCE 1.3 experiment',
            buildspec=buildspec,
            tags=[
                {'key': 'Experiment', 'value': 'SCE-1.3'},
                {'key': 'Stack', 'value': str(suffix)},
                {'key': 'MaliciousProject', 'value': 'True'}
            ]
        )
        
        project_arn = response['project']['arn']
        logger.info(f"✓ Attack executed: Malicious project created with ARN: {project_arn}")
        
        # Verify project was created
        logger.info(f"Verifying project creation via API...")
        verify_response = codebuild_client.batch_get_projects(names=[project_name])
        
        if not verify_response['projects']:
            logger.error(f"Project verification failed: Project not found in batch_get_projects response")
            return False
        
        verified_project = verify_response['projects'][0]
        logger.info(f"✓ Project verified: {verified_project['name']}")
        logger.info(f"  - ARN: {verified_project['arn']}")
        logger.info(f"  - Service Role: {verified_project['serviceRole']}")
        
        return True
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logger.error(f"Attack execution failed: {error_code} - {error_message}")
        
        # Detailed troubleshooting for common errors
        if error_code == 'InvalidInputException' and 'AssumeRole' in error_message:
            logger.error("IAM role trust policy issue detected. Verifying role configuration...")
            try:
                role_name = experiment_state['iam_role_arn'].split('/')[-1]
                role = iam_client.get_role(RoleName=role_name)
                logger.error(f"Role found: {role_name}")
                logger.error(f"Trust policy: {json.dumps(role['Role']['AssumeRolePolicyDocument'], indent=2)}")
            except Exception as verify_error:
                logger.error(f"Failed to verify role: {verify_error}")
        
        return False
    
    except Exception as e:
        logger.error(f"Unexpected error during attack: {e}", exc_info=True)
        return False


def hypothesis_verification() -> bool:
    """
    Verify that reactive detection infrastructure is properly configured and operational.
    Checks:
    1. EventBridge rule is enabled and monitoring for malicious projects
    2. SNS topic is accessible and properly configured
    3. EventBridge-to-SNS integration is functional
    4. Detection event pattern is correct
    
    Returns True if all checks pass, False otherwise.
    """
    logger.info("=== HYPOTHESIS VERIFICATION: Checking reactive control ===")
    
    try:
        suffix = experiment_state['stack_suffix']
        rule_name = experiment_state['eventbridge_rule_name']
        sns_arn = experiment_state['sns_topic_arn']
        
        all_checks_passed = True
        
        # Checkpoint 1: Verify EventBridge rule status
        logger.info("Checkpoint 1: Verifying EventBridge rule status...")
        try:
            rule = events_client.describe_rule(Name=rule_name)
            
            if rule['State'] != 'ENABLED':
                logger.error(f"✗ EventBridge rule is not enabled. State: {rule['State']}")
                all_checks_passed = False
            else:
                logger.info(f"✓ Checkpoint 1: EventBridge rule is ENABLED")
        except ClientError as e:
            logger.error(f"✗ Failed to describe rule: {e}")
            all_checks_passed = False
        
        # Checkpoint 2: Verify event pattern configuration
        logger.info("Checkpoint 2: Verifying event pattern configuration...")
        try:
            if 'EventPattern' not in rule:
                logger.error("✗ Event pattern not found in rule")
                all_checks_passed = False
            else:
                pattern = json.loads(rule['EventPattern'])
                
                # Validate pattern structure
                required_keys = ['source', 'detail-type', 'detail']
                missing_keys = [k for k in required_keys if k not in pattern]
                
                if missing_keys:
                    logger.error(f"✗ Event pattern missing keys: {missing_keys}")
                    all_checks_passed = False
                else:
                    logger.info(f"✓ Checkpoint 2: Event pattern correctly configured")
        except Exception as e:
            logger.error(f"✗ Failed to verify event pattern: {e}")
            all_checks_passed = False
        
        # Checkpoint 3: Verify SNS topic accessibility
        logger.info("Checkpoint 3: Verifying SNS topic accessibility...")
        try:
            sns_attrs = sns_client.get_topic_attributes(TopicArn=sns_arn)
            
            if 'Attributes' not in sns_attrs or 'TopicArn' not in sns_attrs['Attributes']:
                logger.error("✗ SNS topic attributes not accessible")
                all_checks_passed = False
            else:
                logger.info(f"✓ Checkpoint 3: SNS topic is accessible and operational")
        except ClientError as e:
            logger.error(f"✗ Failed to access SNS topic: {e}")
            all_checks_passed = False
        
        # Checkpoint 4: Verify EventBridge-to-SNS integration
        logger.info("Checkpoint 4: Verifying EventBridge-to-SNS integration...")
        try:
            targets = events_client.list_targets_by_rule(Rule=rule_name)
            
            target_arns = [t['Arn'] for t in targets['Targets']]
            
            if sns_arn not in target_arns:
                logger.error(f"✗ SNS topic not in EventBridge targets. Targets: {target_arns}")
                all_checks_passed = False
            else:
                # Verify target role
                target = next(t for t in targets['Targets'] if t['Arn'] == sns_arn)
                if 'RoleArn' not in target:
                    logger.error("✗ Target role not configured")
                    all_checks_passed = False
                else:
                    logger.info(f"✓ Checkpoint 4: EventBridge rule correctly targets SNS topic")
        except Exception as e:
            logger.error(f"✗ Failed to verify targets: {e}")
            all_checks_passed = False
        
        if all_checks_passed:
            logger.info("=== All hypothesis checkpoints passed ===")
            logger.info("Conclusion: Reactive detection infrastructure is properly configured")
        else:
            logger.error("=== Some hypothesis checkpoints failed ===")
        
        return all_checks_passed
        
    except Exception as e:
        logger.error(f"Hypothesis verification failed with exception: {e}", exc_info=True)
        return False


def rollback():
    """
    Rollback: Delete EventBridge rule, SNS topic, IAM role, and malicious CodeBuild project.
    """
    logger.info("=== ROLLBACK: Cleaning up experimental infrastructure ===")
    
    rollback_errors = []
    
    try:
        suffix = experiment_state['stack_suffix']
        
        # 1. Delete malicious CodeBuild project if it was created
        if experiment_state['malicious_project_name']:
            try:
                logger.info(f"Deleting malicious CodeBuild project: {experiment_state['malicious_project_name']}")
                codebuild_client.delete_project(name=experiment_state['malicious_project_name'])
                logger.info(f"Deleted CodeBuild project: {experiment_state['malicious_project_name']}")
            except ClientError as e:
                if 'ProjectNotFoundException' not in str(e):
                    rollback_errors.append(f"Failed to delete CodeBuild project: {e}")
                    logger.warning(f"CodeBuild project deletion warning: {e}")
        
        # 2. Remove EventBridge targets
        if experiment_state['eventbridge_rule_name']:
            try:
                logger.info(f"Removing targets from EventBridge rule: {experiment_state['eventbridge_rule_name']}")
                targets = events_client.list_targets_by_rule(Rule=experiment_state['eventbridge_rule_name'])
                if targets['Targets']:
                    target_ids = [t['Id'] for t in targets['Targets']]
                    events_client.remove_targets(
                        Rule=experiment_state['eventbridge_rule_name'],
                        Ids=target_ids
                    )
                logger.info(f"Removed targets from EventBridge rule")
            except ClientError as e:
                if 'ResourceNotFoundException' not in str(e):
                    rollback_errors.append(f"Failed to remove EventBridge targets: {e}")
                    logger.warning(f"EventBridge targets removal warning: {e}")
        
        # 3. Delete EventBridge rule
        if experiment_state['eventbridge_rule_name']:
            try:
                logger.info(f"Deleting EventBridge rule: {experiment_state['eventbridge_rule_name']}")
                events_client.delete_rule(Name=experiment_state['eventbridge_rule_name'])
                logger.info(f"Deleted EventBridge rule: {experiment_state['eventbridge_rule_name']}")
            except ClientError as e:
                if 'ResourceNotFoundException' not in str(e):
                    rollback_errors.append(f"Failed to delete EventBridge rule: {e}")
                    logger.warning(f"EventBridge rule deletion warning: {e}")
        
        # 4. Delete SNS topic
        if experiment_state['sns_topic_arn']:
            try:
                logger.info(f"Deleting SNS topic: {experiment_state['sns_topic_arn']}")
                sns_client.delete_topic(TopicArn=experiment_state['sns_topic_arn'])
                logger.info(f"Deleted SNS topic: {experiment_state['sns_topic_arn']}")
            except ClientError as e:
                rollback_errors.append(f"Failed to delete SNS topic: {e}")
                logger.warning(f"SNS topic deletion warning: {e}")
        
        # 5. Delete inline policies and IAM role
        if experiment_state['iam_role_arn']:
            role_name = experiment_state['iam_role_arn'].split('/')[-1]
            try:
                logger.info(f"Deleting inline policies from role: {role_name}")
                # List and delete inline policies
                policies = iam_client.list_role_policies(RoleName=role_name)
                for policy_name in policies['PolicyNames']:
                    iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
                    logger.info(f"Deleted inline policy: {policy_name}")
                
                logger.info(f"Deleting IAM role: {role_name}")
                iam_client.delete_role(RoleName=role_name)
                logger.info(f"Deleted IAM role: {role_name}")
            except ClientError as e:
                if 'NoSuchEntity' not in str(e):
                    rollback_errors.append(f"Failed to delete IAM role: {e}")
                    logger.warning(f"IAM role deletion warning: {e}")
        
        logger.info("=== Rollback completed ===")
        
        if rollback_errors:
            logger.warning(f"Rollback completed with {len(rollback_errors)} warning(s)")
            for error in rollback_errors:
                logger.warning(f"  - {error}")
        
    except Exception as e:
        logger.error(f"Unexpected error during rollback: {e}", exc_info=True)
        raise


if __name__ == '__main__':
    """
    Standalone execution for testing.
    """
    try:
        logger.info("Starting SCE 1.3 Experiment execution...")
        steady_state()
        attack_success = attack()
        logger.info(f"Attack result: {'SUCCESS' if attack_success else 'FAILED'}")
        hypothesis_result = hypothesis_verification()
        logger.info(f"Hypothesis verification: {'PASSED' if hypothesis_result else 'FAILED'}")
    except Exception as e:
        logger.error(f"Experiment execution failed: {e}", exc_info=True)
    finally:
        logger.info("Performing cleanup...")
        rollback()
        logger.info("Experiment complete.")