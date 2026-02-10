"""
SCE Experiment 2.5 - Detective Probe (v3 - Simplified)
Attack Nodes: 1.3 - Identify Target EC2 Instance (T1580)
              2.4 - Weaken IMDS Protections (T1562.001)

This experiment validates that CloudTrail successfully logs IMDS configuration
modifications on EC2 instances.

Hypothesis: When an attacker modifies IMDS settings (HttpTokens, HttpPutResponseHopLimit),
CloudTrail will log the ModifyInstanceMetadataOptions API call.

FIXES FROM PREVIOUS EXECUTIONS:
- v1: S3 bucket deletion issues - removed complex Config setup
- v2: CloudFormation timeout (20+ min) - simplified to minimal resources
- v3: Use default VPC, CloudTrail-only detection, minimal infrastructure
"""

import json
import logging
import time
import random
import string

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state for experiment resources
EXPERIMENT_STATE = {
    'stack_name': None,
    'region': None,
    'instance_id': None,
    'timestamp': None,
    'attack_executed_time': None,
    'attack_results': [],
    'infrastructure_ready': False,
    'original_imds_config': None
}

# Constants
EXPERIMENT_TAG = 'sce-experiment-2-5-detective'
STACK_CREATION_TIMEOUT = 900  # 15 minutes
STACK_DELETION_TIMEOUT = 600  # 10 minutes
RETRY_DELAY = 10
CLOUDTRAIL_DETECTION_TIMEOUT = 300  # 5 minutes


def _get_boto3():
    """Import boto3, installing if necessary."""
    try:
        import boto3
        return boto3
    except ImportError:
        logger.info("Installing boto3...")
        import subprocess
        import sys
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'boto3', '-q'])
        import boto3
        return boto3


def _generate_random_suffix(length=6):
    """Generate a random alphanumeric suffix for unique resource names."""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _get_default_vpc_subnet(ec2_client):
    """Get the default VPC and a subnet in it."""
    try:
        # Get default VPC
        vpcs = ec2_client.describe_vpcs(
            Filters=[{'Name': 'is-default', 'Values': ['true']}]
        )
        if not vpcs['Vpcs']:
            logger.error("No default VPC found")
            return None, None
        
        vpc_id = vpcs['Vpcs'][0]['VpcId']
        logger.info(f"Found default VPC: {vpc_id}")
        
        # Get a subnet in the default VPC
        subnets = ec2_client.describe_subnets(
            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
        )
        if not subnets['Subnets']:
            logger.error("No subnets found in default VPC")
            return vpc_id, None
        
        subnet_id = subnets['Subnets'][0]['SubnetId']
        logger.info(f"Found subnet: {subnet_id}")
        
        return vpc_id, subnet_id
    except Exception as e:
        logger.error(f"Error getting default VPC/subnet: {e}")
        return None, None


def _get_cloudformation_template(subnet_id):
    """
    Generate minimal CloudFormation template for the experiment.
    
    Creates only:
    - A test EC2 instance with IMDSv2 enforced (compliant baseline)
    
    Uses existing default VPC subnet to minimize deployment time.
    Detection relies on existing CloudTrail in the account.
    """
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE Experiment 2.5 - Detective Probe - Minimal Infrastructure",
        "Parameters": {
            "SubnetId": {
                "Type": "String",
                "Description": "Subnet ID for the EC2 instance"
            },
            "ExperimentTimestamp": {
                "Type": "String",
                "Description": "Unique timestamp for this experiment run"
            }
        },
        "Resources": {
            "TestSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE Experiment - Isolated security group with no ingress",
                    "SecurityGroupIngress": [],
                    "Tags": [
                        {"Key": "Name", "Value": {"Fn::Sub": "sce-sg-${ExperimentTimestamp}"}},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            },
            "TestEC2Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "InstanceType": "t3.micro",
                    "ImageId": {"Fn::Sub": "{{resolve:ssm:/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2}}"},
                    "SubnetId": {"Ref": "SubnetId"},
                    "SecurityGroupIds": [{"Ref": "TestSecurityGroup"}],
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled"
                    },
                    "Tags": [
                        {"Key": "Name", "Value": {"Fn::Sub": "sce-target-${ExperimentTimestamp}"}},
                        {"Key": "Experiment", "Value": EXPERIMENT_TAG}
                    ]
                }
            }
        },
        "Outputs": {
            "TestInstanceId": {
                "Description": "ID of the test EC2 instance",
                "Value": {"Ref": "TestEC2Instance"}
            },
            "SecurityGroupId": {
                "Description": "ID of the security group",
                "Value": {"Ref": "TestSecurityGroup"}
            }
        }
    }


def _wait_for_stack(cf_client, stack_name, target_status, timeout):
    """Wait for CloudFormation stack to reach target status."""
    start_time = time.monotonic()
    last_status = None
    
    while time.monotonic() - start_time < timeout:
        try:
            response = cf_client.describe_stacks(StackName=stack_name)
            if response['Stacks']:
                current_status = response['Stacks'][0]['StackStatus']
                
                if current_status != last_status:
                    logger.info(f"Stack status: {current_status}")
                    last_status = current_status
                
                if current_status == target_status:
                    return True
                elif 'FAILED' in current_status or current_status == 'ROLLBACK_COMPLETE':
                    logger.error(f"Stack reached failed state: {current_status}")
                    try:
                        events = cf_client.describe_stack_events(StackName=stack_name)
                        for event in events['StackEvents'][:5]:
                            if 'FAILED' in event.get('ResourceStatus', ''):
                                logger.error(f"  {event.get('LogicalResourceId')}: {event.get('ResourceStatusReason', 'No reason')}")
                    except Exception:
                        pass
                    return False
                elif current_status == 'DELETE_COMPLETE':
                    return target_status == 'DELETE_COMPLETE'
        except cf_client.exceptions.ClientError as e:
            if 'does not exist' in str(e):
                return target_status == 'DELETE_COMPLETE'
            logger.warning(f"Error checking stack: {e}")
        
        time.sleep(RETRY_DELAY)
    
    logger.error(f"Timeout waiting for stack to reach {target_status}")
    return False


def _wait_for_instance_running(ec2_client, instance_id, timeout=300):
    """Wait for EC2 instance to be running."""
    start_time = time.monotonic()
    
    while time.monotonic() - start_time < timeout:
        try:
            response = ec2_client.describe_instances(InstanceIds=[instance_id])
            if response['Reservations'] and response['Reservations'][0]['Instances']:
                state = response['Reservations'][0]['Instances'][0]['State']['Name']
                if state == 'running':
                    logger.info(f"Instance {instance_id} is running")
                    return True
                elif state in ['terminated', 'shutting-down']:
                    logger.error(f"Instance {instance_id} is {state}")
                    return False
                logger.info(f"Instance state: {state}")
        except Exception as e:
            logger.warning(f"Error checking instance: {e}")
        time.sleep(10)
    
    logger.error("Timeout waiting for instance to run")
    return False


def steady_state():
    """
    Deploy minimal CloudFormation stack with test EC2 instance.
    Uses default VPC to minimize deployment time.
    """
    global EXPERIMENT_STATE
    
    logger.info("=" * 70)
    logger.info("SCE Experiment 2.5 - Detective Probe - Steady State Setup (v3)")
    logger.info("=" * 70)
    
    boto3 = _get_boto3()
    
    # Generate unique identifiers
    timestamp = str(int(time.time()))
    stack_name = f"sce-2-5-{timestamp}"
    
    EXPERIMENT_STATE['timestamp'] = timestamp
    EXPERIMENT_STATE['stack_name'] = stack_name
    
    # Get region
    session = boto3.Session()
    region = session.region_name or 'us-east-1'
    EXPERIMENT_STATE['region'] = region
    
    logger.info(f"Timestamp: {timestamp}")
    logger.info(f"Stack: {stack_name}")
    logger.info(f"Region: {region}")
    
    # Get default VPC subnet
    ec2_client = boto3.client('ec2', region_name=region)
    vpc_id, subnet_id = _get_default_vpc_subnet(ec2_client)
    
    if not subnet_id:
        raise RuntimeError("Could not find default VPC subnet")
    
    # Create CloudFormation client
    cf_client = boto3.client('cloudformation', region_name=region)
    
    # Check for existing stack
    try:
        response = cf_client.describe_stacks(StackName=stack_name)
        if response['Stacks']:
            status = response['Stacks'][0]['StackStatus']
            if status == 'CREATE_COMPLETE':
                logger.warning(f"Stack {stack_name} already exists")
            elif 'FAILED' in status or status == 'ROLLBACK_COMPLETE':
                logger.info("Deleting failed stack...")
                cf_client.delete_stack(StackName=stack_name)
                _wait_for_stack(cf_client, stack_name, 'DELETE_COMPLETE', 300)
    except cf_client.exceptions.ClientError as e:
        if 'does not exist' not in str(e):
            raise
    
    # Create stack
    template = _get_cloudformation_template(subnet_id)
    
    logger.info("Creating CloudFormation stack (should take 2-4 minutes)...")
    try:
        cf_client.create_stack(
            StackName=stack_name,
            TemplateBody=json.dumps(template),
            Parameters=[
                {'ParameterKey': 'SubnetId', 'ParameterValue': subnet_id},
                {'ParameterKey': 'ExperimentTimestamp', 'ParameterValue': timestamp}
            ],
            Tags=[
                {'Key': 'Experiment', 'Value': EXPERIMENT_TAG},
                {'Key': 'Timestamp', 'Value': timestamp}
            ],
            TimeoutInMinutes=10
        )
    except cf_client.exceptions.AlreadyExistsException:
        logger.warning("Stack already exists, continuing...")
    except Exception as e:
        logger.error(f"Failed to create stack: {e}")
        raise
    
    # Wait for stack
    if not _wait_for_stack(cf_client, stack_name, 'CREATE_COMPLETE', STACK_CREATION_TIMEOUT):
        EXPERIMENT_STATE['infrastructure_ready'] = False
        raise RuntimeError(f"Stack {stack_name} failed to create")
    
    # Get outputs
    response = cf_client.describe_stacks(StackName=stack_name)
    outputs = {o['OutputKey']: o['OutputValue'] for o in response['Stacks'][0].get('Outputs', [])}
    
    EXPERIMENT_STATE['instance_id'] = outputs.get('TestInstanceId')
    logger.info(f"Instance ID: {EXPERIMENT_STATE['instance_id']}")
    
    if not EXPERIMENT_STATE['instance_id']:
        raise RuntimeError("No instance ID in stack outputs")
    
    # Wait for instance
    if not _wait_for_instance_running(ec2_client, EXPERIMENT_STATE['instance_id']):
        raise RuntimeError("Instance failed to start")
    
    # Store original IMDS config
    response = ec2_client.describe_instances(InstanceIds=[EXPERIMENT_STATE['instance_id']])
    EXPERIMENT_STATE['original_imds_config'] = response['Reservations'][0]['Instances'][0].get('MetadataOptions', {})
    logger.info(f"Original IMDS: HttpTokens={EXPERIMENT_STATE['original_imds_config'].get('HttpTokens')}")
    
    EXPERIMENT_STATE['infrastructure_ready'] = True
    logger.info("=" * 70)
    logger.info("Steady state established!")
    logger.info("=" * 70)
    
    return True


def attack():
    """
    Execute Attack Steps 1.3 and 2.4:
    - Step 1.3: Identify Target EC2 Instance (T1580)
    - Step 2.4: Weaken IMDS Protections (T1562.001)
    """
    global EXPERIMENT_STATE
    
    logger.info("=" * 70)
    logger.info("SCE Experiment 2.5 - Executing Attack")
    logger.info("=" * 70)
    
    if not EXPERIMENT_STATE.get('infrastructure_ready'):
        logger.error("Infrastructure not ready")
        return False
    
    instance_id = EXPERIMENT_STATE.get('instance_id')
    if not instance_id:
        logger.error("No instance ID")
        return False
    
    boto3 = _get_boto3()
    ec2_client = boto3.client('ec2', region_name=EXPERIMENT_STATE['region'])
    
    attack_results = []
    
    # Step 1.3: Identify Target
    logger.info("-" * 50)
    logger.info("STEP 1.3: Identify Target EC2 Instance")
    logger.info("TTP: T1580 - Cloud Infrastructure Discovery")
    logger.info("-" * 50)
    
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        metadata = instance.get('MetadataOptions', {})
        
        logger.info(f"Target: {instance_id}")
        logger.info(f"Current HttpTokens: {metadata.get('HttpTokens')}")
        logger.info(f"Current HopLimit: {metadata.get('HttpPutResponseHopLimit')}")
        
        attack_results.append({
            'step': '1.3',
            'success': True,
            'instance_id': instance_id
        })
    except Exception as e:
        logger.error(f"Step 1.3 failed: {e}")
        attack_results.append({'step': '1.3', 'success': False, 'error': str(e)})
    
    # Step 2.4: Weaken IMDS
    logger.info("-" * 50)
    logger.info("STEP 2.4: Weaken IMDS Protections")
    logger.info("TTP: T1562.001 - Impair Defenses")
    logger.info("-" * 50)
    
    try:
        logger.info(f"Modifying IMDS on {instance_id}...")
        logger.info("  --http-tokens optional")
        logger.info("  --http-put-response-hop-limit 2")
        
        EXPERIMENT_STATE['attack_executed_time'] = time.time()
        
        response = ec2_client.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens='optional',
            HttpEndpoint='enabled',
            HttpPutResponseHopLimit=2
        )
        
        new_config = response.get('InstanceMetadataOptions', {})
        logger.info(f"New HttpTokens: {new_config.get('HttpTokens')}")
        logger.info(f"New HopLimit: {new_config.get('HttpPutResponseHopLimit')}")
        
        attack_results.append({
            'step': '2.4',
            'success': True,
            'new_http_tokens': new_config.get('HttpTokens'),
            'new_hop_limit': new_config.get('HttpPutResponseHopLimit')
        })
        
        logger.info("IMDS weakened successfully!")
        
    except Exception as e:
        logger.error(f"Step 2.4 failed: {e}")
        attack_results.append({'step': '2.4', 'success': False, 'error': str(e)})
    
    EXPERIMENT_STATE['attack_results'] = attack_results
    
    # Check if critical attack succeeded
    step_2_4_success = any(r.get('step') == '2.4' and r.get('success') for r in attack_results)
    
    logger.info("=" * 70)
    logger.info(f"Attack Summary: Step 2.4 {'SUCCESS' if step_2_4_success else 'FAILED'}")
    logger.info("=" * 70)
    
    return step_2_4_success


def hypothesis_verification():
    """
    Verify that CloudTrail detected the IMDS modification.
    
    Hypothesis: CloudTrail logs ModifyInstanceMetadataOptions API calls.
    """
    global EXPERIMENT_STATE
    
    logger.info("=" * 70)
    logger.info("SCE Experiment 2.5 - Hypothesis Verification")
    logger.info("=" * 70)
    
    if not EXPERIMENT_STATE.get('infrastructure_ready'):
        logger.error("Infrastructure not ready")
        return False
    
    # Check attack was executed
    attack_2_4 = next(
        (r for r in EXPERIMENT_STATE.get('attack_results', []) if r.get('step') == '2.4'),
        None
    )
    
    if not attack_2_4 or not attack_2_4.get('success'):
        logger.error("Attack 2.4 was not executed successfully")
        return False
    
    boto3 = _get_boto3()
    cloudtrail = boto3.client('cloudtrail', region_name=EXPERIMENT_STATE['region'])
    
    instance_id = EXPERIMENT_STATE['instance_id']
    attack_time = EXPERIMENT_STATE.get('attack_executed_time', time.time() - 300)
    
    logger.info("-" * 50)
    logger.info("Verification: CloudTrail Event Detection")
    logger.info("-" * 50)
    logger.info(f"Looking for ModifyInstanceMetadataOptions on {instance_id}")
    
    start_time = time.monotonic()
    detected = False
    
    while time.monotonic() - start_time < CLOUDTRAIL_DETECTION_TIMEOUT:
        try:
            response = cloudtrail.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'ModifyInstanceMetadataOptions'
                    }
                ],
                StartTime=attack_time - 120,
                EndTime=time.time() + 60,
                MaxResults=50
            )
            
            for event in response.get('Events', []):
                try:
                    event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                    request_params = event_data.get('requestParameters', {})
                    event_instance = request_params.get('instanceId', '')
                    
                    if event_instance == instance_id:
                        detected = True
                        logger.info("✓ CloudTrail event DETECTED!")
                        logger.info(f"  Event Time: {event.get('EventTime')}")
                        logger.info(f"  Event ID: {event.get('EventId')}")
                        logger.info(f"  User: {event.get('Username')}")
                        logger.info(f"  Source IP: {event_data.get('sourceIPAddress')}")
                        
                        # Log the modification details
                        if request_params.get('httpTokens'):
                            logger.info(f"  httpTokens: {request_params.get('httpTokens')}")
                        if request_params.get('httpPutResponseHopLimit'):
                            logger.info(f"  hopLimit: {request_params.get('httpPutResponseHopLimit')}")
                        break
                except json.JSONDecodeError:
                    continue
            
            if detected:
                break
            
            elapsed = int(time.monotonic() - start_time)
            logger.info(f"Waiting for CloudTrail event... ({elapsed}s elapsed)")
            
        except Exception as e:
            logger.warning(f"CloudTrail query error: {e}")
        
        time.sleep(15)
    
    # Summary
    logger.info("=" * 70)
    logger.info("VERIFICATION SUMMARY")
    logger.info("=" * 70)
    logger.info(f"CloudTrail Detection: {'✓ PASSED' if detected else '✗ FAILED'}")
    
    if detected:
        logger.info("")
        logger.info("✓ HYPOTHESIS VERIFIED")
        logger.info("  CloudTrail successfully logged the IMDS modification attack.")
        logger.info("  Detective control is functioning correctly.")
    else:
        logger.info("")
        logger.info("✗ HYPOTHESIS FAILED")
        logger.info("  CloudTrail event not found within timeout.")
        logger.info("  Note: CloudTrail events may take up to 15 minutes to appear.")
    
    logger.info("=" * 70)
    
    return detected


def rollback():
    """Delete CloudFormation stack and clean up resources."""
    global EXPERIMENT_STATE
    
    logger.info("=" * 70)
    logger.info("SCE Experiment 2.5 - Rollback")
    logger.info("=" * 70)
    
    stack_name = EXPERIMENT_STATE.get('stack_name')
    if not stack_name:
        logger.warning("No stack name - nothing to rollback")
        return True
    
    boto3 = _get_boto3()
    region = EXPERIMENT_STATE.get('region', 'us-east-1')
    
    # Restore IMDS if possible
    if EXPERIMENT_STATE.get('instance_id') and EXPERIMENT_STATE.get('original_imds_config'):
        try:
            ec2 = boto3.client('ec2', region_name=region)
            original = EXPERIMENT_STATE['original_imds_config']
            logger.info("Restoring original IMDS configuration...")
            ec2.modify_instance_metadata_options(
                InstanceId=EXPERIMENT_STATE['instance_id'],
                HttpTokens=original.get('HttpTokens', 'required'),
                HttpEndpoint=original.get('HttpEndpoint', 'enabled'),
                HttpPutResponseHopLimit=original.get('HttpPutResponseHopLimit', 1)
            )
            logger.info("IMDS restored")
        except Exception as e:
            logger.warning(f"Could not restore IMDS: {e}")
    
    # Delete stack
    cf = boto3.client('cloudformation', region_name=region)
    
    logger.info(f"Deleting stack: {stack_name}")
    
    try:
        cf.describe_stacks(StackName=stack_name)
    except cf.exceptions.ClientError as e:
        if 'does not exist' in str(e):
            logger.info("Stack already deleted")
            return True
        raise
    
    try:
        cf.delete_stack(StackName=stack_name)
        logger.info("Stack deletion initiated")
        
        if _wait_for_stack(cf, stack_name, 'DELETE_COMPLETE', STACK_DELETION_TIMEOUT):
            logger.info("Stack deleted successfully")
        else:
            logger.warning("Stack deletion may not have completed")
    except Exception as e:
        logger.error(f"Rollback error: {e}")
        return False
    
    logger.info("=" * 70)
    logger.info("Rollback completed")
    logger.info("=" * 70)
    
    return True


def run_experiment():
    """Main entry point for standalone execution."""
    logger.info("#" * 70)
    logger.info("# SCE EXPERIMENT 2.5 - DETECTIVE PROBE (v3)")
    logger.info("# Attack: IMDS Weakening (T1562.001)")
    logger.info("# Detection: CloudTrail API Logging")
    logger.info("#" * 70)
    
    result = False
    
    try:
        steady_state()
        
        if not attack():
            logger.error("Attack failed")
            return False
        
        logger.info("Waiting 30s for CloudTrail to process...")
        time.sleep(30)
        
        result = hypothesis_verification()
        return result
        
    except Exception as e:
        logger.error(f"Experiment failed: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        logger.info("Starting rollback...")
        try:
            rollback()
        except Exception as e:
            logger.error(f"Rollback failed: {e}")


if __name__ == '__main__':
    success = run_experiment()
    exit(0 if success else 1)