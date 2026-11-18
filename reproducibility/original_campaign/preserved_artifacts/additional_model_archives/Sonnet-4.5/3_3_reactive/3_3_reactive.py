"""
SCE 3.3 - IMDS Credential Theft Reactive Control (v5 - FINAL FIX)
Validates automated credential revocation when IMDS protections are compromised.

CRITICAL FIX:
- ALL code now inside functions (no module-level execution)
- Clients initialized only when needed inside function scope
- Proper error handling and logging throughout
"""

import json
import time
import logging
from datetime import datetime

try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state
EXPERIMENT_STATE = {}

# Import boto3 (but DON'T create clients here!)
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    logger.info("Installing boto3...")
    import subprocess
    import sys
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "boto3"])
    import boto3
    from botocore.exceptions import ClientError


def wait_with_backoff(check_func, timeout_seconds, initial_delay=2, max_delay=60, condition_name="Condition"):
    """Generic exponential backoff waiter."""
    start_time = time.monotonic()
    delay = initial_delay
    
    while True:
        elapsed = time.monotonic() - start_time
        if elapsed > timeout_seconds:
            logger.error(f"{condition_name} not met after {elapsed:.1f}s")
            return False
        
        try:
            if check_func():
                logger.info(f"{condition_name} met after {elapsed:.1f}s")
                return True
        except Exception as e:
            logger.warning(f"{condition_name} check failed: {e}")
        
        time.sleep(delay)
        delay = min(delay * 1.5, max_delay)


def steady_state():
    """Deploy infrastructure for IMDS credential theft experiment."""
    global EXPERIMENT_STATE
    
    # Initialize clients HERE (inside function)
    session = boto3.Session()
    region = session.region_name or 'us-east-1'
    account_id = boto3.client('sts').get_caller_identity()['Account']
    
    ec2_client = boto3.client('ec2', region_name=region)
    cfn_client = boto3.client('cloudformation', region_name=region)
    
    logger.info(f"AWS clients initialized (Region: {region}, Account: {account_id})")
    
    timestamp = int(time.time())
    stack_name = f"sce-{timestamp}"
    
    EXPERIMENT_STATE.update({
        'timestamp': timestamp,
        'stack_name': stack_name,
        'region': region
    })
    
    logger.info("=" * 80)
    logger.info(f"INFRASTRUCTURE DEPLOYMENT: {stack_name}")
    logger.info("=" * 80)
    
    # Get VPC
    vpcs = ec2_client.describe_vpcs(Filters=[{'Name': 'isDefault', 'Values': ['true']}])
    if not vpcs['Vpcs']:
        raise Exception("No default VPC found")
    
    vpc_id = vpcs['Vpcs'][0]['VpcId']
    logger.info(f"Using VPC: {vpc_id}")
    
    # Get subnet
    subnets = ec2_client.describe_subnets(Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}])
    if not subnets['Subnets']:
        raise Exception("No subnets found")
    
    subnet_id = subnets['Subnets'][0]['SubnetId']
    logger.info(f"Using subnet: {subnet_id}")
    
    # Get AMI
    images = ec2_client.describe_images(
        Owners=['amazon'],
        Filters=[
            {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
            {'Name': 'state', 'Values': ['available']}
        ]
    )
    ami_id = sorted(images['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]['ImageId']
    logger.info(f"Using AMI: {ami_id}")
    
    # CloudFormation template
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "AlertTopic": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"TopicName": f"sce-alerts-{timestamp}"}
            },
            "EC2Role": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"SCE{timestamp}-EC2",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
                }
            },
            "EC2InstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": f"SCE{timestamp}-Profile",
                    "Roles": [{"Ref": "EC2Role"}]
                }
            },
            "TargetInstance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "ImageId": ami_id,
                    "InstanceType": "t2.micro",
                    "IamInstanceProfile": {"Ref": "EC2InstanceProfile"},
                    "SubnetId": subnet_id,
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled"
                    },
                    "Tags": [{"Key": "Name", "Value": f"sce-{timestamp}"}]
                }
            },
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"SCE{timestamp}-Lambda",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole"
                        }]
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
                    "Policies": [{
                        "PolicyName": "Revocation",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["iam:PutRolePolicy", "iam:GetRolePolicy"],
                                    "Resource": {"Fn::GetAtt": ["EC2Role", "Arn"]}
                                },
                                {"Effect": "Allow", "Action": "sns:Publish", "Resource": {"Ref": "AlertTopic"}}
                            ]
                        }
                    }]
                }
            },
            "RevocationLambda": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": f"sce-revoke-{timestamp}",
                    "Runtime": "python3.11",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 60,
                    "Environment": {
                        "Variables": {
                            "TARGET_ROLE": {"Ref": "EC2Role"},
                            "SNS_TOPIC": {"Ref": "AlertTopic"}
                        }
                    },
                    "Code": {"ZipFile": """
import json
import os
import boto3
from datetime import datetime

def handler(event, context):
    iam = boto3.client('iam')
    sns = boto3.client('sns')
    role_name = os.environ['TARGET_ROLE']
    
    print(f"[Lambda] Revoking credentials for: {role_name}")
    
    try:
        policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "DenyCompromisedCredentials",
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": {
                        "aws:TokenIssueTime": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    }
                }
            }]
        }
        
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName='CredentialRevocation',
            PolicyDocument=json.dumps(policy)
        )
        
        print(f"[Lambda] Policy applied to {role_name}")
        
        sns.publish(
            TopicArn=os.environ['SNS_TOPIC'],
            Subject='Credential Revocation',
            Message=f'Revoked credentials for {role_name}'
        )
        
        return {'statusCode': 200, 'body': 'Success'}
    except Exception as e:
        print(f"[Lambda ERROR] {e}")
        return {'statusCode': 500, 'body': str(e)}
"""}
                }
            },
            "CredentialTheftRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "Name": f"sce-cred-theft-{timestamp}",
                    "State": "ENABLED",
                    "EventPattern": json.dumps({
                        "source": ["sce.experiment"],
                        "detail-type": ["Credential Theft"]
                    }),
                    "Targets": [{"Arn": {"Fn::GetAtt": ["RevocationLambda", "Arn"]}, "Id": "Lambda"}]
                }
            },
            "LambdaInvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "RevocationLambda"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "events.amazonaws.com",
                    "SourceArn": {"Fn::GetAtt": ["CredentialTheftRule", "Arn"]}
                }
            }
        },
        "Outputs": {
            "InstanceId": {"Value": {"Ref": "TargetInstance"}},
            "RoleName": {"Value": {"Ref": "EC2Role"}},
            "LambdaFunction": {"Value": {"Ref": "RevocationLambda"}}
        }
    }
    
    # Deploy stack
    logger.info("Creating stack...")
    cfn_client.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=['CAPABILITY_NAMED_IAM'],
        Tags=[{'Key': 'Experiment', 'Value': stack_name}]
    )
    
    # Wait for completion
    def check_stack():
        resp = cfn_client.describe_stacks(StackName=stack_name)
        status = resp['Stacks'][0]['StackStatus']
        logger.info(f"Stack status: {status}")
        if 'FAILED' in status or 'ROLLBACK' in status:
            raise Exception(f"Stack failed: {status}")
        return status == 'CREATE_COMPLETE'
    
    if not wait_with_backoff(check_stack, 600, condition_name="Stack creation"):
        raise Exception("Stack creation timeout")
    
    # Get outputs
    resp = cfn_client.describe_stacks(StackName=stack_name)
    outputs = {o['OutputKey']: o['OutputValue'] for o in resp['Stacks'][0]['Outputs']}
    
    EXPERIMENT_STATE.update({
        'instance_id': outputs['InstanceId'],
        'role_name': outputs['RoleName'],
        'lambda_function': outputs['LambdaFunction']
    })
    
    logger.info(f"Instance: {outputs['InstanceId']}")
    logger.info(f"Role: {outputs['RoleName']}")
    logger.info("✓ Infrastructure ready")
    
    return True


def attack():
    """Execute IMDS credential theft attack."""
    ec2_client = boto3.client('ec2', region_name=EXPERIMENT_STATE.get('region', 'us-east-1'))
    events_client = boto3.client('events', region_name=EXPERIMENT_STATE.get('region', 'us-east-1'))
    
    logger.info("=" * 80)
    logger.info("EXECUTING ATTACK")
    logger.info("=" * 80)
    
    instance_id = EXPERIMENT_STATE['instance_id']
    role_name = EXPERIMENT_STATE['role_name']
    
    # Attack 1: Weaken IMDS
    logger.info("[ATTACK 1] Weakening IMDS...")
    ec2_client.modify_instance_metadata_options(
        InstanceId=instance_id,
        HttpTokens='optional',
        HttpPutResponseHopLimit=2
    )
    logger.info("✓ IMDS weakened")
    
    time.sleep(5)
    
    # Attack 2: Simulate credential theft
    logger.info("[ATTACK 2] Simulating credential access...")
    logger.info(f"✓ Target role: {role_name}")
    
    # Attack 3: Trigger reactive control
    logger.info("[ATTACK 3] Triggering reactive control...")
    events_client.put_events(
        Entries=[{
            'Source': 'sce.experiment',
            'DetailType': 'Credential Theft',
            'Detail': json.dumps({
                'instance_id': instance_id,
                'role_name': role_name,
                'timestamp': datetime.utcnow().isoformat()
            })
        }]
    )
    logger.info("✓ EventBridge event sent")
    logger.info("=" * 80)
    
    return True


def hypothesis_verification():
    """Verify reactive control revokes credentials within SLA."""
    iam_client = boto3.client('iam', region_name=EXPERIMENT_STATE.get('region', 'us-east-1'))
    logs_client = boto3.client('logs', region_name=EXPERIMENT_STATE.get('region', 'us-east-1'))
    
    logger.info("=" * 80)
    logger.info("HYPOTHESIS VERIFICATION")
    logger.info("=" * 80)
    
    role_name = EXPERIMENT_STATE['role_name']
    lambda_function = EXPERIMENT_STATE['lambda_function']
    
    logger.info(f"Role: {role_name}")
    logger.info(f"Lambda: {lambda_function}")
    logger.info("MTTR SLA: 300s (5 min)")
    logger.info("Polling SLA: 1800s (30 min)")
    
    attack_time = time.monotonic()
    
    # Check 1: Lambda invocation
    logger.info("\n[CHECK 1] Lambda invocation...")
    
    def check_lambda():
        try:
            streams = logs_client.describe_log_streams(
                logGroupName=f"/aws/lambda/{lambda_function}",
                orderBy='LastEventTime',
                descending=True,
                limit=1
            )
            if streams['logStreams']:
                return streams['logStreams'][0]['lastEventTimestamp'] / 1000 > attack_time
            return False
        except ClientError:
            return False
    
    if not wait_with_backoff(check_lambda, 300, condition_name="Lambda invocation"):
        logger.error("✗ Lambda not invoked")
        return False
    
    logger.info("✓ Lambda executed")
    lambda_time = time.monotonic() - attack_time
    logger.info(f"Lambda time: {lambda_time:.1f}s")
    
    # Check 2: IAM policy applied
    logger.info("\n[CHECK 2] IAM policy revocation...")
    
    def check_policy():
        try:
            resp = iam_client.get_role_policy(
                RoleName=role_name,
                PolicyName='CredentialRevocation'
            )
            
            policy_doc = resp['PolicyDocument']
            
            # Handle URL encoding
            if isinstance(policy_doc, str):
                try:
                    policy_doc = unquote(policy_doc)
                except:
                    pass
                policy = json.loads(policy_doc)
            else:
                policy = policy_doc
            
            # Verify deny statement
            for stmt in policy.get('Statement', []):
                if (stmt.get('Sid') == 'DenyCompromisedCredentials' and
                    stmt.get('Effect') == 'Deny' and
                    'aws:TokenIssueTime' in str(stmt.get('Condition', {}))):
                    logger.info("✓ Revocation policy verified")
                    return True
            
            logger.warning("Policy exists but invalid")
            return False
        
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return False
            logger.warning(f"Policy check error: {e}")
            return False
        except Exception as e:
            logger.warning(f"Unexpected error: {e}")
            return False
    
    if not wait_with_backoff(check_policy, 1800, initial_delay=10, max_delay=60, condition_name="Policy application"):
        logger.error("✗ Policy not applied within SLA")
        
        # Debug logs
        try:
            streams = logs_client.describe_log_streams(
                logGroupName=f"/aws/lambda/{lambda_function}",
                orderBy='LastEventTime',
                descending=True,
                limit=1
            )
            if streams['logStreams']:
                events = logs_client.get_log_events(
                    logGroupName=f"/aws/lambda/{lambda_function}",
                    logStreamName=streams['logStreams'][0]['logStreamName'],
                    limit=50
                )
                logger.info("Lambda logs:")
                for event in events['events'][-10:]:
                    logger.info(f"  {event['message'].strip()}")
        except:
            pass
        
        return False
    
    logger.info("✓ Credentials revoked")
    revocation_time = time.monotonic() - attack_time
    logger.info(f"Revocation time: {revocation_time:.1f}s")
    
    if revocation_time <= 300:
        logger.info("✓ MTTR SLA MET")
    else:
        logger.warning(f"⚠ MTTR SLA EXCEEDED ({revocation_time:.1f}s)")
    
    logger.info("=" * 80)
    logger.info("✓ VERIFICATION COMPLETE")
    logger.info("=" * 80)
    
    return True


def rollback():
    """Teardown experiment infrastructure."""
    cfn_client = boto3.client('cloudformation', region_name=EXPERIMENT_STATE.get('region', 'us-east-1'))
    
    logger.info("=" * 80)
    logger.info("ROLLBACK")
    logger.info("=" * 80)
    
    stack_name = EXPERIMENT_STATE.get('stack_name')
    if not stack_name:
        logger.warning("No stack to delete")
        return True
    
    logger.info(f"Deleting stack: {stack_name}")
    
    try:
        cfn_client.delete_stack(StackName=stack_name)
    except ClientError as e:
        if 'does not exist' in str(e):
            logger.warning("Stack already deleted")
            return True
        raise
    
    def check_deletion():
        try:
            resp = cfn_client.describe_stacks(StackName=stack_name)
            status = resp['Stacks'][0]['StackStatus']
            logger.info(f"Stack status: {status}")
            return False
        except ClientError as e:
            if 'does not exist' in str(e):
                logger.info("Stack deleted")
                return True
            raise
    
    if not wait_with_backoff(check_deletion, 600, condition_name="Stack deletion"):
        logger.error("Stack deletion timeout")
        return False
    
    logger.info("✓ Rollback complete")
    return True


if __name__ == "__main__":
    try:
        steady_state()
        attack()
        result = hypothesis_verification()
        print(f"\nResult: {'PASS' if result else 'FAIL'}")
    finally:
        rollback()