"""
Security Chaos Engineering Experiment 2.3 - Preventive Probe
Tests container network isolation preventing IMDS access from containerized workloads
"""

import json
import time
import sys
import subprocess
import os

# Install boto3 if not available
try:
    import boto3
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
    import boto3

# Global variables
STACK_NAME = None
INSTANCE_ID = None
REGION = os.environ.get('AWS_DEFAULT_REGION', 'us-east-1')

def _get_timestamp():
    """Generate unique timestamp suffix"""
    return int(time.time())

def _wait_with_backoff(check_func, max_wait_seconds=1800, check_interval=10):
    """
    Poll until check_func returns True or timeout expires
    Implements 30-minute SLA for AWS eventual consistency
    """
    start = time.monotonic()
    while (time.monotonic() - start) < max_wait_seconds:
        try:
            if check_func():
                return True
        except Exception as e:
            print(f"[WAIT] Check function error (retrying): {e}")
        time.sleep(check_interval)
    return False

def _create_cloudformation_template():
    """
    Create CloudFormation template for EC2 instance with container runtime
    and network isolation controls (iptables rules blocking IMDS from containers)
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 2.3 Preventive - Container Network Isolation Test",
        "Resources": {
            "VPC": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsHostnames": True,
                    "EnableDnsSupport": True,
                    "Tags": [
                        {"Key": "Name", "Value": "sce-2-3-vpc"},
                        {"Key": "Experiment", "Value": "sce-2-3-preventive"}
                    ]
                }
            },
            "InternetGateway": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {
                    "Tags": [
                        {"Key": "Name", "Value": "sce-2-3-igw"},
                        {"Key": "Experiment", "Value": "sce-2-3-preventive"}
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
            "PublicSubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "CidrBlock": "10.0.1.0/24",
                    "MapPublicIpOnLaunch": True,
                    "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    "Tags": [
                        {"Key": "Name", "Value": "sce-2-3-public-subnet"},
                        {"Key": "Experiment", "Value": "sce-2-3-preventive"}
                    ]
                }
            },
            "RouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {
                    "VpcId": {"Ref": "VPC"},
                    "Tags": [
                        {"Key": "Name", "Value": "sce-2-3-rt"},
                        {"Key": "Experiment", "Value": "sce-2-3-preventive"}
                    ]
                }
            },
            "PublicRoute": {
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
                    "SubnetId": {"Ref": "PublicSubnet"},
                    "RouteTableId": {"Ref": "RouteTable"}
                }
            },
            "SecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE 2.3 Security Group",
                    "VpcId": {"Ref": "VPC"},
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "-1",
                            "CidrIp": "0.0.0.0/0"
                        }
                    ],
                    "Tags": [
                        {"Key": "Name", "Value": "sce-2-3-sg"},
                        {"Key": "Experiment", "Value": "sce-2-3-preventive"}
                    ]
                }
            },
            "InstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
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
                        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "TestBankingAppPolicy",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject", "dynamodb:Query"],
                                        "Resource": "*"
                                    }
                                ]
                            }
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "sce-2-3-preventive"}
                    ]
                }
            },
            "InstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "Roles": [{"Ref": "InstanceRole"}]
                }
            },
            "EC2Instance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "InstanceType": "t3.micro",
                    "ImageId": {"Fn::Sub": "{{resolve:ssm:/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2}}"},
                    "IamInstanceProfile": {"Ref": "InstanceProfile"},
                    "SubnetId": {"Ref": "PublicSubnet"},
                    "SecurityGroupIds": [{"Ref": "SecurityGroup"}],
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpPutResponseHopLimit": 1,
                        "HttpEndpoint": "enabled"
                    },
                    "UserData": {
                        "Fn::Base64": {
                            "Fn::Sub": "#!/bin/bash\nset -e\nyum update -y\nyum install -y docker iptables\nservice docker start\nusermod -a -G docker ec2-user\n\n# PREVENTIVE CONTROL: Block container network namespace from accessing IMDS\n# Create iptables rule dropping packets to 169.254.169.254 from docker0 bridge\niptables -I FORWARD -s 172.17.0.0/16 -d 169.254.169.254 -j DROP\niptables -I OUTPUT -o docker0 -d 169.254.169.254 -j DROP\n\n# Persist iptables rules\niptables-save > /etc/sysconfig/iptables\n\n# Create test marker file\necho 'container-isolation-active' > /var/lib/cloud/container-isolation-status\n"
                        }
                    },
                    "Tags": [
                        {"Key": "Name", "Value": "sce-2-3-test-instance"},
                        {"Key": "Experiment", "Value": "sce-2-3-preventive"}
                    ]
                }
            }
        },
        "Outputs": {
            "InstanceId": {
                "Description": "EC2 Instance ID",
                "Value": {"Ref": "EC2Instance"}
            },
            "InstanceRoleName": {
                "Description": "IAM Role Name",
                "Value": {"Ref": "InstanceRole"}
            }
        }
    }
    return json.dumps(template)

def steady_state():
    """
    Provision test environment with hardened EC2 instance running Docker
    with iptables rules blocking IMDS access from container network namespace
    """
    global STACK_NAME, INSTANCE_ID
    
    print("[STEADY_STATE] Starting environment provisioning...")
    
    try:
        cfn_client = boto3.client('cloudformation', region_name=REGION)
        ec2_client = boto3.client('ec2', region_name=REGION)
        ssm_client = boto3.client('ssm', region_name=REGION)
        
        # Generate unique stack name
        timestamp = _get_timestamp()
        STACK_NAME = f"sce-experiment-2-3-{timestamp}"
        print(f"[STEADY_STATE] Stack name: {STACK_NAME}")
        
        # Check if stack already exists
        try:
            cfn_client.describe_stacks(StackName=STACK_NAME)
            print(f"[STEADY_STATE] WARNING: Stack {STACK_NAME} already exists, continuing...")
        except cfn_client.exceptions.ClientError:
            # Stack doesn't exist, create it
            template_body = _create_cloudformation_template()
            
            print("[STEADY_STATE] Creating CloudFormation stack...")
            cfn_client.create_stack(
                StackName=STACK_NAME,
                TemplateBody=template_body,
                Capabilities=['CAPABILITY_IAM'],
                Tags=[
                    {'Key': 'Experiment', 'Value': 'sce-2-3-preventive'},
                    {'Key': 'Timestamp', 'Value': str(timestamp)}
                ]
            )
            
            # Wait for stack creation with 30-minute SLA
            print("[STEADY_STATE] Waiting for stack creation (up to 30 minutes)...")
            def check_stack_complete():
                try:
                    response = cfn_client.describe_stacks(StackName=STACK_NAME)
                    status = response['Stacks'][0]['StackStatus']
                    print(f"[STEADY_STATE] Stack status: {status}")
                    if status == 'CREATE_COMPLETE':
                        return True
                    elif 'FAILED' in status or 'ROLLBACK' in status:
                        raise Exception(f"Stack creation failed with status: {status}")
                    return False
                except Exception as e:
                    print(f"[STEADY_STATE] Error checking stack: {e}")
                    return False
            
            if not _wait_with_backoff(check_stack_complete, max_wait_seconds=1800, check_interval=15):
                raise Exception("Stack creation timeout after 30 minutes")
        
        # Get instance ID from stack outputs
        response = cfn_client.describe_stacks(StackName=STACK_NAME)
        outputs = response['Stacks'][0].get('Outputs', [])
        for output in outputs:
            if output['OutputKey'] == 'InstanceId':
                INSTANCE_ID = output['OutputValue']
                break
        
        if not INSTANCE_ID:
            raise Exception("Failed to retrieve Instance ID from stack outputs")
        
        print(f"[STEADY_STATE] Instance ID: {INSTANCE_ID}")
        
        # Wait for instance to be running and SSM agent ready (30-minute SLA)
        print("[STEADY_STATE] Waiting for instance to be running and SSM ready...")
        def check_instance_ready():
            try:
                # Check instance state
                response = ec2_client.describe_instances(InstanceIds=[INSTANCE_ID])
                state = response['Reservations'][0]['Instances'][0]['State']['Name']
                print(f"[STEADY_STATE] Instance state: {state}")
                
                if state != 'running':
                    return False
                
                # Check SSM agent connectivity
                try:
                    response = ssm_client.describe_instance_information(
                        Filters=[{'Key': 'InstanceIds', 'Values': [INSTANCE_ID]}]
                    )
                    if response['InstanceInformationList']:
                        ping_status = response['InstanceInformationList'][0]['PingStatus']
                        print(f"[STEADY_STATE] SSM ping status: {ping_status}")
                        return ping_status == 'Online'
                except Exception as e:
                    print(f"[STEADY_STATE] SSM not ready yet: {e}")
                    return False
                
                return False
            except Exception as e:
                print(f"[STEADY_STATE] Error checking instance readiness: {e}")
                return False
        
        if not _wait_with_backoff(check_instance_ready, max_wait_seconds=1800, check_interval=20):
            raise Exception("Instance not ready after 30 minutes")
        
        # Wait for user data script completion (iptables rules setup)
        print("[STEADY_STATE] Waiting for user data completion (iptables setup)...")
        def check_userdata_complete():
            try:
                response = ssm_client.send_command(
                    InstanceIds=[INSTANCE_ID],
                    DocumentName='AWS-RunShellScript',
                    Parameters={'commands': ['test -f /var/lib/cloud/container-isolation-status && echo "ready" || echo "not-ready"']}
                )
                command_id = response['Command']['CommandId']
                time.sleep(5)  # Wait for command execution
                
                output_response = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=INSTANCE_ID
                )
                
                if output_response['Status'] == 'Success':
                    output = output_response.get('StandardOutputContent', '').strip()
                    print(f"[STEADY_STATE] User data status: {output}")
                    return 'ready' in output
                return False
            except Exception as e:
                print(f"[STEADY_STATE] User data check error (retrying): {e}")
                return False
        
        if not _wait_with_backoff(check_userdata_complete, max_wait_seconds=1800, check_interval=30):
            print("[STEADY_STATE] WARNING: Could not confirm user data completion, proceeding anyway...")
        
        print("[STEADY_STATE] Environment provisioning complete")
        print(f"[STEADY_STATE] Instance {INSTANCE_ID} ready with container isolation controls")
        
    except Exception as e:
        print(f"[STEADY_STATE] ERROR: {e}")
        raise

def attack():
    """
    Execute attack steps:
    1. Weaken IMDS protections (modify metadata options)
    2. Attempt to access IMDS from container (should be blocked by iptables)
    
    Returns True if attack execution completes (regardless of success/failure)
    """
    global INSTANCE_ID
    
    print("[ATTACK] Starting attack sequence...")
    
    try:
        ec2_client = boto3.client('ec2', region_name=REGION)
        ssm_client = boto3.client('ssm', region_name=REGION)
        
        if not INSTANCE_ID:
            raise Exception("Instance ID not available from steady_state")
        
        # ATTACK STEP 1: Weaken IMDS protections
        print("[ATTACK] Step 1: Modifying instance metadata options to weaken protections...")
        print(f"[ATTACK] Command: aws ec2 modify-instance-metadata-options --instance-id {INSTANCE_ID} --http-tokens optional --http-put-response-hop-limit 2")
        
        ec2_client.modify_instance_metadata_options(
            InstanceId=INSTANCE_ID,
            HttpTokens='optional',  # Allow IMDSv1
            HttpPutResponseHopLimit=2,  # Increase hop limit
            HttpEndpoint='enabled'
        )
        
        print("[ATTACK] Step 1 complete: IMDS protections weakened")
        time.sleep(10)  # Allow metadata service configuration to propagate
        
        # ATTACK STEP 2: Attempt to access IMDS from container
        print("[ATTACK] Step 2: Attempting to access IMDS from container context...")
        print("[ATTACK] Command: docker run --rm alpine:latest sh -c 'wget -q -O - http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>&1'")
        
        # Execute container with IMDS access attempt via SSM
        response = ssm_client.send_command(
            InstanceIds=[INSTANCE_ID],
            DocumentName='AWS-RunShellScript',
            Parameters={
                'commands': [
                    '#!/bin/bash',
                    'set -x',
                    '# Pull alpine image if not present',
                    'docker pull alpine:latest 2>&1',
                    '# Attempt IMDS access from container (should be blocked by iptables)',
                    'docker run --rm alpine:latest sh -c "timeout 10 wget -q -O - http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>&1 || echo BLOCKED"'
                ]
            },
            TimeoutSeconds=120
        )
        
        command_id = response['Command']['CommandId']
        print(f"[ATTACK] Step 2 SSM Command ID: {command_id}")
        
        # Wait for command completion (30-minute SLA)
        print("[ATTACK] Waiting for container IMDS access attempt (up to 30 minutes)...")
        def check_command_complete():
            try:
                output_response = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=INSTANCE_ID
                )
                status = output_response['Status']
                print(f"[ATTACK] Command status: {status}")
                
                if status in ['Success', 'Failed', 'TimedOut']:
                    stdout = output_response.get('StandardOutputContent', '')
                    stderr = output_response.get('StandardErrorContent', '')
                    print(f"[ATTACK] Command output:\n{stdout}")
                    if stderr:
                        print(f"[ATTACK] Command errors:\n{stderr}")
                    return True
                return False
            except Exception as e:
                print(f"[ATTACK] Error checking command: {e}")
                return False
        
        if not _wait_with_backoff(check_command_complete, max_wait_seconds=1800, check_interval=10):
            print("[ATTACK] WARNING: Command did not complete within timeout")
        
        print("[ATTACK] Attack sequence complete")
        return True
        
    except Exception as e:
        print(f"[ATTACK] ERROR: {e}")
        return False

def hypothesis_verification():
    """
    PREVENTIVE PROBE VERIFICATION:
    Verify that container network isolation (iptables rules) successfully blocked
    IMDS access from container despite weakened metadata service configuration.
    
    Expected behavior:
    - Container attempt to access 169.254.169.254 should be blocked by iptables DROP rule
    - Container should receive connection timeout or "BLOCKED" message
    - No IAM role credentials should be accessible from container context
    
    Returns True if preventive control worked (attack blocked), False otherwise
    """
    global INSTANCE_ID
    
    print("[HYPOTHESIS] Verifying preventive control effectiveness...")
    
    try:
        ssm_client = boto3.client('ssm', region_name=REGION)
        
        if not INSTANCE_ID:
            raise Exception("Instance ID not available")
        
        # Verification 1: Check iptables rules are active
        print("[HYPOTHESIS] Verification 1: Checking iptables rules...")
        response = ssm_client.send_command(
            InstanceIds=[INSTANCE_ID],
            DocumentName='AWS-RunShellScript',
            Parameters={
                'commands': [
                    'iptables -L FORWARD -n -v | grep 169.254.169.254',
                    'iptables -L OUTPUT -n -v | grep 169.254.169.254'
                ]
            }
        )
        
        command_id = response['Command']['CommandId']
        time.sleep(10)
        
        def check_iptables_verification():
            try:
                output = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=INSTANCE_ID
                )
                if output['Status'] == 'Success':
                    rules_output = output.get('StandardOutputContent', '')
                    print(f"[HYPOTHESIS] iptables rules:\n{rules_output}")
                    # Check for DROP rules targeting IMDS
                    if 'DROP' in rules_output and '169.254.169.254' in rules_output:
                        print("[HYPOTHESIS] ✓ iptables DROP rules confirmed active")
                        return True
                    else:
                        print("[HYPOTHESIS] ✗ iptables DROP rules not found")
                        return False
                return False
            except Exception as e:
                print(f"[HYPOTHESIS] Error checking iptables: {e}")
                return False
        
        if not _wait_with_backoff(check_iptables_verification, max_wait_seconds=300, check_interval=10):
            print("[HYPOTHESIS] ✗ Failed to verify iptables rules within timeout")
            return False
        
        # Verification 2: Confirm container IMDS access was blocked
        print("[HYPOTHESIS] Verification 2: Verifying container IMDS access was blocked...")
        response = ssm_client.send_command(
            InstanceIds=[INSTANCE_ID],
            DocumentName='AWS-RunShellScript',
            Parameters={
                'commands': [
                    '#!/bin/bash',
                    '# Re-attempt IMDS access from container to verify blocking',
                    'result=$(docker run --rm alpine:latest sh -c "timeout 5 wget -T 5 -q -O - http://169.254.169.254/latest/meta-data/iam/security-credentials/ 2>&1 || echo BLOCKED")',
                    'echo "Container IMDS access result: $result"',
                    '# Check if access was blocked (timeout or BLOCKED message)',
                    'if echo "$result" | grep -qE "BLOCKED|timeout|Connection timed out|wget: download timed out"; then',
                    '  echo "ACCESS_BLOCKED"',
                    'else',
                    '  echo "ACCESS_ALLOWED"',
                    '  echo "Credentials exposed: $result"',
                    'fi'
                ]
            }
        )
        
        command_id = response['Command']['CommandId']
        print(f"[HYPOTHESIS] Verification command ID: {command_id}")
        
        # Wait for verification with 30-minute SLA
        def check_blocking_verification():
            try:
                output = ssm_client.get_command_invocation(
                    CommandId=command_id,
                    InstanceId=INSTANCE_ID
                )
                status = output['Status']
                print(f"[HYPOTHESIS] Verification status: {status}")
                
                if status in ['Success', 'Failed']:
                    stdout = output.get('StandardOutputContent', '')
                    stderr = output.get('StandardErrorContent', '')
                    print(f"[HYPOTHESIS] Verification output:\n{stdout}")
                    
                    if 'ACCESS_BLOCKED' in stdout:
                        print("[HYPOTHESIS] ✓ Container IMDS access successfully blocked by iptables")
                        return True
                    elif 'ACCESS_ALLOWED' in stdout:
                        print("[HYPOTHESIS] ✗ CRITICAL: Container accessed IMDS despite preventive controls")
                        print(f"[HYPOTHESIS] ✗ Exposed data:\n{stdout}")
                        return False
                    else:
                        print("[HYPOTHESIS] ? Inconclusive result, checking for block indicators...")
                        # Check for timeout/block indicators in output
                        if any(indicator in stdout.lower() for indicator in ['blocked', 'timeout', 'timed out', 'connection refused']):
                            print("[HYPOTHESIS] ✓ Block indicators found, access prevented")
                            return True
                        print("[HYPOTHESIS] ✗ No clear block indicators found")
                        return False
                return False
            except Exception as e:
                print(f"[HYPOTHESIS] Error in verification: {e}")
                return False
        
        verification_result = _wait_with_backoff(check_blocking_verification, max_wait_seconds=1800, check_interval=15)
        
        if verification_result:
            print("[HYPOTHESIS] ✓ PREVENTIVE CONTROL VERIFIED: Container network isolation successfully blocked IMDS access")
            print("[HYPOTHESIS] ✓ iptables rules prevented credential exfiltration from container namespace")
            print("[HYPOTHESIS] ✓ Attack surface reduced despite weakened metadata service configuration")
            return True
        else:
            print("[HYPOTHESIS] ✗ PREVENTIVE CONTROL FAILED: Container was able to access IMDS")
            print("[HYPOTHESIS] ✗ Network isolation controls did not prevent credential exposure")
            return False
        
    except Exception as e:
        print(f"[HYPOTHESIS] ERROR during verification: {e}")
        return False

def rollback():
    """
    Clean up all resources by deleting the CloudFormation stack
    Tolerant to errors and missing resources
    """
    global STACK_NAME
    
    print("[ROLLBACK] Starting cleanup...")
    
    try:
        if not STACK_NAME:
            print("[ROLLBACK] No stack name available, skipping deletion")
            return
        
        cfn_client = boto3.client('cloudformation', region_name=REGION)
        
        # Check if stack exists
        try:
            cfn_client.describe_stacks(StackName=STACK_NAME)
        except cfn_client.exceptions.ClientError as e:
            if 'does not exist' in str(e):
                print(f"[ROLLBACK] Stack {STACK_NAME} does not exist, nothing to clean up")
                return
            raise
        
        # Delete stack
        print(f"[ROLLBACK] Deleting stack {STACK_NAME}...")
        cfn_client.delete_stack(StackName=STACK_NAME)
        
        # Wait for deletion (30-minute SLA)
        print("[ROLLBACK] Waiting for stack deletion (up to 30 minutes)...")
        def check_stack_deleted():
            try:
                response = cfn_client.describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                print(f"[ROLLBACK] Stack status: {status}")
                
                if status == 'DELETE_COMPLETE':
                    return True
                elif 'DELETE_FAILED' in status:
                    print(f"[ROLLBACK] WARNING: Stack deletion failed with status {status}")
                    return True  # Consider it done to avoid infinite wait
                return False
            except cfn_client.exceptions.ClientError as e:
                if 'does not exist' in str(e):
                    print("[ROLLBACK] Stack deleted successfully")
                    return True
                print(f"[ROLLBACK] Error checking stack deletion: {e}")
                return False
        
        if _wait_with_backoff(check_stack_deleted, max_wait_seconds=1800, check_interval=20):
            print(f"[ROLLBACK] Stack {STACK_NAME} deleted successfully")
        else:
            print(f"[ROLLBACK] WARNING: Stack deletion did not complete within timeout")
        
    except Exception as e:
        print(f"[ROLLBACK] ERROR during cleanup (continuing anyway): {e}")

def run_experiment():
    """
    Main experiment runner with proper error handling and guaranteed rollback
    """
    try:
        print("=" * 80)
        print("SCE Experiment 2.3 - Preventive Probe: Container Network Isolation")
        print("=" * 80)
        
        steady_state()
        attack()
        result = hypothesis_verification()
        
        print("=" * 80)
        if result:
            print("EXPERIMENT RESULT: SUCCESS - Preventive control blocked the attack")
        else:
            print("EXPERIMENT RESULT: FAILURE - Preventive control did not block the attack")
        print("=" * 80)
        
        return result
        
    except Exception as e:
        print(f"[EXPERIMENT] CRITICAL ERROR: {e}")
        return False
    finally:
        rollback()

if __name__ == "__main__":
    success = run_experiment()
    sys.exit(0 if success else 1)