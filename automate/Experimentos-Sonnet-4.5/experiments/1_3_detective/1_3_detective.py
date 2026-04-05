"""
Security Chaos Engineering Experiment 1.3 - Detective Probe
Validates CloudTrail monitoring for EC2 reconnaissance attempts

FIXES FROM PREVIOUS EXECUTION:
1. Root cause: CloudFormation stack ROLLBACK_COMPLETE after 90s
2. Likely cause: Resource creation timeout or missing permissions
3. Solution: Minimal resource footprint, extended timeouts, better error logging
4. Removed unnecessary IAM InstanceProfile to reduce complexity
5. Added CloudFormation event detail logging for diagnostics
6. Explicit wait for IAM user propagation before proceeding
"""

import json
import time
import sys
import subprocess
import os

# Install boto3 if not available
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# Global variables
STACK_NAME = None
EXPERIMENT_TAG = "sce-experiment-1-3-detective"
TEST_USER_NAME = None
CLOUDTRAIL_NAME = None
BUCKET_NAME = None

def _get_timestamp_suffix():
    """Generate unique timestamp suffix for resource naming"""
    return str(int(time.time()))

def _wait_with_backoff(condition_func, max_wait_seconds=1800, check_interval=10):
    """
    Poll a condition function with exponential backoff up to max_wait_seconds.
    Returns True if condition met, False if timeout.
    """
    start_time = time.monotonic()
    attempt = 0
    while (time.monotonic() - start_time) < max_wait_seconds:
        try:
            if condition_func():
                return True
        except Exception as e:
            print(f"[WARN] Condition check failed: {e}")
        
        attempt += 1
        wait_time = min(check_interval * (1.5 ** (attempt // 5)), 60)
        time.sleep(wait_time)
    
    return False

def _log_cfn_failure_details(stack_name):
    """Detailed logging of CloudFormation failure reasons"""
    try:
        cfn_client = boto3.client('cloudformation')
        response = cfn_client.describe_stack_events(StackName=stack_name)
        
        print("[ERROR] CloudFormation Stack Failure Details:")
        for event in response['StackEvents'][:10]:
            status = event.get('ResourceStatus', '')
            if 'FAILED' in status or 'ROLLBACK' in status:
                print(f"  Resource: {event.get('LogicalResourceId')}")
                print(f"  Type: {event.get('ResourceType')}")
                print(f"  Status: {status}")
                print(f"  Reason: {event.get('ResourceStatusReason', 'N/A')}")
                print(f"  Timestamp: {event.get('Timestamp')}")
                print("  ---")
    except Exception as e:
        print(f"[WARN] Could not retrieve failure details: {e}")

def steady_state():
    """
    Provision minimal AWS resources for reconnaissance attack scenario.
    
    ULTRA-SIMPLIFIED APPROACH:
    - Only essential resources: S3 bucket, IAM user, access key
    - CloudTrail created outside CloudFormation to avoid circular dependencies
    - No EC2 instances (not needed for reconnaissance test)
    - Extended timeout for stack creation
    """
    global STACK_NAME, TEST_USER_NAME, CLOUDTRAIL_NAME, BUCKET_NAME
    
    print("[INFO] Starting steady_state setup...")
    timestamp = _get_timestamp_suffix()
    STACK_NAME = f"sce-recon-{timestamp}"
    TEST_USER_NAME = f"test-user-{timestamp}"
    CLOUDTRAIL_NAME = f"sce-trail-{timestamp}"
    BUCKET_NAME = f"sce-ct-{timestamp}"
    
    cfn_client = boto3.client('cloudformation')
    region = boto3.session.Session().region_name or 'us-east-1'
    account_id = boto3.client('sts').get_caller_identity()['Account']
    
    # Ultra-minimal CloudFormation template
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE Experiment 1.3 - Minimal Setup",
        "Resources": {
            # S3 bucket for CloudTrail
            "TrailBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {
                    "BucketName": BUCKET_NAME,
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "BlockPublicPolicy": True,
                        "IgnorePublicAcls": True,
                        "RestrictPublicBuckets": True
                    }
                }
            },
            # Bucket policy
            "BucketPolicy": {
                "Type": "AWS::S3::BucketPolicy",
                "Properties": {
                    "Bucket": {"Ref": "TrailBucket"},
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AWSCloudTrailAclCheck",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:GetBucketAcl",
                                "Resource": {"Fn::GetAtt": ["TrailBucket", "Arn"]}
                            },
                            {
                                "Sid": "AWSCloudTrailWrite",
                                "Effect": "Allow",
                                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": {"Fn::Sub": "${TrailBucket.Arn}/*"},
                                "Condition": {
                                    "StringEquals": {
                                        "s3:x-amz-acl": "bucket-owner-full-control"
                                    }
                                }
                            }
                        ]
                    }
                }
            },
            # IAM test user
            "TestUser": {
                "Type": "AWS::IAM::User",
                "Properties": {
                    "UserName": TEST_USER_NAME
                }
            },
            # Policy for test user
            "TestUserPolicy": {
                "Type": "AWS::IAM::Policy",
                "Properties": {
                    "PolicyName": f"EC2ReadOnly-{timestamp}",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "ec2:DescribeInstances",
                                "Resource": "*"
                            }
                        ]
                    },
                    "Users": [{"Ref": "TestUser"}]
                }
            },
            # Access key
            "TestUserKey": {
                "Type": "AWS::IAM::AccessKey",
                "Properties": {
                    "UserName": {"Ref": "TestUser"}
                }
            }
        },
        "Outputs": {
            "BucketName": {
                "Value": {"Ref": "TrailBucket"}
            },
            "AccessKeyId": {
                "Value": {"Ref": "TestUserKey"}
            },
            "SecretAccessKey": {
                "Value": {"Fn::GetAtt": ["TestUserKey", "SecretAccessKey"]}
            }
        }
    }
    
    try:
        print(f"[INFO] Creating stack: {STACK_NAME}")
        print(f"[INFO] Resources: S3 bucket, IAM user, access key")
        
        cfn_client.create_stack(
            StackName=STACK_NAME,
            TemplateBody=json.dumps(template),
            Capabilities=['CAPABILITY_NAMED_IAM'],
            Tags=[
                {'Key': 'Experiment', 'Value': EXPERIMENT_TAG},
                {'Key': 'Timestamp', 'Value': timestamp}
            ],
            TimeoutInMinutes=10
        )
        
        # Wait for stack creation with detailed monitoring
        print("[INFO] Waiting for stack creation (up to 10 minutes)...")
        for i in range(40):  # 10 minutes max (40 * 15s)
            try:
                response = cfn_client.describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                print(f"[INFO] Stack status: {status} ({i*15}s elapsed)")
                
                if status == 'CREATE_COMPLETE':
                    print("[INFO] Stack created successfully")
                    break
                elif status in ['CREATE_FAILED', 'ROLLBACK_COMPLETE', 'ROLLBACK_FAILED', 'ROLLBACK_IN_PROGRESS']:
                    print(f"[ERROR] Stack creation failed: {status}")
                    _log_cfn_failure_details(STACK_NAME)
                    return False
                    
                time.sleep(15)
            except ClientError as e:
                print(f"[WARN] Error checking stack: {e}")
                time.sleep(15)
        else:
            print("[ERROR] Stack creation timeout after 10 minutes")
            _log_cfn_failure_details(STACK_NAME)
            return False
        
        # Retrieve outputs
        response = cfn_client.describe_stacks(StackName=STACK_NAME)
        outputs = {o['OutputKey']: o['OutputValue'] 
                  for o in response['Stacks'][0].get('Outputs', [])}
        
        if not outputs:
            print("[ERROR] No stack outputs available")
            return False
        
        # Store credentials
        os.environ['TEST_ACCESS_KEY_ID'] = outputs['AccessKeyId']
        os.environ['TEST_SECRET_ACCESS_KEY'] = outputs['SecretAccessKey']
        os.environ['BUCKET_NAME'] = outputs['BucketName']
        
        print(f"[INFO] Bucket: {outputs['BucketName']}")
        print(f"[INFO] Test user: {TEST_USER_NAME}")
        
        # Wait for IAM propagation
        print("[INFO] Waiting 90s for IAM propagation...")
        time.sleep(90)
        
        # Create CloudTrail (outside CloudFormation)
        try:
            ct_client = boto3.client('cloudtrail')
            print(f"[INFO] Creating CloudTrail: {CLOUDTRAIL_NAME}")
            
            ct_client.create_trail(
                Name=CLOUDTRAIL_NAME,
                S3BucketName=outputs['BucketName'],
                IsMultiRegionTrail=False,
                IncludeGlobalServiceEvents=True
            )
            
            ct_client.start_logging(Name=CLOUDTRAIL_NAME)
            os.environ['CLOUDTRAIL_NAME'] = CLOUDTRAIL_NAME
            
            print("[INFO] CloudTrail logging started")
            time.sleep(30)  # Wait for CloudTrail initialization
            
        except Exception as e:
            print(f"[ERROR] CloudTrail creation failed: {e}")
            return False
        
        print("[INFO] Steady state setup complete")
        return True
        
    except ClientError as e:
        if 'AlreadyExistsException' in str(e):
            print(f"[WARN] Stack {STACK_NAME} already exists")
            return True
        print(f"[ERROR] CloudFormation error: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Setup failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def attack():
    """
    Execute reconnaissance attack using test user credentials.
    """
    print("[INFO] Starting attack phase...")
    
    # Validate prerequisites
    access_key = os.environ.get('TEST_ACCESS_KEY_ID')
    secret_key = os.environ.get('TEST_SECRET_ACCESS_KEY')
    
    if not access_key or not secret_key:
        print("[ERROR] Test user credentials not available")
        print(f"[DEBUG] TEST_ACCESS_KEY_ID present: {bool(access_key)}")
        print(f"[DEBUG] TEST_SECRET_ACCESS_KEY present: {bool(secret_key)}")
        return False
    
    try:
        # Create session with test credentials
        test_session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key
        )
        test_ec2 = test_session.client('ec2')
        
        print(f"[INFO] Executing reconnaissance as user: {TEST_USER_NAME}")
        print("[INFO] Command: ec2:DescribeInstances")
        
        # Execute attack
        response = test_ec2.describe_instances(
            Filters=[
                {'Name': 'instance-state-name', 'Values': ['running']}
            ]
        )
        
        # Count instances
        count = sum(len(r.get('Instances', [])) for r in response.get('Reservations', []))
        print(f"[INFO] Attack completed: {count} instances enumerated")
        
        # Store timestamp
        os.environ['ATTACK_TIMESTAMP'] = str(int(time.time()))
        
        return True
        
    except Exception as e:
        print(f"[ERROR] Attack failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def hypothesis_verification():
    """
    Detective Probe: Verify CloudTrail logged the reconnaissance attack.
    
    SUCCESS CRITERIA:
    1. CloudTrail event exists for DescribeInstances from test user
    2. Event contains userIdentity with correct username
    
    30-MINUTE SLA for CloudTrail event delivery.
    """
    print("[INFO] Starting hypothesis verification...")
    print("[INFO] Detective probe: CloudTrail event detection")
    print("[INFO] Implementing 30-minute SLA...")
    
    attack_time = int(os.environ.get('ATTACK_TIMESTAMP', time.time()))
    cloudtrail_name = os.environ.get('CLOUDTRAIL_NAME')
    
    if not cloudtrail_name:
        print("[ERROR] CloudTrail configuration not available")
        return False
    
    print(f"[INFO] CloudTrail: {cloudtrail_name}")
    print(f"[INFO] Attack time: {attack_time}")
    print(f"[INFO] Test user: {TEST_USER_NAME}")
    
    ct_client = boto3.client('cloudtrail')
    
    def check_cloudtrail_events():
        """Check for DescribeInstances events"""
        try:
            current_time = time.time()
            print(f"[DEBUG] Querying CloudTrail... (elapsed: {int(current_time - attack_time)}s)")
            
            response = ct_client.lookup_events(
                LookupAttributes=[
                    {
                        'AttributeKey': 'EventName',
                        'AttributeValue': 'DescribeInstances'
                    }
                ],
                StartTime=attack_time - 60,
                EndTime=current_time,
                MaxResults=50
            )
            
            events = response.get('Events', [])
            print(f"[DEBUG] Found {len(events)} DescribeInstances events")
            
            # Filter for our test user
            for event in events:
                event_json = json.loads(event.get('CloudTrailEvent', '{}'))
                username = event_json.get('userIdentity', {}).get('userName', '')
                
                if TEST_USER_NAME in username or username == TEST_USER_NAME:
                    print(f"[SUCCESS] CloudTrail event detected!")
                    print(f"[DETAIL] Event ID: {event.get('EventId')}")
                    print(f"[DETAIL] Event Time: {event.get('EventTime')}")
                    print(f"[DETAIL] Username: {username}")
                    print(f"[DETAIL] Source IP: {event_json.get('sourceIPAddress', 'N/A')}")
                    print(f"[DETAIL] User Agent: {event_json.get('userAgent', 'N/A')}")
                    return True
            
            print(f"[DEBUG] No matching events for user: {TEST_USER_NAME}")
            return False
            
        except Exception as e:
            print(f"[WARN] CloudTrail query failed: {e}")
            return False
    
    # Poll for events (30-minute SLA)
    print("[INFO] Polling for CloudTrail events...")
    print("[INFO] This may take several minutes due to CloudTrail delivery latency")
    
    detected = _wait_with_backoff(
        check_cloudtrail_events,
        max_wait_seconds=1800,
        check_interval=30
    )
    
    if not detected:
        print("[FAILURE] CloudTrail event not detected within 30-minute SLA")
        print("[INFO] Possible causes:")
        print("  - CloudTrail event delivery delay (first events can take 15+ minutes)")
        print("  - IAM user not properly configured")
        print("  - Attack did not execute successfully")
        return False
    
    print("[SUCCESS] Detective hypothesis verified!")
    print("[SUCCESS] CloudTrail successfully logged reconnaissance activity")
    return True

def rollback():
    """
    Complete teardown: Delete CloudTrail and CloudFormation stack.
    """
    global STACK_NAME
    
    print("[INFO] Starting rollback...")
    
    # Delete CloudTrail first
    try:
        cloudtrail_name = os.environ.get('CLOUDTRAIL_NAME')
        if cloudtrail_name:
            ct_client = boto3.client('cloudtrail')
            print(f"[INFO] Deleting CloudTrail: {cloudtrail_name}")
            ct_client.delete_trail(Name=cloudtrail_name)
            print("[INFO] CloudTrail deleted")
    except Exception as e:
        print(f"[WARN] CloudTrail deletion: {e}")
    
    # Delete CloudFormation stack
    if not STACK_NAME:
        print("[WARN] No stack name found")
        return True
    
    cfn_client = boto3.client('cloudformation')
    
    try:
        print(f"[INFO] Deleting stack: {STACK_NAME}")
        cfn_client.delete_stack(StackName=STACK_NAME)
        
        # Wait for deletion
        print("[INFO] Waiting for stack deletion...")
        for i in range(40):
            try:
                response = cfn_client.describe_stacks(StackName=STACK_NAME)
                status = response['Stacks'][0]['StackStatus']
                print(f"[INFO] Deletion status: {status} ({i*15}s)")
                
                if status == 'DELETE_COMPLETE':
                    print("[INFO] Stack deleted")
                    return True
                elif status == 'DELETE_FAILED':
                    print("[ERROR] Deletion failed")
                    return False
                    
                time.sleep(15)
            except ClientError as e:
                if 'does not exist' in str(e):
                    print("[INFO] Stack deleted")
                    return True
                time.sleep(15)
        
        print("[WARN] Deletion timeout")
        return False
        
    except ClientError as e:
        if 'does not exist' in str(e):
            print("[INFO] Stack does not exist")
            return True
        print(f"[ERROR] Rollback failed: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Rollback error: {e}")
        import traceback
        traceback.print_exc()
        return False

def run_experiment():
    """Main experiment runner"""
    try:
        print("=" * 80)
        print("SCE Experiment 1.3 - Detective: CloudTrail Reconnaissance Detection")
        print("=" * 80)
        
        if not steady_state():
            print("[FAILURE] Setup failed")
            return False
        
        if not attack():
            print("[FAILURE] Attack failed")
            return False
        
        if not hypothesis_verification():
            print("[FAILURE] Verification failed")
            return False
        
        print("=" * 80)
        print("[SUCCESS] Experiment completed")
        print("=" * 80)
        return True
        
    except Exception as e:
        print(f"[ERROR] Experiment error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        rollback()

if __name__ == "__main__":
    success = run_experiment()
    sys.exit(0 if success else 1)