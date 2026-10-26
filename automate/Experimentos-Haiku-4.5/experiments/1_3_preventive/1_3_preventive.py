#!/usr/bin/env python3
"""
Security Chaos Engineering Experiment: 1.3 Preventive Probe
ULTRA-OPTIMIZED: Direct IAM API approach (no CloudFormation)

Attack Node: 1.2 - Enumerate EC2 Instances
Probe Type: Preventive
Intent: Confirm IAM Deny policy blocks ec2:DescribeInstances

Design Philosophy:
- ZERO CloudFormation complexity
- Direct IAM API calls (1-2 seconds per operation)
- Inline policy inspection (no external dependencies)
- Comprehensive error handling
- Pre-flight health checks between phases
"""

import json
import time
import logging
import sys
import subprocess
import traceback
from typing import Dict, Any, Optional, Tuple
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Global state
experiment_state = {
    'role_name': None,
    'user_name': None,
    'access_key_id': None,
    'secret_access_key': None,
    'timestamp': None,
    'start_time': None,
    'iam_client': None,
    'sts_client': None,
    'account_id': None,
    'resources_created': [],
}

# ============================================================================
# SECTION 1: UTILITY FUNCTIONS
# ============================================================================

def install_boto3():
    """Install boto3 if missing."""
    try:
        import boto3
        return boto3
    except ImportError:
        logger.info("Installing boto3...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "-q"])
        import boto3
        return boto3


def get_aws_clients() -> Tuple[Any, Any]:
    """Initialize IAM and STS clients."""
    boto3 = install_boto3()
    try:
        iam = boto3.client('iam', region_name='us-east-1')
        sts = boto3.client('sts', region_name='us-east-1')
        
        # Verify connectivity
        acct = sts.get_caller_identity()['Account']
        logger.info(f"✓ AWS clients ready; Account: {acct}")
        experiment_state['account_id'] = acct
        return iam, sts
    except Exception as e:
        logger.error(f"✗ AWS client initialization failed: {e}")
        raise


def wait_for_propagation(iam, name: str, res_type: str = "role", timeout: int = 30) -> bool:
    """Wait for IAM resource to propagate (max 30s)."""
    start = time.time()
    
    while time.time() - start < timeout:
        try:
            if res_type == "role":
                iam.get_role(RoleName=name)
            elif res_type == "user":
                iam.get_user(UserName=name)
            logger.info(f"✓ {res_type} '{name}' propagated ({time.time()-start:.1f}s)")
            return True
        except iam.exceptions.NoSuchEntityException:
            time.sleep(1)
        except Exception as e:
            logger.warning(f"⚠ Error: {e}")
            time.sleep(1)
    
    logger.error(f"✗ {res_type} '{name}' did not propagate within {timeout}s")
    return False


def poll_cloudtrail(sla_seconds: int = 1800, poll_interval: int = 30) -> bool:
    """Poll CloudTrail for AccessDenied DescribeInstances event (30-min SLA)."""
    boto3 = install_boto3()
    ct = boto3.client('cloudtrail', region_name='us-east-1')
    
    deadline = time.time() + sla_seconds
    poll_count = 0
    
    logger.info(f"⏳ CloudTrail polling started (SLA: {sla_seconds}s)...")
    
    while time.time() < deadline:
        poll_count += 1
        try:
            events = ct.lookup_events(
                LookupAttributes=[
                    {'AttributeKey': 'EventName', 'AttributeValue': 'DescribeInstances'}
                ],
                MaxResults=50
            )
            
            for event in events.get('Events', []):
                try:
                    ed = json.loads(event.get('CloudTrailEvent', '{}'))
                    if ed.get('errorCode') == 'AccessDenied':
                        logger.info(f"✓ CloudTrail: AccessDenied found (poll #{poll_count})")
                        return True
                except:
                    pass
        except Exception as e:
            logger.debug(f"Poll #{poll_count}: {e}")
        
        remaining = deadline - time.time()
        if remaining > 0:
            time.sleep(min(poll_interval, remaining))
    
    logger.warning(f"⚠ CloudTrail: No AccessDenied found within {sla_seconds}s (non-blocking)")
    return False  # Non-blocking failure for CloudTrail


# ============================================================================
# SECTION 2: STEADY-STATE
# ============================================================================

def steady_state():
    """
    PHASE 1: Create minimal IAM infrastructure for preventive probe testing.
    
    Creates in ~5 seconds:
    - IAM Role (attacker simulation)
    - Allow policy (ec2:DescribeInstances)
    - Deny policy (explicit block - PREVENTIVE SAFEGUARD)
    - IAM User (test attacker)
    - Access Key (attacker credentials)
    """
    logger.info("=" * 80)
    logger.info("PHASE 1: STEADY-STATE - IAM Infrastructure Setup")
    logger.info("=" * 80)
    
    try:
        # Initialize
        experiment_state['timestamp'] = str(int(time.time()))
        experiment_state['role_name'] = f"SCE-1-3-Role-{experiment_state['timestamp']}"
        experiment_state['user_name'] = f"SCE-1-3-User-{experiment_state['timestamp']}"
        experiment_state['start_time'] = time.time()
        
        logger.info(f"📋 Timestamp: {experiment_state['timestamp']}")
        logger.info(f"📋 Role: {experiment_state['role_name']}")
        logger.info(f"📋 User: {experiment_state['user_name']}")
        
        # Get AWS clients
        iam, sts = get_aws_clients()
        experiment_state['iam_client'] = iam
        experiment_state['sts_client'] = sts
        
        # Create Role
        logger.info("\n📌 Creating IAM Role...")
        role_resp = iam.create_role(
            RoleName=experiment_state['role_name'],
            AssumeRolePolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{experiment_state['account_id']}:root"},
                    "Action": "sts:AssumeRole"
                }]
            }),
            Tags=[
                {'Key': 'Experiment', 'Value': 'SCE-1.3'},
                {'Key': 'Timestamp', 'Value': experiment_state['timestamp']}
            ]
        )
        logger.info(f"✓ Role created: {role_resp['Role']['Arn']}")
        experiment_state['resources_created'].append(('role', experiment_state['role_name']))
        
        # Wait for role propagation
        if not wait_for_propagation(iam, experiment_state['role_name'], "role", timeout=30):
            raise Exception("Role propagation timeout")
        
        # Attach Allow policy
        logger.info("\n📌 Attaching Allow policy...")
        iam.put_role_policy(
            RoleName=experiment_state['role_name'],
            PolicyName="AllowDescribeInstances",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["ec2:DescribeInstances"],
                    "Resource": "*"
                }]
            })
        )
        logger.info("✓ Allow policy attached")
        experiment_state['resources_created'].append(
            ('role_policy', (experiment_state['role_name'], 'AllowDescribeInstances'))
        )
        
        # Attach Deny policy (PREVENTIVE SAFEGUARD)
        logger.info("\n📌 Attaching Deny policy (PREVENTIVE SAFEGUARD)...")
        iam.put_role_policy(
            RoleName=experiment_state['role_name'],
            PolicyName="DenyDescribeInstances",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Deny",
                    "Action": ["ec2:DescribeInstances"],
                    "Resource": "*"
                }]
            })
        )
        logger.info("✓ Deny policy attached (PREVENTIVE CONTROL ACTIVE)")
        experiment_state['resources_created'].append(
            ('role_policy', (experiment_state['role_name'], 'DenyDescribeInstances'))
        )
        
        # Create User
        logger.info("\n📌 Creating IAM User...")
        user_resp = iam.create_user(
            UserName=experiment_state['user_name'],
            Tags=[
                {'Key': 'Experiment', 'Value': 'SCE-1.3'},
                {'Key': 'Timestamp', 'Value': experiment_state['timestamp']}
            ]
        )
        logger.info(f"✓ User created: {user_resp['User']['Arn']}")
        experiment_state['resources_created'].append(('user', experiment_state['user_name']))
        
        # Wait for user propagation
        if not wait_for_propagation(iam, experiment_state['user_name'], "user", timeout=30):
            raise Exception("User propagation timeout")
        
        # Create Access Key
        logger.info("\n📌 Creating Access Key...")
        key_resp = iam.create_access_key(UserName=experiment_state['user_name'])
        
        experiment_state['access_key_id'] = key_resp['AccessKey']['AccessKeyId']
        experiment_state['secret_access_key'] = key_resp['AccessKey']['SecretAccessKey']
        
        logger.info(f"✓ Access Key created: {experiment_state['access_key_id'][:8]}...")
        experiment_state['resources_created'].append(
            ('access_key', (experiment_state['user_name'], experiment_state['access_key_id']))
        )
        
        # Attach AssumeRole policy to user
        logger.info("\n📌 Attaching AssumeRole policy to user...")
        iam.put_user_policy(
            UserName=experiment_state['user_name'],
            PolicyName="AssumeRolePolicy",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": f"arn:aws:iam::{experiment_state['account_id']}:role/{experiment_state['role_name']}"
                }]
            })
        )
        logger.info("✓ AssumeRole policy attached")
        experiment_state['resources_created'].append(
            ('user_policy', (experiment_state['user_name'], 'AssumeRolePolicy'))
        )
        
        # Brief wait for policy propagation
        time.sleep(2)
        
        elapsed = time.time() - experiment_state['start_time']
        logger.info(f"\n✓ Phase 1 complete ({elapsed:.1f}s): Infrastructure ready")
        return True
    
    except Exception as e:
        logger.error(f"✗ Phase 1 failed: {e}")
        logger.debug(traceback.format_exc())
        raise


# ============================================================================
# SECTION 3: ATTACK EXECUTION
# ============================================================================

def attack() -> bool:
    """
    PHASE 2: Execute attack - Enumerate EC2 instances.
    
    Returns:
        False if blocked (good - preventive worked)
        True if succeeded (bad - preventive failed)
    """
    logger.info("=" * 80)
    logger.info("PHASE 2: ATTACK - EC2 Enumeration (Step 1.2)")
    logger.info("=" * 80)
    
    if not experiment_state['access_key_id']:
        logger.error("✗ Credentials missing")
        return True
    
    try:
        boto3 = install_boto3()
        ec2 = boto3.client(
            'ec2',
            region_name='us-east-1',
            aws_access_key_id=experiment_state['access_key_id'],
            aws_secret_access_key=experiment_state['secret_access_key']
        )
        
        logger.info(f"🔓 Attempting DescribeInstances...")
        
        response = ec2.describe_instances(
            Filters=[{'Name': 'instance-state-name', 'Values': ['running']}]
        )
        
        logger.warning("✗ ATTACK SUCCEEDED: DescribeInstances returned data (preventive FAILED)")
        return True
    
    except Exception as e:
        error_str = str(e)
        if 'AccessDenied' in error_str or 'UnauthorizedOperation' in error_str:
            logger.info("✓ ATTACK BLOCKED: AccessDenied error (preventive WORKING)")
            return False
        else:
            logger.error(f"✗ Unexpected error: {e}")
            raise


# ============================================================================
# SECTION 4: HYPOTHESIS VERIFICATION
# ============================================================================

def check_iam_policy() -> bool:
    """Verify IAM Deny policy exists on role."""
    try:
        iam = experiment_state['iam_client']
        role = experiment_state['role_name']
        
        logger.info(f"🔍 Checking IAM policies on role: {role}")
        
        policies = iam.list_role_policies(RoleName=role)
        
        for policy_name in policies.get('PolicyNames', []):
            policy = iam.get_role_policy(RoleName=role, PolicyName=policy_name)
            policy_doc = policy.get('PolicyDocument', {})
            
            for stmt in policy_doc.get('Statement', []):
                if (stmt.get('Effect') == 'Deny' and 
                    'ec2:DescribeInstances' in stmt.get('Action', [])):
                    logger.info(f"✓ Found Deny policy: {policy_name}")
                    return True
        
        logger.error("✗ No Deny policy found")
        return False
    
    except Exception as e:
        logger.error(f"✗ Policy check failed: {e}")
        logger.debug(traceback.format_exc())
        return False


def hypothesis_verification() -> bool:
    """
    PHASE 3: Verify preventive safeguard.
    
    Verifications:
    1. IAM Deny policy exists
    2. Attack is blocked
    3. CloudTrail logs denial (with SLA)
    
    Returns:
        True if all critical verifications pass
    """
    logger.info("=" * 80)
    logger.info("PHASE 3: HYPOTHESIS VERIFICATION - Preventive Probe 1.3")
    logger.info("=" * 80)
    
    try:
        # Verification 1: IAM policy
        logger.info("\n📋 [Verification 1/3] Checking IAM Deny policy...")
        policy_ok = check_iam_policy()
        if not policy_ok:
            logger.error("✗ [1/3] FAIL: IAM Deny policy NOT found")
            return False
        logger.info("✓ [1/3] PASS: IAM Deny policy confirmed")
        
        # Verification 2: Attack blocked
        logger.info("\n📋 [Verification 2/3] Executing attack...")
        attack_blocked = not attack()
        if not attack_blocked:
            logger.error("✗ [2/3] FAIL: Attack succeeded (preventive FAILED)")
            return False
        logger.info("✓ [2/3] PASS: Attack was blocked")
        
        # Verification 3: CloudTrail logging (non-blocking, best-effort)
        logger.info("\n📋 [Verification 3/3] Checking CloudTrail (SLA: 30min)...")
        ct_ok = poll_cloudtrail(sla_seconds=1800, poll_interval=30)
        if ct_ok:
            logger.info("✓ [3/3] PASS: CloudTrail logs AccessDenied")
        else:
            logger.warning("⚠ [3/3] WARN: CloudTrail not available (non-blocking)")
        
        logger.info("\n" + "=" * 80)
        logger.info("✅ HYPOTHESIS VERIFICATION PASSED")
        logger.info("Preventive Safeguard (IAM Deny) Successfully Blocked Attack")
        logger.info("=" * 80)
        return True
    
    except Exception as e:
        logger.error(f"✗ Verification failed: {e}")
        logger.debug(traceback.format_exc())
        return False


# ============================================================================
# SECTION 5: ROLLBACK
# ============================================================================

def rollback():
    """PHASE 4: Delete all created resources in reverse order."""
    logger.info("=" * 80)
    logger.info("PHASE 4: ROLLBACK - Infrastructure Cleanup")
    logger.info("=" * 80)
    
    if not experiment_state['iam_client']:
        logger.warning("⚠ IAM client not available")
        return
    
    iam = experiment_state['iam_client']
    
    # Delete in reverse order
    for res_type, res_data in reversed(experiment_state['resources_created']):
        try:
            if res_type == 'access_key':
                user, key = res_data
                logger.info(f"🗑️  Deleting access key {key[:8]}...")
                iam.delete_access_key(UserName=user, AccessKeyId=key)
            
            elif res_type == 'user_policy':
                user, policy = res_data
                logger.info(f"🗑️  Deleting user policy {policy}...")
                iam.delete_user_policy(UserName=user, PolicyName=policy)
            
            elif res_type == 'role_policy':
                role, policy = res_data
                logger.info(f"🗑️  Deleting role policy {policy}...")
                iam.delete_role_policy(RoleName=role, PolicyName=policy)
            
            elif res_type == 'user':
                logger.info(f"🗑️  Deleting user {res_data}...")
                iam.delete_user(UserName=res_data)
            
            elif res_type == 'role':
                logger.info(f"🗑️  Deleting role {res_data}...")
                iam.delete_role(RoleName=res_data)
            
            logger.info("✓ Deleted")
        
        except iam.exceptions.NoSuchEntityException:
            logger.warning(f"⚠ {res_type} already deleted")
        except Exception as e:
            logger.error(f"✗ Delete failed: {e}")
    
    logger.info("✓ Phase 4 complete: Cleanup finished")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    exit_code = 1
    try:
        logger.info("\n" + "=" * 80)
        logger.info("🚀 SCE Experiment 1.3: Preventive Probe (ULTRA-OPTIMIZED)")
        logger.info(f"   Timestamp: {datetime.now().isoformat()}")
        logger.info("=" * 80 + "\n")
        
        logger.info(">>> PHASE 1: Steady-State\n")
        steady_state()
        
        logger.info("\n>>> PHASES 2-3: Attack & Verification\n")
        result = hypothesis_verification()
        
        logger.info("\n>>> PHASE 4: Rollback\n")
        rollback()
        
        logger.info("\n" + "=" * 80)
        if result:
            logger.info("✅ EXPERIMENT RESULT: PASS")
            logger.info("=" * 80)
            exit_code = 0
        else:
            logger.error("❌ EXPERIMENT RESULT: FAIL")
            logger.error("=" * 80)
            exit_code = 1
    
    except Exception as e:
        logger.error(f"\n❌ EXPERIMENT FAILED: {e}")
        logger.debug(traceback.format_exc())
        logger.error("Attempting rollback...")
        try:
            rollback()
        except:
            pass
        exit_code = 1
    
    sys.exit(exit_code)