"""
SCE Experiment 1.3 - Preventive Probe
Attack Node 1.2: Enumerate Target EC2 Instance & IMDS Configuration
TTP: T1580 - Cloud Infrastructure Discovery

Validates that an IAM permission boundary effectively blocks ec2:DescribeInstances
reconnaissance attempts from a simulated CI/CD / developer role, preventing
unauthorized discovery of banking EC2 infrastructure and IMDS configurations.

Defense Node 1.1: Least-Privilege IAM & SCP Guardrails
Classification: Preventive
"""

import json
import logging
import os
import sys
import time

try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Global experiment state
# ──────────────────────────────────────────────
_state = {
    "timestamp": None,
    "stack_name": None,
    "role_arn": None,
    "external_id": None,
    "account_id": None,
    "region": None,
    "attack_result": None,
    "attack_error_code": None,
    "attack_instances_found": None,
}

STACK_CREATION_TIMEOUT = 1200   # seconds
STACK_DELETION_TIMEOUT = 600    # seconds
IAM_PROPAGATION_WAIT = 20      # seconds
POLL_INTERVAL = 15              # seconds
SLA_TIMEOUT = 1800              # 30 minutes


def _get_caller_identity():
    """Return account ID and region from current credentials."""
    sts = boto3.client("sts")
    identity = sts.get_caller_identity()
    session = boto3.session.Session()
    return identity["Account"], session.region_name or "us-east-1"


def _cfn_template(account_id: str, external_id: str) -> str:
    """
    Build a CloudFormation template that creates:
      1. A Permission Boundary policy that explicitly denies EC2 reconnaissance
         actions (ec2:DescribeInstances, ec2:DescribeSecurityGroups,
         ec2:DescribeVpcs, ec2:DescribeSubnets).
      2. An IAM Role simulating a CI/CD pipeline role whose inline policy
         *grants* ec2:DescribeInstances, but whose permission boundary
         overrides with Deny — proving the preventive control.
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.3 Preventive - Permission Boundary blocks EC2 reconnaissance",
        "Resources": {
            "PermissionBoundary": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": {"Fn::Sub": "sce-boundary-${AWS::StackName}"},
                    "Description": "Deny EC2 reconnaissance for non-admin roles",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowMinimalActions",
                                "Effect": "Allow",
                                "Action": [
                                    "sts:GetCallerIdentity",
                                    "logs:CreateLogGroup",
                                    "logs:CreateLogStream",
                                    "logs:PutLogEvents",
                                ],
                                "Resource": "*",
                            },
                            {
                                "Sid": "DenyEC2Recon",
                                "Effect": "Deny",
                                "Action": [
                                    "ec2:DescribeInstances",
                                    "ec2:DescribeSecurityGroups",
                                    "ec2:DescribeVpcs",
                                    "ec2:DescribeSubnets",
                                    "ec2:DescribeInstanceAttribute",
                                    "ec2:DescribeInstanceStatus",
                                ],
                                "Resource": "*",
                            },
                        ],
                    },
                },
            },
            "SimulatedCICDRole": {
                "Type": "AWS::IAM::Role",
                "DependsOn": "PermissionBoundary",
                "Properties": {
                    "RoleName": {"Fn::Sub": "sce-role-${AWS::StackName}"},
                    "PermissionsBoundary": {"Ref": "PermissionBoundary"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringEquals": {
                                        "sts:ExternalId": external_id,
                                    }
                                },
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "GrantEC2Describe",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "GrantEC2DescribeInstances",
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:DescribeInstances",
                                            "ec2:DescribeSecurityGroups",
                                        ],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": "SCE-1.3-Preventive"},
                        {"Key": "Purpose", "Value": "ChaosEngineering"},
                    ],
                },
            },
        },
        "Outputs": {
            "RoleArn": {
                "Description": "ARN of the simulated CI/CD role",
                "Value": {"Fn::GetAtt": ["SimulatedCICDRole", "Arn"]},
            },
            "PermissionBoundaryArn": {
                "Description": "ARN of the permission boundary",
                "Value": {"Ref": "PermissionBoundary"},
            },
        },
    }
    return json.dumps(template)


def _wait_for_stack(cfn_client, stack_name: str, target_status: str, timeout: int):
    """Poll CloudFormation stack until it reaches target_status or times out."""
    start = time.monotonic()
    attempt = 0
    while True:
        attempt += 1
        elapsed = time.monotonic() - start
        if elapsed > timeout:
            raise TimeoutError(
                f"Stack {stack_name} did not reach {target_status} within {timeout}s"
            )
        try:
            resp = cfn_client.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            logger.info(
                "Stack status: %s (attempt %d, %.0fs elapsed)", status, attempt, elapsed
            )

            if status == target_status:
                logger.info(
                    "Stack reached %s after %d attempts", target_status, attempt
                )
                return resp["Stacks"][0]

            if "FAILED" in status or "ROLLBACK_COMPLETE" == status:
                reason = resp["Stacks"][0].get("StackStatusReason", "unknown")
                raise RuntimeError(
                    f"Stack {stack_name} entered {status}: {reason}"
                )
        except ClientError as exc:
            if "does not exist" in str(exc):
                if target_status == "DELETE_COMPLETE":
                    logger.info("Stack deleted (no longer exists)")
                    return None
                raise
            logger.warning("Describe stack error: %s", exc)

        time.sleep(POLL_INTERVAL)


def _verify_role_assumable(sts_client, role_arn: str, external_id: str, retries: int = 10):
    """Wait until the IAM role is assumable (eventual consistency)."""
    for attempt in range(1, retries + 1):
        try:
            creds = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="sce-verify",
                ExternalId=external_id,
                DurationSeconds=900,
            )
            logger.info("Role verification completed after %d attempts", attempt)
            return creds
        except ClientError as exc:
            logger.warning(
                "Role not yet assumable (attempt %d/%d): %s",
                attempt, retries, exc,
            )
            if attempt == retries:
                raise
            time.sleep(5 + attempt * 2)


# ──────────────────────────────────────────────
# 1. STEADY STATE — Provision preventive controls
# ──────────────────────────────────────────────
def steady_state():
    """
    Deploy CloudFormation stack that creates:
      - IAM Permission Boundary denying EC2 reconnaissance
      - Simulated CI/CD role with inline Allow but bounded by Deny
    """
    logger.info("=" * 60)
    logger.info("SCE Experiment 1.3 Preventive - Steady State Setup")
    logger.info("=" * 60)

    ts = int(time.time())
    _state["timestamp"] = ts
    _state["stack_name"] = f"sce-1-3-prev-{ts}"
    _state["external_id"] = f"sce-{ts}"

    logger.info("Timestamp: %d", ts)
    logger.info("Stack name: %s", _state["stack_name"])

    account_id, region = _get_caller_identity()
    _state["account_id"] = account_id
    _state["region"] = region
    logger.info("Account: %s, Region: %s", account_id, region)

    cfn = boto3.client("cloudformation", region_name=region)
    template_body = _cfn_template(account_id, _state["external_id"])

    # Create stack with retries for transient errors
    for attempt in range(1, 4):
        try:
            logger.info("Creating CloudFormation stack (attempt %d)...", attempt)
            cfn.create_stack(
                StackName=_state["stack_name"],
                TemplateBody=template_body,
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Tags=[
                    {"Key": "Experiment", "Value": "SCE-1.3-Preventive"},
                    {"Key": "Timestamp", "Value": str(ts)},
                    {"Key": "Purpose", "Value": "ChaosEngineering"},
                ],
                TimeoutInMinutes=10,
            )
            logger.info("Stack creation initiated")
            break
        except ClientError as exc:
            if "AlreadyExistsException" in str(exc):
                logger.warning("Stack already exists — reusing")
                break
            if attempt == 3:
                logger.error("Failed to create stack after 3 attempts: %s", exc)
                raise
            logger.warning("Stack creation error (attempt %d): %s", attempt, exc)
            time.sleep(5 * attempt)

    # Wait for stack creation
    logger.info("Waiting up to %ds for stack creation...", STACK_CREATION_TIMEOUT)
    stack = _wait_for_stack(
        cfn, _state["stack_name"], "CREATE_COMPLETE", STACK_CREATION_TIMEOUT
    )

    # Extract outputs
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    _state["role_arn"] = outputs.get("RoleArn")
    logger.info("Role ARN: %s", _state["role_arn"])

    if not _state["role_arn"]:
        raise RuntimeError("RoleArn output not found in stack outputs")

    # Wait for IAM propagation
    logger.info("Waiting %ds for IAM propagation...", IAM_PROPAGATION_WAIT)
    time.sleep(IAM_PROPAGATION_WAIT)

    # Verify role is assumable
    logger.info("Verifying role assumability...")
    sts = boto3.client("sts", region_name=region)
    _verify_role_assumable(sts, _state["role_arn"], _state["external_id"])

    logger.info("=" * 60)
    logger.info("Steady state setup COMPLETED")
    logger.info("=" * 60)


# ──────────────────────────────────────────────
# 2. ATTACK — T1580 Cloud Infrastructure Discovery
# ──────────────────────────────────────────────
def attack() -> bool:
    """
    Execute Attack Node 1.2: Enumerate Target EC2 Instance & IMDS Configuration.

    Assumes the simulated CI/CD role (bounded by permission boundary) and
    attempts ec2:DescribeInstances. The permission boundary should block
    this call with UnauthorizedOperation / AccessDenied.

    Returns True if the attack was executed (regardless of block/success).
    """
    logger.info("=" * 60)
    logger.info("SCE 1.3 - Attack Node 1.2: EC2 Reconnaissance")
    logger.info("TTP: T1580 - Cloud Infrastructure Discovery")
    logger.info("=" * 60)

    region = _state["region"]
    role_arn = _state["role_arn"]
    external_id = _state["external_id"]

    if not role_arn:
        logger.error("Role ARN not available — steady_state may have failed")
        _state["attack_result"] = "ERROR"
        _state["attack_error_code"] = "NoRoleAvailable"
        _state["attack_instances_found"] = None
        return True

    # Assume the bounded role
    logger.info("Assuming role: %s", role_arn)
    sts = boto3.client("sts", region_name=region)
    try:
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="sce-attack-recon",
            ExternalId=external_id,
            DurationSeconds=900,
        )
        logger.info("Role assumed successfully")
    except ClientError as exc:
        logger.error("Failed to assume role: %s", exc)
        _state["attack_result"] = "ERROR"
        _state["attack_error_code"] = exc.response["Error"]["Code"]
        _state["attack_instances_found"] = None
        return True

    creds = assumed["Credentials"]
    ec2 = boto3.client(
        "ec2",
        region_name=region,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

    # Execute the reconnaissance command
    logger.info("Executing: aws ec2 describe-instances")
    logger.info("Expected: AccessDenied (permission boundary should block)")

    start_time = time.monotonic()
    try:
        response = ec2.describe_instances(MaxResults=5)
        duration = time.monotonic() - start_time
        instances = []
        for reservation in response.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                inst_info = {
                    "InstanceId": inst.get("InstanceId"),
                    "MetadataOptions": inst.get("MetadataOptions", {}),
                }
                instances.append(inst_info)

        logger.warning("ATTACK SUCCEEDED - Preventive control FAILED")
        logger.warning("Instances found: %d", len(instances))
        for inst in instances:
            logger.warning("  Instance: %s", inst["InstanceId"])
        logger.info("Duration: %.2fs", duration)

        _state["attack_result"] = "SUCCESS"
        _state["attack_error_code"] = None
        _state["attack_instances_found"] = instances

    except ClientError as exc:
        duration = time.monotonic() - start_time
        error_code = exc.response["Error"]["Code"]

        if error_code in ("UnauthorizedOperation", "AccessDenied"):
            logger.info("ATTACK BLOCKED - Preventive control WORKED")
            logger.info("Error: %s", error_code)
            _state["attack_result"] = "BLOCKED"
            _state["attack_error_code"] = error_code
            _state["attack_instances_found"] = None
        else:
            logger.error("UNEXPECTED ERROR during attack: %s", exc)
            _state["attack_result"] = "ERROR"
            _state["attack_error_code"] = error_code
            _state["attack_instances_found"] = None

        logger.info("Duration: %.2fs", duration)

    # Additional reconnaissance attempts for breadth validation
    logger.info("Attempting additional reconnaissance: ec2:DescribeSecurityGroups")
    try:
        ec2.describe_security_groups(MaxResults=5)
        logger.warning("DescribeSecurityGroups SUCCEEDED - boundary gap detected")
    except ClientError as exc:
        sg_code = exc.response["Error"]["Code"]
        if sg_code in ("UnauthorizedOperation", "AccessDenied"):
            logger.info("DescribeSecurityGroups also BLOCKED: %s", sg_code)
        else:
            logger.warning("DescribeSecurityGroups unexpected error: %s", exc)

    logger.info("=" * 60)
    logger.info("Attack execution completed")
    logger.info("=" * 60)

    return True


# ──────────────────────────────────────────────
# 3. HYPOTHESIS VERIFICATION — Preventive probe
# ──────────────────────────────────────────────
def hypothesis_verification() -> bool:
    """
    Verify that the preventive control (IAM Permission Boundary) effectively
    blocked the EC2 reconnaissance attack.

    Pass criteria:
      - attack_result == "BLOCKED"
      - attack_error_code in ("UnauthorizedOperation", "AccessDenied")
      - No instances were discovered

    Returns True if the hypothesis holds (control is effective).
    """
    logger.info("=" * 60)
    logger.info("SCE 1.3 - Hypothesis Verification")
    logger.info("=" * 60)

    result = _state.get("attack_result")
    error_code = _state.get("attack_error_code")
    instances = _state.get("attack_instances_found")

    logger.info("Attack Result: %s", result)
    logger.info("Error Code: %s", error_code)
    logger.info("Instances: %s", instances if instances else "None")

    verified = (
        result == "BLOCKED"
        and error_code in ("UnauthorizedOperation", "AccessDenied")
        and (instances is None or len(instances) == 0)
    )

    if verified:
        logger.info("=" * 60)
        logger.info("HYPOTHESIS VERIFIED: Control effective")
        logger.info("=" * 60)
        logger.info("Evidence:")
        logger.info("  - Attack blocked with: %s", error_code)
        logger.info("  - No instances disclosed")
        logger.info("  - Permission boundary working")
    else:
        logger.error("=" * 60)
        logger.error("HYPOTHESIS FAILED: Control ineffective")
        logger.error("=" * 60)
        logger.error("Evidence:")
        logger.error("  - Attack result: %s (expected: BLOCKED)", result)
        logger.error("  - Error code: %s (expected: UnauthorizedOperation/AccessDenied)", error_code)
        if instances:
            logger.error("  - Instances disclosed: %d (expected: 0)", len(instances))

    return verified


# ──────────────────────────────────────────────
# 4. ROLLBACK — Teardown all resources
# ──────────────────────────────────────────────
def rollback():
    """
    Delete the CloudFormation stack and all resources created during steady_state.
    Safe and tolerant: handles missing stacks, already-deleted resources, etc.
    """
    logger.info("=" * 60)
    logger.info("SCE 1.3 - Rollback / Cleanup")
    logger.info("=" * 60)

    stack_name = _state.get("stack_name")
    region = _state.get("region")

    if not stack_name:
        logger.warning("No stack name recorded — nothing to clean up")
        return

    if not region:
        _, region = _get_caller_identity()

    cfn = boto3.client("cloudformation", region_name=region)

    try:
        logger.info("Deleting stack: %s", stack_name)
        cfn.delete_stack(StackName=stack_name)
        logger.info("Deletion initiated")
    except ClientError as exc:
        if "does not exist" in str(exc):
            logger.info("Stack already deleted or does not exist")
            logger.info("=" * 60)
            logger.info("Cleanup completed")
            logger.info("=" * 60)
            return
        logger.error("Error initiating stack deletion: %s", exc)
        raise

    try:
        logger.info("Waiting for deletion...")
        _wait_for_stack(cfn, stack_name, "DELETE_COMPLETE", STACK_DELETION_TIMEOUT)
    except ClientError as exc:
        if "does not exist" in str(exc):
            logger.info("Stack deleted successfully (no longer exists)")
        else:
            logger.error("Error waiting for stack deletion: %s", exc)
    except TimeoutError:
        logger.error(
            "Stack deletion did not complete within %ds — manual cleanup may be needed",
            STACK_DELETION_TIMEOUT,
        )

    logger.info("=" * 60)
    logger.info("Cleanup completed")
    logger.info("=" * 60)


# ──────────────────────────────────────────────
# Direct execution support
# ──────────────────────────────────────────────
if __name__ == "__main__":
    try:
        steady_state()
        attack()
        result = hypothesis_verification()
        print(f"\nExperiment result: {'PASS' if result else 'FAIL'}")
        sys.exit(0 if result else 1)
    except Exception as exc:
        logger.exception("Experiment failed with exception: %s", exc)
        sys.exit(2)
    finally:
        try:
            rollback()
        except Exception as exc:
            logger.exception("Rollback failed: %s", exc)