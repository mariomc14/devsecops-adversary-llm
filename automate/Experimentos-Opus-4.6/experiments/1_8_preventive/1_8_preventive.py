"""
SCE Experiment 1.8 - Preventive Probe
Attack Steps 1.2 & 1.7: EC2 IMDS Protection Weakening via ModifyInstanceMetadataOptions

This experiment validates that an SCP-style IAM policy DENIES:
  1.2 - ec2:DescribeInstances (reconnaissance / enumeration of IMDS config)
  1.7 - ec2:ModifyInstanceMetadataOptions (downgrade IMDSv2 to IMDSv1 + increase hop limit)

The preventive control under test is an explicit IAM deny policy attached to a
test role. The experiment creates a scoped IAM role, attaches a deny policy,
launches a minimal EC2 instance, then assumes the restricted role and verifies
that both API calls are rejected with AccessDenied / UnauthorizedOperation.
"""

import json
import logging
import os
import time
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Ensure boto3 is available
# ---------------------------------------------------------------------------
try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
_TIMESTAMP = str(int(time.time()))
_STACK_NAME = f"sce-experiment-1-8-{_TIMESTAMP}"
_EXPERIMENT_TAG = "sce-experiment-1-8"
_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
_SLA_TIMEOUT = 1800  # 30 minutes
_POLL_INTERVAL = 15
_STACK_OUTPUTS: dict = {}
_ATTACK_RESULTS: dict = {}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts():
    return time.monotonic()


def _cfn_client():
    return boto3.client("cloudformation", region_name=_REGION)


def _sts_client():
    return boto3.client("sts", region_name=_REGION)


def _ec2_client():
    return boto3.client("ec2", region_name=_REGION)


def _get_default_vpc_subnet():
    """Return the first subnet in the default VPC, or any available subnet."""
    ec2 = _ec2_client()
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
        if vpcs["Vpcs"]:
            vpc_id = vpcs["Vpcs"][0]["VpcId"]
            subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
            if subnets["Subnets"]:
                return subnets["Subnets"][0]["SubnetId"]
    except ClientError as exc:
        logger.error("Error finding default VPC subnet: %s", exc)
    # Fallback: pick any subnet
    try:
        subnets = ec2.describe_subnets(MaxResults=5)
        if subnets["Subnets"]:
            return subnets["Subnets"][0]["SubnetId"]
    except ClientError as exc:
        logger.error("Error finding any subnet: %s", exc)
    return None


def _get_amazon_linux_ami():
    """Return latest Amazon Linux 2023 AMI ID."""
    ec2 = _ec2_client()
    try:
        resp = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": ["x86_64"]},
            ],
        )
        images = sorted(resp["Images"], key=lambda x: x["CreationDate"], reverse=True)
        if images:
            return images[0]["ImageId"]
    except ClientError as exc:
        logger.error("Error finding AMI: %s", exc)
    return None


def _get_caller_account_id():
    return _sts_client().get_caller_identity()["Account"]


def _build_cfn_template(account_id: str, subnet_id: str, ami_id: str) -> str:
    """
    Build a CloudFormation template that creates:
    - An EC2 instance with IMDSv2 enforced (the target)
    - An IAM Role with an explicit DENY on ec2:DescribeInstances and
      ec2:ModifyInstanceMetadataOptions (the preventive control)
    - A matching IAM InstanceProfile (unused by app, just for EC2 creation)
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 Preventive Probe - IMDS downgrade prevention",
        "Resources": {
            "SCESecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "SCE 1.8 experiment - no ingress",
                    "VpcId": {"Fn::Select": ["0", {"Fn::Split": ["/", subnet_id]}]} if "/" in subnet_id else {"Ref": "AWS::NoValue"},
                    "SecurityGroupIngress": [],
                    "Tags": [
                        {"Key": "experiment", "Value": _EXPERIMENT_TAG},
                        {"Key": "timestamp", "Value": _TIMESTAMP},
                    ],
                },
            },
            "SCEInstance": {
                "Type": "AWS::EC2::Instance",
                "Properties": {
                    "InstanceType": "t3.micro",
                    "ImageId": ami_id,
                    "SubnetId": subnet_id,
                    "SecurityGroupIds": [{"Fn::GetAtt": ["SCESecurityGroup", "GroupId"]}],
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpEndpoint": "enabled",
                        "HttpPutResponseHopLimit": 1,
                    },
                    "Tags": [
                        {"Key": "Name", "Value": f"sce-1-8-target-{_TIMESTAMP}"},
                        {"Key": "experiment", "Value": _EXPERIMENT_TAG},
                        {"Key": "timestamp", "Value": _TIMESTAMP},
                    ],
                },
            },
            "SCEDenyPolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": f"sce-1-8-deny-imds-{_TIMESTAMP}",
                    "Description": "Deny DescribeInstances and ModifyInstanceMetadataOptions",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DenyIMDSEnumAndModify",
                                "Effect": "Deny",
                                "Action": [
                                    "ec2:DescribeInstances",
                                    "ec2:ModifyInstanceMetadataOptions",
                                ],
                                "Resource": "*",
                            }
                        ],
                    },
                },
            },
            "SCEAllowBaselinePolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": f"sce-1-8-allow-baseline-{_TIMESTAMP}",
                    "Description": "Allow minimal EC2 read for role assumption validation",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "AllowEC2Baseline",
                                "Effect": "Allow",
                                "Action": [
                                    "ec2:DescribeInstances",
                                    "ec2:ModifyInstanceMetadataOptions",
                                    "ec2:DescribeInstanceAttribute",
                                ],
                                "Resource": "*",
                            }
                        ],
                    },
                },
            },
            "SCERestrictedRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-1-8-restricted-{_TIMESTAMP}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        {"Ref": "SCEAllowBaselinePolicy"},
                        {"Ref": "SCEDenyPolicy"},
                    ],
                    "Tags": [
                        {"Key": "experiment", "Value": _EXPERIMENT_TAG},
                        {"Key": "timestamp", "Value": _TIMESTAMP},
                    ],
                },
            },
        },
        "Outputs": {
            "InstanceId": {
                "Value": {"Ref": "SCEInstance"},
            },
            "RestrictedRoleArn": {
                "Value": {"Fn::GetAtt": ["SCERestrictedRole", "Arn"]},
            },
            "DenyPolicyArn": {
                "Value": {"Ref": "SCEDenyPolicy"},
            },
        },
    }

    # Fix SecurityGroup - remove VpcId ref hack, use subnet lookup instead
    # We need to get VPC from subnet; simpler: just omit VpcId and let SG go to default VPC
    # Actually, for non-default VPC subnets we need VpcId. Let's query it.
    ec2 = _ec2_client()
    try:
        sub_resp = ec2.describe_subnets(SubnetIds=[subnet_id])
        vpc_id = sub_resp["Subnets"][0]["VpcId"]
        template["Resources"]["SCESecurityGroup"]["Properties"]["VpcId"] = vpc_id
    except (ClientError, IndexError, KeyError) as exc:
        logger.warning("Could not determine VPC for subnet %s: %s. Omitting VpcId.", subnet_id, exc)
        template["Resources"]["SCESecurityGroup"]["Properties"].pop("VpcId", None)

    return json.dumps(template)


def _wait_for_stack(stack_name: str, target_status: str, timeout: int = 900):
    """Poll CloudFormation until stack reaches target status or times out."""
    cfn = _cfn_client()
    start = _ts()
    while (_ts() - start) < timeout:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            logger.info("Stack %s status: %s", stack_name, status)
            if status == target_status:
                return True
            if "FAILED" in status or "ROLLBACK_COMPLETE" in status:
                reason = resp["Stacks"][0].get("StackStatusReason", "unknown")
                logger.error("Stack %s reached %s: %s", stack_name, status, reason)
                # Try to get events for more detail
                try:
                    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
                    for ev in events[:10]:
                        if "FAILED" in ev.get("ResourceStatus", ""):
                            logger.error("  Resource %s: %s", ev["LogicalResourceId"],
                                         ev.get("ResourceStatusReason", ""))
                except Exception:
                    pass
                return False
            if status == "DELETE_COMPLETE" and target_status != "DELETE_COMPLETE":
                logger.error("Stack was deleted unexpectedly.")
                return False
        except ClientError as exc:
            if "does not exist" in str(exc):
                if target_status == "DELETE_COMPLETE":
                    return True
                logger.error("Stack %s does not exist.", stack_name)
                return False
            logger.warning("Describe stack error: %s", exc)
        time.sleep(15)
    logger.error("Timed out waiting for stack %s to reach %s", stack_name, target_status)
    return False


def _get_stack_outputs(stack_name: str) -> dict:
    """Retrieve stack outputs as a dict."""
    cfn = _cfn_client()
    try:
        resp = cfn.describe_stacks(StackName=stack_name)
        outputs = resp["Stacks"][0].get("Outputs", [])
        return {o["OutputKey"]: o["OutputValue"] for o in outputs}
    except (ClientError, IndexError, KeyError) as exc:
        logger.error("Failed to get stack outputs: %s", exc)
        return {}


def _wait_for_iam_propagation(role_arn: str, timeout: int = 120):
    """Wait until the role can be assumed (IAM eventual consistency)."""
    sts = _sts_client()
    start = _ts()
    while (_ts() - start) < timeout:
        try:
            sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="sce-propagation-check",
                DurationSeconds=900,
            )
            logger.info("IAM role %s is assumable.", role_arn)
            return True
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDenied", "MalformedPolicyDocument"):
                logger.info("IAM role not yet propagated, retrying... (%s)", code)
            else:
                logger.warning("Unexpected error assuming role: %s", exc)
        time.sleep(10)
    logger.error("Timed out waiting for IAM role propagation.")
    return False


# ---------------------------------------------------------------------------
# 1. steady_state – Provision all resources
# ---------------------------------------------------------------------------

def steady_state():
    """
    Provision CloudFormation stack with:
    - EC2 instance (IMDSv2 enforced, hop-limit=1)
    - IAM restricted role with explicit DENY on DescribeInstances and
      ModifyInstanceMetadataOptions (simulates SCP preventive control)
    """
    global _STACK_OUTPUTS
    logger.info("=" * 70)
    logger.info("STEADY STATE: Provisioning resources for SCE 1.8 Preventive Probe")
    logger.info("Stack name: %s", _STACK_NAME)
    logger.info("=" * 70)

    cfn = _cfn_client()
    account_id = _get_caller_account_id()
    logger.info("Account ID: %s", account_id)

    # Discover subnet and AMI
    subnet_id = _get_default_vpc_subnet()
    if not subnet_id:
        raise RuntimeError("No subnet found. Cannot proceed.")
    logger.info("Using subnet: %s", subnet_id)

    ami_id = _get_amazon_linux_ami()
    if not ami_id:
        raise RuntimeError("No suitable AMI found. Cannot proceed.")
    logger.info("Using AMI: %s", ami_id)

    # Build template
    template_body = _build_cfn_template(account_id, subnet_id, ami_id)

    # Check for existing stack
    try:
        existing = cfn.describe_stacks(StackName=_STACK_NAME)
        status = existing["Stacks"][0]["StackStatus"]
        if status in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            logger.warning("Stack %s already exists in %s state. Reusing.", _STACK_NAME, status)
            _STACK_OUTPUTS = _get_stack_outputs(_STACK_NAME)
            logger.info("Stack outputs: %s", _STACK_OUTPUTS)
            return True
        elif "IN_PROGRESS" in status:
            logger.info("Stack creation in progress. Waiting...")
            _wait_for_stack(_STACK_NAME, "CREATE_COMPLETE", timeout=900)
            _STACK_OUTPUTS = _get_stack_outputs(_STACK_NAME)
            return True
        else:
            logger.warning("Stack in unexpected state %s. Deleting and recreating.", status)
            cfn.delete_stack(StackName=_STACK_NAME)
            _wait_for_stack(_STACK_NAME, "DELETE_COMPLETE", timeout=600)
    except ClientError as exc:
        if "does not exist" not in str(exc):
            logger.error("Unexpected error checking stack: %s", exc)

    # Create stack
    logger.info("Creating CloudFormation stack...")
    try:
        cfn.create_stack(
            StackName=_STACK_NAME,
            TemplateBody=template_body,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": "experiment", "Value": _EXPERIMENT_TAG},
                {"Key": "timestamp", "Value": _TIMESTAMP},
            ],
            TimeoutInMinutes=15,
        )
    except ClientError as exc:
        if "AlreadyExistsException" in str(exc):
            logger.warning("Stack already exists (race). Continuing.")
        else:
            logger.error("Failed to create stack: %s", exc)
            raise

    # Wait for creation
    success = _wait_for_stack(_STACK_NAME, "CREATE_COMPLETE", timeout=900)
    if not success:
        raise RuntimeError(f"Stack {_STACK_NAME} failed to create.")

    _STACK_OUTPUTS = _get_stack_outputs(_STACK_NAME)
    logger.info("Stack outputs: %s", _STACK_OUTPUTS)

    # Wait for IAM propagation
    role_arn = _STACK_OUTPUTS.get("RestrictedRoleArn")
    if role_arn:
        _wait_for_iam_propagation(role_arn, timeout=120)
    else:
        raise RuntimeError("RestrictedRoleArn not found in stack outputs.")

    # Wait for instance to be running
    instance_id = _STACK_OUTPUTS.get("InstanceId")
    if instance_id:
        ec2 = _ec2_client()
        logger.info("Waiting for instance %s to reach running state...", instance_id)
        try:
            waiter = ec2.get_waiter("instance_running")
            waiter.wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 15, "MaxAttempts": 40})
            logger.info("Instance %s is running.", instance_id)
        except WaiterError as exc:
            logger.error("Instance did not reach running state: %s", exc)
            raise
    else:
        raise RuntimeError("InstanceId not found in stack outputs.")

    logger.info("STEADY STATE: Complete.")
    return True


# ---------------------------------------------------------------------------
# 2. attack – Execute attack steps 1.2 and 1.7 using the restricted role
# ---------------------------------------------------------------------------

def attack() -> bool:
    """
    Assume the restricted IAM role and attempt:
      1.2 - ec2:DescribeInstances (enumerate IMDS configuration)
      1.7 - ec2:ModifyInstanceMetadataOptions (downgrade to IMDSv1, increase hop limit)

    Both calls should be DENIED by the preventive IAM policy.
    Returns True if both attack steps were attempted (regardless of outcome).
    The actual pass/fail determination happens in hypothesis_verification().
    """
    global _ATTACK_RESULTS
    logger.info("=" * 70)
    logger.info("ATTACK: Executing steps 1.2 and 1.7 as restricted role")
    logger.info("=" * 70)

    role_arn = _STACK_OUTPUTS.get("RestrictedRoleArn")
    instance_id = _STACK_OUTPUTS.get("InstanceId")

    if not role_arn or not instance_id:
        logger.error("Missing stack outputs. role_arn=%s, instance_id=%s", role_arn, instance_id)
        _ATTACK_RESULTS = {
            "step_1_2": {"executed": False, "error": "missing outputs"},
            "step_1_7": {"executed": False, "error": "missing outputs"},
        }
        return True

    # Assume the restricted role
    sts = _sts_client()
    try:
        assumed = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"sce-attack-{_TIMESTAMP}",
            DurationSeconds=900,
        )
        creds = assumed["Credentials"]
        logger.info("Successfully assumed restricted role.")
    except ClientError as exc:
        logger.error("Failed to assume restricted role: %s", exc)
        _ATTACK_RESULTS = {
            "step_1_2": {"executed": False, "error": str(exc)},
            "step_1_7": {"executed": False, "error": str(exc)},
        }
        return True

    # Create EC2 client with restricted credentials
    restricted_ec2 = boto3.client(
        "ec2",
        region_name=_REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

    # --- Attack Step 1.2: Enumerate IMDS configuration ---
    logger.info("-" * 50)
    logger.info("ATTACK STEP 1.2: ec2:DescribeInstances (T1580)")
    step_1_2_result = {"executed": True, "denied": False, "error": None, "data": None}
    try:
        resp = restricted_ec2.describe_instances(
            InstanceIds=[instance_id],
        )
        # If we get here, the call SUCCEEDED (deny policy did not work)
        instances = resp.get("Reservations", [{}])[0].get("Instances", [{}])
        if instances:
            md = instances[0].get("MetadataOptions", {})
            step_1_2_result["data"] = {
                "HttpTokens": md.get("HttpTokens"),
                "HttpEndpoint": md.get("HttpEndpoint"),
                "HopLimit": md.get("HttpPutResponseHopLimit"),
                "State": md.get("State"),
            }
        step_1_2_result["denied"] = False
        logger.warning("STEP 1.2: DescribeInstances SUCCEEDED - preventive control DID NOT block.")
        logger.info("  IMDS Config retrieved: %s", step_1_2_result["data"])
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_msg = exc.response["Error"]["Message"]
        step_1_2_result["error"] = f"{error_code}: {error_msg}"
        if error_code in ("UnauthorizedOperation", "AccessDenied", "Client.UnauthorizedOperation"):
            step_1_2_result["denied"] = True
            logger.info("STEP 1.2: DescribeInstances DENIED as expected. Code: %s", error_code)
        else:
            step_1_2_result["denied"] = False
            logger.error("STEP 1.2: Unexpected error: %s - %s", error_code, error_msg)

    _ATTACK_RESULTS["step_1_2"] = step_1_2_result

    # --- Attack Step 1.7: Modify IMDS options ---
    logger.info("-" * 50)
    logger.info("ATTACK STEP 1.7: ec2:ModifyInstanceMetadataOptions (T1562.001)")
    step_1_7_result = {"executed": True, "denied": False, "error": None, "data": None}
    try:
        resp = restricted_ec2.modify_instance_metadata_options(
            InstanceId=instance_id,
            HttpTokens="optional",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=2,
        )
        # If we get here, the modification SUCCEEDED (deny policy did not work)
        step_1_7_result["denied"] = False
        step_1_7_result["data"] = {
            "HttpTokens": resp.get("InstanceMetadataOptions", {}).get("HttpTokens"),
            "HopLimit": resp.get("InstanceMetadataOptions", {}).get("HttpPutResponseHopLimit"),
        }
        logger.warning("STEP 1.7: ModifyInstanceMetadataOptions SUCCEEDED - preventive control DID NOT block.")
        logger.info("  New IMDS Config: %s", step_1_7_result["data"])
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        error_msg = exc.response["Error"]["Message"]
        step_1_7_result["error"] = f"{error_code}: {error_msg}"
        if error_code in ("UnauthorizedOperation", "AccessDenied", "Client.UnauthorizedOperation"):
            step_1_7_result["denied"] = True
            logger.info("STEP 1.7: ModifyInstanceMetadataOptions DENIED as expected. Code: %s", error_code)
        else:
            step_1_7_result["denied"] = False
            logger.error("STEP 1.7: Unexpected error: %s - %s", error_code, error_msg)

    _ATTACK_RESULTS["step_1_7"] = step_1_7_result

    logger.info("=" * 70)
    logger.info("ATTACK: Complete. Results: %s", json.dumps(_ATTACK_RESULTS, indent=2))
    logger.info("=" * 70)
    return True


# ---------------------------------------------------------------------------
# 3. hypothesis_verification – Verify preventive controls blocked the attacks
# ---------------------------------------------------------------------------

def hypothesis_verification() -> bool:
    """
    Verify the preventive probe:
    - Step 1.2 (DescribeInstances) MUST have been denied by the IAM deny policy
    - Step 1.7 (ModifyInstanceMetadataOptions) MUST have been denied by the IAM deny policy
    - Additionally verify the EC2 instance still has IMDSv2 enforced and hop-limit=1
      (defense was not weakened)

    Returns True if ALL preventive controls held. False otherwise.

    Uses 30-minute SLA polling for eventual consistency verification.
    """
    logger.info("=" * 70)
    logger.info("HYPOTHESIS VERIFICATION: Preventive Probe SCE 1.8")
    logger.info("=" * 70)

    all_passed = True
    results_summary = {}

    # Check 1: Step 1.2 was denied
    step_1_2 = _ATTACK_RESULTS.get("step_1_2", {})
    if not step_1_2.get("executed", False):
        logger.error("CHECK 1 FAIL: Step 1.2 was not executed.")
        results_summary["step_1_2_denied"] = False
        all_passed = False
    elif step_1_2.get("denied", False):
        logger.info("CHECK 1 PASS: Step 1.2 (DescribeInstances) was DENIED by preventive control.")
        results_summary["step_1_2_denied"] = True
    else:
        logger.error("CHECK 1 FAIL: Step 1.2 (DescribeInstances) was NOT denied. "
                      "Preventive control failed to block reconnaissance.")
        results_summary["step_1_2_denied"] = False
        all_passed = False

    # Check 2: Step 1.7 was denied
    step_1_7 = _ATTACK_RESULTS.get("step_1_7", {})
    if not step_1_7.get("executed", False):
        logger.error("CHECK 2 FAIL: Step 1.7 was not executed.")
        results_summary["step_1_7_denied"] = False
        all_passed = False
    elif step_1_7.get("denied", False):
        logger.info("CHECK 2 PASS: Step 1.7 (ModifyInstanceMetadataOptions) was DENIED by preventive control.")
        results_summary["step_1_7_denied"] = True
    else:
        logger.error("CHECK 2 FAIL: Step 1.7 (ModifyInstanceMetadataOptions) was NOT denied. "
                      "Preventive control failed to block IMDS downgrade.")
        results_summary["step_1_7_denied"] = False
        all_passed = False

    # Check 3: Verify instance IMDS is still enforced (using the ORIGINAL caller, not restricted role)
    # Poll with 30-minute SLA for eventual consistency
    instance_id = _STACK_OUTPUTS.get("InstanceId")
    if instance_id:
        logger.info("CHECK 3: Verifying EC2 instance IMDS configuration is unchanged...")
        ec2 = _ec2_client()  # Use original privileged credentials
        start = _ts()
        imds_verified = False

        while (_ts() - start) < _SLA_TIMEOUT:
            try:
                resp = ec2.describe_instances(InstanceIds=[instance_id])
                instances = resp.get("Reservations", [{}])[0].get("Instances", [])
                if instances:
                    md = instances[0].get("MetadataOptions", {})
                    http_tokens = md.get("HttpTokens", "")
                    hop_limit = md.get("HttpPutResponseHopLimit", -1)
                    http_endpoint = md.get("HttpEndpoint", "")

                    logger.info("  Current IMDS: HttpTokens=%s, HopLimit=%s, HttpEndpoint=%s",
                                http_tokens, hop_limit, http_endpoint)

                    if http_tokens == "required" and hop_limit == 1:
                        logger.info("CHECK 3 PASS: IMDS configuration intact. "
                                    "IMDSv2 enforced (HttpTokens=required), HopLimit=1.")
                        results_summary["imds_intact"] = True
                        imds_verified = True
                        break
                    elif http_tokens == "optional" or hop_limit > 1:
                        logger.error("CHECK 3 FAIL: IMDS was WEAKENED! "
                                     "HttpTokens=%s, HopLimit=%s", http_tokens, hop_limit)
                        results_summary["imds_intact"] = False
                        all_passed = False
                        imds_verified = True
                        break
                    else:
                        logger.info("  IMDS state pending. Retrying in %ds...", _POLL_INTERVAL)
                else:
                    logger.warning("  Instance not found in response. Retrying...")
            except ClientError as exc:
                logger.warning("  Error checking IMDS: %s. Retrying...", exc)

            time.sleep(_POLL_INTERVAL)

        if not imds_verified:
            logger.error("CHECK 3 FAIL: Could not verify IMDS state within SLA timeout (%ds).",
                         _SLA_TIMEOUT)
            results_summary["imds_intact"] = False
            all_passed = False
    else:
        logger.error("CHECK 3 SKIP: No InstanceId available.")
        results_summary["imds_intact"] = False
        all_passed = False

    # Final summary
    logger.info("=" * 70)
    logger.info("HYPOTHESIS VERIFICATION RESULTS:")
    for check, passed in results_summary.items():
        status = "PASS" if passed else "FAIL"
        logger.info("  %s: %s", check, status)
    logger.info("OVERALL: %s", "PASS" if all_passed else "FAIL")
    logger.info("=" * 70)

    return all_passed


# ---------------------------------------------------------------------------
# 4. rollback – Tear down all resources
# ---------------------------------------------------------------------------

def rollback():
    """
    Delete the CloudFormation stack and all resources created during the experiment.
    Tolerant of already-deleted stacks and partial failures.
    """
    logger.info("=" * 70)
    logger.info("ROLLBACK: Deleting stack %s", _STACK_NAME)
    logger.info("=" * 70)

    cfn = _cfn_client()

    # If the attack succeeded in modifying IMDS (shouldn't happen if preventive works),
    # revert it before stack deletion to avoid stuck resources
    instance_id = _STACK_OUTPUTS.get("InstanceId")
    if instance_id:
        try:
            ec2 = _ec2_client()
            ec2.modify_instance_metadata_options(
                InstanceId=instance_id,
                HttpTokens="required",
                HttpEndpoint="enabled",
                HttpPutResponseHopLimit=1,
            )
            logger.info("Reverted IMDS settings on %s as safety measure.", instance_id)
        except ClientError as exc:
            logger.warning("Could not revert IMDS on %s (may already be deleted): %s",
                           instance_id, exc)

    # Terminate instance first to speed up stack deletion
    if instance_id:
        try:
            ec2 = _ec2_client()
            ec2.terminate_instances(InstanceIds=[instance_id])
            logger.info("Initiated instance termination for %s.", instance_id)
        except ClientError as exc:
            logger.warning("Could not terminate instance %s: %s", instance_id, exc)

    # Delete the stack
    try:
        cfn.delete_stack(StackName=_STACK_NAME)
        logger.info("Stack deletion initiated for %s.", _STACK_NAME)
    except ClientError as exc:
        if "does not exist" in str(exc):
            logger.info("Stack %s already deleted. Nothing to do.", _STACK_NAME)
            return True
        logger.error("Error deleting stack: %s", exc)
        return False

    # Wait for deletion
    success = _wait_for_stack(_STACK_NAME, "DELETE_COMPLETE", timeout=900)
    if success:
        logger.info("ROLLBACK: Stack %s successfully deleted.", _STACK_NAME)
    else:
        logger.error("ROLLBACK: Stack deletion may have failed. Manual cleanup may be needed.")

    return success


# ---------------------------------------------------------------------------
# Main execution (when run directly)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logger.info("SCE Experiment 1.8 - Preventive Probe")
    logger.info("Attack Steps: 1.2 (DescribeInstances), 1.7 (ModifyInstanceMetadataOptions)")
    logger.info("Hypothesis: IAM deny policy prevents both reconnaissance and IMDS downgrade")
    logger.info("")

    try:
        # Phase 1: Provision
        steady_state()

        # Phase 2: Attack
        attack()

        # Phase 3: Verify
        result = hypothesis_verification()

        if result:
            logger.info("EXPERIMENT PASSED: Preventive controls successfully blocked all attack steps.")
            sys.exit(0)
        else:
            logger.error("EXPERIMENT FAILED: One or more preventive controls did not hold.")
            sys.exit(1)

    except Exception as exc:
        logger.exception("EXPERIMENT ERROR: Unhandled exception: %s", exc)
        sys.exit(2)

    finally:
        # Phase 4: Always rollback
        try:
            rollback()
        except Exception as exc:
            logger.exception("ROLLBACK ERROR: %s", exc)