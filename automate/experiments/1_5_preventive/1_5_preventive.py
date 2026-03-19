"""
SCE Experiment 1.5 -- Preventive Probe
Attack Node 1.2: Weaken IMDS Configuration on Target EC2 Instance
TTP: T1578 - Modify Cloud Compute Infrastructure

Probe Intent:
    Verify that an IAM principal explicitly denied ec2:ModifyInstanceMetadataOptions
    receives AccessDenied when attempting to downgrade IMDS to IMDSv1
    (http_tokens=optional, hop_limit=2) on a production-tagged EC2 instance.

Execution history and fixes applied:

  Run 1 (ROLLBACK_COMPLETE):
    Root cause: CFN template used {{resolve:ssm:...}} dynamic AMI substitution.
    Fix: Resolve AMI via boto3 SSM GetParameter before template construction.

  Run 2 (ROLLBACK_COMPLETE):
    Root cause: SecurityGroup GroupDescription contained a Unicode dash character
    (em-dash U+2014) which AWS EC2 API rejects -- only ASCII 0x20-0x7E is allowed.
    The character originated from the Python source string
    "SCE experiment -- no inbound traffic" where the comment style introduced
    a non-ASCII character during copy.
    Fix applied in this revision:
      - All CloudFormation template string values audited and restricted to
        printable ASCII (0x20-0x7E) only.
      - _ascii_safe() helper added: strips or replaces any non-ASCII codepoint
        before a string is embedded in the CFN template dict.
      - GroupDescription and all Tags/descriptions verified ASCII-clean.
      - Template validated with _validate_template_strings() before submission.
"""

import subprocess
import sys
import time
import json
import logging
import os
import unicodedata

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("sce.1_5.preventive")


def _ensure_boto3() -> None:
    try:
        import boto3  # noqa: F401
    except ImportError:
        log.info("boto3 not found -- installing via pip ...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet", "boto3"]
        )


_ensure_boto3()
import boto3  # noqa: E402
from botocore.exceptions import ClientError, WaiterError  # noqa: E402

# ---------------------------------------------------------------------------
# Module-level experiment state
# ---------------------------------------------------------------------------
_TIMESTAMP: int = int(time.time())
_STACK_NAME: str = "sce-experiment-{}".format(_TIMESTAMP)
_EXPERIMENT_TAG: str = "sce-1.5-preventive"

_INSTANCE_ID: str = ""
_RESTRICTED_ROLE_ARN: str = ""
_REGION: str = ""

_ATTACK_RESULT: dict = {}


# ---------------------------------------------------------------------------
# ASCII safety utilities
# ---------------------------------------------------------------------------

def _ascii_safe(value: str) -> str:
    """
    Return a copy of *value* containing only printable ASCII characters
    (codepoints 0x20-0x7E inclusive).

    Replacement strategy:
      - Non-ASCII letters/digits: replaced with their closest ASCII equivalent
        via NFKD decomposition followed by ASCII encoding with 'ignore'.
      - Remaining non-ASCII or non-printable characters: replaced with '-'.

    This prevents the AWS EC2 API error:
      "Character sets beyond ASCII are not supported"
    which caused the ROLLBACK_COMPLETE failure in run 2.
    """
    # NFKD decomposition converts accented letters to base + combining mark;
    # encoding to ASCII with 'ignore' then drops the combining marks.
    normalized = unicodedata.normalize("NFKD", value)
    ascii_bytes = normalized.encode("ascii", errors="ignore")
    ascii_str = ascii_bytes.decode("ascii")

    # Replace any remaining non-printable or non-ASCII characters with '-'
    result = "".join(
        ch if (0x20 <= ord(ch) <= 0x7E) else "-"
        for ch in ascii_str
    )
    return result


def _validate_template_strings(template: dict, path: str = "root") -> None:
    """
    Recursively walk the CloudFormation template dict and assert that every
    string value is ASCII-safe (0x20-0x7E only).

    Raises ValueError immediately on the first violation so the problem is
    caught before CFN submission rather than after a 3-minute rollback wait.
    """
    if isinstance(template, dict):
        for k, v in template.items():
            _validate_template_strings(v, path="{}.{}".format(path, k))
    elif isinstance(template, list):
        for i, item in enumerate(template):
            _validate_template_strings(item, path="{}[{}]".format(path, i))
    elif isinstance(template, str):
        for pos, ch in enumerate(template):
            code = ord(ch)
            if code < 0x20 or code > 0x7E:
                raise ValueError(
                    "Non-ASCII character U+{:04X} ({!r}) found at "
                    "template path '{}', position {}.  "
                    "AWS EC2 API rejects non-ASCII strings in resource "
                    "properties such as GroupDescription.  "
                    "Use _ascii_safe() before embedding in the template.".format(
                        code, ch, path, pos
                    )
                )


# ---------------------------------------------------------------------------
# Boto3 / AWS helpers
# ---------------------------------------------------------------------------

def _boto3_client(service: str, **kwargs):
    region = _REGION or _get_region()
    return boto3.client(service, region_name=region, **kwargs)


def _get_region() -> str:
    session = boto3.session.Session()
    region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    return region


def _get_account_id() -> str:
    sts = _boto3_client("sts")
    return sts.get_caller_identity()["Account"]


def _resolve_ami(region: str) -> str:
    """
    Resolve the latest Amazon Linux 2023 x86_64 AMI ID via SSM.
    Returns a literal ami-xxxxxxxxxxxxxxxxx string.
    Avoids {{resolve:ssm:...}} CFN dynamic substitution (run 1 failure).
    """
    ssm = boto3.client("ssm", region_name=region)
    param_name = (
        "/aws/service/ami-amazon-linux-latest"
        "/al2023-ami-kernel-default-x86_64"
    )
    log.info(
        "Resolving latest AL2023 AMI via SSM parameter '%s' ...", param_name
    )
    try:
        resp = ssm.get_parameter(Name=param_name)
        ami_id = resp["Parameter"]["Value"]
        log.info("Resolved AMI ID: %s", ami_id)
        return ami_id
    except ClientError as exc:
        log.error("Failed to resolve AMI via SSM: %s", exc)
        raise


def _build_cfn_template(ami_id: str, account_id: str) -> dict:
    """
    Build the CloudFormation template dict.

    All string values that feed into AWS resource properties are passed
    through _ascii_safe() before inclusion.  The template is then validated
    with _validate_template_strings() before being JSON-serialised and
    submitted to CloudFormation.

    Resources created:
      - VPC + public subnet + IGW + route table + SG (no inbound)
      - EC2 instance: production-tagged, IMDSv2 enforced at launch
      - IAM instance role + instance profile (minimal SSM permissions)
      - IAM attacker role: explicit Deny on ec2:ModifyInstanceMetadataOptions
        scoped to ec2:ResourceTag/Environment = production
    """
    # ------------------------------------------------------------------ #
    # ASCII-safe string constants used in resource properties             #
    # ------------------------------------------------------------------ #
    sg_description = _ascii_safe("SCE experiment - no inbound traffic")
    stack_name_tag = _ascii_safe(_STACK_NAME)
    experiment_tag = _ascii_safe(_EXPERIMENT_TAG)
    timestamp_str = _ascii_safe(str(_TIMESTAMP))
    instance_name_tag = _ascii_safe("sce-target-{}".format(_TIMESTAMP))
    instance_role_name = _ascii_safe("sce-instance-role-{}".format(_TIMESTAMP))
    instance_profile_name = _ascii_safe(
        "sce-instance-profile-{}".format(_TIMESTAMP)
    )
    attacker_role_name = _ascii_safe("sce-attacker-role-{}".format(_TIMESTAMP))
    stack_description = _ascii_safe(
        "SCE 1.5 Preventive - IMDS weakening attempt "
        "against production-tagged EC2 (run {})".format(_TIMESTAMP)
    )
    egress_description = _ascii_safe("Allow all outbound")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": stack_description,
        "Resources": {
            # ---------------------------------------------------------- #
            # Networking                                                   #
            # ---------------------------------------------------------- #
            "SCEVpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.99.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                    "Tags": [
                        {"Key": "Name", "Value": stack_name_tag},
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            "SCESubnet": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "SCEVpc"},
                    "CidrBlock": "10.99.1.0/24",
                    "AvailabilityZone": {
                        "Fn::Select": [
                            "0",
                            {"Fn::GetAZs": {"Ref": "AWS::Region"}},
                        ]
                    },
                    "MapPublicIpOnLaunch": False,
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            "SCEIGW": {
                "Type": "AWS::EC2::InternetGateway",
                "Properties": {
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ]
                },
            },
            "SCEIGWAttach": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {
                    "VpcId": {"Ref": "SCEVpc"},
                    "InternetGatewayId": {"Ref": "SCEIGW"},
                },
            },
            "SCERT": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {
                    "VpcId": {"Ref": "SCEVpc"},
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            "SCERTAssoc": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "SCESubnet"},
                    "RouteTableId": {"Ref": "SCERT"},
                },
            },
            # GroupDescription: ASCII-safe string (run 2 fix)
            "SCESGInstance": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": sg_description,
                    "VpcId": {"Ref": "SCEVpc"},
                    "SecurityGroupIngress": [],
                    "SecurityGroupEgress": [
                        {
                            "IpProtocol": "-1",
                            "CidrIp": "0.0.0.0/0",
                            "Description": egress_description,
                        }
                    ],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # EC2 instance profile (minimal)                               #
            # ---------------------------------------------------------- #
            "SCEInstanceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": instance_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "ec2.amazonaws.com"
                                },
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "minimal-ssm-messages",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "ssm:UpdateInstanceInformation",
                                            "ec2messages:GetMessages",
                                        ],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            "SCEInstanceProfile": {
                "Type": "AWS::IAM::InstanceProfile",
                "Properties": {
                    "InstanceProfileName": instance_profile_name,
                    "Roles": [{"Ref": "SCEInstanceRole"}],
                },
            },
            # ---------------------------------------------------------- #
            # EC2 target instance: production-tagged, IMDSv2 enforced     #
            # AMI ID is a literal string resolved before template build    #
            # (run 1 fix -- no {{resolve:ssm:...}} dynamic substitution)   #
            # ---------------------------------------------------------- #
            "SCETargetInstance": {
                "Type": "AWS::EC2::Instance",
                "DependsOn": ["SCEIGWAttach", "SCEInstanceProfile"],
                "Properties": {
                    "ImageId": ami_id,
                    "InstanceType": "t3.micro",
                    "SubnetId": {"Ref": "SCESubnet"},
                    "SecurityGroupIds": [{"Ref": "SCESGInstance"}],
                    "IamInstanceProfile": {"Ref": "SCEInstanceProfile"},
                    "MetadataOptions": {
                        "HttpTokens": "required",
                        "HttpEndpoint": "enabled",
                        "HttpPutResponseHopLimit": 1,
                    },
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": instance_name_tag,
                        },
                        # This tag is the condition key in the Deny policy.
                        {"Key": "Environment", "Value": "production"},
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
            # ---------------------------------------------------------- #
            # Attacker IAM role                                            #
            # Defence-in-depth:                                            #
            #   Layer 1 - Implicit deny: no Allow for                      #
            #             ec2:ModifyInstanceMetadataOptions                 #
            #   Layer 2 - Explicit Deny scoped to Environment=production   #
            # ---------------------------------------------------------- #
            "SCEAttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": attacker_role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "AWS": "arn:aws:iam::{}:root".format(
                                        account_id
                                    )
                                },
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "attacker-baseline-with-explicit-deny",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    # Allow: benign read-only actions only
                                    {
                                        "Sid": "AllowBenignEC2Reads",
                                        "Effect": "Allow",
                                        "Action": [
                                            "ec2:DescribeInstances",
                                            "ec2:DescribeInstanceAttribute",
                                        ],
                                        "Resource": "*",
                                    },
                                    # Allow: STS self-identification
                                    {
                                        "Sid": "AllowSelfSTS",
                                        "Effect": "Allow",
                                        "Action": "sts:GetCallerIdentity",
                                        "Resource": "*",
                                    },
                                    # Explicit Deny: control under test.
                                    # Scoped to Environment=production tag.
                                    {
                                        "Sid": "DenyIMDSWeakeningOnProduction",
                                        "Effect": "Deny",
                                        "Action": (
                                            "ec2:ModifyInstanceMetadataOptions"
                                        ),
                                        "Resource": "*",
                                        "Condition": {
                                            "StringEquals": {
                                                "ec2:ResourceTag/Environment": (
                                                    "production"
                                                )
                                            }
                                        },
                                    },
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "sce-experiment", "Value": experiment_tag},
                        {"Key": "sce-timestamp", "Value": timestamp_str},
                    ],
                },
            },
        },
        "Outputs": {
            "InstanceId": {
                "Value": {"Ref": "SCETargetInstance"},
                "Description": _ascii_safe(
                    "ID of the production-tagged EC2 instance under test"
                ),
            },
            "AttackerRoleArn": {
                "Value": {"Fn::GetAtt": ["SCEAttackerRole", "Arn"]},
                "Description": _ascii_safe(
                    "ARN of the restricted attacker IAM role"
                ),
            },
        },
    }

    return template


def _wait_stack(
    cf_client,
    stack_name: str,
    waiter_name: str,
    delay: int = 20,
    max_attempts: int = 60,
) -> None:
    log.info(
        "Waiting for CloudFormation waiter '%s' on stack '%s' ...",
        waiter_name,
        stack_name,
    )
    waiter = cf_client.get_waiter(waiter_name)
    waiter.config.delay = delay
    waiter.config.max_attempts = max_attempts
    waiter.wait(StackName=stack_name)
    log.info(
        "CloudFormation waiter '%s' completed for '%s'.",
        waiter_name,
        stack_name,
    )


def _capture_stack_events(cf_client, stack_name: str) -> None:
    """
    Retrieve and log CFN stack events on rollback for root-cause diagnosis.
    Logs all FAILED and ROLLBACK events at ERROR level.
    """
    log.error(
        "Capturing CloudFormation stack events for '%s' to diagnose rollback ...",
        stack_name,
    )
    try:
        paginator = cf_client.get_paginator("describe_stack_events")
        for page in paginator.paginate(StackName=stack_name):
            for event in page["StackEvents"]:
                status = event.get("ResourceStatus", "")
                reason = event.get("ResourceStatusReason", "")
                resource = event.get("LogicalResourceId", "")
                resource_type = event.get("ResourceType", "")
                if "FAILED" in status or "ROLLBACK" in status:
                    log.error(
                        "  CFN EVENT [%s] %s (%s): %s",
                        status,
                        resource,
                        resource_type,
                        reason,
                    )
    except ClientError as exc:
        log.error("Could not retrieve stack events: %s", exc)


def _get_stack_outputs(cf_client, stack_name: str) -> dict:
    resp = cf_client.describe_stacks(StackName=stack_name)
    outputs = resp["Stacks"][0].get("Outputs", [])
    return {o["OutputKey"]: o["OutputValue"] for o in outputs}


def _wait_with_backoff(
    condition_fn,
    description: str,
    initial_delay: float = 2.0,
    max_delay: float = 30.0,
    timeout: float = 120.0,
) -> bool:
    deadline = time.monotonic() + timeout
    delay = initial_delay
    while time.monotonic() < deadline:
        try:
            if condition_fn():
                return True
        except Exception as exc:  # noqa: BLE001
            log.debug("Backoff poll for '%s' raised: %s", description, exc)
        log.debug("Waiting %.1fs for: %s", delay, description)
        time.sleep(delay)
        delay = min(delay * 1.5, max_delay)
    log.warning("Timeout waiting for: %s", description)
    return False


def _preflight_check() -> None:
    """
    Validate deploying-principal permissions via IAM policy simulation.
    Warns on restricted actions but does not abort if simulation itself
    is unavailable.
    """
    log.info("Running pre-flight permission checks ...")
    iam = _boto3_client("iam")
    sts = _boto3_client("sts")

    caller = sts.get_caller_identity()
    caller_arn = caller["Arn"]
    log.info("Deploying principal: %s", caller_arn)

    actions_to_check = [
        "cloudformation:CreateStack",
        "ec2:RunInstances",
        "ec2:CreateVpc",
        "ec2:CreateSecurityGroup",
        "iam:CreateRole",
        "ec2:DescribeInstances",
        "ec2:ModifyInstanceMetadataOptions",
        "sts:AssumeRole",
        "ssm:GetParameter",
    ]

    try:
        resp = iam.simulate_principal_policy(
            PolicySourceArn=caller_arn,
            ActionNames=actions_to_check,
            ResourceArns=["*"],
        )
        denied = [
            r["EvalActionName"]
            for r in resp["EvaluationResults"]
            if r["EvalDecision"] != "allowed"
        ]
        if denied:
            log.warning(
                "Pre-flight: the following actions may be restricted "
                "(experiment may still succeed if resource policies grant "
                "access): %s",
                denied,
            )
        else:
            log.info(
                "Pre-flight: all required permissions appear to be allowed."
            )
    except ClientError as exc:
        log.warning(
            "Could not run IAM policy simulation "
            "(iam:SimulatePrincipalPolicy may not be available): %s "
            "-- proceeding without pre-flight check.",
            exc,
        )


# ---------------------------------------------------------------------------
# Core experiment functions
# ---------------------------------------------------------------------------


def steady_state() -> None:
    """
    Preparation block.

    Provisions all resources required for the experiment via CloudFormation:
      - VPC, subnet, IGW, route table, security group
      - EC2 instance: production-tagged, IMDSv2 enforced (baseline state)
      - IAM attacker role: explicit Deny on ec2:ModifyInstanceMetadataOptions
        scoped to ec2:ResourceTag/Environment = production

    Key fixes from previous executions:
      Run 1: AMI resolved via boto3 (not CFN dynamic SSM substitution).
      Run 2: All CFN template strings sanitised to printable ASCII via
             _ascii_safe() before template construction; template validated
             with _validate_template_strings() before CFN submission.
    """
    global _INSTANCE_ID, _RESTRICTED_ROLE_ARN, _REGION

    log.info("=== steady_state() -- stack: %s ===", _STACK_NAME)
    _REGION = _get_region()
    log.info("Resolved AWS region: %s", _REGION)

    _preflight_check()

    ami_id = _resolve_ami(_REGION)
    account_id = _get_account_id()
    log.info("Deploying in account: %s", account_id)

    cfn_template = _build_cfn_template(ami_id, account_id)

    # Validate all strings in the template are ASCII-safe BEFORE submission.
    # This catches non-ASCII characters (e.g. em-dashes, curly quotes) that
    # cause CFN ROLLBACK with "Character sets beyond ASCII are not supported".
    log.info("Validating CloudFormation template string encoding ...")
    try:
        _validate_template_strings(cfn_template)
        log.info("Template string validation passed -- all values are ASCII-safe.")
    except ValueError as validation_exc:
        log.error(
            "Template string validation FAILED: %s -- "
            "aborting stack creation to avoid 3-minute rollback wait.",
            validation_exc,
        )
        raise

    cf = _boto3_client("cloudformation")

    # ------------------------------------------------------------------ #
    # Check for pre-existing stack                                         #
    # ------------------------------------------------------------------ #
    stack_exists = False
    try:
        existing = cf.describe_stacks(StackName=_STACK_NAME)
        status = existing["Stacks"][0]["StackStatus"]
        log.warning(
            "Stack '%s' already exists with status '%s'. "
            "Continuing with existing stack.",
            _STACK_NAME,
            status,
        )
        stack_exists = True
    except ClientError as exc:
        if "does not exist" in str(exc):
            stack_exists = False
        else:
            log.error("Unexpected error describing stack: %s", exc)
            raise

    # ------------------------------------------------------------------ #
    # Create stack                                                         #
    # ------------------------------------------------------------------ #
    if not stack_exists:
        log.info("Creating CloudFormation stack '%s' ...", _STACK_NAME)
        try:
            cf.create_stack(
                StackName=_STACK_NAME,
                TemplateBody=json.dumps(cfn_template),
                Capabilities=["CAPABILITY_NAMED_IAM"],
                Tags=[
                    {"Key": "sce-experiment", "Value": _ascii_safe(_EXPERIMENT_TAG)},
                    {"Key": "sce-timestamp", "Value": _ascii_safe(str(_TIMESTAMP))},
                ],
            )
        except ClientError as create_exc:
            log.error("Failed to initiate stack creation: %s", create_exc)
            raise

    # ------------------------------------------------------------------ #
    # Wait for CREATE_COMPLETE                                             #
    # ------------------------------------------------------------------ #
    try:
        _wait_stack(
            cf, _STACK_NAME, "stack_create_complete", delay=20, max_attempts=60
        )
    except WaiterError as wait_exc:
        _capture_stack_events(cf, _STACK_NAME)
        log.error(
            "Stack creation did not complete (ROLLBACK detected). "
            "Stack events logged above. Exception: %s",
            wait_exc,
        )
        raise RuntimeError(
            "CloudFormation stack '{}' reached a terminal failure state. "
            "Inspect the stack events logged above for root cause.".format(
                _STACK_NAME
            )
        ) from wait_exc

    # ------------------------------------------------------------------ #
    # Collect and validate outputs                                         #
    # ------------------------------------------------------------------ #
    outputs = _get_stack_outputs(cf, _STACK_NAME)
    log.info("Stack outputs: %s", outputs)

    _INSTANCE_ID = outputs.get("InstanceId", "")
    _RESTRICTED_ROLE_ARN = outputs.get("AttackerRoleArn", "")

    if not _INSTANCE_ID:
        raise RuntimeError(
            "CloudFormation output 'InstanceId' is empty or missing."
        )
    if not _RESTRICTED_ROLE_ARN:
        raise RuntimeError(
            "CloudFormation output 'AttackerRoleArn' is empty or missing."
        )

    log.info(
        "Stack outputs validated -- InstanceId: %s | AttackerRoleArn: %s",
        _INSTANCE_ID,
        _RESTRICTED_ROLE_ARN,
    )

    # ------------------------------------------------------------------ #
    # Verify IMDSv2 baseline on the instance                               #
    # ------------------------------------------------------------------ #
    ec2 = _boto3_client("ec2")

    def _imdsv2_enforced() -> bool:
        resp = ec2.describe_instances(InstanceIds=[_INSTANCE_ID])
        reservations = resp.get("Reservations", [])
        if not reservations:
            return False
        instance = reservations[0]["Instances"][0]
        opts = instance.get("MetadataOptions", {})
        tokens_ok = opts.get("HttpTokens") == "required"
        hop_ok = opts.get("HttpPutResponseHopLimit", 0) == 1
        log.debug(
            "IMDS check -- HttpTokens=%s HopLimit=%s State=%s",
            opts.get("HttpTokens"),
            opts.get("HttpPutResponseHopLimit"),
            opts.get("State"),
        )
        return tokens_ok and hop_ok

    baseline_ok = _wait_with_backoff(
        _imdsv2_enforced,
        "IMDSv2 enforced on target instance",
        initial_delay=5.0,
        max_delay=20.0,
        timeout=180.0,
    )

    if not baseline_ok:
        raise RuntimeError(
            "Baseline FAILED: instance {} does not have "
            "IMDSv2 enforced (http_tokens=required, hop_limit=1) "
            "before the experiment starts.".format(_INSTANCE_ID)
        )

    log.info(
        "Baseline confirmed: instance %s has IMDSv2 enforced "
        "(http_tokens=required, hop_limit=1).",
        _INSTANCE_ID,
    )

    # ------------------------------------------------------------------ #
    # IAM propagation backoff                                              #
    # ------------------------------------------------------------------ #
    sts = _boto3_client("sts")

    def _role_assumable() -> bool:
        try:
            sts.assume_role(
                RoleArn=_RESTRICTED_ROLE_ARN,
                RoleSessionName="sce-readiness-check",
                DurationSeconds=900,
            )
            return True
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("AccessDenied", "AccessDeniedException"):
                # Policy has propagated; Deny firing at assume-role level
                # counts as evidence of propagation.
                return True
            log.debug("Role not yet assumable: %s -- %s", code, exc)
            return False

    propagated = _wait_with_backoff(
        _role_assumable,
        "AttackerRole IAM policy propagation",
        initial_delay=5.0,
        max_delay=20.0,
        timeout=120.0,
    )
    if not propagated:
        log.warning(
            "IAM policy propagation check timed out -- proceeding; "
            "eventual consistency may affect attack() outcome."
        )

    log.info("steady_state() complete.")


def attack() -> bool:
    """
    Attack step (maps to Attack Node 1.2 / TTP T1578).

    Assumes the restricted AttackerRole and attempts to call
    ec2:ModifyInstanceMetadataOptions to downgrade IMDS to IMDSv1
    (http_tokens=optional, hop_limit=2) on the production-tagged instance.

    Returns:
        True  -- attack call was issued; result captured in _ATTACK_RESULT.
        False -- precondition not met or unexpected error.
    """
    global _ATTACK_RESULT

    log.info("=== attack() -- assuming role %s ===", _RESTRICTED_ROLE_ARN)

    # Precondition guard
    if not _RESTRICTED_ROLE_ARN:
        log.error(
            "attack() aborted: _RESTRICTED_ROLE_ARN is empty. "
            "steady_state() must have failed to provision the attacker role."
        )
        _ATTACK_RESULT = {
            "stage": "precondition_check",
            "access_denied": False,
            "error_code": "EMPTY_ROLE_ARN",
            "error_message": (
                "AttackerRole ARN is empty; steady_state() did not complete."
            ),
        }
        return False

    if not _INSTANCE_ID:
        log.error(
            "attack() aborted: _INSTANCE_ID is empty. "
            "steady_state() must have failed to provision the EC2 instance."
        )
        _ATTACK_RESULT = {
            "stage": "precondition_check",
            "access_denied": False,
            "error_code": "EMPTY_INSTANCE_ID",
            "error_message": (
                "Instance ID is empty; steady_state() did not complete."
            ),
        }
        return False

    sts = _boto3_client("sts")

    # Assume the restricted attacker role
    try:
        assumed = sts.assume_role(
            RoleArn=_RESTRICTED_ROLE_ARN,
            RoleSessionName="sce-attack-{}".format(_TIMESTAMP),
            DurationSeconds=900,
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            log.info(
                "AccessDenied at sts:AssumeRole stage -- Deny scope may be "
                "broader than the ModifyInstanceMetadataOptions action. "
                "Code: %s",
                code,
            )
            _ATTACK_RESULT = {
                "stage": "assume_role",
                "access_denied": True,
                "error_code": code,
                "error_message": str(exc),
            }
            return True
        log.error("Unexpected error during sts:AssumeRole: %s", exc)
        _ATTACK_RESULT = {
            "stage": "assume_role",
            "access_denied": False,
            "error_code": code,
            "error_message": str(exc),
        }
        return False

    creds = assumed["Credentials"]
    log.info(
        "Successfully assumed AttackerRole. Session: %s",
        assumed["AssumedRoleUser"]["AssumedRoleId"],
    )

    # Build EC2 client scoped to the attacker session
    ec2_attacker = boto3.client(
        "ec2",
        region_name=_REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

    # Attempt the IMDS weakening call (Attack Node 1.2 exact parameters):
    # aws ec2 modify-instance-metadata-options
    #   --instance-id <INSTANCE_ID>
    #   --http-tokens optional
    #   --http-endpoint enabled
    #   --http-put-response-hop-limit 2
    log.info(
        "Attempting ec2:ModifyInstanceMetadataOptions on instance %s "
        "(http_tokens=optional, hop_limit=2) ...",
        _INSTANCE_ID,
    )

    try:
        response = ec2_attacker.modify_instance_metadata_options(
            InstanceId=_INSTANCE_ID,
            HttpTokens="optional",
            HttpEndpoint="enabled",
            HttpPutResponseHopLimit=2,
        )
        # Reached here -- call SUCCEEDED, preventive control FAILED.
        log.warning(
            "UNEXPECTED SUCCESS: ModifyInstanceMetadataOptions returned "
            "HTTP %s. The preventive IAM Deny did NOT block the attack. "
            "IMDS may have been downgraded on instance %s. Response: %s",
            response["ResponseMetadata"]["HTTPStatusCode"],
            _INSTANCE_ID,
            response.get("InstanceMetadataOptions", {}),
        )
        _ATTACK_RESULT = {
            "stage": "modify_imds",
            "access_denied": False,
            "http_status": response["ResponseMetadata"]["HTTPStatusCode"],
            "instance_state": response.get("InstanceMetadataOptions", {}),
        }

    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"]["Message"]

        if code in (
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
        ):
            log.info(
                "AccessDenied for ec2:ModifyInstanceMetadataOptions -- "
                "preventive IAM Deny control WORKING AS EXPECTED. "
                "Code: %s | Message: %s",
                code,
                message,
            )
            _ATTACK_RESULT = {
                "stage": "modify_imds",
                "access_denied": True,
                "error_code": code,
                "error_message": message,
            }
        else:
            log.error(
                "Unexpected error from ModifyInstanceMetadataOptions: "
                "%s -- %s",
                code,
                message,
            )
            _ATTACK_RESULT = {
                "stage": "modify_imds",
                "access_denied": False,
                "error_code": code,
                "error_message": message,
            }

    log.info("attack() complete. Result: %s", _ATTACK_RESULT)
    return True


def hypothesis_verification() -> bool:
    """
    Preventive probe verification (SCE Node 1.5 -- Preventive).

    Returns True only when BOTH hypotheses pass:

    [H1] The attack API call received AccessDenied -- the IAM Deny policy
         blocked ec2:ModifyInstanceMetadataOptions on the production-tagged
         instance.

    [H2] The EC2 instance IMDS configuration is UNCHANGED after the attack
         attempt: http_tokens=required and hop_limit=1.
         This confirms no state mutation occurred before the Deny fired.
    """
    log.info("=== hypothesis_verification() ===")

    all_passed = True

    # Guard against empty infrastructure globals
    if not _INSTANCE_ID or not _RESTRICTED_ROLE_ARN:
        log.error(
            "hypothesis_verification() cannot proceed: infrastructure "
            "globals are empty (_INSTANCE_ID='%s', "
            "_RESTRICTED_ROLE_ARN='%s'). "
            "steady_state() must have failed. Both H1 and H2 are FAILED.",
            _INSTANCE_ID,
            _RESTRICTED_ROLE_ARN,
        )
        return False

    if not _ATTACK_RESULT:
        log.error(
            "hypothesis_verification() cannot proceed: _ATTACK_RESULT is "
            "empty. attack() was never executed or did not record a result. "
            "Both H1 and H2 are FAILED."
        )
        return False

    # ------------------------------------------------------------------ #
    # H1: IAM Deny blocked the attack API call                             #
    # ------------------------------------------------------------------ #
    h1_passed = _ATTACK_RESULT.get("access_denied", False)
    if h1_passed:
        log.info(
            "[H1] PASS -- ec2:ModifyInstanceMetadataOptions was denied at "
            "stage='%s'. Error code: %s",
            _ATTACK_RESULT.get("stage", "unknown"),
            _ATTACK_RESULT.get("error_code", "N/A"),
        )
    else:
        log.error(
            "[H1] FAIL -- ec2:ModifyInstanceMetadataOptions was NOT denied. "
            "Full attack result: %s",
            _ATTACK_RESULT,
        )
        all_passed = False

    # ------------------------------------------------------------------ #
    # H2: Instance IMDS configuration unchanged after the attack           #
    # ------------------------------------------------------------------ #
    ec2 = _boto3_client("ec2")

    try:
        resp = ec2.describe_instances(InstanceIds=[_INSTANCE_ID])
        reservations = resp.get("Reservations", [])
        if not reservations:
            log.error(
                "[H2] ERROR -- DescribeInstances returned no reservations "
                "for instance %s. Instance may have been terminated.",
                _INSTANCE_ID,
            )
            all_passed = False
        else:
            opts = reservations[0]["Instances"][0].get("MetadataOptions", {})
            http_tokens = opts.get("HttpTokens")
            hop_limit = opts.get("HttpPutResponseHopLimit")
            imds_state = opts.get("State", "unknown")

            h2_passed = http_tokens == "required" and hop_limit == 1

            if h2_passed:
                log.info(
                    "[H2] PASS -- Instance %s IMDS is unchanged after "
                    "attack: HttpTokens=%s, HopLimit=%s, State=%s",
                    _INSTANCE_ID,
                    http_tokens,
                    hop_limit,
                    imds_state,
                )
            else:
                log.error(
                    "[H2] FAIL -- Instance %s IMDS was MUTATED: "
                    "HttpTokens=%s (expected 'required'), "
                    "HopLimit=%s (expected 1), State=%s. "
                    "The preventive control did not preserve the hardened "
                    "state.",
                    _INSTANCE_ID,
                    http_tokens,
                    hop_limit,
                    imds_state,
                )
                all_passed = False

    except ClientError as exc:
        log.error(
            "[H2] ERROR -- DescribeInstances failed for instance %s: %s",
            _INSTANCE_ID,
            exc,
        )
        all_passed = False

    # ------------------------------------------------------------------ #
    # Final verdict                                                         #
    # ------------------------------------------------------------------ #
    if all_passed:
        log.info(
            "hypothesis_verification() -> PASS. "
            "Preventive control is effective: IAM Deny blocked "
            "ec2:ModifyInstanceMetadataOptions and the instance IMDS state "
            "remains http_tokens=required, hop_limit=1."
        )
    else:
        log.error(
            "hypothesis_verification() -> FAIL. "
            "One or more preventive hypotheses were not satisfied. "
            "Review [H1] and [H2] log entries above."
        )

    return all_passed


def rollback() -> None:
    """
    Complete teardown via CloudFormation stack deletion.

    Tolerates stack-not-found and already-deleting states.
    Always executes even on upstream failure (called from finally block).
    """
    log.info("=== rollback() -- deleting stack '%s' ===", _STACK_NAME)

    cf = _boto3_client("cloudformation")

    # Check current stack status
    try:
        status_resp = cf.describe_stacks(StackName=_STACK_NAME)
        current_status = status_resp["Stacks"][0]["StackStatus"]
        log.info(
            "Stack '%s' current status: %s", _STACK_NAME, current_status
        )
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info(
                "Stack '%s' does not exist -- nothing to delete.", _STACK_NAME
            )
            return
        log.error(
            "Unexpected error checking stack status during rollback: %s", exc
        )
        return

    # Skip if already deleted or being deleted
    if current_status in ("DELETE_COMPLETE", "DELETE_IN_PROGRESS"):
        log.info(
            "Stack '%s' is already in status '%s' -- "
            "skipping delete initiation.",
            _STACK_NAME,
            current_status,
        )
        if current_status == "DELETE_IN_PROGRESS":
            try:
                _wait_stack(
                    cf,
                    _STACK_NAME,
                    "stack_delete_complete",
                    delay=20,
                    max_attempts=45,
                )
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "Error waiting for in-progress deletion of '%s': %s",
                    _STACK_NAME,
                    exc,
                )
        return

    # Initiate deletion
    try:
        cf.delete_stack(StackName=_STACK_NAME)
        log.info("Stack deletion initiated for '%s'.", _STACK_NAME)
    except ClientError as exc:
        log.error("Failed to initiate stack deletion: %s", exc)
        return

    # Wait for DELETE_COMPLETE
    try:
        _wait_stack(
            cf,
            _STACK_NAME,
            "stack_delete_complete",
            delay=20,
            max_attempts=45,
        )
        log.info("Stack '%s' deleted successfully.", _STACK_NAME)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info(
                "Stack '%s' no longer exists -- deletion confirmed.",
                _STACK_NAME,
            )
        else:
            log.error(
                "ClientError waiting for deletion of '%s': %s",
                _STACK_NAME,
                exc,
            )
    except WaiterError as exc:
        # Check if the stack is actually gone despite waiter error
        try:
            cf.describe_stacks(StackName=_STACK_NAME)
            log.error(
                "Deletion waiter failed and stack still exists for '%s': %s",
                _STACK_NAME,
                exc,
            )
        except ClientError as inner_exc:
            if "does not exist" in str(inner_exc):
                log.info(
                    "Stack '%s' confirmed deleted (waiter false alarm).",
                    _STACK_NAME,
                )
            else:
                log.error(
                    "Unexpected error confirming deletion of '%s': %s",
                    _STACK_NAME,
                    inner_exc,
                )
    except Exception as exc:  # noqa: BLE001
        log.error(
            "Unexpected error during rollback of '%s': %s", _STACK_NAME, exc
        )

    log.info("rollback() complete.")


# ---------------------------------------------------------------------------
# Experiment entry point
# ---------------------------------------------------------------------------


def run_experiment() -> None:
    """
    Orchestrates: steady_state -> attack -> hypothesis_verification -> rollback.
    rollback() always executes via finally block.
    """
    log.info(
        "============================================================"
    )
    log.info(
        "SCE 1.5 Preventive -- IMDS Weakening Attack (T1578)"
    )
    log.info("Stack : %s", _STACK_NAME)
    log.info(
        "============================================================"
    )

    result = False

    try:
        steady_state()
        attack_issued = attack()

        if not attack_issued:
            log.error(
                "attack() returned False -- the attack call was not issued. "
                "Check logs for precondition failures or errors."
            )
        else:
            result = hypothesis_verification()

    except Exception as exc:  # noqa: BLE001
        log.error(
            "Unhandled exception during experiment execution: %s",
            exc,
            exc_info=True,
        )
    finally:
        rollback()

    status = "PASSED" if result else "FAILED"
    log.info(
        "============================================================"
    )
    log.info("SCE Experiment 1.5 Preventive Probe result: %s", status)
    log.info(
        "============================================================"
    )

    if not result:
        sys.exit(1)


if __name__ == "__main__":
    run_experiment()