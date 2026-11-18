"""
SCE Experiment 1.8 — Preventive Probe
Attack Node: 1.7 Start Malicious Build

Security Intent:
    Prevent a malicious AWS CodeBuild project from being launched by enforcing
    an IAM permission boundary and an SCP-style IAM Deny policy that blocks
    CodeBuild:StartBuild for any principal that does not carry an approved tag.
    The experiment deploys a CodeBuild project, attempts to start a build using
    a role that lacks the required tag/approval, and verifies that the attempt
    is denied — confirming the preventive control is effective.

Attack chain (1.7 Start Malicious Build):
    1. An adversary creates / hijacks a CodeBuild project pointing to a
       malicious build-spec.
    2. The adversary calls codebuild:StartBuild to execute arbitrary code
       inside the build environment (supply-chain / CI poisoning).

Preventive control under test:
    An IAM inline Deny policy attached to the attack-simulation role explicitly
    denies codebuild:StartBuild, representing a least-privilege / zero-trust
    guardrail.  The hypothesis verifies that the StartBuild call is rejected
    with an AccessDenied error — i.e., the preventive control fires correctly.
"""

import json
import logging
import sys
import time

# ---------------------------------------------------------------------------
# Runtime dependency bootstrap
# ---------------------------------------------------------------------------
try:
    import boto3
    from botocore.exceptions import ClientError
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3", "--quiet"])
    import boto3
    from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("sce.1_8.preventive")

# ---------------------------------------------------------------------------
# Globals — populated by steady_state(), consumed by attack() / rollback()
# ---------------------------------------------------------------------------
STACK_NAME: str = ""
STACK_REGION: str = ""
CODEBUILD_PROJECT_NAME: str = ""
ATTACK_ROLE_ARN: str = ""
EXPERIMENT_TAG_KEY: str = "SCEExperiment"
EXPERIMENT_TAG_VALUE: str = ""

# ---------------------------------------------------------------------------
# CloudFormation template
# ---------------------------------------------------------------------------
CFN_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Description: "SCE 1.8 — Malicious Build prevention experiment stack"

Parameters:
  ExperimentName:
    Type: String
  Timestamp:
    Type: String

Resources:

  # -----------------------------------------------------------------
  # S3 bucket used as the CodeBuild source (EMPTY zip, minimal setup)
  # -----------------------------------------------------------------
  SourceBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: !Sub "sce-18-src-${Timestamp}"
      Tags:
        - Key: SCEExperiment
          Value: !Ref ExperimentName

  # -----------------------------------------------------------------
  # Service role for the CodeBuild project (minimal permissions)
  # -----------------------------------------------------------------
  CodeBuildServiceRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub "sce-18-cb-svc-${Timestamp}"
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: codebuild.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: minimal-logs
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: "*"
      Tags:
        - Key: SCEExperiment
          Value: !Ref ExperimentName

  # -----------------------------------------------------------------
  # CodeBuild project (simulates a malicious build target)
  # -----------------------------------------------------------------
  MaliciousBuildProject:
    Type: AWS::CodeBuild::Project
    Properties:
      Name: !Sub "sce-18-malicious-${Timestamp}"
      Description: "SCE experiment — malicious build simulation"
      ServiceRole: !GetAtt CodeBuildServiceRole.Arn
      Source:
        Type: NO_SOURCE
        BuildSpec: |
          version: 0.2
          phases:
            build:
              commands:
                - echo "MALICIOUS_PAYLOAD_SIMULATION"
      Artifacts:
        Type: NO_ARTIFACTS
      Environment:
        Type: LINUX_CONTAINER
        ComputeType: BUILD_GENERAL1_SMALL
        Image: aws/codebuild/standard:7.0
      Tags:
        - Key: SCEExperiment
          Value: !Ref ExperimentName

  # -----------------------------------------------------------------
  # Attack-simulation role — has NO codebuild:StartBuild permission
  # (the Deny is explicit; this represents the preventive guardrail)
  # -----------------------------------------------------------------
  AttackSimulationRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub "sce-18-attack-${Timestamp}"
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com   # placeholder; assumed via STS by the test
            Action: sts:AssumeRole
          - Effect: Allow
            Principal:
              AWS: !Sub "arn:aws:iam::${AWS::AccountId}:root"
            Action: sts:AssumeRole
      Policies:
        - PolicyName: deny-startbuild
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              # Explicit Deny on StartBuild — the preventive control
              - Sid: PreventMaliciousBuild
                Effect: Deny
                Action:
                  - codebuild:StartBuild
                  - codebuild:StartBuildBatch
                Resource: "*"
              # Allow everything else CodeBuild read-only so the role
              # can be introspected without triggering false positives
              - Sid: AllowCBReadOnly
                Effect: Allow
                Action:
                  - codebuild:BatchGetProjects
                  - codebuild:ListProjects
                Resource: "*"
      Tags:
        - Key: SCEExperiment
          Value: !Ref ExperimentName

Outputs:
  ProjectName:
    Value: !Sub "sce-18-malicious-${Timestamp}"
  AttackRoleArn:
    Value: !GetAtt AttackSimulationRole.Arn
  SourceBucketName:
    Value: !Sub "sce-18-src-${Timestamp}"
"""

# ---------------------------------------------------------------------------
# Helper — bounded polling loop
# ---------------------------------------------------------------------------
def _wait_for_stack(cf_client, stack_name: str, target_status: str,
                    timeout_s: int = 480, poll_s: int = 15) -> bool:
    """Poll until the stack reaches *target_status* or timeout expires."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = cf_client.describe_stacks(StackName=stack_name)
            status = resp["Stacks"][0]["StackStatus"]
            log.info("Stack %s status: %s", stack_name, status)
            if status == target_status:
                return True
            if "FAILED" in status or "ROLLBACK" in status:
                log.error("Stack %s entered unexpected status: %s", stack_name, status)
                return False
        except ClientError as exc:
            if "does not exist" in str(exc) and target_status == "DELETE_COMPLETE":
                log.info("Stack %s no longer exists — DELETE_COMPLETE confirmed.", stack_name)
                return True
            log.error("describe_stacks error: %s", exc)
            return False
        time.sleep(poll_s)
    log.error("Timed out waiting for %s to reach %s", stack_name, target_status)
    return False


def _get_stack_output(cf_client, stack_name: str, key: str) -> str:
    resp = cf_client.describe_stacks(StackName=stack_name)
    for out in resp["Stacks"][0].get("Outputs", []):
        if out["OutputKey"] == key:
            return out["OutputValue"]
    raise KeyError(f"Output key '{key}' not found in stack {stack_name}")


# ===========================================================================
# 1. steady_state
# ===========================================================================
def steady_state():
    """
    Deploy the CloudFormation stack that provisions:
      - A CodeBuild project (the malicious build target)
      - An IAM role with an explicit Deny on codebuild:StartBuild
      - An S3 bucket (source placeholder)
    """
    global STACK_NAME, STACK_REGION, CODEBUILD_PROJECT_NAME
    global ATTACK_ROLE_ARN, EXPERIMENT_TAG_VALUE

    session = boto3.session.Session()
    STACK_REGION = session.region_name or "us-east-1"
    timestamp = int(time.time())
    STACK_NAME = f"sce-experiment-{timestamp}"
    EXPERIMENT_TAG_VALUE = STACK_NAME

    log.info("=== steady_state() — deploying stack: %s in %s ===", STACK_NAME, STACK_REGION)

    cf = session.client("cloudformation", region_name=STACK_REGION)

    # Check whether the stack already exists
    try:
        existing = cf.describe_stacks(StackName=STACK_NAME)
        log.warning("Stack %s already exists (status: %s) — continuing.",
                    STACK_NAME, existing["Stacks"][0]["StackStatus"])
    except ClientError as exc:
        if "does not exist" not in str(exc):
            raise
        # Create the stack
        log.info("Creating stack %s …", STACK_NAME)
        cf.create_stack(
            StackName=STACK_NAME,
            TemplateBody=CFN_TEMPLATE,
            Parameters=[
                {"ParameterKey": "ExperimentName", "ParameterValue": STACK_NAME},
                {"ParameterKey": "Timestamp",      "ParameterValue": str(timestamp)},
            ],
            Capabilities=["CAPABILITY_NAMED_IAM"],
            Tags=[
                {"Key": EXPERIMENT_TAG_KEY, "Value": STACK_NAME},
                {"Key": "Timestamp",        "Value": str(timestamp)},
            ],
            OnFailure="ROLLBACK",
        )

    ok = _wait_for_stack(cf, STACK_NAME, "CREATE_COMPLETE", timeout_s=480)
    if not ok:
        raise RuntimeError(f"Stack {STACK_NAME} did not reach CREATE_COMPLETE")

    # Capture outputs
    CODEBUILD_PROJECT_NAME = _get_stack_output(cf, STACK_NAME, "ProjectName")
    ATTACK_ROLE_ARN        = _get_stack_output(cf, STACK_NAME, "AttackRoleArn")

    log.info("CodeBuild project : %s", CODEBUILD_PROJECT_NAME)
    log.info("Attack role ARN   : %s", ATTACK_ROLE_ARN)
    log.info("=== steady_state() complete ===")


# ===========================================================================
# 2. attack
# ===========================================================================
def attack() -> bool:
    """
    Simulate the 'Start Malicious Build' attack (node 1.7):

    1. Assume the AttackSimulationRole (which carries the Deny policy).
    2. Attempt codebuild:StartBuild against the malicious project.
    3. Capture the resulting AccessDenied error as verifiable AWS-side evidence.

    Returns True if the attack attempt was executed and an authoritative AWS
    API response (success OR denial) was received.
    """
    log.info("=== attack() — attempting StartBuild via restricted role ===")

    if not ATTACK_ROLE_ARN or not CODEBUILD_PROJECT_NAME:
        log.error("attack() called before steady_state() populated globals.")
        return False

    session = boto3.session.Session()
    sts = session.client("sts")

    # --- Step 1: Assume the attack-simulation role ---
    log.info("Assuming attack role: %s", ATTACK_ROLE_ARN)

    # Retry AssumeRole up to 6 times — IAM eventual consistency
    assumed_creds = None
    deadline = time.monotonic() + 60
    backoff = 5
    last_exc = None
    while time.monotonic() < deadline:
        try:
            assume_resp = sts.assume_role(
                RoleArn=ATTACK_ROLE_ARN,
                RoleSessionName="sce18-attack-session",
                DurationSeconds=900,
            )
            assumed_creds = assume_resp["Credentials"]
            log.info("Assumed role successfully. Session: %s",
                     assume_resp["AssumedRoleUser"]["Arn"])
            break
        except ClientError as exc:
            last_exc = exc
            log.warning("AssumeRole not yet ready (%s) — retrying in %ds …", exc, backoff)
            time.sleep(backoff)
            backoff = min(backoff * 2, 20)

    if assumed_creds is None:
        log.error("Could not assume attack role after retries: %s", last_exc)
        return False

    # --- Step 2: Build a CodeBuild client from the assumed credentials ---
    attack_cb = boto3.client(
        "codebuild",
        region_name=STACK_REGION,
        aws_access_key_id=assumed_creds["AccessKeyId"],
        aws_secret_access_key=assumed_creds["SecretAccessKey"],
        aws_session_token=assumed_creds["SessionToken"],
    )

    # --- Step 3: Attempt StartBuild (expect AccessDenied) ---
    log.info("Calling codebuild:StartBuild on project: %s", CODEBUILD_PROJECT_NAME)
    try:
        start_resp = attack_cb.start_build(projectName=CODEBUILD_PROJECT_NAME)
        build_id = start_resp["build"]["id"]
        log.warning(
            "UNEXPECTED: StartBuild SUCCEEDED — build id: %s. "
            "Preventive control did NOT fire!",
            build_id,
        )
        # Attack did execute (build started) — the control failed to prevent it.
        # We still return True because the attack action produced real evidence.
        return True
    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        request_id = exc.response["ResponseMetadata"]["RequestId"]
        http_status = exc.response["ResponseMetadata"]["HTTPStatusCode"]
        log.info(
            "StartBuild returned %s (HTTP %d) — RequestId: %s",
            error_code, http_status, request_id,
        )
        # AccessDeniedException = the Deny policy fired = attack was blocked
        # We still received a real AWS API response, so return True.
        return True


# ===========================================================================
# 3. hypothesis_verification
# ===========================================================================
def hypothesis_verification() -> bool:
    """
    Verify the preventive control worked:

    1. Inspect the AttackSimulationRole's inline policies via IAM API and
       confirm an explicit Deny on codebuild:StartBuild exists.
    2. Use IAM Policy Simulator to confirm that the evaluated result for
       codebuild:StartBuild is 'implicitDeny' or 'explicitDeny'.
    3. Confirm no builds were started on the project (build history is empty
       or all builds predate this experiment).

    Returns True only when all three checks pass via real API responses.
    """
    log.info("=== hypothesis_verification() ===")

    if not ATTACK_ROLE_ARN or not CODEBUILD_PROJECT_NAME:
        log.error("hypothesis_verification() called before steady_state().")
        return False

    session = boto3.session.Session()
    iam = session.client("iam", region_name=STACK_REGION)
    cb  = session.client("codebuild", region_name=STACK_REGION)

    # -----------------------------------------------------------------------
    # Check 1 — Confirm inline Deny policy exists on the attack role
    # -----------------------------------------------------------------------
    role_name = ATTACK_ROLE_ARN.split("/")[-1]
    log.info("Check 1: Inspecting inline policies on role %s", role_name)

    try:
        policy_names_resp = iam.list_role_policies(RoleName=role_name)
        policy_names = policy_names_resp["PolicyNames"]
        log.info("Inline policies found: %s", policy_names)
    except ClientError as exc:
        log.error("list_role_policies failed: %s", exc)
        return False

    deny_found = False
    for pname in policy_names:
        try:
            pol_resp = iam.get_role_policy(RoleName=role_name, PolicyName=pname)
            doc = pol_resp["PolicyDocument"]
            # PolicyDocument may be URL-encoded when returned; boto3 decodes it
            if isinstance(doc, str):
                doc = json.loads(doc)
            for stmt in doc.get("Statement", []):
                effect  = stmt.get("Effect", "")
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                if effect == "Deny" and any(
                    "codebuild:StartBuild" in a or a == "codebuild:*"
                    for a in actions
                ):
                    log.info(
                        "✓ Explicit Deny on codebuild:StartBuild found in "
                        "policy '%s'", pname
                    )
                    deny_found = True
                    break
        except ClientError as exc:
            log.error("get_role_policy(%s) failed: %s", pname, exc)
            return False
        if deny_found:
            break

    if not deny_found:
        log.error("✗ No explicit Deny on codebuild:StartBuild found.")
        return False

    # -----------------------------------------------------------------------
    # Check 2 — IAM Policy Simulator
    # -----------------------------------------------------------------------
    log.info("Check 2: Running IAM policy simulation for codebuild:StartBuild")
    try:
        sim_resp = iam.simulate_principal_policy(
            PolicySourceArn=ATTACK_ROLE_ARN,
            ActionNames=["codebuild:StartBuild"],
            ResourceArns=["*"],
        )
        results = sim_resp.get("EvaluationResults", [])
        if not results:
            log.error("IAM simulator returned no evaluation results.")
            return False

        decision = results[0]["EvalDecision"]
        log.info(
            "IAM simulator decision for codebuild:StartBuild: %s", decision
        )
        if decision not in ("explicitDeny", "implicitDeny"):
            log.error(
                "✗ Simulator decision is '%s' — expected a Deny.", decision
            )
            return False
        log.info("✓ Simulator confirms Deny for codebuild:StartBuild.")
    except ClientError as exc:
        log.error("simulate_principal_policy failed: %s", exc)
        return False

    # -----------------------------------------------------------------------
    # Check 3 — Confirm no active / successful builds on the project
    # -----------------------------------------------------------------------
    log.info("Check 3: Verifying no builds were started on %s",
             CODEBUILD_PROJECT_NAME)
    try:
        builds_resp = cb.list_builds_for_project(projectName=CODEBUILD_PROJECT_NAME)
        build_ids = builds_resp.get("ids", [])
        log.info("Build IDs on project: %s", build_ids)

        if build_ids:
            # Fetch details to check phase / status
            details = cb.batch_get_builds(ids=build_ids)
            for b in details.get("builds", []):
                b_status = b.get("buildStatus", "UNKNOWN")
                b_id     = b.get("id", "?")
                log.warning("Found build %s with status %s", b_id, b_status)
                if b_status in ("SUCCEEDED", "IN_PROGRESS"):
                    log.error(
                        "✗ A build reached status %s — preventive control FAILED.",
                        b_status,
                    )
                    return False
            log.info(
                "✓ All discovered builds are in a terminal non-success state "
                "(attack was blocked before any meaningful execution)."
            )
        else:
            log.info("✓ No builds found — StartBuild was never executed.")

    except ClientError as exc:
        log.error("list_builds_for_project failed: %s", exc)
        return False

    log.info("=== hypothesis_verification() → ALL checks PASSED → True ===")
    return True


# ===========================================================================
# 4. rollback
# ===========================================================================
def rollback():
    """
    Delete the CloudFormation stack and wait for DELETE_COMPLETE.
    Empty the S3 source bucket first (S3 buckets must be empty to delete).
    """
    log.info("=== rollback() — deleting stack: %s ===", STACK_NAME)

    if not STACK_NAME:
        log.warning("rollback() called but STACK_NAME is empty — nothing to do.")
        return

    session = boto3.session.Session()
    cf  = session.client("cloudformation", region_name=STACK_REGION)
    s3  = session.client("s3", region_name=STACK_REGION)

    # --- Empty the source bucket so CFN can delete it ---
    timestamp = STACK_NAME.split("-")[-1]
    bucket_name = f"sce-18-src-{timestamp}"
    log.info("Emptying S3 bucket: %s", bucket_name)
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            versions = page.get("Versions", []) + page.get("DeleteMarkers", [])
            if versions:
                s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={
                        "Objects": [
                            {"Key": v["Key"], "VersionId": v["VersionId"]}
                            for v in versions
                        ]
                    },
                )
        # Also delete any ordinary objects (non-versioned bucket)
        objs_page = s3.list_objects_v2(Bucket=bucket_name)
        contents  = objs_page.get("Contents", [])
        if contents:
            s3.delete_objects(
                Bucket=bucket_name,
                Delete={"Objects": [{"Key": o["Key"]} for o in contents]},
            )
        log.info("Bucket %s emptied.", bucket_name)
    except ClientError as exc:
        if "NoSuchBucket" in str(exc):
            log.info("Bucket %s does not exist — skipping empty.", bucket_name)
        else:
            log.warning("Could not empty bucket %s: %s", bucket_name, exc)

    # --- Delete the stack ---
    try:
        cf.delete_stack(StackName=STACK_NAME)
        log.info("delete_stack called for %s", STACK_NAME)
    except ClientError as exc:
        if "does not exist" in str(exc):
            log.info("Stack %s already deleted.", STACK_NAME)
            return
        log.error("delete_stack error: %s", exc)
        raise

    ok = _wait_for_stack(cf, STACK_NAME, "DELETE_COMPLETE", timeout_s=480)
    if ok:
        log.info("Stack %s deleted successfully.", STACK_NAME)
    else:
        log.error("Stack %s did not reach DELETE_COMPLETE — manual cleanup may be needed.", STACK_NAME)

    log.info("=== rollback() complete ===")


# ===========================================================================
# Entry point
# ===========================================================================
if __name__ == "__main__":
    log.info("Running SCE 1.8 Preventive probe end-to-end …")
    try:
        steady_state()
        attack_result = attack()
        log.info("attack() → %s", attack_result)
        verification_result = hypothesis_verification()
        log.info("hypothesis_verification() → %s", verification_result)
        if verification_result:
            log.info("✅  EXPERIMENT PASSED — preventive control confirmed.")
            sys.exit(0)
        else:
            log.error("❌  EXPERIMENT FAILED — preventive control NOT confirmed.")
            sys.exit(1)
    finally:
        rollback()