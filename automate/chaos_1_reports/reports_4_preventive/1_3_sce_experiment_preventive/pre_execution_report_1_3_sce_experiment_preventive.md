# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The attack implementation in the Python file directly and precisely corresponds to ADT node 1.2 "Create Malicious CodeBuild Project":

- **Tactic match**: The ADT specifies `aws codebuild create-project` as the attack command, and the Python `attack()` function calls exactly `cb.create_project(...)` via the boto3 CodeBuild client — a direct SDK-level equivalent.
- **Technique match**: The ADT cites TTP T1552.005 (Unsecured Credentials via Cloud Instance Metadata). The malicious buildspec constructed in `attack()` explicitly harvests credentials from the ECS metadata endpoint (`http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`) and exfiltrates them to an attacker-controlled URL — a textbook implementation of T1552.005.
- **Dependencies match**: The ADT lists `iam:PassRole` and `codebuild:CreateProject` as dependencies. The CFN stack grants `AWSCodeBuildAdminAccess` (covering both) to the attack role, and `CODEBUILD_ROLE_ARN` is passed as `serviceRole`, which would normally require `iam:PassRole`.
- **Result match**: ADT states "Malicious project creation" as the result. The code captures both the success path (project ARN logged as `ATTACK SUCCEEDED`) and the blocked path (AccessDeniedException), exactly mapping to the ADT's expected outcome under the preventive control.
- **Implementation quality**: The attack phase uses assumed-role credentials (not the admin session), correctly simulating a real attacker operating through a constrained principal. The malicious buildspec is realistic and matches the credential-exfiltration scenario. Error handling is thorough, and state is correctly propagated to the hypothesis phase via function attributes.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The defense implementation corresponds fully to ADT node 1.1 "IAM Least Privilege Control":

- **Strategy match**: ADT specifies "Restrict CodeBuild IAM permissions" via "Fine-grained IAM role scoping." The CFN template deploys an explicit `Deny` managed policy (`DenyCodeBuildCreatePolicy`) on `codebuild:CreateProject`, which is precisely an IAM least-privilege mechanism at the action level.
- **AWS-native correctness**: The code correctly notes that in a single-account context (no AWS Organizations), a permission boundary/deny policy is the appropriate substitute for an SCP. The implementation uses an IAM managed policy with `"Effect": "Deny"` and `"Action": ["codebuild:CreateProject"]` on `"Resource": "*"` — this is the correct AWS-native preventive pattern.
- **Deny-overrides-Allow logic**: The attack role is deliberately given broad allow (`AWSCodeBuildAdminAccess`) alongside the explicit Deny, which correctly tests that IAM's evaluation logic (explicit Deny overrides any Allow) is functioning as expected. This is a high-fidelity test of the control's actual mechanism.
- **CFN infrastructure quality**: The CloudFormation template is well-structured with proper `DependsOn`, meaningful resource names using timestamps for uniqueness, correct trust policies, and exports for stack introspection.
- **Hypothesis cross-check**: `hypothesis_verification()` not only checks project absence but also verifies the deny policy remains attached to the attack role (`list_attached_role_policies`), validating that the control itself was not tampered with during the experiment — a defense-in-depth verification step that goes beyond minimal compliance.
- **Rollback completeness**: The `rollback()` function handles the rogue-project safety net and waits for `DELETE_COMPLETE`, ensuring no residual resources compromise the account's security posture.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The preventive probe fully corresponds to the defensive intent articulated in ADT node 1.3:

- **Probe question match**: The ADT's Preventive Probe asks "Can IAM restrictions block project creation?" The `hypothesis_verification()` function directly answers this by querying `BatchGetProjects` for the malicious project name using admin credentials (ground-truth view) — if the project is absent, the IAM restriction blocked creation; if present, it did not.
- **Steady-state hypothesis correctness**: The JSON manifest's SSH title ("Malicious CodeBuild project does not exist and deny policy is active") is operationally verified by both checks in `hypothesis_verification()`: (1) project absence via `batch_get_projects`, and (2) deny policy attachment via `list_attached_role_policies`. Both conditions must be true for the hypothesis to pass.
- **Tolerance value correctness**: The manifest sets `"tolerance": true`, consistent with the probe returning a boolean where `True` = control effective = expected steady state.
- **Chaos Toolkit structural compliance**: The manifest correctly separates SSH probes (pre/post verification) from method actions (steady_state → attack), follows the Chaos Toolkit schema, and includes a rollback action. The Python module path is consistent across all manifest references.
- **Evidence chain**: The probe design creates a complete evidence chain: `attack()` records whether `project_created` was set, and `hypothesis_verification()` independently verifies via the AWS API — avoiding any reliance on potentially unreliable in-process state for the final determination.
- **False-positive resistance**: Using `batch_get_projects` with admin credentials (not the attack role) eliminates the possibility of a false-positive pass caused by the attack role's own permissions hiding the project's existence.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**✅ AUTHORIZE EXECUTION**

The experiment demonstrates full correspondence across all three quality factors. The attack faithfully implements T1552.005 credential exfiltration via CodeBuild project creation, the defense correctly implements IAM least-privilege deny policy as specified in the ADT, and the preventive probe directly validates whether the control blocks the attack. The implementation is production-quality with proper error handling, state management, rollback safety nets, and AWS-native correctness.

---

## Recommendations

The experiment scores at maximum across all factors. The following minor enhancements could be considered for future iterations but are **not required** for execution authorization:

1. **IAM propagation delay**: The `_wait` loop for `AttackRole assumable` uses a 60-second timeout; consider increasing to 90 seconds in environments with elevated IAM propagation latency.
2. **CloudTrail integration**: The experiment could optionally emit a CloudTrail lookup after the attack to verify the `AccessDenied` event was recorded (supporting the Detective probe node 1.4 as well).
3. **SCP coverage note**: The code comment correctly identifies SCP as the preferred control in multi-account environments. A future variant could test SCP enforcement if an AWS Organizations sandbox is available.
4. **Parameterization**: Hard-coded values (`DurationSeconds=900`, `BUILD_GENERAL1_SMALL`, `standard:7.0`) could be surfaced as manifest-level configuration for broader reusability.