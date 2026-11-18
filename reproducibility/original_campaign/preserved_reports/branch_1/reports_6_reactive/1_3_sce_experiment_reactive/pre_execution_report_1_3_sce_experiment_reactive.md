# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2024-01-XX

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: The ADT specifies attack node **1.2 Create Malicious CodeBuild Project** with the command `aws codebuild create-project`, dependencies on `iam:PassRole` and `codebuild:CreateProject`, resulting in malicious project creation, mapped to TTP T1552.005 (Unsecured Credentials).

The experiment implementation's `attack()` function directly corresponds:
- It calls `codebuild_client.create_project()` — the exact API call specified in the ADT.
- The malicious buildspec contains credential exfiltration commands (`curl` to an attacker server with base64-encoded credentials from `/root/.aws/credentials`), directly aligning with T1552.005 (Unsecured Credentials — Cloud Instance Metadata API).
- The project uses the CodeBuild service role created via CloudFormation, which implicitly exercises `iam:PassRole` and `codebuild:CreateProject` permissions.
- The tactic (Credential Access) and technique (Unsecured Credentials via CodeBuild buildspec exfiltration) are fully aligned.
- The implementation quality is high: proper error handling, logging, resource tagging, and the buildspec content is realistically malicious with both `curl` and `wget` exfiltration patterns.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**: The ADT specifies reactive defense node **1.5 Incident Response** with:
- **Classification**: Reactive
- **Strategy**: Automated project deletion
- **Mechanism**: Lambda-triggered remediation

The experiment implementation fully corresponds:
- **EventBridge Rule** (`CodeBuildEventRule`): Monitors for `CreateProject` API calls via CloudTrail, matching the detective-to-reactive pipeline described in the ADT.
- **Lambda Function** (`ReactiveControlLambda`): Implements the automated remediation logic — it inspects the CodeBuild project's buildspec for malicious patterns (`curl`, `wget`, `exfil`, `malicious`, `attacker`) and calls `codebuild.delete_project()` if malicious content is detected.
- The defense corresponds exactly to "Automated project deletion" via "Lambda-triggered remediation."
- Code quality is high: the CloudFormation template properly sets up IAM roles with least privilege (only `codebuild:BatchGetProjects`, `codebuild:DeleteProject`, and CloudWatch Logs permissions), includes proper DependsOn ordering, Lambda permissions for EventBridge invocation, and comprehensive tagging.
- The Lambda function includes pattern-based detection logic, proper error handling, and structured response payloads.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: The ADT's SCE node 1.3 specifies a **Reactive Probe**: "Can automatic remediation trigger?" The experiment's probe type is explicitly **Reactive**.

The `hypothesis_verification()` function directly tests this defensive intent:
1. It first verifies the EventBridge rule is deployed and ENABLED (confirming the reactive infrastructure is in place).
2. It invokes the Lambda function with a synthetic CloudTrail event matching the `CreateProject` pattern (simulating the reactive trigger mechanism). The use of synthetic invocation is well-justified in the code comments — CloudTrail event delivery to EventBridge can take 5-15 minutes, so direct invocation validates the reactive logic while remaining practical.
3. It verifies the malicious CodeBuild project has been deleted by checking `batch_get_projects` with retry logic (up to 5 retries).
4. The hypothesis returns `True` only if the project was successfully remediated (deleted), directly answering the probe question "Can automatic remediation trigger?"

The steady-state hypothesis in the manifest correctly states: "Malicious CodeBuild project is automatically deleted by reactive control," which is exactly the reactive defensive intent. The probe validates both the triggering mechanism and the remediation outcome.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

---

## Recommendations

The experiment is well-designed and ready for execution. Minor observations for future iterations:

1. **CloudTrail Latency Note**: The experiment correctly acknowledges that CloudTrail-to-EventBridge delivery can take 5-15 minutes and compensates with synthetic Lambda invocation. For a more end-to-end validation, a longer-running variant could wait for the natural EventBridge trigger to confirm the full pipeline.

2. **Module Path**: The manifest references `chaosaws.ec2.1_3_sce_experiment_reactive` — the `ec2` submodule seems like a misnomer for a CodeBuild-focused experiment. Consider using `chaosaws.codebuild.1_3_sce_experiment_reactive` for clarity.

3. **Timestamp Determinism**: The `TIMESTAMP` is generated at module import time, meaning the manifest and implementation must be loaded in the same process for consistent resource naming. This is acceptable for direct execution but could cause issues in distributed experiment runners.