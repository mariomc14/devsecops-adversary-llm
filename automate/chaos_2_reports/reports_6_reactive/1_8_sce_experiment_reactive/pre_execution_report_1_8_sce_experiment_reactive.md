# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Reactive
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2024-01-01

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: 

The ADT specifies attack node **1.7 Start Malicious Build** with the command `aws codebuild start-build`, a dependency on a malicious project existing, and the result being a credential exposure attempt (TTP: T1098.001 Account Manipulation).

The experiment implementation directly corresponds:
- The `attack()` function calls `cb.start_build(projectName=PROJECT_NAME)`, which is the exact AWS CLI equivalent via the SDK (`aws codebuild start-build`).
- The dependency on a malicious project existing is satisfied by the `steady_state()` function, which deploys a CloudFormation stack containing a CodeBuild project with a malicious buildspec (`echo 'Malicious payload executing'` followed by `sleep 120`).
- The tactic (Execution of a malicious build) and technique (starting an unauthorized CodeBuild build to potentially extract credentials) are fully aligned.
- The implementation quality is high: proper error handling, logging, state management, and the buildspec includes a `sleep 120` to give the reactive control time to act, which is a well-thought-out design choice.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**: 

The ADT specifies two relevant defense nodes for the 1.8 SCE Experiment context:
- **1.10 Credential Revocation (Reactive)**: Immediate credential invalidation via automated IAM role rotation.
- **1.9 Runtime Container Monitoring (Detective)**: Container runtime analysis and behavioral anomaly detection.

The experiment's reactive probe focuses on the reactive defense mechanism. The ADT node 1.8 explicitly asks: "**Reactive Probe:** Can build be immediately terminated?"

The implementation deploys:
1. An **EventBridge rule** (`BuildEventRule`) that monitors CodeBuild build state changes for `IN_PROGRESS` status on the specific project.
2. A **Lambda function** (`StopBuildLambda`) that calls `codebuild:StopBuild` when triggered.
3. Proper IAM permissions scoped to the specific CodeBuild project for the Lambda execution role.

This directly implements the reactive control described in the ADT (automated build termination). While the ADT node 1.10 mentions "Credential Revocation" specifically, the 1.8 SCE Experiment node's reactive probe question is "Can build be immediately terminated?" — and the implementation precisely addresses this. The code quality is excellent: CloudFormation for infrastructure-as-code, proper `DependsOn` relationships, least-privilege IAM policies scoped to the specific project ARN, Lambda permission for EventBridge invocation, and proper resource tagging.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: 

The ADT's SCE node 1.8 defines the **Reactive Probe** as: "Can build be immediately terminated?"

The `hypothesis_verification()` function directly tests this defensive intent:
1. It retrieves the build ID from the attack phase.
2. It polls the build status for up to 180 seconds (reasonable window for EventBridge → Lambda pipeline latency of 10-60 seconds).
3. It checks specifically for the `STOPPED` status, which indicates the reactive control successfully terminated the build.
4. It distinguishes between `STOPPED` (reactive control worked) and other terminal statuses like `SUCCEEDED`, `FAILED`, `FAULT`, `TIMED_OUT` (reactive control failed to intervene in time).
5. Returns `True` only if the build was stopped, `False` otherwise.

The experiment manifest's steady-state hypothesis also correctly frames this: "Malicious build should be reactively stopped by the EventBridge-Lambda control" with tolerance set to `true` (expecting the build to be stopped).

The probe fully validates the reactive defensive intent — it doesn't just check if the control exists, but verifies that the automated reactive pipeline (EventBridge detection → Lambda invocation → StopBuild execution) actually works end-to-end.

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

The experiment is well-designed and ready for execution. Minor suggestions for potential enhancement (not required):

1. **Enhanced observability**: Consider adding a check of the Lambda function's CloudWatch Logs to confirm the Lambda was actually invoked by EventBridge (rather than the build stopping for another reason), providing stronger causal evidence.
2. **Timing metrics**: Record the time between build start and build stop to measure the reactive control's response latency, which could be valuable for SLA validation.
3. **Module path**: The Chaos Toolkit manifest references `chaosaws.ec2.1_8_sce_experiment_reactive` — the `ec2` sub-module seems like a misnomer for a CodeBuild experiment. Consider using a more appropriate module path like `chaosaws.codebuild.1_8_sce_experiment_reactive`.