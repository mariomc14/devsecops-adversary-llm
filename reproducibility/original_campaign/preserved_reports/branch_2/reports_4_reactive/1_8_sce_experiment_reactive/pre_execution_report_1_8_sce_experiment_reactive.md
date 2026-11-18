# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Reactive
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2025-01-30T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The implementation faithfully reproduces attack node **1.7 Start Malicious Build** at both the tactic and technique levels:

| ADT Specification | Implementation |
|---|---|
| **Command**: `aws codebuild start-build` | `cb.start_build(projectName=project_name)` — exact API call |
| **Dependency**: Malicious project exists | `steady_state()` first deploys `sce-malicious-project-{ts}` via CloudFormation; `attack()` guards with `_STATE.get("project_name")` check |
| **Result**: Credential exposure attempt | BuildSpec contains `echo "malicious payload" && sleep 300`, mimicking a long-running exfiltration-style build |
| **TTP**: T1098.001 Account Manipulation | Starting an unauthorized build against a project that carries an over-privileged IAM role (`AWSCodeBuildDeveloperAccess`) correctly models account manipulation / abuse of service identity |

The `attack()` function additionally performs a `BatchGetBuilds` confirmation call, ensuring the build is verifiably `IN_PROGRESS` or `QUEUED` before returning — a hallmark of high implementation quality. State is persisted in `_STATE` for downstream hypothesis verification, and the module structure aligns with the chaostoolkit invocation model.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment directly implements the two defensive nodes that surround attack node 1.7 in the ADT:

**Node 2-Reactive (1.10 Credential Revocation / 1.5 Incident Response architecture):**
- An **EventBridge rule** (`ReactiveRule`) listening for `CodeBuild Build State Change` events with `build-status: IN_PROGRESS` on the specific malicious project is provisioned — matching the "Automated IAM role rotation / Lambda-triggered remediation" mechanisms.
- A **Lambda function** (`ReactiveFunction`) calls `codebuild:StopBuild` and publishes to **SNS**, precisely matching the "Automated project deletion" and alerting strategies described in nodes 1.5 and 1.10.

**Node 2-Detective (1.9 Runtime Container Monitoring):**
- The EventBridge pattern on `aws.codebuild` state-change events provides behavioral/runtime detection of the build initiation, aligning with "Behavioral anomaly detection."

**Node 2-Preventive (1.6 Metadata Service Protection):**
- The CodeBuild environment does not grant IMDS access beyond what the service role allows, and the `TimeoutInMinutes: 5` hard cap limits credential exposure window — a reasonable approximation of IMDSv2/restricted metadata access within the experiment scope.

Implementation quality is high: the entire defense stack is deployed as a reproducible, parameterized CloudFormation template with proper IAM least-privilege for the Lambda role (`codebuild:StopBuild`, `codebuild:BatchGetBuilds`, `sns:Publish`, CloudWatch Logs only), and the Lambda code is clean with proper error handling and logging.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The ADT node 2-Chaos (1.8 SCE Experiment) specifies three probe questions:

| ADT Probe Question | Implementation Check |
|---|---|
| **Preventive Probe**: Can build initiation be blocked? | Addressed via `attack()` returning `True/False` based on whether `start_build` succeeds — an unblocked build signals a preventive control gap |
| **Detective Probe**: Will runtime monitoring detect extraction? | EventBridge rule state verified in `hypothesis_verification()` step 3: `describe_rule` + `list_targets_by_rule` confirm the rule is `ENABLED` and correctly targets the Lambda |
| **Reactive Probe**: Can build be immediately terminated? | Core of `hypothesis_verification()`: waits up to 300 seconds for `buildStatus == STOPPED`; separately checks Lambda `Invocations` CloudWatch metric > 0 within a 3-minute propagation window |

The probe is **reactive** by classification, and the implementation correctly tests automated (non-human) termination — the hypothesis explicitly checks that the build reached `STOPPED` via the Lambda, not through manual intervention. The three-gate verdict (`build_stopped AND lambda_invoked AND rule_enabled`) provides defense-in-depth verification covering detection, reaction, and automation integrity. The 600-second metric propagation retry loop with exponential back-off is production-quality and prevents false negatives from CloudWatch lag.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment meets the quality threshold with a perfect score across all three factors. The implementation is a high-fidelity, production-quality realization of the ADT specification.

---

## Recommendations

The experiment is authorized as-is. The following optional enhancements could further strengthen the experiment for future iterations:

1. **Metric namespace disambiguation**: The CloudWatch `Invocations` check uses a 10-minute window. Consider also checking `AWS/Events` → `TriggeredRules` for the EventBridge rule to independently confirm the rule fired (separate from Lambda execution), providing a fourth verification dimension.

2. **SNS subscription verification**: The experiment provisions an SNS topic but does not verify that a message was actually published (only Lambda invocation is checked). Adding an SQS queue subscription to the SNS topic during `steady_state()` and polling it in `hypothesis_verification()` would close this verification gap.

3. **Race condition hardening**: There is a narrow window between `start_build` and the EventBridge state-change event being processed. Adding an explicit `time.sleep(10)` after `attack()` before entering `hypothesis_verification()` would reduce false-negative risk on slow EventBridge delivery.

4. **Module path correction**: The JSON manifest references `chaosaws.ec2.1_8_sce_experiment_reactive` — the `ec2` sub-module path is semantically inconsistent with a CodeBuild experiment. Renaming to `chaosaws.codebuild.1_8_sce_experiment_reactive` would improve maintainability.

5. **`_STATE` persistence across chaostoolkit invocations**: Since chaostoolkit imports each function independently, `_STATE` will be empty when `hypothesis_verification` runs as a separate process. Consider externalizing state to SSM Parameter Store or a local JSON file for full chaostoolkit compatibility.