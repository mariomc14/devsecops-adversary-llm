# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The implementation directly and faithfully reproduces the ADT's "1.2 Create Malicious CodeBuild Project" attack node with high fidelity on both the tactic and technique dimensions:

- **Tactic alignment (T1552.005 — Unsecured Credentials)**: The `attack()` function creates a CodeBuild project whose build spec explicitly issues a `curl` call to the EC2 Instance Metadata Service (`http://169.254.169.254/latest/meta-data/iam/security-credentials/`), which is the canonical technique for harvesting temporary IAM credentials from within a compute environment — precisely what T1552.005 describes.

- **Technique alignment**: The ADT specifies the exact AWS CLI command `aws codebuild create-project` with dependencies `iam:PassRole` and `codebuild:CreateProject`. The Python implementation calls `cb.create_project(...)` (the SDK equivalent) and uses an IAM role (`MaliciousCodeBuildRole`) carrying `AdministratorAccess` — satisfying the `iam:PassRole` dependency by provisioning and passing an overly-permissive role, exactly as the ADT intends.

- **Malicious indicators are faithfully reproduced**: The environment variable `EXFIL_ENDPOINT=https://attacker.example.com/steal` and the tag `MaliciousIndicator=true` reinforce the adversarial intent described in the ADT node.

- **Implementation quality**: The attack is scoped, self-cleaning (project is deleted immediately after evidence capture), and isolated within a timestamped stack. Error handling via `ClientError` is present. The separation of concerns across `steady_state()`, `attack()`, `hypothesis_verification()`, and `rollback()` phases is clean and reproducible.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The ADT's detective defense node (1.4 — CodeBuild Activity Monitoring) specifies: **Strategy** = CloudTrail logging + CloudWatch alerts; **Mechanism** = Real-time project creation monitoring. The implementation corresponds fully and with high code quality:

- **CloudTrail → EventBridge pipeline**: The `_cfn_template()` function provisions an `AWS::Events::Rule` with an event pattern that matches `source: aws.codebuild`, `detail-type: AWS API Call via CloudTrail`, and `eventName: CreateProject`. This is the correct, standard AWS pattern for intercepting CodeBuild API calls as recorded by CloudTrail — directly implementing the ADT's stated mechanism.

- **CloudWatch Logs group**: The template provisions a `AWS::Logs::LogGroup` with a 1-day retention policy and a resource policy granting `events.amazonaws.com` permission to write (`logs:CreateLogStream`, `logs:PutLogEvents`). This implements the "CloudWatch alerts" element of the ADT defense strategy.

- **Dependency ordering**: The CFN template uses `DependsOn` correctly (`LogGroupPolicy` → `DetectiveLogGroup`; `CodeBuildCreateRule` → `LogGroupPolicy`), ensuring the log group is ready to receive events before the rule is activated. This prevents a race condition that would undermine the detective control.

- **Stack outputs**: `MaliciousRoleArn`, `ArtefactBucketName`, `LogGroupName`, and `EventRuleName` are exported and consumed by subsequent phases, showing sound integration between the infrastructure layer and the experimental logic.

- **Code quality**: Resource naming is deterministic and collision-safe via a UNIX timestamp suffix. The S3 bucket is emptied before stack deletion in `rollback()`, preventing `DELETE_FAILED` states — a common production concern that is handled correctly here.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The SCE node 1.3's detective probe question is: *"Will logging capture suspicious project setup?"* The `hypothesis_verification()` function directly and rigorously answers this question:

- **Correct observable**: The function queries the CloudWatch Logs group for log events whose JSON payload contains the specific project name created during `attack()`. This is the correct observable — the EventBridge rule routes CloudTrail-captured `CreateProject` events to the log group, so the presence of the project name in a log event is the precise evidence that the detective control fired.

- **Realistic latency accommodation**: EventBridge delivery of CloudTrail events can take 2–15 minutes in practice. The probe uses a 300-second (5-minute) polling loop with exponential back-off (starting at 10 s, capped at 30 s, multiplier 1.3×) — a calibrated and realistic tolerance window that avoids both false negatives from premature termination and unnecessary waiting.

- **Multi-stream coverage**: The probe enumerates up to 10 log streams ordered by `LastEventTime` (descending) and searches events within the last 10 minutes, correctly handling the case where EventBridge creates multiple log streams within the same log group.

- **Steady-state hypothesis alignment**: The JSON manifest's `steady-state-hypothesis` probe (`hypothesis_verification`) is correctly wired to this same function, so the Chaos Toolkit framework will execute the probe both before and after the method steps — confirming that the control exists before the attack and that it captured the event after.

- **Pass/fail semantics**: The function returns a boolean (`True` = detected, `False` = not detected) with clear log messages distinguishing confirmed detection from timeout failure, directly mapping to the `tolerance: true` value in the manifest.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

---

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves a perfect pre-execution quality score. All three factors are fully aligned with the ADT specification, and the implementation demonstrates production-grade code quality with correct AWS resource dependency ordering, appropriate event delivery latency handling, safe rollback procedures, and direct traceability from the ADT attack/defense nodes to the experimental code.

---

## Recommendations

Although the score is maximal, the following optional enhancements would increase operational robustness in edge-case environments:

1. **CloudWatch Logs Insights query as fallback**: Supplement the `get_log_events` polling with a `start_query` / `get_query_results` Logs Insights query filtering on `$.detail.requestParameters.name = PROJECT_NAME`. This handles cases where the EventBridge event is delivered as a structured JSON field rather than a flat string, and provides richer forensic output.

2. **EventBridge rule state verification in steady-state hypothesis**: Before the attack, add an `events.describe_rule()` check confirming the rule's `State == ENABLED` and that its target ARN matches `LOG_GROUP_NAME`. This prevents a silent failure where the rule exists but is disabled or misconfigured.

3. **Jitter in polling loop**: Add a small random jitter (±2 s) to the `time.sleep()` call in `hypothesis_verification()` to reduce thundering-herd behaviour when multiple concurrent experiment instances share the same log group.

4. **Module path correction in manifest**: The manifest references `chaosaws.ec2.1_3_sce_experiment_detective` as the Python module path. Since CodeBuild is not an EC2 service, a more accurate path such as `chaosaws.codebuild.1_3_sce_experiment_detective` would improve discoverability and CI/CD integration.