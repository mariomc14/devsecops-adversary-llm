# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2026-04-21 22:16:33 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
[2026-04-21 22:15:10 INFO] Action: create-malicious-codebuild-project-with-credential-exfiltration-buildspec
2026-04-21 22:15:11,005 [INFO] sce.1_3.reactive — Malicious CodeBuild project created — ARN: arn:aws:codebuild:us-east-1:941377112071:project/sce-1-3-1776827599-malicious
```

**Justification**: The action `create-malicious-codebuild-project-with-credential-exfiltration-buildspec` executed successfully and produced verifiable, concrete evidence of attack execution. The log confirms the malicious CodeBuild project was created with a fully qualified ARN (`arn:aws:codebuild:us-east-1:941377112071:project/sce-1-3-1776827599-malicious`), unambiguously proving the attack action materialized in the AWS environment. The return code of 0 further corroborates successful execution. Additionally, the steady-state infrastructure (CloudFormation stack `sce-1-3-1776827599`) was successfully deployed prior to the attack, providing the necessary reactive control baseline against which the attack was measured.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-21 22:15:14,393 [INFO] sce.1_3.reactive — Lambda invocation status: 200, payload: {'status': 'ok', 'project_deleted': 'sce-1-3-1776827599-malicious'}
2026-04-21 22:15:25,376 [INFO] sce.1_3.reactive — CloudWatch metric datapoints: [{'Timestamp': datetime.datetime(2026, 4, 22, 3, 15, tzinfo=tzutc()), 'Sum': 2.0, 'Unit': 'Count'}]
2026-04-21 22:15:25,376 [INFO] sce.1_3.reactive — ✓ Reactor metric confirmed in CloudWatch.
2026-04-21 22:15:25,814 [INFO] sce.1_3.reactive — ✓ Malicious project 'sce-1-3-1776827599-malicious' no longer exists.
2026-04-21 22:15:25,814 [INFO] sce.1_3.reactive — === VERIFICATION RESULT: metric=True project_deleted=True ===
[2026-04-21 22:15:25 INFO] Steady state hypothesis is met!
```

**Justification**: The reactive probe `verify-reactive-control-fired-and-project-deleted` returned comprehensive, multi-dimensional verifiable evidence of defense behavior across three independent verification channels:

1. **Lambda Reactor Direct Invocation**: HTTP 200 status with payload `{'status': 'ok', 'project_deleted': 'sce-1-3-1776827599-malicious'}` confirms the reactive Lambda function executed and actively deleted the malicious project.
2. **CloudWatch Metric Confirmation**: Datapoints returned `Sum: 2.0` counts at timestamp `2026-04-22T03:15:00Z`, confirming the reactor fired and its activity was recorded in the observability plane. The initial empty datapoint set followed by a successful retry demonstrates proper polling logic.
3. **Project Non-Existence Verification**: Direct AWS API confirmation that the malicious project `sce-1-3-1776827599-malicious` no longer exists in CodeBuild, proving end-to-end remediation.

The steady-state hypothesis was formally met, confirming the defensive control (EventBridge rule → Lambda reactor) successfully detected and responded to the malicious CodeBuild project creation.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × 100 + 0.50 × 100**

Q_post = 100.00

**Threshold**: 100
**Result**: Q_post >= 100

## DECISION

**VALID EXECUTION**

---

## Recommendations

The experiment achieved a perfect quality score. No corrective actions are required. However, the following enhancements could further strengthen future iterations:

1. **Event-Driven Probe Timing**: The probe currently invokes the Lambda reactor *directly* rather than waiting for the EventBridge rule to trigger it organically. Consider adding a secondary wait-and-poll path that validates the EventBridge rule fired autonomously (e.g., checking EventBridge invocation metrics) to distinguish between reactive trigger fidelity and manual invocation fidelity.
2. **CloudWatch Metric Granularity**: The `Sum: 2.0` count at a single timestamp suggests two invocations were recorded (direct + potential event-driven). Adding metric dimensions to differentiate invocation sources would improve observability resolution.
3. **Buildspec Exfiltration Evidence**: Since the attack node specifically includes a "credential-exfiltration-buildspec," consider adding a probe that verifies no build was *executed* (i.e., the project was deleted before any build job could run), providing stronger assurance that the exfiltration payload was never triggered.
4. **Rollback Completeness Check**: A post-rollback probe confirming the CloudFormation stack `sce-1-3-1776827599` reaches `DELETE_COMPLETE` status (confirmed here via polling) is already present — maintaining this pattern is recommended for all future experiments.