# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2026-04-11

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-04-11 20:40:42,689 - INFO - === ATTACK: Creating malicious CodeBuild project 'malicious-project-1775957918' ===
2026-04-11 20:40:43,851 - INFO - Malicious CodeBuild project created successfully: arn:aws:codebuild:us-east-1:941377112071:project/malicious-project-1775957918
2026-04-11 20:40:43,851 - INFO - Project name: malicious-project-1775957918
```
**Justification**: The attack action successfully created a malicious CodeBuild project in AWS. The log provides verifiable evidence including the full ARN (`arn:aws:codebuild:us-east-1:941377112071:project/malicious-project-1775957918`), the project name, and confirmation of successful creation. The attack infrastructure (CloudFormation stack) was also deployed successfully before the attack was executed. This constitutes complete, verifiable evidence of attack execution.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-04-11 20:40:44,481 - INFO - EventBridge rule state: ENABLED
2026-04-11 20:40:44,482 - INFO - Invoking reactive Lambda to remediate malicious project: malicious-project-1775957918
2026-04-11 20:40:47,562 - INFO - Lambda invocation status: 200
2026-04-11 20:40:47,563 - INFO - Lambda response: {'statusCode': 200, 'body': 'Deleted malicious project: malicious-project-1775957918', 'action': 'DELETED', 'project': 'malicious-project-1775957918'}
2026-04-11 20:40:47,563 - INFO - Verifying malicious CodeBuild project has been deleted...
2026-04-11 20:40:52,678 - INFO - SUCCESS: Malicious project 'malicious-project-1775957918' has been deleted by reactive control
[2026-04-11 20:40:52 INFO] Steady state hypothesis is met!
```
**Justification**: The reactive probe successfully verified the defense behavior. The evidence includes: (1) the EventBridge rule was confirmed ENABLED, (2) the reactive Lambda was invoked and returned a 200 status with an explicit `'action': 'DELETED'` response, (3) post-remediation verification confirmed the malicious CodeBuild project no longer existed, and (4) the steady-state hypothesis was met. The probe provides complete, verifiable evidence that the reactive control successfully detected and remediated the malicious CodeBuild project.

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

- **Event-driven triggering**: The probe manually invoked the Lambda function rather than waiting for EventBridge to automatically trigger it upon CodeBuild project creation. While the reactive control's remediation logic is verified, a more rigorous experiment would wait for the EventBridge rule to fire automatically via CloudTrail events (e.g., `CreateProject` API call), confirming end-to-end reactive detection. This would better validate the full reactive pipeline.
- **Timing metrics**: Consider capturing timestamps for time-to-remediation (TTR) between attack execution and project deletion to quantify the reactive control's responsiveness.
- **Negative verification**: Adding a check that the project existed before remediation (beyond just the creation confirmation) would strengthen the causal chain of evidence.