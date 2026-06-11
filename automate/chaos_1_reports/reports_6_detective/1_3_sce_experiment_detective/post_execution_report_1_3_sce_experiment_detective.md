# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2026-04-08T21:38:14Z

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-04-08 21:37:03,171 [INFO] === attack() - Creating malicious CodeBuild project: malicious-codebuild-1775702129 ===
2026-04-08 21:37:04,413 [INFO] Malicious CodeBuild project created successfully!
2026-04-08 21:37:04,414 [INFO]   Project ARN: arn:aws:codebuild:us-east-1:941377112071:project/malicious-codebuild-1775702129
2026-04-08 21:37:04,414 [INFO]   Project Name: malicious-codebuild-1775702129
2026-04-08 21:37:04,414 [INFO]   HTTP Status: 200
```
**Justification**: The attack action executed successfully and returned verifiable evidence of execution. A malicious CodeBuild project (`malicious-codebuild-1775702129`) was created in AWS account `941377112071` in `us-east-1`. The API returned HTTP 200 and provided a valid project ARN, confirming the `CreateProject` API call succeeded. The attack was performed using a dedicated CodeBuild service role (`sce-codebuild-role-1775702129`) provisioned via CloudFormation. This constitutes clear, verifiable evidence of attack execution.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-04-08 21:37:04,920 [INFO] EventBridge rule 'sce-detect-codebuild-1775702129' state: ENABLED
2026-04-08 21:37:26,004 [INFO] DETECTION CONFIRMED: Found CreateProject event in log stream '69ed4be7-cdf1-3675-9085-5591e6645dea'
2026-04-08 21:37:26,004 [INFO]   Event Name: CreateProject
2026-04-08 21:37:26,004 [INFO]   Project Name in Event: arn:aws:codebuild:us-east-1:941377112071:project/malicious-codebuild-1775702129
2026-04-08 21:37:26,004 [INFO]   Event Source: codebuild.amazonaws.com
2026-04-08 21:37:26,004 [INFO]   Event Time: 2026-04-09T02:37:04Z
2026-04-08 21:37:26,004 [INFO]   User Identity: {"type": "IAMUser", "principalId": "AIDA5WLTSZADR57FVL7I4", "arn": "arn:aws:iam::941377112071:user/sce_user", ...
2026-04-08 21:37:26,004 [INFO] FULL MATCH: Detected creation of our specific malicious project!
[32m[2026-04-08 21:37:26 INFO] Steady state hypothesis is met!
```
**Justification**: The detective probe returned comprehensive, verifiable evidence of defense behavior. The EventBridge rule was confirmed as ENABLED, and within ~22 seconds of the attack, the detective control captured the `CreateProject` CloudTrail event in the CloudWatch Log Group. The probe verified a **full match** — confirming the exact malicious project name, event source (`codebuild.amazonaws.com`), event name (`CreateProject`), timestamp, and the identity of the user who performed the action (`sce_user`). The steady-state hypothesis was confirmed as met, demonstrating the detective control pipeline (CloudTrail → EventBridge → CloudWatch Logs) functioned correctly.

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

The experiment executed flawlessly with no issues. A few minor suggestions for further strengthening:

1. **Latency metrics**: Consider recording the exact detection latency (time between `CreateProject` and log appearance) as a formal metric. In this case it was ~22 seconds, which is excellent.
2. **Negative testing**: Consider adding a steady-state check *before* the attack to confirm the log group contains no pre-existing `CreateProject` events, reducing false positive risk.
3. **Alert verification**: Beyond logging to CloudWatch, consider extending the detective control to also trigger an SNS notification or Security Hub finding, and verify that additional alerting channel as well.
4. **Cleanup verification**: The rollback was thorough (CodeBuild project deleted, CloudFormation stack deleted, log group confirmed deleted). This is exemplary practice.