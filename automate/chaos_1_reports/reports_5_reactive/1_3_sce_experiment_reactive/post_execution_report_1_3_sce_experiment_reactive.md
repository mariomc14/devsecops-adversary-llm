# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2026-04-27

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**: 
```
2026-04-27 18:49:34,246 - INFO - ATTACK: Creating malicious CodeBuild project
2026-04-27 18:49:34,709 - INFO - Creating malicious CodeBuild project: malicious-exfil-project-1777333659
2026-04-27 18:49:35,347 - INFO - Malicious project created with ARN: arn:aws:codebuild:us-east-1:941377112071:project/malicious-exfil-project-1777333659
2026-04-27 18:49:35,347 - INFO - Attack executed successfully - waiting for reactive control to respond...
```
**Justification**: The ACTION was executed successfully with verifiable evidence. The malicious CodeBuild project was created with a specific ARN (`arn:aws:codebuild:us-east-1:941377112071:project/malicious-exfil-project-1777333659`) in AWS account 941377112071. The log clearly shows the project creation was completed and acknowledged by AWS with a valid resource ARN. This constitutes concrete, verifiable evidence that the attack action (creating a malicious CodeBuild project) was successfully executed.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**: 
```
2026-04-27 18:49:35,834 - INFO - Project malicious-exfil-project-1777333659 still exists, waiting for reactive control...
2026-04-27 18:49:50,951 - INFO - Malicious project malicious-exfil-project-1777333659 NOT FOUND - reactive control worked!
2026-04-27 18:49:51,479 - INFO - Lambda function exists: arn:aws:lambda:us-east-1:941377112071:function:sce-reactive-codebuild-1777333659
2026-04-27 18:49:52,062 - INFO - Lambda log evidence: [INFO]	2026-04-27T23:49:42.942Z	621449a5-2c2b-422c-b10f-bfcd2c7597a0	Received event: {"version": "0", "id": "e1a482c1-0634-5c89-b0f4-49e0ec9f5871", "detail-type": "AWS API Call via CloudTrail"...
2026-04-27 18:49:52,063 - INFO - Lambda log evidence: [WARNING]	2026-04-27T23:49:44.720Z	621449a5-2c2b-422c-b10f-bfcd2c7597a0	Detected potentially malicious CodeBuild project: arn:aws:codebuild:us-east-1:941377112071:project/malicious-exfil-project-17773...
2026-04-27 18:49:52,063 - INFO - Lambda log evidence: [INFO]	2026-04-27T23:49:45.045Z	621449a5-2c2b-422c-b10f-bfcd2c7597a0	Successfully deleted malicious project: arn:aws:codebuild:us-east-1:941377112071:project/malicious-exfil-project-1777333659
2026-04-27 18:49:52,063 - INFO - HYPOTHESIS VERIFIED: Reactive control successfully deleted malicious project
[2026-04-27 18:49:52 INFO] Steady state hypothesis is met!
```
**Justification**: The PROBE returned comprehensive verifiable evidence of the reactive defense behavior:

1. **Detection Evidence**: The Lambda function log shows it received the CloudTrail event and detected the malicious project with a WARNING log entry.

2. **Remediation Evidence**: The Lambda log explicitly shows "Successfully deleted malicious project" with the exact ARN.

3. **Verification Evidence**: The probe confirmed the project no longer exists after the reactive control executed (`malicious-exfil-project-1777333659 NOT FOUND - reactive control worked!`).

4. **Timing Evidence**: The logs show the project existed at 18:49:35, the Lambda detected and deleted it around 18:49:44-45, and verification confirmed deletion at 18:49:50.

This provides complete end-to-end evidence that the reactive control properly detected, responded to, and remediated the malicious CodeBuild project creation attack.

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

The experiment execution was successful and all criteria were met. Some observations for future experiments:

1. **Excellent logging**: The experiment provided comprehensive logging at each stage, making verification straightforward.

2. **Evidence chain**: The complete evidence chain from attack creation through detection, remediation, and verification was well-documented.

3. **Resource cleanup**: The rollback phase properly cleaned up all resources including the CloudFormation stack.

4. **Potential enhancement**: Consider adding metrics collection for response time (time from project creation to deletion) to establish baseline reactive control performance KPIs.