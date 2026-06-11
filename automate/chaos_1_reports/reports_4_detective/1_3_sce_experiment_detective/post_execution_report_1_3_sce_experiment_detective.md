# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2026-04-08 21:53:02 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
[2026-04-08 21:51:54 INFO] Action: Create malicious CodeBuild project with overly-permissive role and exfiltration environment variable
2026-04-08 21:51:54,484 [INFO] Creating malicious CodeBuild project: sce-malicious-project-1775703021
2026-04-08 21:51:55,212 [INFO] Attack evidence — CodeBuild project ARN: arn:aws:codebuild:us-east-1:941377112071:project/sce-malicious-project-1775703021
2026-04-08 21:51:55,417 [INFO] Malicious CodeBuild project deleted post-evidence capture.
```
**Justification**: The attack action was executed successfully and produced verifiable, concrete evidence. A malicious CodeBuild project (`sce-malicious-project-1775703021`) was created in account `941377112071` in region `us-east-1`, with a confirmed ARN (`arn:aws:codebuild:us-east-1:941377112071:project/sce-malicious-project-1775703021`). The project was configured with an overly-permissive IAM role (`sce-malicious-cb-role-1775703021`) and an exfiltration-related environment variable, consistent with the attack node specification (1.2 Create Malicious CodeBuild Project). Post-evidence capture deletion confirms the full attack lifecycle was executed as designed.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
[2026-04-08 21:51:55 INFO] Probe: codebuild-create-project-detected-in-cloudwatch-logs
2026-04-08 21:51:55,437 [INFO] Polling CloudWatch Logs group '/sce/codebuild-detective/1775703021' for evidence of project 'sce-malicious-project-1775703021' creation...
2026-04-08 21:51:55,953 [INFO] No matching log event yet (299 s remaining). Retrying in 10 s...
2026-04-08 21:52:06,364 [INFO] No matching log event yet (289 s remaining). Retrying in 13 s...
2026-04-08 21:52:20,157 [INFO] Detective control CONFIRMED — found project name in log event. Stream: 62566a13-4c79-3fdb-9829-f80fcf485f4a | Preview: {"version":"0","id":"6516b79f-6ccb-27ff-e5e1-dde67812ecfd","detail-type":"AWS API Call via CloudTrail","source":"aws.codebuild","account":"941377112071","time":"2026-04-09T02:51:55Z","region":"us-east
[2026-04-08 21:52:20 INFO] Steady state hypothesis is met!
```
**Justification**: The detective probe returned fully verifiable, positive evidence of defensive behavior. The probe polled CloudWatch Logs group `/sce/codebuild-detective/1775703021` and, within approximately 25 seconds of the attack action, confirmed detection of the malicious project creation event. The log event preview is a CloudTrail-sourced EventBridge event (`"detail-type":"AWS API Call via CloudTrail"`, `"source":"aws.codebuild"`) routed to CloudWatch Logs via the deployed EventBridge rule (`sce-detect-cb-create-1775703021`). The detection matched the exact project name (`sce-malicious-project-1775703021`), in the correct account and region, confirming the end-to-end detective control chain (CloudTrail → EventBridge → CloudWatch Logs) functioned as intended. The steady-state hypothesis was confirmed satisfied.

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

The experiment executed flawlessly end-to-end with both factors scoring at maximum. No corrective actions are required. The following optional enhancements could further strengthen future iterations:

1. **Extend CloudTrail event preview capture**: The log event preview was truncated in the output (`"region":"us-east`). Capturing the full JSON payload in the evidence record would improve auditability and post-hoc forensic analysis.
2. **Add latency metric recording**: The detection latency (~25 seconds from project creation to CloudWatch Logs confirmation) is valuable operational data. Explicitly recording this as an experiment output metric would enable tracking of detective control performance over time.
3. **Expand attack variants**: Consider additional malicious project configurations (e.g., different exfiltration endpoints, alternative overly-permissive policies) to test the robustness of the detective control against variations of the 1.2 attack node.
4. **Cross-region coverage**: The experiment ran in `us-east-1`. If CodeBuild projects can be created in other regions, extending the detective control and SCE experiment to cover multi-region scenarios would provide broader assurance.