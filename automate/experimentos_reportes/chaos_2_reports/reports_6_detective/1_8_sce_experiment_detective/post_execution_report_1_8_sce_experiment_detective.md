# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2026-04-27

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-04-27 17:13:11,202 - INFO - === ATTACK: Starting Malicious Build ===
2026-04-27 17:13:11,749 - INFO - Confirmed project exists: malicious-build-target-1777327882
2026-04-27 17:13:12,003 - INFO - Malicious build started successfully!
2026-04-27 17:13:12,003 - INFO -   Build ID: malicious-build-target-1777327882:ec729424-f704-4823-ab7c-e75023b76cf4
2026-04-27 17:13:12,003 - INFO -   Build ARN: arn:aws:codebuild:us-east-1:941377112071:build/malicious-build-target-1777327882:ec729424-f704-4823-ab7c-e75023b76cf4
2026-04-27 17:13:12,003 - INFO -   HTTP Status: 200
```
**Justification**: The attack action (Start Malicious Build) executed successfully with comprehensive verifiable evidence. A CodeBuild project was confirmed to exist, a malicious build was started, and the system returned a concrete Build ID, Build ARN, and HTTP 200 status code. The build was later confirmed as having reached `SUCCEEDED` status, proving full execution of the attack. All evidence is concrete, traceable, and verifiable through AWS resource identifiers.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-04-27 17:13:42,597 - INFO - EventBridge rule 'sce-detect-build-1777327882' state: ENABLED
2026-04-27 17:13:43,033 - INFO - Found 2 log stream(s)
2026-04-27 17:13:43,185 - INFO - Log event found: {"version":"0","id":"6d34c0bd-73a5-af61-639e-6455253efb1e","detail-type":"CodeBuild Build State Change","source":"aws.codebuild","account":"941377112071","time":"2026-04-27T22:13:20Z","region":"us-eas...
2026-04-27 17:13:43,185 - INFO - DETECTED: Build state change for project 'malicious-build-target-1777327882', status: 'SUCCEEDED'
2026-04-27 17:13:43,185 - INFO - ✅ HYPOTHESIS VERIFIED: Detective control successfully detected the malicious build start.
[2026-04-27 17:13:43 INFO] Steady state hypothesis is met!
```
**Justification**: The detective probe successfully verified that the defensive control (EventBridge rule forwarding CodeBuild state changes to CloudWatch Logs) was operational and detected the malicious build. The probe confirmed: (1) the EventBridge rule was in ENABLED state, (2) log streams existed in the target CloudWatch Logs group, (3) a specific log event was found containing the `CodeBuild Build State Change` detail-type matching the exact malicious build project name `malicious-build-target-1777327882` with status `SUCCEEDED`. The steady-state hypothesis was met, providing verifiable evidence that the detective control functioned as designed.

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

The experiment executed excellently. A few minor suggestions for further hardening:

1. **Timing resilience**: The probe succeeded on the first check attempt (attempt 1/8), which is ideal. However, documenting the retry logic (8 attempts) is good practice for environments with higher latency.
2. **Build status specificity**: The detection caught `SUCCEEDED` status. Consider also verifying detection of `IN_PROGRESS` state to ensure earlier-stage detection, which would reduce the window of exposure.
3. **Rollback completeness**: The warning about the log group already being deleted is cosmetic but could be handled more gracefully to avoid confusion in automated evaluations.
4. **Additional enrichment**: Consider adding a probe that verifies the content of the CloudWatch log event includes specific fields (e.g., initiator identity, source IP) to validate detection fidelity for forensic purposes.