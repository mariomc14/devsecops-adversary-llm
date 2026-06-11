# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2026-04-11 21:38:01

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-11 21:36:56,286 [INFO] Executing attack: Starting malicious build
2026-04-11 21:36:56,944 [INFO] Malicious build started: sce-build-project-1775961309:b21d48ce-3927-463e-b964-eee6c69e555d, status: IN_PROGRESS
2026-04-11 21:37:02,066 [INFO] Build status (attempt 1): STOPPED
```

**Justification**: 
The ACTION (start-malicious-build) successfully executed and returned verifiable evidence of attack execution. The logs clearly show:
1. The malicious build action was initiated (`Executing attack: Starting malicious build`)
2. A specific CodeBuild project was created and build was started with a unique build ID (`b21d48ce-3927-463e-b964-eee6c69e555d`)
3. Initial build status was confirmed as `IN_PROGRESS`, proving the attack action was successfully triggered
4. The build transitioned to `STOPPED` state, providing concrete evidence that the attack was executed and subsequently blocked

The ACTION provided complete traceability with AWS ARNs, build IDs, and status transitions, which constitutes full verifiable evidence of attack execution.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-11 21:37:02,070 [INFO] Verifying hypothesis: Preventive control blocked malicious build
2026-04-11 21:37:02,543 [INFO] Final build status: STOPPED
2026-04-11 21:37:02,543 [INFO] ✓ Build was successfully stopped by preventive control
2026-04-11 21:37:08,277 [INFO] ✓ Lambda preventive control was invoked: Suspicious build detected: arn:aws:codebuild:us-east-1:941377112071:build/sce-build-project-17759613
2026-04-11 21:37:08,801 [INFO] ✓ EventBridge rule is enabled
2026-04-11 21:37:08,801 [INFO] ✓ HYPOTHESIS VERIFIED: Preventive control successfully blocked malicious build
```

**Justification**: 
The PROBE (verify-preventive-control-blocked-build) returned comprehensive verifiable evidence of defense behavior. The probe successfully validated multiple defense mechanisms:
1. **Build Status Verification**: Confirmed the build reached `STOPPED` status, indicating termination by preventive control
2. **Lambda Function Invocation**: Verified the Lambda preventive control was triggered and logged detection of suspicious build activity with specific ARN
3. **EventBridge Rule Status**: Confirmed the monitoring rule was `ENABLED` and functioning
4. **Hypothesis Verification**: Explicitly confirmed the preventive control blocked the malicious build before execution

The probe demonstrated multi-layered verification across AWS services (CodeBuild, Lambda, EventBridge) with concrete evidence (status codes, log messages, rule states), providing irrefutable proof of defense behavior.

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

This experiment demonstrates exemplary execution quality. The following strengths are noted:

1. **Complete Traceability**: Every action and verification step includes timestamps, resource identifiers, and status codes
2. **Multi-Layer Verification**: The probe validates defense at multiple levels (build status, Lambda logs, EventBridge configuration)
3. **Clean Rollback**: Proper cleanup was performed, deleting the CloudFormation stack and all associated resources
4. **Clear Success Indicators**: Use of checkmark symbols (✓) and explicit hypothesis verification messages enhance readability

**Best Practices Observed**:
- Unique resource naming with timestamps prevents conflicts
- Polling mechanism with multiple attempts ensures accurate status detection
- Verification of both the attack execution and the defense response
- Proper error handling (no errors in STDERR beyond informational messages)

This experiment serves as a reference implementation for SCE preventive control testing.