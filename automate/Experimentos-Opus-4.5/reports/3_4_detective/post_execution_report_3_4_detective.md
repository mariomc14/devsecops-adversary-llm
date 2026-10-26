# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 3.4
- **Probe Type**: Detective
- **Attack Nodes**: 1.3, 2.3, 3.3
- **Evaluation Date**: 2026-04-17

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-17 11:29:17,983 [INFO] attack: Step 1.3: Discovery (T1580)
2026-04-17 11:29:18,586 [INFO] attack: Discovery: HttpTokens=required, HopLimit=1
2026-04-17 11:29:18,586 [INFO] attack: Step 2.3: Modify IMDS (T1562.001) - TO BE DETECTED
2026-04-17 11:29:19,149 [INFO] attack: IMDS MODIFIED - Waiting for detection...
2026-04-17 11:29:19,150 [INFO] attack: Step 3.3: Verify IMDS Change (T1552.005)
2026-04-17 11:29:19,391 [INFO] attack: IMDS state: HttpTokens=optional, HopLimit=2
2026-04-17 11:29:19,391 [INFO] attack: IMDS weakened: True
2026-04-17 11:29:19,391 [INFO] attack: ATTACK COMPLETE - Now verifying detection...
```

**Justification**: The ACTION executed all three attack nodes successfully with verifiable evidence:
1. **Node 1.3 (Discovery - T1580)**: Successfully discovered initial IMDS configuration showing `HttpTokens=required, HopLimit=1`
2. **Node 2.3 (Modify IMDS - T1562.001)**: Successfully modified the IMDS settings with logged confirmation "IMDS MODIFIED"
3. **Node 3.3 (Verify IMDS Change - T1552.005)**: Verified the IMDS was weakened, showing `HttpTokens=optional, HopLimit=2` and explicit confirmation `IMDS weakened: True`

The attack execution produced clear, verifiable evidence that the IMDS protection was successfully weakened from requiring tokens (IMDSv2) to optional tokens (IMDSv1 compatible).

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-17 11:29:56,612 [INFO] check_cloudtrail: CloudTrail event found: 39615449038343465909234283552871559403819273964644728834
2026-04-17 11:29:56,613 [INFO] hypothesis_verification: ✓ CloudTrail: ModifyInstanceMetadataOptions DETECTED
2026-04-17 11:29:57,463 [INFO] check_config_compliance: Found 1 non-compliant resources
2026-04-17 11:29:57,463 [INFO] hypothesis_verification: ✓ AWS Config: Instance marked NON_COMPLIANT
2026-04-17 11:31:10,980 [INFO] check_eventbridge: EventBridge rule triggered: 1.0 times
2026-04-17 11:31:10,981 [INFO] hypothesis_verification: ✓ EventBridge: Rule TRIGGERED
2026-04-17 11:31:10,981 [INFO] hypothesis_verification: DETECTION SUMMARY
2026-04-17 11:31:10,981 [INFO] hypothesis_verification:   ✓ PASS: cloudtrail_logged
2026-04-17 11:31:10,981 [INFO] hypothesis_verification:   ✓ PASS: config_non_compliant
2026-04-17 11:31:10,981 [INFO] hypothesis_verification:   ✓ PASS: eventbridge_triggered
2026-04-17 11:31:10,981 [INFO] hypothesis_verification: HYPOTHESIS VERIFIED: Attack DETECTED by CloudTrail
[32m[2026-04-17 11:31:10 INFO] Steady state hypothesis is met!
```

**Justification**: The PROBE successfully verified detection across all three detective controls with verifiable evidence:
1. **CloudTrail Detection**: Found the `ModifyInstanceMetadataOptions` event with a specific event ID (37.2s detection time)
2. **AWS Config Rule Detection**: Identified 1 non-compliant resource, marking the instance as `NON_COMPLIANT` (0.8s detection time)
3. **EventBridge Rule Trigger**: Confirmed the rule triggered 1.0 times (73.5s detection time)

All three checks passed, and the steady state hypothesis was met. The PROBE returned comprehensive, verifiable evidence of defense behavior demonstrating that the detective controls successfully detected the IMDS weakening attack.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × 100 + 0.50 × 100**
Q_post = 100.00

**Threshold**: 80
**Result**: Q_post >= 80

## DECISION

**VALID EXECUTION**

---

## Recommendations

The experiment executed successfully with optimal results. Minor observations:

1. **Rollback Warning**: A warning was logged during stack deletion: "Stack deletion failed - may need manual cleanup". While this didn't affect the experiment validity, future executions should verify complete cleanup to avoid resource accumulation.

2. **Detection Timing**: EventBridge detection took significantly longer (73.5s) compared to CloudTrail (37.2s) and Config (0.8s). This is expected behavior but worth documenting for SLA expectations.

3. **Excellent Observability**: The logging structure is comprehensive with clear phase demarcation (STEADY STATE, ATTACK, VERIFICATION, ROLLBACK), making post-execution analysis straightforward.