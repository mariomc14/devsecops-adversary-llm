# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.8
- **Probe Type**: Reactive
- **Attack Nodes**: 1.3, 2.3
- **Evaluation Date**: 2026-04-16

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-16T17:50:03Z - INFO - [attack] - ============================================================
2026-04-16T17:50:03Z - INFO - [attack] - ATTACK: Executing IMDS weakening (T1562.001)
2026-04-16T17:50:03Z - INFO - [attack] - ============================================================
2026-04-16T17:50:03Z - INFO - [attack] - Target: i-03f6b643a8114be8a
2026-04-16T17:50:03Z - INFO - [attack] - Executing: modify-instance-metadata-options
2026-04-16T17:50:03Z - INFO - [attack] -   --http-tokens optional
2026-04-16T17:50:03Z - INFO - [attack] -   --http-put-response-hop-limit 2
2026-04-16T17:50:04Z - INFO - [attack] - Response: HttpTokens=optional
2026-04-16T17:50:04Z - INFO - [attack] - ATTACK EXECUTED
```

**Justification**: The ACTION executed successfully and returned verifiable evidence of attack execution. The logs clearly show:
1. The infrastructure was deployed successfully (CloudFormation stack created)
2. The target EC2 instance was identified (i-03f6b643a8114be8a)
3. The IMDS weakening attack was executed using `modify-instance-metadata-options`
4. The attack parameters were applied (`--http-tokens optional`, `--http-put-response-hop-limit 2`)
5. The response confirmed the change (`HttpTokens=optional`)
6. The attack aligns with MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools)

The attack representing nodes 1.3 and 2.3 (IMDS configuration weakening) was demonstrably executed with verified AWS API response.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-16T17:50:04Z - INFO - [hypothesis_verification] - ============================================================
2026-04-16T17:50:04Z - INFO - [hypothesis_verification] - VERIFICATION: Checking reactive controls
2026-04-16T17:50:04Z - INFO - [hypothesis_verification] - ============================================================
2026-04-16T17:50:04Z - INFO - [hypothesis_verification] - SLA: 1800s, Poll: 15s
2026-04-16T17:50:04Z - INFO - [hypothesis_verification] - --- Iteration 1 | Elapsed: 0s | Remaining: 1799s ---
2026-04-16T17:50:06Z - INFO - [hypothesis_verification] -   Status: 0/3 passed
...
2026-04-16T18:19:59Z - INFO - [hypothesis_verification] -   Status: 0/3 passed
2026-04-16T18:20:14Z - ERROR - [hypothesis_verification] - VERIFICATION TIMEOUT
2026-04-16T18:20:14Z - ERROR - [hypothesis_verification] -   imds_reverted: FAILED
2026-04-16T18:20:14Z - ERROR - [hypothesis_verification] -   policy_attached: FAILED
2026-04-16T18:20:14Z - ERROR - [hypothesis_verification] -   lambda_ran: FAILED
[31m[2026-04-16 18:20:14 CRITICAL] Steady state probe 'Verify reactive controls executed within 30-minute SLA' is not in the given tolerance so failing this experiment
```

**Justification**: The PROBE returned verifiable evidence of defense behavior (or lack thereof). The probe:
1. Clearly defined and monitored 3 specific reactive control criteria: `imds_reverted`, `policy_attached`, `lambda_ran`
2. Polled continuously for 1800 seconds (30 minutes) at 15-second intervals (111 iterations)
3. Provided clear status updates at each polling interval
4. Produced a definitive result: all 3 defensive controls FAILED to activate
5. The hypothesis verification reached a conclusive outcome: "VERIFICATION TIMEOUT"
6. The experiment correctly concluded with status "deviated" indicating a security weakness was discovered

The probe successfully measured the reactive security controls and determined they did NOT respond to the IMDS weakening attack within the 30-minute SLA. This is a valid and verifiable probe result demonstrating a security gap.

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

While the experiment execution was technically valid and well-structured, the following observations may be useful:

1. **Security Finding Identified**: The experiment successfully discovered that reactive controls for IMDS protection weakening are not functioning as expected. No automated remediation occurred within the 30-minute SLA.

2. **Remediation Priority**: The organization should investigate why:
   - IMDS configuration was not automatically reverted
   - Restrictive IAM policies were not attached
   - Lambda remediation functions did not execute

3. **Potential Root Causes to Investigate**:
   - EventBridge rules may not be configured to detect `ModifyInstanceMetadataOptions` API calls
   - Lambda functions may not be deployed or may have insufficient permissions
   - CloudWatch alarms or Config rules for IMDS monitoring may be absent

4. **Experiment Enhancement**: Consider adding intermediate visibility into the detection pipeline (e.g., checking if CloudTrail events were generated, if EventBridge received events, etc.) to pinpoint exactly where the reactive control chain breaks down.