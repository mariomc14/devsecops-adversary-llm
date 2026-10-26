# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.5
- **Probe Type**: Detective
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2026-04-08T14:05:50Z

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-04-08T13:03:46Z [INFO] attack - === attack START ===
2026-04-08T13:03:46Z [INFO] attack - Calling ModifyInstanceMetadataOptions on i-085274053ee213571: HttpTokens=optional, HopLimit=2 ...
2026-04-08T13:03:47Z [INFO] attack - Attack succeeded (attempt 1): HttpTokens=optional HopLimit=2
2026-04-08T13:03:47Z [INFO] attack - === attack COMPLETE - IMDS weakened on i-085274053ee213571 at 2026-04-08T11:03:47Z ===
```
Additionally, baseline verification confirmed the pre-attack state:
```
2026-04-08T13:03:23Z [INFO] _verify_baseline_imdsv2 - Baseline IMDS: instance=i-085274053ee213571 HttpTokens=required HopLimit=1
2026-04-08T13:03:23Z [INFO] _verify_baseline_imdsv2 - Baseline confirmed: IMDSv2 enforced.
```

**Justification**: The attack action (Attack Node 1.2 — `ModifyInstanceMetadataOptions`) executed successfully and verifiably. The log confirms:
1. A pre-attack baseline was established: the EC2 instance `i-085274053ee213571` had `HttpTokens=required` and `HopLimit=1` (IMDSv2 enforced).
2. The API call `ModifyInstanceMetadataOptions` was invoked on the correct instance with `HttpTokens=optional` and `HttpPutResponseHopLimit=2`, succeeding on the first attempt.
3. The state transition is unambiguous: IMDS was weakened from IMDSv2-only to IMDSv1-compatible, and the hop limit was expanded from 1 to 2, enabling credential harvesting from containers and SSRF-vulnerable workloads.
4. The attack completed within 1 second, confirming no API-level resistance.

This constitutes strong, verifiable evidence of attack execution with confirmed pre/post state contrast.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-04-08T13:03:44Z [INFO] _verify_controls_armed -   OK EventBridge rule ENABLED
2026-04-08T13:03:45Z [INFO] _verify_controls_armed -   OK CloudWatch alarm exists
2026-04-08T13:03:46Z [INFO] _verify_controls_armed -   OK SQS queue reachable
...
2026-04-08T13:33:53Z [ERROR] _poll_until - FAIL [EventBridge IMDS event on SQS] NOT satisfied within the 1800-second SLA.
2026-04-08T13:33:53Z [WARNING] hypothesis_verification - [B] Config Rule sub-check SKIPPED - Config recorder not active or rule not created.
2026-04-08T14:04:02Z [ERROR] _poll_until - FAIL [CloudWatch Alarm ALARM state] NOT satisfied within the 1800-second SLA.
2026-04-08T14:04:02Z [INFO] hypothesis_verification - Hypothesis results: {"A_eventbridge_sqs": "False", "B_config_noncompliant": "None", "C_cloudwatch_alarm": "False"}
2026-04-08T14:04:02Z [ERROR] hypothesis_verification - FAIL PRIMARY detective control [A] FAILED - EventBridge did not deliver the IMDS event to SQS within the 1800-second SLA.
[CRITICAL] Steady state probe ... is not in the given tolerance so failing this experiment
```

**Justification**: The detective probe executed fully and returned verifiable, deterministic results across all three sub-checks:

1. **Pre-flight verification (armed state)**: All three detective controls (EventBridge rule ENABLED, CloudWatch Alarm present, SQS queue reachable) were confirmed operational before the attack, establishing probe validity.

2. **Check [A] — EventBridge → SQS**: The probe actively polled the SQS queue for 1800 seconds (70 attempts, ~25-second intervals). No message arrived. The failure is a definitive negative result: the primary detective control did **not** fire. This is the critical security finding.

3. **Check [B] — AWS Config Rule**: Correctly identified as inconclusive due to the Config recorder not being active. Skipped with appropriate warning rather than a false result.

4. **Check [C] — CloudWatch Alarm**: The probe polled the CloudWatch Alarm `sce-cwa-4b8019a4` state for an additional 1800 seconds (87 attempts, ~20-second intervals). The alarm remained in `OK` state throughout, meaning the CloudTrail → metric filter → alarm pipeline also failed to trigger.

5. **Outcome encoding**: Results were precisely encoded as `{"A_eventbridge_sqs": "False", "B_config_noncompliant": "None", "C_cloudwatch_alarm": "False"}`, and the experiment correctly terminated with `deviated` status and return code 1.

The probe demonstrated full observability: it exercised the complete detection pipeline, waited through realistic SLAs, and produced unambiguous evidence that **no detective control successfully detected the IMDS weakening attack**. This is a high-quality security finding (a genuine weakness discovered).

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

Although the execution quality is maximal (Q_post = 100), the experiment revealed critical security gaps that warrant immediate remediation:

### Critical Finding: Detective Controls Blind to IMDS Weakening
Both the EventBridge → SNS → SQS pipeline and the CloudTrail → metric filter → CloudWatch Alarm pipeline failed to detect `ModifyInstanceMetadataOptions` with `HttpTokens=optional`.

**Root Cause Investigation Priorities**:

1. **EventBridge Rule Misconfiguration**: Verify the event pattern matches the actual CloudTrail event structure for `ModifyInstanceMetadataOptions`. The narrowing to a specific `instanceId` and `httpTokens=optional` filter may have introduced a pattern mismatch (e.g., the event detail path may differ between EC2 API event schemas).

2. **CloudTrail → CloudWatch Logs Delivery Lag**: The trail was created ~3 minutes before the attack. CloudTrail management events typically deliver to CloudWatch Logs within 5-15 minutes, but the CW Alarm never fired even after 30+ minutes. Verify: (a) the trail was actively capturing `ec2:ModifyInstanceMetadataOptions` management events, (b) the CloudWatch Logs metric filter pattern correctly matches the log event structure, (c) the alarm evaluation period and threshold are correctly configured.

3. **EventBridge Default Bus vs. CloudTrail Events**: Confirm that `ModifyInstanceMetadataOptions` EC2 API calls generate EventBridge events on the default event bus. Some EC2 API events require specific event source routing.

4. **AWS Config Recorder Gap**: The Config recorder was not active, leaving the compliance check blind. Enabling AWS Config with the `ec2-imdsv2-check` managed rule is strongly recommended as an independent detective layer.

**Remediation Actions**:
- Deploy and test EventBridge rule patterns against real `ModifyInstanceMetadataOptions` CloudTrail events using EventBridge's test event functionality.
- Reduce CloudWatch Alarm evaluation period and verify metric filter pattern against actual log stream content.
- Enable AWS Config recorder with IMDSv2 compliance rule.
- Re-run this SCE experiment after fixes to confirm detection capability.