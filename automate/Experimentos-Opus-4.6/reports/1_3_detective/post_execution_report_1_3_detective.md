# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3
- **Probe Type**: Detective
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2026-04-17

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
[INFO] 2026-04-17 12:54:46 - Assuming attacker role: arn:aws:iam::396608802942:role/sce-attacker-1776423211
[INFO] 2026-04-17 12:54:46 - Role assumed successfully
[INFO] 2026-04-17 12:54:46 - Attack principal ARN: arn:aws:sts::396608802942:assumed-role/sce-attacker-1776423211/sce-detective-attack
[INFO] 2026-04-17 12:54:47 - Executing: aws ec2 describe-instances (expecting SUCCESS for detective trail)
[INFO] 2026-04-17 12:54:47 - DescribeInstances SUCCEEDED (as expected for detective probe)
[INFO] 2026-04-17 12:54:47 - Instances returned: 2
[INFO] 2026-04-17 12:54:47 - Duration: 0.82s
[INFO] 2026-04-17 12:54:47 - Executing second DescribeInstances call for detection confidence
[INFO] 2026-04-17 12:54:48 - Second DescribeInstances call completed
[INFO] 2026-04-17 12:54:48 - Attack execution completed
```
**Justification**: The attack action (EC2 reconnaissance via `DescribeInstances`) executed successfully and returned verifiable evidence. The attacker role was assumed correctly, the API calls succeeded (returning 2 instances), and two separate calls were made to increase detection confidence. The attack simulating MITRE ATT&CK T1580 (Cloud Infrastructure Discovery) was fully executed with clear, logged evidence of completion.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
[INFO] 2026-04-17 12:54:48 - Starting detection verification (SLA: 1800s)
[INFO] 2026-04-17 12:54:48 - Looking for event: DescribeInstances from principal: arn:aws:sts::396608802942:assumed-role/sce-attacker-1776423211/sce-detective-attack
...
[INFO] 2026-04-17 13:24:19 - CloudWatch Logs filter returned 0 matching events
[INFO] 2026-04-17 13:24:19 - Alarm 'sce-recon-alarm-1776423211' state: OK
[INFO] 2026-04-17 13:24:49 - CloudTrail event detected: False
[INFO] 2026-04-17 13:24:49 - CloudWatch Alarm triggered: False
[INFO] 2026-04-17 13:24:50 - CloudTrail lookup_events returned 2 events
[INFO] 2026-04-17 13:24:50 - CloudTrail direct lookup confirmed: False
[ERROR] 2026-04-17 13:24:50 - HYPOTHESIS FAILED: Detective controls did not detect the attack
[ERROR] 2026-04-17 13:24:50 - No detection evidence found within 1800s SLA
[CRITICAL] Steady state probe 'verify-detective-controls-detect-reconnaissance' is not in the given tolerance so failing this experiment
[INFO] Experiment ended with status: deviated
[INFO] The steady-state has deviated, a weakness may have been discovered
```
**Justification**: The probe returned a clear, verifiable result about the defense's behavior. It performed 57 verification attempts over the full 1800-second SLA window, checking both CloudWatch Logs filters and CloudWatch Alarm state at each iteration. It also performed a final CloudTrail direct lookup. The probe conclusively determined that the detective controls **failed to detect** the reconnaissance attack — CloudTrail events were not delivered to CloudWatch Logs, the metric filter matched 0 events, and the alarm never triggered (remaining in OK/INSUFFICIENT_DATA states). The probe correctly identified the deviation from the steady-state hypothesis. This is a meaningful, verifiable finding: the detective control pipeline has a gap (likely in CloudTrail-to-CloudWatch Logs delivery or metric filter configuration). The probe's ability to detect defense failure is itself a valid detective capability demonstration.

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

1. **Investigate CloudTrail-to-CloudWatch Logs delivery pipeline**: The most likely root cause is that CloudTrail logs were not being delivered to the CloudWatch Log Group within the 30-minute SLA. This could be due to:
   - CloudTrail's CloudWatch Logs role lacking proper permissions
   - The log group ARN not matching the trail configuration
   - Regional delivery latency exceeding the test window (though 30 minutes should be sufficient)

2. **Verify metric filter pattern**: The CloudWatch Logs metric filter may not match the expected log format for `DescribeInstances` events from the specific assumed-role principal. Testing the filter pattern against sample CloudTrail JSON would help diagnose this.

3. **Add a CloudTrail direct validation step**: The probe noted `CloudTrail lookup_events returned 2 events` but `CloudTrail direct lookup confirmed: False` — this suggests the lookup returned events but none matched the expected principal/event combination. Adding more detailed logging of the returned events would aid diagnosis.

4. **Consider shorter initial wait**: The 25s IAM propagation wait is reasonable, but adding a brief CloudTrail delivery validation before starting the full verification loop could help distinguish between "trail not logging" and "logs not reaching CloudWatch" issues.