# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.5
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2026-03-17 13:30:47 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-03-17T13:26:31Z [INFO] sce.1_5.reactive - Assumed AttackerRole. Session: AROAVYV52CB7NYI7DAGBP:sce-attack-1773750196-a42c3b1d
2026-03-17T13:26:31Z [INFO] sce.1_5.reactive - Calling ModifyInstanceMetadataOptions on instance i-09adf0d2ec09cea6f (http_tokens=optional, hop_limit=2) -- reactive pipeline should fire within 90s SLA ...
2026-03-17T13:26:32Z [INFO] sce.1_5.reactive - ModifyInstanceMetadataOptions succeeded (HTTP 200). CloudTrail event generated. Lambda reactive pipeline firing.
```
**Justification**: The attack action produced clear, verifiable evidence of execution. The attacker IAM role was successfully assumed (session token `AROAVYV52CB7NYI7DAGBP:sce-attack-1773750196-a42c3b1d` is confirmed). The `ModifyInstanceMetadataOptions` API call on instance `i-09adf0d2ec09cea6f` returned HTTP 200, successfully downgrading IMDS from IMDSv2 (enforced) to IMDSv1 (`http_tokens=optional`, `hop_limit=2`). This constitutes the IMDS protection weakening attack (Attack Node 1.2), and the log explicitly confirms a CloudTrail event was generated, which is the trigger for the reactive defense pipeline. The baseline state prior to the attack was confirmed with IMDSv2 enforced and CloudTrail logging active.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-03-17T13:26:49Z [INFO] sce.1_5.reactive - [H2] PASS -- Deny-all policy 'SCE-REACTIVE-DENY-ALL' found on role 'sce-attacker-role-1773750196-a42c3b1d' 15.9s after attack.
2026-03-17T13:26:50Z [INFO] sce.1_5.reactive - [H3] PASS -- Reactive SNS notification received 15.9s after attack. Actions: ['IMDS_REHARDENED', 'DENY_ALL_POLICY_APPLIED']
2026-03-17T13:28:17Z [ERROR] sce.1_5.reactive - [H1] FAIL -- IMDS NOT re-hardened within 90s SLA. Final state: HttpTokens=optional HopLimit=2. Total elapsed: 106.1s.
2026-03-17T13:28:17Z [ERROR] sce.1_5.reactive - hypothesis_verification() -> FAIL. H1=False H2=True H3=True. Total elapsed: 106.1s.
```
**Justification**: The reactive probe demonstrated full observability and returned verifiable, differentiated results across all three hypotheses. This is a high-quality probe execution:

- **H1 (IMDS Re-hardening)**: The probe correctly polled the EC2 instance metadata options and detected that `HttpTokens` remained `optional` after the 90-second SLA window (final observation at 106.1s elapsed). This is a definitive, measurable result indicating a real weakness — the Lambda function's IMDS re-hardening action failed or was delayed beyond the SLA.
- **H2 (Deny-all policy)**: The probe confirmed via IAM API inspection that policy `SCE-REACTIVE-DENY-ALL` was applied to the attacker role within 15.9s — well within the 90s SLA. This is a precise, timestamped, named-policy verification.
- **H3 (SNS notification)**: The probe confirmed receipt of an SNS→SQS message within 15.9s, including structured action metadata (`['IMDS_REHARDENED', 'DENY_ALL_POLICY_APPLIED']`) — providing behavioral evidence of the Lambda's execution path.

The probe's round-robin polling architecture correctly isolated the single failing component (H1) while confirming the remainder of the defense pipeline operated correctly. The outcome constitutes a meaningful security finding: the Lambda reported IMDS re-hardening in the SNS notification (H3 actions list contains `IMDS_REHARDENED`), yet the actual EC2 metadata options state did not reflect enforcement — revealing a discrepancy between reported and actual remediation state, which is itself a high-value weakness discovery.

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

Although the execution is valid and the experiment produced a meaningful finding, the following improvements are recommended to increase the experiment's diagnostic depth:

1. **H1/H3 Discrepancy Root-Cause Instrumentation**: The SNS notification (H3) claimed `IMDS_REHARDENED` in its action list, yet H1 confirmed the re-hardening did not materialize. The Lambda function should be instrumented to distinguish between *invoking* the `ModifyInstanceMetadataOptions` call and *confirming* the resulting state (e.g., a post-action `DescribeInstances` verification loop before publishing the SNS notification). This would prevent false-positive reporting in the notification payload.

2. **Extended H1 Polling Window**: The 90-second SLA is tight for a cold-start Lambda triggered via CloudTrail → EventBridge (which can have up to ~15 minutes of CloudTrail delivery latency in non-data-event pipelines). Consider whether the SLA threshold is realistic for the CloudTrail delivery path, and consider using EventBridge → direct rule matching on real-time EC2 API calls (via CloudTrail integration with under-2-minute delivery) versus S3-based trail delivery.

3. **Lambda Execution Log Correlation**: Add a probe hypothesis (H4) that retrieves the Lambda function's CloudWatch Logs execution record to verify the exact API call made during remediation — this would disambiguate between (a) Lambda never invoked, (b) Lambda invoked but API call failed, and (c) Lambda invoked, API call succeeded but EC2 propagation was delayed.

4. **Eventual Consistency Guard**: EC2 metadata option changes may have eventual consistency delays. Consider adding a post-SLA extended check (e.g., at T+120s) to distinguish between "permanently failed to re-harden" and "re-hardened with delay" — the former is a critical vulnerability, the latter is an SLA calibration issue.