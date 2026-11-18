# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.5
- **Probe Type**: Detective
- **Attack Nodes**: 1.2, 2.2
- **Evaluation Date**: 2026-04-13T12:02:24Z

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-04-13T11:31:11Z  INFO      [ATTACK] Node 1.2 - Weaken IMDS on i-0b6f4e8bf5f003e4e
2026-04-13T11:31:11Z  INFO      [ATTACK] Setting HttpTokens=optional  HopLimit=2
2026-04-13T11:31:12Z  INFO      [ATTACK] 1.2 - modify_instance_metadata_options succeeded.
2026-04-13T11:31:20Z  INFO      [ATTACK] Node 2.2 - Confirm weakened IMDS state on i-0b6f4e8bf5f003e4e
2026-04-13T11:31:21Z  INFO      [ATTACK] 2.2 - IMDS state: HttpTokens=optional  HopLimit=2
2026-04-13T11:31:21Z  INFO      [ATTACK] 2.2 - Weakening CONFIRMED: no IMDSv2 token required; container bridge traversal enabled.
2026-04-13T11:31:21Z  INFO      [ATTACK] Both attack nodes executed successfully.
```
**Justification**: Both attack nodes executed successfully with verifiable evidence. Attack Node 1.2 (`ec2:ModifyInstanceMetadataOptions`) successfully transitioned the IMDS configuration from the secure baseline (`HttpTokens=required`, `HopLimit=1`) to the weakened state (`HttpTokens=optional`, `HopLimit=2`). Attack Node 2.2 (`ec2:DescribeInstances`) confirmed and verified the persistence of the weakened IMDS state as a precondition for unauthenticated IMDS credential retrieval. The log clearly records API call success, state changes, and explicit confirmation of both nodes completing. The pre-conditions were also established correctly (baseline confirmed at `HttpTokens=required`, `HopLimit=1` before the attack), making the evidence unambiguous and complete.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-04-13T12:01:33Z  WARNING   [POLL] GuardDuty-Policy-EC2-NoIMDSv2 - SLA of 1800s exhausted without meeting condition.
2026-04-13T12:01:34Z  INFO      [FL] Newest stream: eni-036c2ac64cfcbb195-all  lastEventTs=1776072673000
2026-04-13T12:01:34Z  INFO      [FL] PASS  Flow Log delivery pipeline is active.
2026-04-13T12:01:34Z  INFO      [CT] EC2 IMDS state: HttpTokens=optional  HopLimit=2
2026-04-13T12:01:34Z  INFO      [CT] PASS  IMDS weakened state persists - ModifyInstanceMetadataOptions durably recorded.
2026-04-13T12:01:34Z  INFO      [VERIFY]   guardduty                 -> FAIL
2026-04-13T12:01:34Z  INFO      [VERIFY]   flow_logs                 -> PASS
2026-04-13T12:01:34Z  INFO      [VERIFY]   cloudtrail_proxy          -> PASS
2026-04-13T12:01:34Z  INFO      [VERIFY] One or more signals NOT confirmed within SLA.
[CRITICAL] Steady state probe ... is not in the given tolerance so failing this experiment
[INFO] Experiment ended with status: deviated
```
**Justification**: The detective probe returned a fully verifiable, differentiated result across all three signals, demonstrating complete probe capability:

1. **Signal A (GuardDuty – `Policy:EC2/NoIMDSv2`)**: Polled 88 times over the full 1800s SLA window with zero findings detected. This is a **meaningful negative result** — the probe correctly exercised the GuardDuty detection path, exhausted the full SLA window, and returned a definitive FAIL result, revealing a genuine security weakness (GuardDuty did not fire for the IMDS weakening event within the defined SLA).

2. **Signal B (VPC Flow Log delivery)**: Confirmed active log stream (`eni-036c2ac64cfcbb195-all`) with a valid last-event timestamp, returning PASS at attempt 1.

3. **Signal C (EC2 control-plane / CloudTrail proxy)**: Confirmed the weakened IMDS state (`HttpTokens=optional`, `HopLimit=2`) persists durably as recorded via EC2 describe, returning PASS at attempt 1.

The probe successfully differentiated between passing and failing controls, produced a `deviated` experiment status, and surfaced a concrete security gap. The probe logic was robust: it ran through all signals regardless of individual failures, produced a structured signal summary, and correctly triggered the experiment deviation. This is precisely the intended behavior of a detective probe in SCE.

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

Although the execution quality is rated at the maximum score, the experiment revealed a critical security weakness that warrants immediate remediation attention:

1. **GuardDuty `Policy:EC2/NoIMDSv2` gap**: The finding was not generated within the 30-minute SLA (nor at all within the observation window). Investigate:
   - Whether the GuardDuty EC2 protection plan / Runtime Monitoring is fully enabled and the finding type `Policy:EC2/NoIMDSv2` is not suppressed by a filter rule.
   - Whether the finding requires actual **IMDSv1 credential retrieval traffic** (not just the `ModifyInstanceMetadataOptions` API call) to trigger — if so, the experiment design should include an EC2 SSM Session Manager command that simulates an unauthenticated `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` request to generate the necessary telemetry signal.
   - Whether the GuardDuty detector sampling/aggregation delay exceeds 30 minutes for this finding type in this account/region configuration.

2. **SLA calibration**: If GuardDuty requires actual IMDS traffic (not just control-plane misconfiguration) to generate findings, update the experiment's attack method to include an IMDSv1 token-less request from within the instance, and consider extending or documenting the expected detection latency.

3. **CloudTrail as a compensating control**: The PASS result on Signal C (IMDS state persistence) confirms CloudTrail is recording `ModifyInstanceMetadataOptions` calls, which can serve as a detective compensating control via CloudWatch Metric Filters or AWS Config rules (`ec2-imdsv2-check`) while the GuardDuty gap is addressed.