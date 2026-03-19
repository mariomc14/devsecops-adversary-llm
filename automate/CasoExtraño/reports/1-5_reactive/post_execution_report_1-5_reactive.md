# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1-5
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2026-03-17 13:00:59 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-03-17T12:56:44Z [INFO] sce.1_5.reactive - Assumed AttackerRole. Session: AROAVYV52CB7OSJ4QH4PN:sce-attack-1773748409-8ca025f6
2026-03-17T12:56:44Z [INFO] sce.1_5.reactive - Calling ModifyInstanceMetadataOptions on i-0ef9724abff3fe85e (http_tokens=optional, hop_limit=2) -- reactive pipeline should fire ...
2026-03-17T12:56:45Z [INFO] sce.1_5.reactive - ModifyInstanceMetadataOptions succeeded (HTTP 200). CloudTrail event generated. Lambda reactive pipeline firing ...
```
**Justification**: The attack action produced clear, verifiable evidence of execution. The attacker IAM role (`sce-attacker-role-1773748409-8ca025f6`) was successfully assumed, and `ec2:ModifyInstanceMetadataOptions` was called against instance `i-0ef9724abff3fe85e` with `http_tokens=optional` (IMDSv1) and `hop_limit=2`. The API call returned HTTP 200, confirming the IMDS downgrade was applied and a CloudTrail event was generated. This is precisely the attack behavior intended for SCE node 1.2 (IMDS Protection Weakening), and the downstream effect was confirmed when the reactive pipeline fired (H2 and H3 both passed, proving the CloudTrail event was delivered and processed).

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-03-17T12:57:00Z [INFO] sce.1_5.reactive - Polling H1 (IMDS re-hardened), H2 (deny-all policy), H3 (SNS) in unified round-robin loop. SLA: 90 seconds from now.
2026-03-17T12:57:01Z [INFO] sce.1_5.reactive - [H2] PASS -- Deny-all policy 'SCE-REACTIVE-DENY-ALL' on role 'sce-attacker-role-1773748409-8ca025f6' 15.9s after attack.
2026-03-17T12:57:02Z [INFO] sce.1_5.reactive - [H3] PASS -- Reactive SNS notification received 15.9s after attack. Actions: ['IMDS_REHARDENED', 'DENY_ALL_POLICY_APPLIED']
2026-03-17T12:58:31Z [ERROR] sce.1_5.reactive - [H1] FAIL -- IMDS NOT re-hardened within SLA. Final: HttpTokens=optional HopLimit=2. Total elapsed: 106.6s.
2026-03-17T12:58:31Z [ERROR] sce.1_5.reactive - hypothesis_verification() -> FAIL. H1=False H2=True H3=True. Total elapsed: 106.6s.
[CRITICAL] Steady state probe '...' is not in the given tolerance so failing this experiment
```
**Justification**: The reactive probe demonstrated full capability to measure defense behavior across all three hypothesis dimensions (H1, H2, H3):

- **H2 (PASS, 15.9s)**: The probe successfully detected that the Lambda function applied a deny-all inline policy (`SCE-REACTIVE-DENY-ALL`) to the attacker role within the 90-second SLA, with precise timing attribution.
- **H3 (PASS, 15.9s)**: The probe confirmed SNS notification delivery and correctly parsed the action payload `['IMDS_REHARDENED', 'DENY_ALL_POLICY_APPLIED']`, revealing an important discrepancy — the Lambda *claimed* to have re-hardened IMDS (SNS payload), but the actual EC2 metadata options were not updated.
- **H1 (FAIL, 106.6s)**: The probe correctly identified that `HttpTokens=optional` and `HopLimit=2` persisted beyond the 90-second SLA, producing a definitive, timestamped failure verdict.

The probe not only returned verifiable results for all three sub-hypotheses but also surfaced a meaningful security weakness: the Lambda reactive function has a bug or insufficient IAM permissions to execute `ec2:ModifyInstanceMetadataOptions` for re-hardening, despite successfully applying IAM containment and publishing a false-positive SNS notification. This is high-quality observability that exposes a real gap in the automated remediation pipeline.

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

Although the experiment is VALID (Q_post = 100), the execution revealed a **critical weakness** in the reactive defense pipeline that warrants immediate remediation:

1. **Root Cause Investigation for H1 Failure**: The SNS notification payload contained `'IMDS_REHARDENED'` as a completed action, yet the EC2 instance metadata options remained `HttpTokens=optional` after 106.6 seconds. This strongly suggests either:
   - The Lambda function lacks `ec2:ModifyInstanceMetadataOptions` permission in its execution role, causing a silent failure in the re-hardening step while still publishing the SNS notification.
   - A race condition or exception swallowing in the Lambda handler where the SNS publish occurs before the EC2 API call result is validated.

2. **Lambda IAM Permission Audit**: Verify the Lambda execution role includes `ec2:ModifyInstanceMetadataOptions` with appropriate resource scope covering the target instance(s).

3. **Lambda Error Handling**: Refactor the Lambda handler to publish SNS notifications *after* confirming successful EC2 API responses, or distinguish between "attempted" and "confirmed" actions in the notification payload.

4. **SLA Tuning**: The 90-second SLA was sufficient for H2/H3 (both resolved at ~15.9s) but H1 was still unresolved at 106.6s. If H1 re-hardening is expected to succeed (once the permission bug is fixed), consider adjusting the SLA to 120s to account for CloudTrail-to-EventBridge-to-Lambda latency variability.

5. **Add H1 Pre-Check in Lambda**: Before publishing SNS, the Lambda should poll `DescribeInstanceAttribute` to confirm `HttpTokens=required` was actually applied, implementing a retry loop with exponential backoff if the EC2 API call fails transiently.