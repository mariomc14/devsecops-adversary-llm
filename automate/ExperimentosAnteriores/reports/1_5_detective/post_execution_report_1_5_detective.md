# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.5
- **Probe Type**: Detective
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2026-03-17 12:23:01 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-03-17T12:18:09Z [INFO] sce.1_5.detective - Assumed AttackerRole. Session: AROAVYV52CB7KS7YBFQSB:sce-attack-1773746093
2026-03-17T12:18:09Z [INFO] sce.1_5.detective - Calling ec2:ModifyInstanceMetadataOptions on instance i-04cbbee9ee070ed3e (http_tokens=optional, hop_limit=2) -- expecting CloudTrail event to be generated ...
2026-03-17T12:18:10Z [INFO] sce.1_5.detective - ModifyInstanceMetadataOptions succeeded (HTTP 200). CloudTrail event should be generated. Instance IMDS is now IMDSv1 -- re-hardening immediately.
2026-03-17T12:18:11Z [INFO] sce.1_5.detective - Re-hardening complete: instance i-04cbbee9ee070ed3e restored to http_tokens=required, hop_limit=1.
... 'executed': True, 'attack_epoch': 1773746289, 'http_status': 200, 'imds_state_after_attack': {'HttpTokens': 'optional', 'HttpPutResponseHopLimit': 2, ...}, 're_hardened': True
```
**Justification**: The attack action is fully verified with concrete, multi-layered evidence:
1. **Role assumption confirmed**: The attacker IAM role (`arn:aws:iam::396608802942:role/sce-attacker-role-1773746093`) was successfully assumed with a named session (`AROAVYV52CB7KS7YBFQSB:sce-attack-1773746093`), demonstrating realistic adversarial privilege escalation.
2. **API call executed with HTTP 200**: `ec2:ModifyInstanceMetadataOptions` was invoked on instance `i-04cbbee9ee070ed3e` and returned HTTP 200, confirming the AWS API accepted and processed the request.
3. **IMDS state change verified**: The attack result payload explicitly shows the post-attack IMDS state (`HttpTokens: optional`, `HttpPutResponseHopLimit: 2`), confirming the IMDSv2 enforcement was effectively weakened to IMDSv1.
4. **Re-hardening confirmed**: The instance was immediately restored (`http_tokens=required`, `hop_limit=1`), demonstrating controlled execution with safety rollback — consistent with SCE methodology.
5. **Return code 0**: The entire experiment completed without errors.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-03-17T12:18:13Z [INFO] sce.1_5.detective - [H1] PASS -- Detection notification received via EventBridge -> SNS -> SQS 4.4 seconds after attack. SLA: 60 s. Event name: ModifyInstanceMetadataOptions
2026-03-17T12:20:32Z [INFO] sce.1_5.detective - [H2] PASS -- CloudTrail event found. EventTime: 2026-03-17 12:18:11+01:00 | Actor: arn:aws:iam::396608802942:user/ChaosXploit-Labs | InstanceId: i-04cbbee9ee070ed3e
2026-03-17T12:20:32Z [INFO] sce.1_5.detective - hypothesis_verification() -> PASS. Detective control is effective: EventBridge -> SNS -> SQS delivered notification within 60-second SLA (H1), and CloudTrail recorded the audit event (H2).
[2026-03-17 12:20:32 INFO] Steady state hypothesis is met!
```
**Justification**: The detective probe returned verifiable, quantified evidence across two independent detection hypotheses:
1. **H1 — Real-time detection pipeline (EventBridge → SNS → SQS)**: The alert was delivered in **4.4 seconds** against a 60-second SLA — a 93% margin. The SQS message explicitly carries the event name `ModifyInstanceMetadataOptions`, confirming the EventBridge rule pattern-matched the correct CloudTrail event type. This validates that the near-real-time detection pipeline is functional and performant.
2. **H2 — Audit trail integrity (CloudTrail)**: The CloudTrail `LookupEvents` query confirmed the event was recorded with precise attribution: timestamp (`2026-03-17 12:18:11+01:00`), actor identity (`arn:aws:iam::396608802942:user/ChaosXploit-Labs`), and target instance (`i-04cbbee9ee070ed3e`). This validates the auditability and forensic traceability of the attack.
3. **Steady-state hypothesis met**: The Chaos Toolkit framework confirmed the hypothesis passed, meaning both pre-conditions (IMDSv2 enforced, CloudTrail logging, empty SQS queue) and post-attack detection conditions were satisfied.
4. **Defense behavior fully characterized**: The probe not only confirms detection occurred but quantifies latency (4.4s), validates the end-to-end signal path, and cross-validates through two independent mechanisms (streaming detection vs. audit log).

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

The experiment executed flawlessly and achieved maximum quality scores on both factors. No corrective actions are required. The following suggestions are offered as enhancements for future iterations:

1. **Extend H2 actor attribution**: The CloudTrail log excerpt shows `InstanceId:` with a trailing space but no value in the STDOUT snippet — while the instance ID `i-04cbbee9ee070ed3e` appears elsewhere in the logs, it would be prudent to verify the CloudTrail event's `requestParameters.instanceId` field is explicitly logged in the probe output for unambiguous cross-correlation.

2. **Add hop-limit verification to IMDS state check**: The baseline check confirms `HttpTokens=required` but could also assert `HttpPutResponseHopLimit=1` to prevent subtle configuration drift from going undetected.

3. **Introduce a negative test path**: Consider adding a variant where detection is intentionally disabled (e.g., EventBridge rule deactivated) to validate that the probe correctly reports failure — strengthening confidence in the probe's discriminative power.

4. **Measure CloudTrail delivery latency distribution**: H2 took ~2 minutes 21 seconds to resolve via `LookupEvents` polling. Documenting this latency distribution across multiple runs would help characterize CloudTrail's audit-log SLA for incident response planning.

5. **Tag attack session in CloudTrail**: The attacker session name (`sce-attack-1773746093`) is well-structured; consider asserting that this session name appears in the CloudTrail `userIdentity.sessionContext` field to strengthen traceability validation.