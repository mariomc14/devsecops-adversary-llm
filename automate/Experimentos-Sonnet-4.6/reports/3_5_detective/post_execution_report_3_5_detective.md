# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 3.5
- **Probe Type**: Detective
- **Attack Nodes**: 1.2, 2.2, 3.2
- **Evaluation Date**: 2026-04-13 13:10:13 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-13T12:39:23Z  INFO      [STS] Assumed role. AccessKeyId=ASIAVYV52CB7FT7A34XC  Expiration=2026-04-13 10:54:23+00:00
2026-04-13T12:39:23Z  INFO      [ATTACK] 1.2 - Credentials obtained. Timestamp=1776076763
2026-04-13T12:39:28Z  INFO      [ATTACK] 2.2 - Identity: arn:aws:sts::396608802942:assumed-role/sce-inst-det35-1776076686/SCEDetectiveAttackSim  Timestamp=1776076768
2026-04-13T12:39:29Z  INFO      [ATTACK] 3.2a - Policies enumerated: []
2026-04-13T12:39:30Z  INFO      [ATTACK] 3.2b - Buckets enumerated: 17 buckets
2026-04-13T12:39:30Z  INFO      [ATTACK] Node 3.2 complete. Timestamp=1776076770
2026-04-13T12:39:30Z  INFO      [ATTACK] All attack nodes executed.
```

**Justification**: All three attack nodes executed successfully with verifiable, concrete evidence:
- **Node 1.2** (T1562.008 proxy / credential theft simulation): `sts:AssumeRole` on the instance-simulation role succeeded, returning a valid temporary `AccessKeyId=ASIAVYV52CB7FT7A34XC` with a confirmed expiration timestamp.
- **Node 2.2** (T1552.005 / identity verification with stolen credentials): `sts:GetCallerIdentity` returned the confirmed ARN `arn:aws:sts::396608802942:assumed-role/sce-inst-det35-1776076686/SCEDetectiveAttackSim`, proving the stolen credentials were operationally valid.
- **Node 3.2** (T1078.004 / lateral movement enumeration): Both `iam:ListAttachedRolePolicies` (returning an empty list, which is a valid result) and `s3:ListAllMyBuckets` (enumerating 17 buckets) completed with concrete, measurable outputs.

The entire attack chain executed within approximately 8 seconds, leaving a coherent and timestamped forensic trail in CloudTrail. Infrastructure prerequisites (CloudFormation stack, IAM roles, CloudTrail trail with `IsLogging=True`) were all confirmed operational before attack execution.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-13T13:09:47Z  WARNING   [POLL] GuardDuty-CredentialAccess-Recon - SLA of 1800s exhausted without meeting condition.
2026-04-13T13:09:50Z  INFO      [CW] Attack-chain events found in CW Logs: {'ListAttachedRolePolicies', 'AssumeRole'}
2026-04-13T13:09:50Z  INFO      [CW] PASS  2 attack-chain event types confirmed in CloudTrail CW Logs delivery.
2026-04-13T13:09:52Z  INFO      [CT-LOOKUP] AssumeRole events after attack timestamp: 9
2026-04-13T13:09:52Z  INFO      [CT-LOOKUP] PASS  AssumeRole event for instance role found. EventTime=2026-04-13 12:39:23+02:00
2026-04-13T13:09:52Z  INFO      [VERIFY]   guardduty_finding                   -> FAIL
2026-04-13T13:09:52Z  INFO      [VERIFY]   cloudtrail_cw_events                -> PASS
2026-04-13T13:09:52Z  INFO      [VERIFY]   cloudtrail_assume_role              -> PASS
2026-04-13T13:09:52Z  INFO      [VERIFY] One or more detective signals NOT confirmed within SLA - a detection gap exists in the monitoring chain.
```

**Justification**: The detective probe demonstrated full capability across all three signal channels, returning differentiated, verifiable results for each:

- **Signal A (GuardDuty CredentialAccess/Recon finding)**: The probe executed 88 polling attempts over the full 1800-second SLA window, consistently returning `[GD] Findings since buffered attack timestamp: 0`. The exhaustion of the SLA without a finding is itself a verified, actionable result — it definitively identifies a **detection gap** in GuardDuty coverage for this attack pattern.
- **Signal B (CloudTrail CW Logs attack-chain events)**: The probe queried 4 CloudWatch log streams and confirmed two distinct attack-chain event types (`ListAttachedRolePolicies`, `AssumeRole`), satisfying the ≥2 event types threshold at attempt 1 (0s elapsed). This confirms the CloudTrail-to-CloudWatch Logs delivery pipeline is fully operational.
- **Signal C (CloudTrail AssumeRole event lookup)**: The probe found 9 `AssumeRole` events post-attack and confirmed the specific instance role event at `EventTime=2026-04-13 12:39:23+02:00`, matching the attack execution timestamp precisely.

The probe produced a clear, differentiated signal summary (2 PASS / 1 FAIL), correctly triggered the experiment deviation decision, and led to a complete and clean rollback. The probe's ability to discriminate between functioning and non-functioning detective controls — rather than returning a binary pass/fail — represents high-quality detective probe behavior.

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

Although the execution is valid and scored at maximum, the following observations are worth addressing based on experimental findings:

1. **GuardDuty Coverage Gap (Critical Finding)**: GuardDuty failed to generate any `CredentialAccess` or `Recon` finding within the full 30-minute SLA despite clear credential theft and enumeration activity. Investigate whether:
   - The attack simulation role (`sce-inst-det35-1776076686`) lacks characteristics GuardDuty associates with "instance credentials" (e.g., sourcing from an EC2 metadata endpoint vs. an explicit `AssumeRole` from a developer workstation).
   - GuardDuty finding types like `CredentialAccess:IAMUser/AnomalousBehavior` or `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` require additional behavioral signals (e.g., calls from an external IP, anomalous API volume) not present in this simulation.
   - The GuardDuty detector's threat intelligence or ML baseline may need additional warm-up time in this account.

2. **Attack Realism Enhancement**: Consider sourcing the stolen credentials from an actual EC2 instance metadata endpoint (IMDSv1/v2) rather than a direct `sts:AssumeRole` call, as GuardDuty's `InstanceCredentialExfiltration` detection logic specifically monitors for instance credential use from outside AWS IP ranges.

3. **Additional Detective Signal**: Consider adding a CloudWatch Metric Filter + Alarm on the CW Logs group as a fourth signal (Signal D) to validate near-real-time alerting capability, not just log delivery.

4. **s3:ListBuckets Enumeration Not Captured**: Signal B confirmed `AssumeRole` and `ListAttachedRolePolicies` but not `ListAllMyBuckets`. Verify whether `s3.amazonaws.com` is included in the CloudTrail data events configuration or confirm it appears under management events for this attack pattern.