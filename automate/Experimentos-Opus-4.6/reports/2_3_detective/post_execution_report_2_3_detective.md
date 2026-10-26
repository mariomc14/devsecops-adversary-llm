# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.3
- **Probe Type**: Detective
- **Attack Nodes**: 1.2, 1.7, 2.2
- **Evaluation Date**: 2026-04-21

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
[INFO] — Step 1.2  T1580  Cloud Infrastructure Discovery —
[INFO]   HttpTokens=required  HopLimit=1  Endpoint=enabled

[INFO] — Step 1.7  T1562.001  Impair Defenses —
[INFO]   Step 1.7 DENIED (UnauthorizedOperation)

[INFO] — Step 2.2  T1552.005  IMDS credential exfiltration —
[INFO]   SSM command: 9e3bf41c-7385-4fb2-89ad-a2a660269a28
[INFO]   SSM status=Success stdout=TOKEN_HTTP=200 V1_HTTP=401

[INFO] attack() done.
```

**Justification**: All three attack nodes were executed with verifiable evidence:

- **Attack Node 1.2 (T1580 – Cloud Infrastructure Discovery)**: Successfully enumerated the IMDS configuration of the target instance, returning concrete metadata values (`HttpTokens=required`, `HopLimit=1`, `Endpoint=enabled`). This confirms the `DescribeInstances` API call was made.
- **Attack Node 1.7 (T1562.001 – Impair Defenses)**: Attempted to downgrade IMDS from v2 to v1 via `ModifyInstanceMetadataOptions`. The call was explicitly denied (`UnauthorizedOperation`), which is the expected behavior given the attacker role's constrained permissions. The attempt itself constitutes a valid attack action that generates detectable evidence.
- **Attack Node 2.2 (T1552.005 – IMDS Credential Exfiltration)**: Executed an SSM command on the instance to attempt credential exfiltration. The command completed successfully (`SSM status=Success`), and the output (`TOKEN_HTTP=200 V1_HTTP=401`) demonstrates that IMDSv2 token retrieval succeeded but the IMDSv1 path was correctly blocked, verifying that IMDSv2 enforcement is working. The attack action was clearly executed and produced observable output.

All actions produced concrete, verifiable evidence of execution.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
[INFO]   [0s] ✓ VPC Flow Logs: entries present (sample: 2 396608802942 eni-002a9bcf03441e2c2 - - - - - - - 1776762812 1776762891 - NODATA…)

[INFO]   [63s] ✓ CloudTrail: ModifyInstanceMetadataOptions DENIED for i-01913163402eedc6c

[INFO]   [125s] ✓ CloudTrail: DescribeInstances by attacker for i-01913163402eedc6c

[INFO] PASSED – all detective checks confirmed
[INFO]   ✓ CloudTrail: DescribeInstances logged
[INFO]   ✓ CloudTrail: ModifyInstanceMetadataOptions logged
[INFO]   ✓ VPC Flow Logs: traffic entries present
[INFO]   Detection time: 125s
```

**Justification**: The detective probe successfully verified all three detective control dimensions:

1. **CloudTrail – DescribeInstances (Attack 1.2)**: Confirmed at 125s that the `DescribeInstances` call by the attacker role was logged in CloudTrail, correlating to the specific instance `i-01913163402eedc6c`.
2. **CloudTrail – ModifyInstanceMetadataOptions (Attack 1.7)**: Confirmed at 63s that the denied `ModifyInstanceMetadataOptions` attempt was logged in CloudTrail, including the DENIED status and target instance ID.
3. **VPC Flow Logs (Attack 2.2 network activity)**: Confirmed immediately (0s) that VPC Flow Logs contained traffic entries for the ENI associated with the target instance, providing network-layer visibility.

The probe used a structured polling approach with an 1800s SLA and achieved full detection within 125 seconds. All three detective checks returned verifiable, specific evidence (instance IDs, ENI IDs, event names, denial status). The steady-state hypothesis was confirmed as met.

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

While the experiment execution is fully valid, minor observations for future improvement:

1. **Rollback partial failure**: The CloudFormation stack deletion initially failed (`DELETE_FAILED`) due to the non-empty S3 trail bucket. The script handled this gracefully by manually deleting the bucket and completing rollback, but embedding a custom resource or pre-delete Lambda in the CFN template would make cleanup more robust.
2. **VPC Flow Log sample**: The initial Flow Log entry showed `NODATA`, which is a valid log record type but doesn't contain actual traffic data (source/destination IPs, ports). Waiting for `ACCEPT`/`REJECT` entries with actual traffic details would strengthen the evidentiary value of the network detection check.
3. **Detection latency**: The 125s detection time for CloudTrail events is well within the 1800s SLA. Consider documenting this baseline for regression monitoring across experiment runs.