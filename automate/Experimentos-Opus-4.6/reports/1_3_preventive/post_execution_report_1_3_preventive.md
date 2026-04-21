# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2026-04-17

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
[INFO] 2026-04-17 12:11:04 - Assuming role: arn:aws:iam::396608802942:role/sce-role-sce-1-3-prev-1776420595
[INFO] 2026-04-17 12:11:04 - Role assumed successfully
[INFO] 2026-04-17 12:11:04 - Executing: aws ec2 describe-instances
[INFO] 2026-04-17 12:11:04 - Expected: AccessDenied (permission boundary should block)
[INFO] 2026-04-17 12:11:05 - ATTACK BLOCKED - Preventive control WORKED
[INFO] 2026-04-17 12:11:05 - Error: UnauthorizedOperation
[INFO] 2026-04-17 12:11:05 - Duration: 0.55s
[INFO] 2026-04-17 12:11:05 - Attempting additional reconnaissance: ec2:DescribeSecurityGroups
[INFO] 2026-04-17 12:11:05 - DescribeSecurityGroups also BLOCKED: UnauthorizedOperation
```
**Justification**: The ACTION executed verifiably against real AWS infrastructure. The experiment successfully assumed an IAM role (with a permission boundary applied via CloudFormation), then attempted two distinct EC2 reconnaissance API calls (`describe-instances` and `DescribeSecurityGroups`), both corresponding to MITRE ATT&CK TTP T1580 (Cloud Infrastructure Discovery). Both calls returned concrete `UnauthorizedOperation` errors from AWS, which constitutes verifiable evidence that the attack was actually executed against the cloud environment. The role ARN, account ID, error codes, and timing are all present and consistent.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
[INFO] 2026-04-17 12:11:05 - Attack Result: BLOCKED
[INFO] 2026-04-17 12:11:05 - Error Code: UnauthorizedOperation
[INFO] 2026-04-17 12:11:05 - Instances: None
[INFO] 2026-04-17 12:11:05 - HYPOTHESIS VERIFIED: Control effective
[INFO] 2026-04-17 12:11:05 -   - Attack blocked with: UnauthorizedOperation
[INFO] 2026-04-17 12:11:05 -   - No instances disclosed
[INFO] 2026-04-17 12:11:05 -   - Permission boundary working
[32m[2026-04-17 12:11:05 INFO] Steady state hypothesis is met!
```
**Justification**: The PROBE produced a clear, verifiable result confirming the defensive behavior of the IAM permission boundary. It verified three specific aspects: (1) the attack was blocked with `UnauthorizedOperation`, (2) no EC2 instance data was disclosed, and (3) the permission boundary is functioning as intended. The steady-state hypothesis was formally evaluated and confirmed met by the Chaos Toolkit framework. Additionally, a secondary reconnaissance attempt (`DescribeSecurityGroups`) was also verified as blocked, providing additional defense validation coverage. The probe clearly distinguishes between a successful preventive control (attack blocked) versus a failed one (data disclosed).

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

- The experiment is exemplary in its execution. Minor enhancements could include:
  - Testing additional EC2 reconnaissance APIs (e.g., `describe-vpcs`, `describe-subnets`, `describe-network-interfaces`) to broaden attack surface coverage.
  - Including a positive control test (verifying that allowed actions still succeed under the permission boundary) to confirm the boundary is not overly broad or misconfigured in a way that blocks everything trivially.
  - Logging the full permission boundary policy document for audit trail completeness.
  - Adding a timestamp-correlated CloudTrail verification to confirm the denied events were recorded for detective monitoring purposes.