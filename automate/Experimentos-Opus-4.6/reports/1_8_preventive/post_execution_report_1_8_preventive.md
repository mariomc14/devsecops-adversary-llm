# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2, 1.7
- **Evaluation Date**: 2026-04-20

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-20 12:10:19,563 [INFO] STEP 1.2: DescribeInstances DENIED as expected. Code: UnauthorizedOperation
2026-04-20 12:10:19,776 [INFO] STEP 1.7: ModifyInstanceMetadataOptions DENIED as expected. Code: UnauthorizedOperation
```

```json
"step_1_2": {
    "executed": true,
    "denied": true,
    "error": "UnauthorizedOperation: You are not authorized to perform this operation. User: arn:aws:sts::396608802942:assumed-role/sce-1-8-restricted-1776679765/sce-attack-1776679765 is not authorized to perform: ec2:DescribeInstances with an explicit deny in an identity-based policy: arn:aws:iam::396608802942:policy/sce-1-8-deny-imds-1776679765",
    "data": null
},
"step_1_7": {
    "executed": true,
    "denied": true,
    "error": "UnauthorizedOperation: You are not authorized to perform this operation. User: arn:aws:sts::396608802942:assumed-role/sce-1-8-restricted-1776679765/sce-attack-1776679765 is not authorized to perform: ec2:ModifyInstanceMetadataOptions on resource: arn:aws:ec2:us-east-1:396608802942:instance/i-0c29fb694ab0777ef with an explicit deny in an identity-based policy: arn:aws:iam::396608802942:policy/sce-1-8-deny-imds-1776679765",
    "data": null
}
```

**Justification**: Both attack steps (1.2 and 1.7) were executed with full verifiable evidence. The restricted IAM role was successfully assumed, and both `ec2:DescribeInstances` (MITRE T1580 - Cloud Infrastructure Discovery) and `ec2:ModifyInstanceMetadataOptions` (MITRE T1562.001 - Disable or Modify Tools) API calls were attempted against real AWS infrastructure. The responses include specific AWS error codes (`UnauthorizedOperation`), full ARNs identifying the assumed role, the target resource, and the explicit deny policy ARN responsible for blocking the calls. The encoded authorization failure message further confirms genuine AWS API interaction. Both attack actions were clearly executed and produced verifiable, detailed evidence.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-20 12:10:19,779 [INFO] CHECK 1 PASS: Step 1.2 (DescribeInstances) was DENIED by preventive control.
2026-04-20 12:10:19,779 [INFO] CHECK 2 PASS: Step 1.7 (ModifyInstanceMetadataOptions) was DENIED by preventive control.
2026-04-20 12:10:20,522 [INFO]   Current IMDS: HttpTokens=required, HopLimit=1, HttpEndpoint=enabled
2026-04-20 12:10:20,522 [INFO] CHECK 3 PASS: IMDS configuration intact. IMDSv2 enforced (HttpTokens=required), HopLimit=1.
2026-04-20 12:10:20,522 [INFO]   step_1_2_denied: PASS
2026-04-20 12:10:20,522 [INFO]   step_1_7_denied: PASS
2026-04-20 12:10:20,522 [INFO]   imds_intact: PASS
2026-04-20 12:10:20,522 [INFO] OVERALL: PASS
```

**Justification**: The probe performed a comprehensive three-check verification of the preventive defense behavior:

1. **Check 1**: Verified that `ec2:DescribeInstances` was explicitly denied by the IAM deny policy — confirming the preventive control blocked IMDS enumeration (Attack Node 1.2).
2. **Check 2**: Verified that `ec2:ModifyInstanceMetadataOptions` was explicitly denied — confirming the preventive control blocked IMDS downgrade attempts (Attack Node 1.7).
3. **Check 3**: Independently queried the EC2 instance's actual IMDS configuration and verified it remained unchanged (`HttpTokens=required`, `HopLimit=1`, `HttpEndpoint=enabled`), providing a ground-truth verification that the defense held.

The probe correctly validated that the explicit deny in the identity-based policy (`sce-1-8-deny-imds-1776679765`) was the mechanism responsible for blocking both attack actions. The after-method-only steady-state strategy was appropriately applied. The probe returned clear, verifiable evidence of defense behavior with specific configuration values and pass/fail determinations.

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

- The experiment execution is exemplary. Minor enhancements could include:
  - **CloudTrail validation**: Adding a check that the denied API calls were logged in CloudTrail with `errorCode: Client.UnauthorizedOperation` to verify detective observability alongside the preventive control.
  - **SCP-level testing**: Consider testing with Service Control Policies (SCPs) in addition to identity-based policies to validate defense-in-depth at the organizational level.
  - **Negative control**: Adding a brief test where a privileged role *can* perform these actions would further confirm that the deny policy specifically is the blocking mechanism rather than a broader network or service issue.