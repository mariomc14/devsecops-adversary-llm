# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2026-04-13 17:22:33

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
[INFO] 2026-04-13 17:22:08 - SCE 1.3 - Attack Node 1.2: EC2 Reconnaissance
[INFO] 2026-04-13 17:22:08 - TTP: T1580 - Cloud Infrastructure Discovery
[INFO] 2026-04-13 17:22:08 - Assuming role: arn:aws:iam::396608802942:role/sce-role-1776093649
[INFO] 2026-04-13 17:22:08 - Role assumed successfully
[INFO] 2026-04-13 17:22:08 - Executing: aws ec2 describe-instances
[INFO] 2026-04-13 17:22:08 - Expected: AccessDenied (permission boundary should block)
[INFO] 2026-04-13 17:22:09 - ATTACK BLOCKED - Preventive control WORKED
[INFO] 2026-04-13 17:22:09 - Error: UnauthorizedOperation
[INFO] 2026-04-13 17:22:09 - Duration: 0.75s
```

**Justification**: The ACTION (attack execution) was performed successfully with verifiable evidence. The experiment:
1. Successfully deployed the preventive control infrastructure via CloudFormation stack
2. Created and verified the IAM role with permission boundary
3. Assumed the role successfully for the attack simulation
4. Executed the `aws ec2 describe-instances` reconnaissance command (MITRE ATT&CK T1580)
5. Received a verifiable response (`UnauthorizedOperation` error) demonstrating the attack was attempted and blocked
6. Recorded precise timing (0.75s duration)

The execution log provides complete evidence chain from infrastructure setup through attack attempt completion.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
[INFO] 2026-04-13 17:22:09 - SCE 1.3 - Hypothesis Verification
[INFO] 2026-04-13 17:22:09 - Attack Result: BLOCKED
[INFO] 2026-04-13 17:22:09 - Error Code: UnauthorizedOperation
[INFO] 2026-04-13 17:22:09 - Instances: None
[INFO] 2026-04-13 17:22:09 - HYPOTHESIS VERIFIED: Control effective
[INFO] 2026-04-13 17:22:09 - Evidence:
[INFO] 2026-04-13 17:22:09 -   - Attack blocked with: UnauthorizedOperation
[INFO] 2026-04-13 17:22:09 -   - No instances disclosed
[INFO] 2026-04-13 17:22:09 -   - Permission boundary working
[32m[2026-04-13 17:22:09 INFO] Steady state hypothesis is met!
```

**Justification**: The PROBE (verification of preventive control effectiveness) returned verifiable evidence of defense behavior:
1. Clearly determined the attack result status: `BLOCKED`
2. Captured the specific error code: `UnauthorizedOperation`
3. Verified no sensitive data was disclosed: `Instances: None`
4. Confirmed the permission boundary control mechanism is functioning
5. The hypothesis "Least-privilege IAM permission boundary blocks EC2 reconnaissance" was verified with concrete evidence
6. The Chaos Toolkit framework confirmed: "Steady state hypothesis is met!"

The probe successfully validated that the preventive control (IAM permission boundary) effectively blocked the reconnaissance attack as designed.

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

The experiment executed flawlessly with maximum quality scores. However, for enhanced observability in future experiments, consider:

1. **Additional Attack Variations**: Include multiple reconnaissance commands (e.g., `describe-security-groups`, `describe-vpcs`) to validate the permission boundary's breadth
2. **CloudTrail Evidence**: Capture and log the CloudTrail event ID for forensic correlation
3. **Timing Metrics**: Add baseline comparison timing (how long would a successful call take vs. blocked call)
4. **Control Specificity**: Log which specific policy statement in the permission boundary caused the denial

Overall, this experiment demonstrates excellent execution quality with complete evidence chains for both attack simulation and defense verification.