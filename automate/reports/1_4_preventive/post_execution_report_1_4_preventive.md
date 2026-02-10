# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.4
- **Probe Type**: Preventive
- **Attack Nodes**: 1.3
- **Evaluation Date**: 2026-02-10 15:53:58 (based on log timestamps)

## Factor 1: Effectiveness of the ACTION in Executing the Attack
**Score**: 100

**Analysis**:
- Evidence of ACTION execution: The ACTION successfully deployed test infrastructure via CloudFormation, assumed a restricted IAM role, and attempted EC2 instance enumeration using the `ec2:DescribeInstances` API call.
- Attack indicators found: Clear evidence of attack execution with specific AWS API calls and responses
- Verification status: Verifiable

**Log Excerpts**:
```
2026-02-10 15:52:31,963 - INFO - SCE Experiment 1.4 - Executing Attack Step 1.3
2026-02-10 15:52:31,963 - INFO - Attack: EC2 Instance Enumeration (T1580 - Cloud Infrastructure Discovery)
2026-02-10 15:52:32,437 - INFO - Successfully assumed restricted role
2026-02-10 15:52:32,478 - INFO - Attempting ec2:DescribeInstances with restricted role...
2026-02-10 15:52:32,478 - INFO - Command: aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions]'
2026-02-10 15:52:33,014 - INFO - ATTACK BLOCKED - Received UnauthorizedOperation
2026-02-10 15:52:33,014 - INFO - Error message: You are not authorized to perform this operation. User: arn:aws:sts::396608802942:assumed-role/sce-restricted-role-1770735097/sce-attack-simulation is not authorized to perform: ec2:DescribeInstances with an explicit deny in an identity-based policy: arn:aws:iam::396608802942:policy/sce-restricted-policy-1770735097 (sce-restricted-policy-1770735097)
2026-02-10 15:52:33,015 - INFO - Attack Result: BLOCKED
```

**Justification**: The ACTION clearly executed the attack simulation. The log shows:
1. Successful assumption of the restricted IAM role (`Successfully assumed restricted role`)
2. Explicit attempt to execute the EC2 enumeration attack via `aws ec2 describe-instances`
3. Clear outcome of the attack attempt (BLOCKED with UnauthorizedOperation error)
4. Detailed error message from AWS confirming the attack was attempted and denied by IAM policy

The attack execution is fully verifiable with concrete evidence of the API call and its result.

---

## Factor 2: PROBE Capability to Verify and Report the Attack Outcome
**Score**: 100

**Analysis**:
- PROBE verification results: The PROBE successfully verified that the preventive control (IAM least privilege policy) blocked the EC2 enumeration attack
- Defense behavior evidence: Clear evidence of IAM policy enforcement with explicit deny
- Observable indicators: UnauthorizedOperation error, zero instances enumerated, attack blocked status
- Reliability assessment: High reliability - multiple verification criteria checked and confirmed

**Log Excerpts**:
```
2026-02-10 15:52:33,016 - INFO - ============================================================
2026-02-10 15:52:33,017 - INFO - SCE Experiment 1.4 - Hypothesis Verification
2026-02-10 15:52:33,018 - INFO - ============================================================
2026-02-10 15:52:33,018 - INFO - Verification Criteria:
2026-02-10 15:52:33,019 - INFO - 1. Attack was blocked by IAM policy
2026-02-10 15:52:33,019 - INFO - 2. Error type is AccessDenied or UnauthorizedOperation
2026-02-10 15:52:33,019 - INFO - 3. No instances were enumerated
2026-02-10 15:52:33,020 - INFO - 
2026-02-10 15:52:33,020 - INFO - Attack blocked: True
2026-02-10 15:52:33,021 - INFO - Error type: UnauthorizedOperation
2026-02-10 15:52:33,022 - INFO - Instances enumerated: 0
2026-02-10 15:52:33,022 - INFO - 
2026-02-10 15:52:33,023 - INFO - ✓ HYPOTHESIS VERIFIED
2026-02-10 15:52:33,023 - INFO - The preventive control (IAM least privilege policy) successfully
2026-02-10 15:52:33,024 - INFO - blocked the EC2 enumeration attack with AccessDenied response.
2026-02-10 15:52:33,027 - INFO - Verification Result: PASSED
[32m[2026-02-10 15:52:33 INFO] Steady state hypothesis is met!
```

**Justification**: The PROBE demonstrated comprehensive verification capabilities:
1. Clearly defined verification criteria (3 specific conditions)
2. Verified each criterion with explicit results:
   - Attack blocked: True
   - Error type: UnauthorizedOperation (matches expected AccessDenied/UnauthorizedOperation)
   - Instances enumerated: 0
3. Produced a clear hypothesis verification result (PASSED)
4. The Chaos Toolkit framework confirmed "Steady state hypothesis is met!"

The PROBE provided reliable, verifiable evidence that the preventive control (IAM least privilege policy) successfully blocked the attack, demonstrating the system's defensive behavior.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × f1 + 0.50 × f2**
**Q_post = 0.50 × 100 + 0.50 × 100**
**Q_post = 50 + 50**
**Q_post = 100**

**Threshold**: 100
**Result**: Q_post >= 100

## DECISION

**VALID EXECUTION**

The experiment execution is valid. Both the ACTION and PROBE performed their functions correctly:
- The ACTION successfully executed the EC2 enumeration attack simulation
- The PROBE successfully verified that the preventive control blocked the attack
- All evidence is clearly documented and verifiable in the execution logs

---

## Detailed Observations

1. **Infrastructure Lifecycle**: The experiment properly managed the full lifecycle:
   - Created CloudFormation stack (`sce-experiment-1-4-1770735097`)
   - Deployed test resources (IAM role, EC2 instance)
   - Executed attack simulation
   - Verified hypothesis
   - Cleaned up resources (stack deleted successfully)

2. **MITRE ATT&CK Alignment**: The attack correctly maps to T1580 (Cloud Infrastructure Discovery), demonstrating proper threat modeling alignment.

3. **Preventive Control Validation**: The IAM policy (`sce-restricted-policy-1770735097`) with explicit deny successfully prevented the enumeration attack, validating the least privilege principle.

4. **Experiment Completion**: The experiment completed with status "completed" and return code 0, indicating successful execution without errors.

## Recommendations

No critical recommendations needed as the experiment achieved a perfect post-execution quality score. Minor suggestions for enhancement:

1. **Additional Metrics**: Consider capturing CloudTrail events as additional evidence of the blocked API call for audit purposes.

2. **Timing Metrics**: Include execution duration metrics for performance baseline establishment.

3. **Multiple Attack Vectors**: Consider testing additional enumeration methods (e.g., `describe-security-groups`, `describe-vpcs`) to validate broader coverage of the preventive control.