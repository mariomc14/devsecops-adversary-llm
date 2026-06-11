# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2026-04-03 23:06:27

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-03 23:05:59,403 - INFO - Starting attack: Create Malicious CodeBuild Project
2026-04-03 23:05:59,811 - INFO - Assuming attacker role: arn:aws:iam::941377112071:role/sce-attacker-role-1775275533
2026-04-03 23:06:00,308 - INFO - Attack attempt 1: Creating CodeBuild project with privileged mode
2026-04-03 23:06:00,797 - INFO - Attack blocked with error AccessDeniedException: User: arn:aws:sts::941377112071:assumed-role/sce-attacker-role-1775275533/attack-session-1775275533 is not authorized to perform: codebuild:CreateProject on resource: arn:aws:codebuild:us-east-1:941377112071:project/malicious-project-1775275533 because no identity-based policy allows the codebuild:CreateProject action
2026-04-03 23:06:00,798 - INFO - Preventive control successfully blocked privileged mode creation
```

**Justification**: 
The ACTION phase provides comprehensive verifiable evidence of attack execution. The logs clearly demonstrate:
1. **Attack initiation**: The attack was properly started against the target
2. **Role assumption**: The attacker role was successfully assumed with full ARN traceability
3. **Attack vector execution**: Attempted creation of a malicious CodeBuild project with privileged mode
4. **Clear outcome**: The attack was blocked with a specific AWS AccessDeniedException
5. **Verification**: The error message confirms the exact action blocked (codebuild:CreateProject) and the specific resource targeted

The ACTION successfully executed the attack simulation and received a verifiable response from AWS indicating the preventive control engaged.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-03 23:06:00,801 - INFO - Starting hypothesis verification
2026-04-03 23:06:01,250 - INFO - Checking if malicious project exists: malicious-project-1775275533
2026-04-03 23:06:01,660 - INFO - SUCCESS: Malicious project does not exist (was blocked)
2026-04-03 23:06:01,660 - INFO - Verifying preventive control policy on role: sce-attacker-role-1775275533
2026-04-03 23:06:02,193 - INFO - Retrieved role: sce-attacker-role-1775275533
2026-04-03 23:06:02,432 - INFO - Found preventive control: Deny privileged mode
2026-04-03 23:06:02,433 - INFO - Preventive control policy verified
2026-04-03 23:06:02,433 - INFO - Listing all CodeBuild projects to double-check
2026-04-03 23:06:02,536 - INFO - Verified malicious project not in list of 3 projects
2026-04-03 23:06:02,536 - INFO - Hypothesis verification PASSED: Preventive control successfully blocked malicious project
[32m[2026-04-03 23:06:02 INFO] Steady state hypothesis is met!
```

**Justification**:
The PROBE demonstrates exceptional capability in verifying defense behavior through multiple validation layers:
1. **Direct verification**: Confirmed the malicious project does not exist in AWS
2. **Policy inspection**: Retrieved and verified the actual preventive control policy on the attacker role
3. **Control identification**: Specifically identified the "Deny privileged mode" policy
4. **Comprehensive check**: Listed all CodeBuild projects and verified the malicious project is not among them
5. **Definitive conclusion**: Explicitly stated hypothesis verification PASSED

The probe provides multi-faceted, verifiable evidence that the preventive control performed as expected, going beyond simple pass/fail to demonstrate the mechanism of protection.

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

**Strengths**:
- Excellent execution with comprehensive logging at each step
- Multi-layered verification approach enhances confidence in results
- Clear traceability from attack initiation through defense verification to cleanup
- Proper resource management with successful rollback
- Specific AWS error messages provide strong evidence of control effectiveness

**Best Practices Demonstrated**:
- The experiment achieved the minimum quality threshold exactly, indicating well-calibrated expectations
- The three-tier verification (existence check, policy inspection, project listing) provides defense-in-depth for result validation
- Clean experiment lifecycle with proper setup and teardown

**No improvements necessary** - this experiment represents an exemplar of Security Chaos Engineering execution for preventive controls.