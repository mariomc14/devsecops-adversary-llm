# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2026-04-11

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**: 
```
2026-04-11 21:56:02,232 - INFO - Executing attack: Start Malicious Build
2026-04-11 21:56:02,718 - INFO - Assumed attacker role: arn:aws:iam::941377112071:role/sce-attacker-role-1775962503
2026-04-11 21:56:02,736 - INFO - Attempting malicious build on project: sce-build-project-1775962503
2026-04-11 21:56:03,266 - INFO - Build attempt response - Code: AccessDeniedException, Status: 400
2026-04-11 21:56:03,266 - INFO - Error message: User: arn:aws:sts::941377112071:assumed-role/sce-attacker-role-1775962503/sce-malicious-build-attempt is not authorized to perform: codebuild:StartBuild on resource: arn:aws:codebuild:us-east-1:941377112071:project/sce-build-project-1775962503 with an explicit deny in an identity-based policy
```
**Justification**: The ACTION was fully executed with complete verifiable evidence. The logs demonstrate:
1. The attacker role was successfully assumed (arn:aws:iam::941377112071:role/sce-attacker-role-1775962503)
2. A malicious build attempt was made against a specific CodeBuild project (sce-build-project-1775962503)
3. The response code (AccessDeniedException, Status: 400) and detailed error message provide concrete evidence of the attack attempt
4. The attack was executed and received a definitive response from AWS

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**: 
```
[32m[2026-04-11 21:56:03 INFO] Steady state hypothesis: Preventive control blocks malicious build attempts
[32m[2026-04-11 21:56:03 INFO] Probe: verify-malicious-build-blocked
2026-04-11 21:56:03,270 - INFO - Verifying hypothesis: Preventive control blocked malicious build
2026-04-11 21:56:03,692 - INFO - Found 0 builds for project sce-build-project-1775962503
2026-04-11 21:56:04,241 - INFO - Preventive IAM policy with Deny for StartBuild confirmed
2026-04-11 21:56:04,241 - INFO - Preventive control VERIFIED - Attack blocked. Reason: AccessDeniedException: User: arn:aws:sts::941377112071:assumed-role/sce-attacker-role-1775962503/sce-malicious-build-attempt is not authorized to perform: codebuild:StartBuild on resource: arn:aws:codebuild:us-east-1:941377112071:project/sce-build-project-1775962503 with an explicit deny in an identity-based policy
[32m[2026-04-11 21:56:04 INFO] Steady state hypothesis is met!
```
**Justification**: The PROBE successfully verified the preventive control behavior with comprehensive evidence:
1. The probe verified zero builds were started for the target project (confirming the attack was blocked)
2. The preventive IAM policy with explicit Deny for StartBuild was confirmed to exist
3. The verification explicitly stated the reason for blocking - "explicit deny in an identity-based policy"
4. The steady state hypothesis was confirmed as met
5. This is a preventive control experiment, and the PROBE correctly verified that the preventive measure (IAM policy deny) successfully blocked the malicious build attempt

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

The experiment execution was fully successful and valid. Some observations for future enhancements:

1. **Additional Evidence Collection**: Consider capturing CloudTrail events that log the denied API call for additional audit trail verification.

2. **Policy Verification**: The experiment could be enhanced by explicitly outputting the IAM policy document that caused the denial.

3. **Timing Metrics**: Adding timing information about how quickly the preventive control responded could provide additional security posture insights.

4. **Multiple Attack Vectors**: Consider testing the preventive control against multiple attack patterns (e.g., different IAM principals, different build configurations) to validate comprehensive coverage.