# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2026-04-04 21:23:07

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**: 
```
2026-04-04 21:22:39,288 - INFO - Attempting to create malicious CodeBuild project: malicious-exfil-project-1775355713
2026-04-04 21:22:39,978 - WARNING - ATTACK SUCCEEDED - Malicious project created: arn:aws:codebuild:us-east-1:941377112071:project/malicious-exfil-project-1775355713
```
**Justification**: The ACTION (attack attempt to create a malicious CodeBuild project) executed successfully and returned verifiable evidence. The log clearly shows that the malicious CodeBuild project was created with a specific ARN (`arn:aws:codebuild:us-east-1:941377112071:project/malicious-exfil-project-1775355713`). The attack action deployed infrastructure, assumed the preventive control role, and successfully created the malicious project. This constitutes complete verifiable evidence of attack execution.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**: 
```
2026-04-04 21:22:40,079 - INFO - Starting hypothesis verification
2026-04-04 21:22:40,490 - INFO - AWS Context - Account: 941377112071, Region: us-east-1
2026-04-04 21:22:40,927 - ERROR - VERIFICATION FAILED - Malicious project exists: arn:aws:codebuild:us-east-1:941377112071:project/malicious-exfil-project-1775355713
[31m[2026-04-04 21:22:40 CRITICAL] Steady state probe 'verify-preventive-control-blocks-malicious-codebuild' is not in the given tolerance so failing this experiment
[32m[2026-04-04 21:23:07 INFO] Experiment ended with status: deviated
[32m[2026-04-04 21:23:07 INFO] The steady-state has deviated, a weakness may have been discovered
```
**Justification**: The PROBE successfully verified the defense behavior by checking whether the malicious CodeBuild project existed after the attack attempt. The probe returned a clear, verifiable result indicating that the preventive control **failed** to block the malicious project creation. The probe correctly identified that the project exists (which it should not if the preventive control was working), determined this was outside tolerance, and properly flagged the experiment as "deviated" indicating a weakness was discovered. This is exactly what a preventive probe should do - verify whether the defense successfully prevented the attack.

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

While the experiment execution is valid, the following observations are noteworthy:

1. **Security Finding Discovered**: The experiment revealed a genuine security weakness - the preventive control failed to block malicious CodeBuild project creation. This is a successful SCE experiment that identified a gap in defensive controls.

2. **Cleanup Issue**: There was a minor cleanup failure during the attack phase due to missing `codebuild:DeleteProject` permissions on the preventive control role. However, the rollback mechanism successfully cleaned up resources using elevated permissions.

3. **Remediation Needed**: The preventive control IAM policies should be strengthened to deny `codebuild:CreateProject` actions that match patterns associated with malicious configurations (e.g., projects with exfiltration-related names or suspicious buildspec configurations).

4. **Consider SCP Implementation**: An AWS Service Control Policy (SCP) at the organization level might provide more robust prevention against this attack vector.