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
2026-04-11 22:02:40,122 [INFO] Attempting malicious StartBuild on project 'sce-build-1775962896' with source override…
2026-04-11 22:02:40,880 [WARNING] Malicious build was ALLOWED — build ID: sce-build-1775962896:9dc6002b-a00e-44ae-b74c-056e3639f858
```
**Justification**: The ACTION executed successfully and produced verifiable evidence. A CodeBuild project was deployed via CloudFormation (`sce-experiment-1775962896`), an attacker IAM role was assumed, and a malicious `StartBuild` call was made with a source override pointing to `https://github.com/malicious-actor/evil-repo.git`. The build was allowed to start and a concrete build ID was returned (`sce-build-1775962896:9dc6002b-a00e-44ae-b74c-056e3639f858`), providing full verifiable evidence that the attack action (node 1.7 - Start Malicious Build) was executed.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-04-11 22:02:40,996 [ERROR] ✗ Preventive control FAILED: malicious build was allowed to start.
2026-04-11 22:02:41,475 [INFO] Builds found for project 'sce-build-1775962896': 1
2026-04-11 22:02:41,609 [ERROR] ✗ Found malicious build: sce-build-1775962896:9dc6002b-a00e-44ae-b74c-056e3639f858 with source https://github.com/malicious-actor/evil-repo.git
[2026-04-11 22:02:41 CRITICAL] Steady state probe 'verify-malicious-build-was-prevented' is not in the given tolerance so failing this experiment
[2026-04-11 22:03:03 INFO] Experiment ended with status: deviated
[2026-04-11 22:03:03 INFO] The steady-state has deviated, a weakness may have been discovered
```
**Justification**: The PROBE (`verify-malicious-build-was-prevented`) returned a clear, verifiable result. It checked whether the preventive IAM policy blocked the malicious build start, enumerated the builds for the project (found 1), identified the specific malicious build with its source URL, and conclusively determined that the preventive control failed. The probe correctly evaluated the steady-state hypothesis against the defined tolerance: the build should have been denied but was allowed. The experiment status was correctly marked as `deviated`, indicating a weakness was discovered. This is a fully functioning probe that produced actionable, verifiable evidence of the defense behavior (or lack thereof).

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

1. **Fix the Preventive IAM Policy**: The experiment revealed a genuine weakness — the IAM deny policy intended to block `StartBuild` with source overrides did not prevent the malicious build. The IAM policy condition logic should be reviewed. Common issues include:
   - Missing or incorrect `StringNotEquals` / `StringLike` conditions on `codebuild:SourceOverride`
   - The IAM deny policy not being properly attached to the attacker role
   - AWS IAM condition keys for CodeBuild source overrides may not behave as expected (verify supported condition keys in the AWS documentation)

2. **Consider SCP-level Controls**: In addition to IAM policies on individual roles, consider implementing Service Control Policies (SCPs) at the organization level to deny `codebuild:StartBuild` with source overrides across all accounts.

3. **Add Detective Controls as Defense-in-Depth**: Even after fixing the preventive control, add a detective layer (e.g., CloudTrail + EventBridge rule) to alert on any `StartBuild` API call with a source override parameter, as a fallback mechanism.

4. **Re-run After Remediation**: Once the IAM policy is corrected, re-execute this experiment to validate the fix and confirm the steady-state hypothesis holds.