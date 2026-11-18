# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**: 

The experiment demonstrates excellent correspondence between the ADT attack specification and the implementation:

1. **Tactic Alignment**: The ADT specifies attack node "1.2 Create Malicious CodeBuild Project" with command `aws codebuild create-project`. The implementation directly executes this through the `attack()` function using `codebuild_client.create_project()`.

2. **Technique Alignment**: 
   - The ADT indicates TTP T1552.005 (Unsecured Credentials) with dependencies on `iam:PassRole` and `codebuild:CreateProject`
   - The implementation creates a malicious project with:
     - Credential exfiltration commands in buildspec (`curl -X POST -d "$(env)"`)
     - Data exfiltration attempts (`aws s3 cp s3://sensitive-bucket/`)
     - Proper IAM role assumption and PassRole permission

3. **Implementation Quality**: 
   - The malicious project name follows suspicious patterns (`malicious-exfil-project-{timestamp}`)
   - The buildspec contains realistic exfiltration commands
   - Environment variables configured for attack simulation
   - Proper error handling and logging throughout

The attack implementation fully matches both the tactic (CodeBuild project creation abuse) and technique (credential/data exfiltration via malicious buildspec) specified in the ADT.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**: 

The experiment implementation precisely corresponds to ADT defense node "1.1 IAM Least Privilege Control":

1. **ADT Defense Specification**:
   - Classification: Preventive
   - Strategy: Restrict CodeBuild IAM permissions
   - Mechanism: Fine-grained IAM role scoping

2. **Implementation Correspondence**:
   - The CloudFormation template creates `PreventiveControlRole` with explicit deny policy:
     ```python
     {
         "Sid": "DenyMaliciousCodeBuildProjects",
         "Effect": "Deny",
         "Action": ["codebuild:CreateProject", "codebuild:UpdateProject"],
         "Resource": "*",
         "Condition": {
             "StringLike": {
                 "codebuild:ProjectName": ["*malicious*", "*exfil*", "*attack*"]
             }
         }
     }
     ```
   - This implements fine-grained IAM role scoping through condition-based deny statements
   - The policy restricts CodeBuild IAM permissions as specified

3. **Code Quality**:
   - Well-structured CloudFormation template with proper resource definitions
   - Clear separation between service role and preventive control role
   - Proper IAM policy hierarchy (explicit deny takes precedence)
   - Comprehensive tagging for resource tracking
   - Robust error handling with retry logic (`wait_with_backoff`)
   - Clean resource cleanup in rollback function

The defense implementation is a high-quality, direct implementation of the ADT's preventive control specification.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**: 

The experiment probe fully corresponds to the preventive defensive intent specified in the ADT:

1. **ADT SCE Experiment Node (1.3)**:
   - Preventive Probe: "Can IAM restrictions block project creation?"

2. **Implementation Alignment**:
   
   a) **Hypothesis Statement**: The manifest explicitly states:
      > "Malicious CodeBuild project creation should be denied by preventive control"
   
   b) **Verification Logic**: The `hypothesis_verification()` function validates:
      - The malicious project does not exist (via `batch_get_projects`)
      - The attack was attempted and denied (`CREATED_RESOURCES['attack_denied']`)
      - IAM policy simulation confirms explicit deny for malicious patterns
   
   c) **Defensive Intent Validation**:
      - Returns `True` only when preventive control successfully blocked the attack
      - Multiple verification layers (project existence check, policy simulation)
      - Proper tracking of attack attempt and denial status

3. **Probe Type Correctness**: 
   - This is correctly classified as a Preventive probe
   - It tests whether controls PREVENT the attack from succeeding
   - The verification checks that the IAM deny policy blocked project creation BEFORE execution

The probe directly answers the ADT's preventive probe question by verifying that IAM restrictions successfully block malicious CodeBuild project creation.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × [100] + 0.30 × [100] + 0.30 × [100]**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

---

## Recommendations

While the experiment achieves the maximum score and is authorized for execution, the following enhancements could further strengthen the experiment:

1. **Enhanced Detection Coverage**: Consider adding CloudTrail event verification in `hypothesis_verification()` to confirm the AccessDenied event was logged, providing audit trail evidence.

2. **Additional Attack Patterns**: The current implementation tests project name-based blocking. Consider adding tests for other suspicious patterns (e.g., buildspec content analysis, service role restrictions).

3. **Negative Test Case**: Add a legitimate project creation test to ensure the preventive control doesn't over-block legitimate operations (false positive testing).

4. **Metrics Collection**: Add timing metrics for how quickly the preventive control responds to provide performance baseline data.

5. **Documentation**: Consider adding inline documentation explaining the relationship between ADT nodes and code sections for maintainability.