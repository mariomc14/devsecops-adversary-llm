# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2024-12-19T10:30:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**: 

The experiment demonstrates **full correspondence** with the ADT attack node "1.2 Create Malicious CodeBuild Project":

**Attack Node Specification (ADT)**:
- Command: `aws codebuild create-project`
- Dependencies: `iam:PassRole`, `codebuild:CreateProject`
- Result: Malicious project creation
- TTP: T1552.005 Unsecured Credentials

**Implementation Analysis**:
1. **Exact Command Match**: The `attack()` function executes `attacker_codebuild.create_project()` which directly maps to the AWS CLI command specified in the ADT.

2. **Dependency Fulfillment**: 
   - The attacker assumes a role (`sts.assume_role()`) demonstrating IAM role interaction
   - Attempts `codebuild:CreateProject` action explicitly
   - Passes `serviceRole=codebuild_role_arn` satisfying the `iam:PassRole` dependency

3. **Malicious Configuration**: The implementation includes specific dangerous configurations:
   - `privilegedMode': True` - enables Docker privileged mode (container escape vector)
   - Custom buildspec with environment variable dumping (`env` command)
   - Attacker-controlled build specification
   - Tags marking it as malicious for tracking

4. **TTP Alignment**: Maps to T1552.005 (Unsecured Credentials: Cloud Instance Metadata API) by:
   - Creating privileged containers that can access host resources
   - Attempting to expose environment variables containing credentials
   - Setting up infrastructure for credential exfiltration

5. **Implementation Quality**:
   - Proper error handling with specific `ClientError` catching
   - Logging of attack attempts and outcomes
   - Realistic attacker workflow (role assumption → credential use → malicious action)
   - Clean separation of attacker context from legitimate infrastructure

The attack implementation is technically accurate, tactically aligned, and demonstrates high code quality.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment shows **full correspondence** with defense node "1.1 IAM Least Privilege Control" and implements it with high quality:

**Defense Node Specification (ADT)**:
- Classification: Preventive
- Strategy: Restrict CodeBuild IAM permissions
- Mechanism: Fine-grained IAM role scoping

**Implementation Analysis**:

1. **Defense Strategy Implementation**:
   The `steady_state()` function deploys an "AttackerRole" with a comprehensive preventive control policy:

   ```json
   {
     "Sid": "DenyPrivilegedContainers",
     "Effect": "Deny",
     "Action": "codebuild:CreateProject",
     "Resource": "*",
     "Condition": {
       "StringEquals": {
         "codebuild:PrivilegedMode": "true"
       }
     }
   }
   ```

2. **Fine-Grained IAM Scoping**:
   - **Deny with Conditions**: Uses IAM condition keys (`codebuild:PrivilegedMode`) to deny specific dangerous configurations
   - **Least Privilege**: Attacker role only has `ListProjects` and `BatchGetProjects` (read-only)
   - **Resource Restrictions**: Limits actions to specific regions and configurations
   - **Explicit Denies**: Implements defense-in-depth with multiple deny statements

3. **Mechanism Quality**:
   - **Separation of Concerns**: Creates distinct roles (CodeBuildRole for legitimate operations, AttackerRole for testing)
   - **Infrastructure as Code**: Uses CloudFormation for repeatable, auditable deployment
   - **Comprehensive Coverage**: Addresses both privileged mode and cross-region creation attempts

4. **Defense Validation**:
   - The CloudFormation template properly defines IAM policies before attack execution
   - Role assumption mechanism ensures the restrictive policy is actually tested
   - Tags enable tracking and audit trail

5. **Code Quality**:
   - Proper use of AWS CloudFormation capabilities (`CAPABILITY_NAMED_IAM`)
   - Stack state management with waiter logic
   - Error handling for already-existing resources
   - Output extraction for downstream use

The defense implementation is architecturally sound, uses AWS best practices, and directly implements the preventive control specified in the ADT.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The probe **fully corresponds** to the defensive intent specified in the ADT:

**ADT Probe Specification**:
- "Preventive Probe: Can IAM restrictions block project creation?"

**Implementation Analysis**:

1. **Direct Intent Mapping**:
   The `hypothesis_verification()` function explicitly validates that IAM restrictions blocked the malicious project creation through three verification checks:

2. **Verification Check 1 - Project Non-Existence**:
   ```python
   response = codebuild.batch_get_projects(names=[malicious_project_name])
   projects = response.get('projects', [])
   if projects:
       logger.error(f"FAILURE: Malicious project exists")
       return False
   ```
   - Directly answers "Can IAM restrictions **block** project creation?"
   - Tests the negative case (project should NOT exist)

3. **Verification Check 2 - Policy Validation**:
   ```python
   if 'codebuild:CreateProject' in actions:
       if 'codebuild:PrivilegedMode' in conditions['StringEquals']:
           logger.info("Found preventive control: Deny privileged mode")
           has_preventive_control = True
   ```
   - Confirms the IAM restriction mechanism is in place
   - Validates the preventive control configuration

4. **Verification Check 3 - Comprehensive Project List Check**:
   ```python
   response = codebuild.list_projects()
   all_projects = response.get('projects', [])
   if malicious_project_name in all_projects:
       logger.error(f"FAILURE: Malicious project found")
       return False
   ```
   - Double-checks against false negatives
   - Ensures no bypass occurred

5. **Defensive Intent Fulfillment**:
   - **Binary Success Criteria**: Returns `True` only if all checks pass (project blocked)
   - **Failure Detection**: Explicitly logs and fails if malicious project exists
   - **Mechanism Verification**: Validates both outcome (blocked) and mechanism (policy exists)
   - **Completeness**: Tests the entire preventive control chain from policy to enforcement

6. **Probe Quality**:
   - Multi-layered verification reduces false positives/negatives
   - Clear success/failure logging for observability
   - Exception handling prevents probe failures from masking security failures
   - Aligned with Chaos Engineering principle: "What happens when preventive control is tested?"

The probe's implementation directly tests whether IAM restrictions successfully prevent malicious CodeBuild project creation, which is exactly the defensive intent specified in the ADT node.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

This SCE experiment demonstrates exceptional quality across all three evaluation factors:

✅ **Perfect Attack Correspondence**: The implementation precisely replicates the attack vector specified in the ADT with appropriate malicious configurations and TTP alignment.

✅ **Perfect Defense Correspondence**: The preventive control uses fine-grained IAM policies with condition-based denies, exactly matching the defense strategy.

✅ **Perfect Probe Correspondence**: The hypothesis verification comprehensively validates that IAM restrictions block malicious project creation through multi-layered checks.

**Strengths**:
- Clean separation of steady-state, attack, and verification phases
- Comprehensive CloudFormation-based infrastructure deployment
- Proper AWS SDK usage with error handling
- Excellent logging and observability
- Realistic attacker simulation with role assumption
- Multi-check verification reducing false results
- Complete cleanup in rollback phase

**Technical Excellence**:
- Uses IAM condition keys (`codebuild:PrivilegedMode`) for precise control
- Implements exponential backoff for resource readiness
- Proper credential management with temporary session tokens
- Infrastructure-as-Code approach enables repeatability

This experiment is ready for execution and will provide valid security chaos engineering insights.

---

## Recommendations

**No improvements required** - the experiment meets all quality criteria. 

**Optional Enhancements** (for future iterations):
1. Add CloudTrail log verification to confirm the denial event was logged
2. Include metrics collection for response time of preventive control
3. Test additional malicious configurations (e.g., environment variable exfiltration patterns)
4. Implement parallel experiments testing detective and reactive controls from nodes 1.4 and 1.5