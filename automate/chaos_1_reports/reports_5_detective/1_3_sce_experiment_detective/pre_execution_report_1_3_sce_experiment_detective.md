# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**: 

The experiment implementation demonstrates **full correspondence** with the ADT attack node "1.2 Create Malicious CodeBuild Project":

1. **Tactic Alignment**: The attack function executes `codebuild_client.create_project()` which directly corresponds to the ADT specification of `aws codebuild create-project` command.

2. **Technique Alignment**: The implementation creates a malicious CodeBuild project with:
   - A buildspec that attempts credential harvesting via IMDS (`curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`)
   - Environment variables flagged as malicious (`MALICIOUS_FLAG: credential_harvesting`)
   - Tags indicating malicious intent (`Malicious: true`)

3. **TTP Correspondence**: The attack aligns with **T1552.005 (Unsecured Credentials: Cloud Instance Metadata API)** as specified in the ADT. The buildspec explicitly attempts to access the metadata service for credential extraction.

4. **Dependencies Met**: The experiment properly handles IAM dependencies by:
   - Creating a CodeBuild service role via CloudFormation
   - Using `iam:PassRole` implicitly through the role assignment
   - Granting `codebuild:CreateProject` permissions to the executing principal

5. **Implementation Quality**: The code is well-structured with proper error handling, logging, state management, and follows security chaos engineering best practices.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment implements detective controls that **fully correspond** to ADT node "1.4 CodeBuild Activity Monitoring":

1. **CloudTrail Logging**: The ADT specifies "CloudTrail logging" as the detection strategy. The implementation:
   - Uses EventBridge rules that monitor CloudTrail events (`"detail-type": ["AWS API Call via CloudTrail"]`)
   - Falls back to direct CloudTrail lookup via `cloudtrail_client.lookup_events()` for verification

2. **CloudWatch Alerts**: The ADT specifies "CloudWatch alerts" as part of the detective mechanism. The implementation:
   - Creates a dedicated CloudWatch Log Group (`/aws/events/codebuild-detection-{suffix}`)
   - Configures EventBridge to route detection events to CloudWatch Logs
   - Sets up proper resource policies for event delivery

3. **Real-time Monitoring**: The ADT specifies "Real-time project creation monitoring". The implementation:
   - Uses EventBridge rules with event pattern matching for `CreateProject` events from CodeBuild
   - The rule is configured with `State: ENABLED` for immediate detection
   - Event pattern specifically targets `codebuild.amazonaws.com` as the source

4. **High-Quality Code**: 
   - Complete CloudFormation template for infrastructure deployment
   - Proper IAM policies and resource policies
   - Error handling with fallback verification mechanisms
   - Clean resource tagging for experiment tracking

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The probe implementation **fully corresponds** to the defensive intent specified in the ADT:

1. **ADT Detective Probe Question**: "Will logging capture suspicious project setup?"
   
   The `hypothesis_verification()` function directly answers this question by:
   - Checking EventBridge-triggered CloudWatch Logs for `CreateProject` events
   - Verifying that the specific malicious project name was captured
   - Using CloudTrail as a fallback verification mechanism

2. **Verification Logic**:
   - Queries log streams created after the attack timestamp
   - Parses JSON event data to identify `CreateProject` events
   - Validates that the detected project matches the malicious project created during the attack
   - Returns `True` only when the specific malicious project creation is confirmed in logs

3. **Robust Detection Verification**:
   - Multiple retry attempts (12 attempts with 15-second intervals)
   - Dual verification paths (EventBridge logs + CloudTrail direct lookup)
   - Time-bounded search starting from attack timestamp

4. **Clear Success/Failure Criteria**:
   - `HYPOTHESIS VERIFIED` when detection is confirmed
   - `HYPOTHESIS FAILED` when detection is not found within timeframe
   - Proper logging of all verification steps

5. **Alignment with Chaos Engineering Principles**:
   - Steady state is established before attack
   - Attack is executed in controlled manner
   - Hypothesis verification tests the specific detective control
   - Rollback ensures clean environment restoration

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

The experiment demonstrates excellent correspondence across all three quality factors:

1. **Attack Implementation (100/100)**: Precisely implements the CodeBuild project creation attack with credential harvesting buildspec, matching the ADT specification and TTP T1552.005.

2. **Defense Implementation (100/100)**: Correctly deploys CloudTrail-based logging with EventBridge rules and CloudWatch integration for real-time detection, matching the ADT detective control specification.

3. **Probe Verification (100/100)**: The hypothesis verification directly tests whether logging captures the suspicious project setup, which is the exact defensive intent stated in the ADT.

---

## Recommendations

While the experiment scores 100 and is authorized for execution, the following enhancements could further strengthen the implementation:

1. **Additional Detection Signals**: Consider adding verification for CloudWatch alarms (not just logs) to fully exercise the "CloudWatch alerts" capability mentioned in the ADT.

2. **Metrics Collection**: Add timing metrics to measure detection latency (time from attack to detection event in logs).

3. **False Positive Testing**: Consider adding a legitimate project creation to verify the detection system doesn't over-alert.

4. **Documentation**: Add inline comments explaining the relationship between code sections and specific ADT nodes for traceability.