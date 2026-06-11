# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**: 

The ADT specifies Attack Node 1.7 "Start Malicious Build" with:
- **Command**: `aws codebuild start-build`
- **Dependencies**: Malicious project exists
- **Result**: Credential exposure attempt
- **TTP**: T1098.001 Account Manipulation

The experiment implementation in the `attack()` function directly corresponds to this specification:

1. **Command Correspondence**: The implementation uses `codebuild.start_build(projectName=BUILD_PROJECT_NAME, ...)` which is the SDK equivalent of `aws codebuild start-build`.

2. **Dependencies Satisfied**: The `steady_state()` function creates the malicious CodeBuild project via CloudFormation (`MaliciousBuildProject` resource), satisfying the "Malicious project exists" dependency.

3. **Attack Semantics**: The attack function:
   - Starts a build on a project designed to simulate malicious activity
   - Includes environment variables marking it as an attack simulation (`ATTACK_MARKER`, `ATTACK_TIMESTAMP`)
   - The buildspec in the project echoes "Malicious build simulation"

4. **Implementation Quality**: High quality implementation with:
   - Proper error handling with try/except blocks
   - Logging of attack evidence (Build ID, ARN, status, start time)
   - Verification that the build was actually started
   - Global state management for rollback purposes

The tactic (execution of unauthorized builds) and technique (CodeBuild start-build API) are fully aligned with the ADT specification.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**: 

The ADT specifies the detective control at Node 1.9 "Runtime Container Monitoring" with:
- **Classification**: Detective
- **Strategy**: Container runtime analysis
- **Mechanism**: Behavioral anomaly detection

The SCE Node 1.8 detective probe asks: "Will runtime monitoring detect extraction?"

The experiment implementation provides comprehensive detective controls:

1. **EventBridge Rule** (`BuildStateChangeRule`):
   - Monitors CodeBuild Build State Change events
   - Filters for the specific malicious project
   - Routes events to CloudWatch Logs for analysis

2. **CloudWatch Logs** (`BuildEventLogGroup`):
   - Captures all build events for forensic analysis
   - Provides audit trail of build activities

3. **CloudWatch Metric Filter** (`BuildStartMetricFilter`):
   - Filters for builds with "IN_PROGRESS" status
   - Creates custom metric `MaliciousBuildStarts`
   - Enables quantitative monitoring

4. **CloudWatch Alarm** (`BuildStartAlarm`):
   - Triggers when malicious build count >= 1
   - Provides alerting capability for security teams

5. **Implementation Quality**: Excellent implementation with:
   - Infrastructure-as-Code approach using CloudFormation
   - Proper IAM permissions and resource policies
   - Multiple detection vectors (events, logs, metrics, alarms)
   - Comprehensive hypothesis verification checking all detection mechanisms
   - Wait functions with exponential backoff for eventual consistency

The detective controls fully correspond to the ADT's intent of detecting malicious build activity through runtime monitoring and behavioral analysis.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**: 

The ADT SCE Node 1.8 specifies the Detective Probe question: **"Will runtime monitoring detect extraction?"**

The experiment's `hypothesis_verification()` function directly validates this defensive intent:

1. **Verification of Detection Capability**:
   - Checks if EventBridge rule is active and properly configured
   - Searches CloudWatch Logs for evidence of captured build events
   - Verifies CloudWatch metric recorded the malicious build start
   - Checks CloudWatch Alarm state

2. **Evidence-Based Validation**:
   ```python
   detection_evidence = {
       'eventbridge_rule_active': False,
       'logs_contain_build_event': False,
       'metric_recorded': False
   }
   ```
   The function systematically validates each detection mechanism.

3. **Success Criteria Alignment**:
   ```python
   detection_successful = (
       detection_evidence['eventbridge_rule_active'] and
       (detection_evidence['logs_contain_build_event'] or detection_evidence['metric_recorded'])
   )
   ```
   The hypothesis verification confirms that detective controls can identify the malicious build start.

4. **Defensive Intent Correspondence**:
   - The probe answers whether runtime monitoring (EventBridge + CloudWatch) can detect the malicious build activity
   - The experiment validates detection occurred within a reasonable timeframe
   - The verification provides clear pass/fail determination with detailed logging

The probe fully corresponds to the defensive intent of validating detective control effectiveness against malicious build starts.

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

The experiment demonstrates excellent correspondence across all three evaluation factors:

1. **Attack Implementation**: The `attack()` function precisely implements the ADT's "Start Malicious Build" node using the correct AWS CodeBuild API.

2. **Defense Implementation**: Comprehensive detective controls are deployed including EventBridge rules, CloudWatch Logs, metrics, and alarms - exceeding the ADT's specification.

3. **Probe Validation**: The hypothesis verification systematically validates that detective controls can identify malicious build activity, directly addressing the SCE experiment's detective probe question.

---

## Recommendations

No recommendations required as the experiment achieves the maximum score. However, for future enhancements:

1. **Consider adding**: SNS notifications to the CloudWatch Alarm for real-time security team alerting
2. **Consider adding**: GuardDuty integration for additional threat detection correlation
3. **Consider adding**: Automated build termination as a reactive control (which would align with Node 1.10)