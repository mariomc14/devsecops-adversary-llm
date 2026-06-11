# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2026-04-15 21:15:47 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-04-15T21:03:22  INFO      Resources ready → project=sce-experiment-1776304867-malicious-build  
                                log_group=/sce/sce-experiment-1776304867/malicious-build-events  
                                alarm=sce-experiment-1776304867-malicious-build-alarm
2026-04-15T21:03:38  INFO      Malicious build started  
                                arn=arn:aws:codebuild:us-east-1:941377112071:build/sce-experiment-1776304867-malicious-build:4335e2e9-b934-48be-b5df-b23378630efe  
                                status=IN_PROGRESS
2026-04-15T21:14:57  INFO      Stopped build sce-experiment-1776304867-malicious-build:4335e2e9-b934-48be-b5df-b23378630efe.
```
**Justification**: The attack action (Attack Node 1.7 — Start Malicious Build) was executed with full verifiable evidence. The CloudFormation stack was successfully created (`CREATE_COMPLETE`), provisioning all required resources (CodeBuild project, EventBridge rule, CloudWatch log group, and alarm). The malicious CodeBuild build was successfully started and assigned a concrete ARN (`arn:aws:codebuild:us-east-1:941377112071:build/sce-experiment-1776304867-malicious-build:4335e2e9-b934-48be-b5df-b23378630efe`) with status `IN_PROGRESS`. The build ran until rollback, where it was explicitly stopped. This constitutes unambiguous, verifiable evidence of attack execution.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-04-15T21:03:38  INFO      === HYPOTHESIS VERIFICATION  
                                alarm=sce-experiment-1776304867-malicious-build-alarm  
                                log_group=/sce/sce-experiment-1776304867/malicious-build-events ===
2026-04-15T21:03:39  INFO      Alarm sce-experiment-1776304867-malicious-build-alarm → OK
2026-04-15T21:03:39  INFO      No log streams in /sce/sce-experiment-1776304867/malicious-build-events yet.
...
[10 verification attempts across ~11 minutes]
...
2026-04-15T21:14:57  ERROR     Hypothesis verification timed out – detective control did NOT fire.
[CRITICAL] Steady state probe 'Verify detective control detected the malicious build invocation' 
           is not in the given tolerance so failing this experiment
[INFO] Experiment ended with status: deviated
[INFO] The steady-state has deviated, a weakness may have been discovered
```
**Justification**: The detective probe functioned completely and returned a definitive, verifiable result. It performed 10 structured polling attempts over approximately 11 minutes, checking both the CloudWatch Alarm state (`sce-experiment-1776304867-malicious-build-alarm`) and the CloudWatch Log Group (`/sce/sce-experiment-1776304867/malicious-build-events`) on each iteration. The probe correctly identified and reported that the alarm remained in `OK` state throughout and that no log streams were ever populated. It conclusively determined that the detective control **did NOT fire**, returned a terminal `ERROR` verdict, triggered the CRITICAL steady-state deviation, and caused the experiment to conclude with status `deviated`. The probe did not fail silently or error out — it produced a clear, actionable determination: the defense was absent/ineffective. This is a fully valid probe result revealing a genuine security weakness.

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

Although the experiment is VALID and successfully uncovered a real security weakness, the following remediation and improvement recommendations are warranted given the critical finding (detective control failure):

### 🔴 Critical Security Finding
The detective control **completely failed** to detect the malicious CodeBuild invocation. Neither the CloudWatch Alarm nor the EventBridge-to-CloudWatch Logs pipeline fired during the ~11-minute observation window. This represents a confirmed gap in the CI/CD supply chain attack detection posture.

### Remediation Recommendations

1. **Verify EventBridge Rule Configuration**: Confirm the EventBridge rule correctly targets CodeBuild `StartBuild` API events (event pattern: `source: aws.codebuild`, `detail-type: CodeBuild Build State Change`) and is in `ENABLED` state.

2. **Validate CloudTrail Integration**: Ensure CloudTrail is active in `us-east-1` and that management events (write operations including `codebuild:StartBuild`) are being captured and forwarded to EventBridge.

3. **Check EventBridge Target Permissions**: Verify that the EventBridge rule has the necessary IAM permissions to write to the CloudWatch Log Group and/or trigger the metric filter that feeds the alarm.

4. **Review CloudWatch Alarm Metric Filter**: Confirm the metric filter is correctly defined on the log group and that the alarm threshold/period is appropriate for detecting individual build invocations (threshold = 1, period ≤ 60s).

5. **Add GuardDuty Integration**: Consider enabling AWS GuardDuty with CodeBuild protection as a secondary detective layer for malicious build activity.

6. **Re-run Experiment Post-Fix**: After implementing fixes, re-execute SCE 1.8 to confirm the detective control now fires within an acceptable time window (recommended SLO: < 2 minutes from build start to alarm).