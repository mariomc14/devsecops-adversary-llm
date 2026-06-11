# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Reactive
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2026-04-16 22:27:37 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-04-16 22:24:52,122 [INFO] ATTACK: Starting malicious build on project sce-malicious-project-1776396180 …
2026-04-16 22:24:52,743 [INFO] Malicious build started — id=sce-malicious-project-1776396180:314687d5-2e0c-4b77-a201-63311f22d92a arn=arn:aws:codebuild:us-east-1:941377112071:build/sce-malicious-project-1776396180:314687d5-2e0c-4b77-a201-63311f22d92a status=IN_PROGRESS
2026-04-16 22:24:52,878 [INFO] Confirmed build status via BatchGetBuilds: IN_PROGRESS
```
**Justification**: The attack action (1.7 Start Malicious Build) produced clear, verifiable evidence of execution. A real AWS CodeBuild build was successfully launched under the designated malicious project (`sce-malicious-project-1776396180`), assigned a unique build ID (`314687d5-2e0c-4b77-a201-63311f22d92a`), and confirmed `IN_PROGRESS` via an independent `BatchGetBuilds` API call. The build ARN and project name are concrete, traceable identifiers within a live AWS environment, satisfying full verifiability.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-04-16 22:25:06,154 [INFO] Build sce-malicious-project-1776396180:314687d5-2e0c-4b77-a201-63311f22d92a status: STOPPED
2026-04-16 22:25:06,156 [INFO] Build final status: STOPPED
2026-04-16 22:25:06,156 [INFO] ✓ Build was stopped by reactive control (status=STOPPED).
2026-04-16 22:25:45,105 [INFO] Lambda sce-reactive-fn-1776396180 invocation count (last 10 min): 1.0
2026-04-16 22:25:45,106 [INFO] ✓ Reactive Lambda was invoked 1 time(s).
2026-04-16 22:25:45,692 [INFO] EventBridge rule sce-malicious-build-rule-1776396180 state: ENABLED
2026-04-16 22:25:45,805 [INFO] ✓ EventBridge rule targets reactive Lambda.
2026-04-16 22:25:45,806 [INFO] hypothesis_verification PASSED — reactive control behaved as expected.
```
**Justification**: The reactive probe delivered multi-layered, independently verifiable evidence of the defense mechanism functioning correctly:
1. **Build termination**: The malicious build transitioned from `IN_PROGRESS` to `STOPPED` within approximately 13 seconds of launch — a concrete outcome in AWS CodeBuild.
2. **Lambda invocation**: CloudWatch metrics confirmed the reactive Lambda function (`sce-reactive-fn-1776396180`) was invoked exactly once, correlating precisely with the attack event.
3. **EventBridge rule integrity**: The EventBridge rule was confirmed `ENABLED` and correctly targeting the reactive Lambda, validating the end-to-end detection pipeline.
All three corroborating signals collectively prove that the reactive defense control (EventBridge → Lambda → StopBuild) operated as intended.

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

The experiment achieved a perfect score and the execution was fully valid. The following observations are noted for continuous improvement:

1. **CloudWatch metric propagation latency**: The Lambda invocation metric required ~53 seconds to appear in CloudWatch (two polling cycles with zero counts). Consider adding a note in the experiment documentation about this expected delay to avoid premature false-negative interpretations in future runs.
2. **SNS alert verification**: The `AlertTopicArn` (`sce-malicious-build-alert-1776396180`) was provisioned but no probe verified that an SNS notification was actually published. Adding an SNS message verification step (e.g., via SQS subscriber or CloudWatch Logs inspection) would further strengthen observability.
3. **Timing window documentation**: The build was stopped in ~13 seconds. Documenting the expected detection-to-stop latency as a formal SLO (e.g., "reactive control must stop build within 60 seconds") would make future regressions detectable.
4. **Build phase reached**: The logs do not indicate which CodeBuild phase the malicious build reached before being stopped. Capturing this information (e.g., via `BatchGetBuilds` phase details) would help quantify attacker dwell time within the build environment.