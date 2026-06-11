# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2026-04-08 22:35:05

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-08 22:29:15,202 - INFO - Created malicious CodeBuild project: arn:aws:codebuild:us-east-1:941377112071:project/malicious-build-1775705323
2026-04-08 22:29:15,510 - INFO - Started malicious build: malicious-build-1775705323:e7f89697-672d-4337-93e4-ab0d5a2d7aba
2026-04-08 22:29:25,629 - INFO - Build status: SUCCEEDED
2026-04-08 22:29:26,253 - INFO - Found malicious log entry: [Container] 2026/04/09 03:29:23.381419 Running command echo "Starting malicious activity"
2026-04-08 22:29:26,253 - INFO - Attack executed successfully - malicious logs written
```

**Justification**: 
The ACTION phase executed completely and successfully with full verifiable evidence:
1. **Defensive Infrastructure Deployed**: CloudFormation stack created successfully with all required resources (CodeBuild role, CloudWatch alarm, SNS topic, log group)
2. **Attack Executed**: Malicious CodeBuild project was created with ARN confirmation
3. **Build Triggered**: Build started and completed with SUCCEEDED status
4. **Malicious Activity Confirmed**: The log entry containing "Starting malicious activity" was successfully written and verified
5. **Complete Execution Chain**: All steps from infrastructure deployment through attack execution were completed with success confirmations

The ACTION provided comprehensive, verifiable evidence of both the defensive control deployment and the attack execution.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-08 22:29:26 INFO] Probe: verify-cloudwatch-alarm-triggered
2026-04-08 22:29:26,863 - INFO - Verifying reactive control: Checking alarm MaliciousCodeBuildAlarm-1775705323
2026-04-08 22:30:57,391 - INFO - Alarm state: OK
2026-04-08 22:30:57,391 - INFO - State reason: Threshold Crossed: 1 datapoint [0.0 (09/04/26 03:29:00)] was not greater than or equal to the threshold (1.0).
[... multiple polling iterations ...]
2026-04-08 22:34:10,781 - INFO - Final alarm state: OK
[2026-04-08 22:34:10 CRITICAL] Steady state probe 'verify-cloudwatch-alarm-triggered' is not in the given tolerance so failing this experiment
```

**Justification**:
The PROBE demonstrated complete capability and returned definitive, verifiable results:
1. **Alarm Identification**: Successfully located and monitored the correct CloudWatch alarm (MaliciousCodeBuildAlarm-1775705323)
2. **State Monitoring**: Executed multiple polling iterations over ~5 minutes, capturing alarm state transitions
3. **Detailed Metrics**: Retrieved specific datapoint values (0.0), thresholds (1.0), timestamps, and state reasons
4. **Definitive Result**: Determined that the alarm remained in "OK" state and did NOT trigger despite malicious activity
5. **Tolerance Evaluation**: Properly evaluated the result against expected tolerance and failed the experiment appropriately

The PROBE successfully detected that the **reactive defense control FAILED** to detect the malicious activity. This is verifiable evidence of defense behavior (specifically, the absence of expected detection), which reveals a security weakness. The probe functioned perfectly by discovering this gap.

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

While this experiment receives full marks for execution quality, the **substantive security finding** is critical:

### Security Finding
The reactive CloudWatch alarm **failed to detect malicious CodeBuild activity** despite:
- Malicious commands being executed
- Logs being written with suspicious patterns
- Build completing successfully

### Root Cause Analysis Needed
1. **Metric Filter Accuracy**: Verify the CloudWatch Logs metric filter pattern correctly matches "malicious activity" string
2. **Log Group Association**: Confirm the metric filter is attached to the correct log group (`/aws/codebuild/malicious-build-1775705323`)
3. **Metric Data Publishing**: Check if metric data points are being published to CloudWatch (current datapoint shows 0.0)
4. **Timing/Latency**: Consider if CloudWatch Logs-to-Metrics propagation delay exceeds the 5-minute observation window
5. **Alarm Configuration**: Validate alarm evaluation periods, datapoints to alarm, and statistic configuration

### Recommended Improvements
1. Extend PROBE timeout beyond 5 minutes to account for AWS service latency
2. Add intermediate verification to confirm metric filter is functioning
3. Query CloudWatch Metrics directly to verify metric data publication
4. Implement fallback probe to directly search CloudWatch Logs as secondary verification
5. Add alerting validation (check SNS topic for notifications)

**This experiment successfully identified a security control gap - the intended outcome of Security Chaos Engineering.**