# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Reactive
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2026-04-16 21:51:23

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
[32m[2026-04-16 21:50:46 INFO] Action: start-malicious-build
2026-04-16 21:50:47,073 - INFO - Executing attack: Starting malicious build
2026-04-16 21:50:47,486 - INFO - Starting build for project: malicious-build-1776394217
2026-04-16 21:50:48,013 - INFO - Build started successfully:
2026-04-16 21:50:48,013 - INFO -   Build ID: malicious-build-1776394217:55f7e7c4-a416-4b5a-9ba3-82f6905a2e8d
2026-04-16 21:50:48,013 - INFO -   Build ARN: arn:aws:codebuild:us-east-1:941377112071:build/malicious-build-1776394217:55f7e7c4-a416-4b5a-9ba3-82f6905a2e8d
2026-04-16 21:50:48,013 - INFO -   Initial Status: IN_PROGRESS
2026-04-16 21:50:53,130 - INFO - Build status: IN_PROGRESS
2026-04-16 21:50:53,241 - INFO - Attack executed successfully. Build final status: IN_PROGRESS
```

**Justification**: 
The ACTION phase demonstrates clear and verifiable evidence of successful attack execution. The malicious build was successfully initiated with complete traceable artifacts including:
- Specific Build ID: `55f7e7c4-a416-4b5a-9ba3-82f6905a2e8d`
- Full ARN reference to the AWS CodeBuild resource
- Status confirmation showing the build progressed from initiation to IN_PROGRESS state
- Explicit success message: "Attack executed successfully"

The action completed its intended purpose of simulating a malicious build attack within the AWS CodeBuild environment, providing concrete evidence through AWS API responses and status tracking.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
[32m[2026-04-16 21:50:53 INFO] Probe: verify-reactive-logging-control
2026-04-16 21:50:53,884 - INFO - Verifying reactive security control: CloudWatch Logs capture
2026-04-16 21:50:54,302 - INFO - Checking log group: /aws/codebuild/malicious-build-1776394217
2026-04-16 21:50:54,772 - INFO - Log group /aws/codebuild/malicious-build-1776394217 exists
2026-04-16 21:51:05,202 - INFO - Found 1 log stream(s)
2026-04-16 21:51:05,300 - INFO - Examining log stream: 55f7e7c4-a416-4b5a-9ba3-82f6905a2e8d
2026-04-16 21:51:05,473 - INFO - Retrieved 36 log events from stream 55f7e7c4-a416-4b5a-9ba3-82f6905a2e8d
2026-04-16 21:51:05,474 - INFO - EVIDENCE FOUND: 'malicious build' in log message
2026-04-16 21:51:05,474 - INFO -   Message: [Container] 2026/04/17 02:50:54.777366 Running command echo 'Starting malicious build simulation'
2026-04-16 21:51:05,474 - INFO - SUCCESS: Reactive control verified - malicious activity logged to CloudWatch
[32m[2026-04-16 21:51:05 INFO] Steady state hypothesis is met!
```

**Justification**: 
The PROBE demonstrates exceptional capability in verifying the reactive security control. The probe successfully:
- Confirmed existence of the CloudWatch log group
- Located the specific log stream matching the build ID from the attack
- Retrieved 36 log events from the stream
- Identified specific evidence of malicious activity with the exact log message containing "malicious build"
- Provided the actual log content showing the command execution
- Explicitly confirmed success with "SUCCESS: Reactive control verified"
- Met the steady-state hypothesis validation

The probe provided complete, verifiable evidence that the reactive logging control successfully captured the malicious build activity, demonstrating full defensive capability assessment.

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

This experiment represents an exemplary SCE execution with no immediate improvements required. However, for future enhancements consider:

1. **Extended Detection Coverage**: Expand probes to verify additional reactive controls such as CloudWatch alarms, SNS notifications, or EventBridge rule triggers
2. **Timing Analysis**: Add metrics to measure the latency between attack execution and log availability for performance baseline establishment
3. **Pattern Matching**: Enhance probe logic to detect multiple indicators of compromise beyond the single keyword match
4. **Retention Verification**: Validate that log retention policies are properly configured for forensic analysis requirements
5. **Cross-Service Correlation**: Extend verification to ensure logs are properly integrated with SIEM or centralized logging solutions