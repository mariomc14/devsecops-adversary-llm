# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2026-04-27

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
[2026-04-27 17:58:58 INFO] Action: start-malicious-build
2026-04-27 17:58:58,131 - INFO - Starting malicious build on project: sce-malicious-build-detect-1777330637-malicious-project
2026-04-27 17:58:58,747 - INFO - Attack executed - Build started:
2026-04-27 17:58:58,747 - INFO -   Build ID: sce-malicious-build-detect-1777330637-malicious-project:3ac3e656-3d4d-4e14-b9f4-31857a33908e
2026-04-27 17:58:58,747 - INFO -   Build ARN: arn:aws:codebuild:us-east-1:941377112071:build/sce-malicious-build-detect-1777330637-malicious-project:3ac3e656-3d4d-4e14-b9f4-31857a33908e
2026-04-27 17:58:58,747 - INFO -   Initial Status: IN_PROGRESS
2026-04-27 17:58:58,747 - INFO -   Start Time: 2026-04-27 17:58:58.664000-05:00
2026-04-27 17:59:03,877 - INFO - Build current status: IN_PROGRESS
```

**Justification**: The ACTION (start-malicious-build) executed successfully and returned comprehensive verifiable evidence:
1. A specific Build ID was generated: `sce-malicious-build-detect-1777330637-malicious-project:3ac3e656-3d4d-4e14-b9f4-31857a33908e`
2. A full Build ARN was recorded as proof of AWS resource creation
3. The build status was confirmed as `IN_PROGRESS`
4. A precise timestamp of execution was logged
5. The experiment was carried out against a real CodeBuild project in AWS account `941377112071`

This represents complete verifiable evidence that the attack action (starting a malicious build) was successfully executed.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
[2026-04-27 17:59:03 INFO] Steady state hypothesis: Detective controls should detect malicious build starts
[2026-04-27 17:59:03 INFO] Probe: verify-malicious-build-detected
2026-04-27 17:59:04,424 - INFO - EventBridge rule state: ENABLED
2026-04-27 17:59:04,530 - INFO - EventBridge rule targets: 1
2026-04-27 17:59:04,530 - INFO - Waiting for events to propagate to CloudWatch Logs...
2026-04-27 17:59:05,135 - INFO - Found build event in logs: {"version":"0","id":"78c79d9c-5185-f930-ed5b-da403d0d6086","detail-type":"CodeBuild Build State Change","source":"aws.codebuild","account":"941377112071","time":"2026-04-27T22:58:58Z","region":"us-eas...
2026-04-27 17:59:05,562 - INFO - Metric datapoints: [{'Timestamp': datetime.datetime(2026, 4, 27, 22, 58, tzinfo=tzutc()), 'Sum': 1.0, 'Unit': 'None'}]
2026-04-27 17:59:05,562 - INFO - Total malicious build starts recorded: 1.0
2026-04-27 17:59:05,694 - INFO - CloudWatch Alarm state: OK
2026-04-27 17:59:05,694 - INFO - Detection evidence summary: {'eventbridge_rule_active': True, 'logs_contain_build_event': True, 'metric_recorded': True}
2026-04-27 17:59:05,694 - INFO - HYPOTHESIS VERIFIED: Detective control successfully detected the malicious build
[2026-04-27 17:59:05 INFO] Steady state hypothesis is met!
```

**Justification**: The PROBE (verify-malicious-build-detected) returned comprehensive verifiable evidence of the detective control's behavior:
1. **EventBridge rule verification**: Rule state confirmed as `ENABLED` with 1 target configured
2. **Log evidence**: Build event found in CloudWatch Logs with event ID `78c79d9c-5185-f930-ed5b-da403d0d6086`
3. **Metric recording**: CloudWatch metric datapoint confirmed with `Sum: 1.0` at the correct timestamp
4. **Detection evidence summary**: Structured evidence showing all three detection mechanisms worked:
   - `eventbridge_rule_active: True`
   - `logs_contain_build_event: True`
   - `metric_recorded: True`
5. **Hypothesis verification**: The probe explicitly confirmed "HYPOTHESIS VERIFIED: Detective control successfully detected the malicious build"

This demonstrates complete, verifiable evidence that the detective control successfully detected the malicious build start.

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

The experiment execution was exemplary with no improvements needed. Notable positive aspects:

1. **Comprehensive logging**: Both action and probe phases provided detailed, timestamped evidence
2. **Multi-layer detection verification**: The probe validated detection across multiple mechanisms (EventBridge, CloudWatch Logs, CloudWatch Metrics)
3. **Proper cleanup**: Resources were properly rolled back after the experiment
4. **Clear hypothesis validation**: The probe explicitly stated whether the hypothesis was met

For future experiments, consider:
- Adding alarm state transition verification (although the alarm was in OK state, which is expected for detective controls that record but don't necessarily alert immediately)
- Including latency measurements for detection time (time between attack execution and detection confirmation)