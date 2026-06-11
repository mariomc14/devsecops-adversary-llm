# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2026-04-13 00:10:29

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
[32m[2026-04-13 00:03:27 INFO] Action: Execute malicious build with credential exfiltration attempt
2026-04-13 00:03:28,331 - INFO - Executing malicious build with credential exfiltration attempt...
2026-04-13 00:03:28,910 - INFO - Starting malicious build in project: sce-malicious-build-sce-experiment-1-8-1776056574
2026-04-13 00:03:29,609 - INFO - Build started: sce-malicious-build-sce-experiment-1-8-1776056574:acac57a6-2b92-48fb-8428-2fd5ef80c5ec
2026-04-13 00:03:29,610 - INFO - Build ARN: arn:aws:codebuild:us-east-1:941377112071:build/sce-malicious-build-sce-experiment-1-8-1776056574:acac57a6-2b92-48fb-8428-2fd5ef80c5ec
2026-04-13 00:03:29,740 - INFO - Build status: IN_PROGRESS
```

**Justification**: 
The ACTION phase successfully executed the malicious build attack. The logs provide comprehensive verifiable evidence including:
- Explicit confirmation of malicious build execution with credential exfiltration attempt
- Unique build project identifier: `sce-malicious-build-sce-experiment-1-8-1776056574`
- Complete Build ARN for traceability
- Build ID: `acac57a6-2b92-48fb-8428-2fd5ef80c5ec`
- Status monitoring showing the build ran for approximately 5 minutes (300 seconds) before timing out
- The timeout is expected behavior for a malicious build scenario

The infrastructure deployment also completed successfully (CREATE_COMPLETE status), establishing the necessary environment for the attack. The ACTION definitively executed and is fully verifiable through AWS CodeBuild identifiers and state transitions.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
[32m[2026-04-13 00:08:34 INFO] Probe: Verify CloudWatch alarm detects malicious build indicators
2026-04-13 00:08:35,278 - INFO - Verifying detective control detected malicious activity...
2026-04-13 00:08:35,750 - INFO - Checking alarm: SCE-CodeBuild-MaliciousActivity-sce-experiment-1-8-1776056574
2026-04-13 00:08:35,750 - INFO - Log group: /aws/codebuild/sce-malicious-build-sce-experiment-1-8-1776056574
2026-04-13 00:08:35,750 - INFO - Waiting 90 seconds for metric propagation...
2026-04-13 00:10:06,881 - INFO - Alarm state: ALARM
2026-04-13 00:10:06,885 - INFO - ✓ Detective control DETECTED malicious activity (alarm in ALARM state)
[32m[2026-04-13 00:10:07 INFO] Steady state hypothesis is met!
```

**Justification**:
The PROBE successfully verified the detective control's capability with complete evidence:
- Specific alarm identifier queried: `SCE-CodeBuild-MaliciousActivity-sce-experiment-1-8-1776056574`
- Associated log group verified: `/aws/codebuild/sce-malicious-build-sce-experiment-1-8-1776056574`
- Appropriate wait time (90 seconds) for CloudWatch metric propagation
- **Definitive alarm state confirmation**: ALARM state achieved
- Explicit confirmation that detective control DETECTED the malicious activity
- Steady state hypothesis validated

The probe returned unambiguous, verifiable evidence that the detective control (CloudWatch alarm) successfully detected the malicious build activity, fulfilling its intended purpose. The transition to ALARM state confirms the defense mechanism is functioning as designed.

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

The experiment executed flawlessly with both attack and detective control performing as expected. The following strengths are noted:

1. **Complete Traceability**: All AWS resources are uniquely identified with ARNs and IDs
2. **Proper Timing**: Adequate wait time for metric propagation ensures reliable detection
3. **Clean Rollback**: Stack deletion completed successfully, demonstrating proper cleanup
4. **Clear Success Criteria**: Alarm state provides binary, verifiable detection outcome

**Optional Enhancements** (not required, as execution is already valid):
- Consider capturing alarm state reason/message for additional forensic context
- Log the specific metric data points that triggered the alarm for deeper analysis
- Document the time delta between attack initiation and alarm trigger for performance metrics

This experiment serves as an excellent template for detective control validation in Security Chaos Engineering.