# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2026-04-08 21:26:22

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**: 
```
2026-04-08 21:24:36,420 - INFO - Creating malicious CodeBuild project: malicious-project-1775701380
2026-04-08 21:24:37,088 - INFO - Successfully created malicious CodeBuild project: arn:aws:codebuild:us-east-1:941377112071:project/malicious-project-1775701380
```
**Justification**: The ACTION successfully executed the attack by creating a malicious CodeBuild project. The log clearly shows:
1. The project name: `malicious-project-1775701380`
2. The full ARN of the created resource: `arn:aws:codebuild:us-east-1:941377112071:project/malicious-project-1775701380`
3. Confirmation message stating successful creation

This provides verifiable evidence that the attack (creating a malicious CodeBuild project) was successfully executed in the target AWS environment.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**: 
```
2026-04-08 21:25:38,094 - INFO - EventBridge rule state: ENABLED
2026-04-08 21:25:38,575 - INFO - Found 1 log streams
2026-04-08 21:25:38,707 - INFO - Found CreateProject event for: arn:aws:codebuild:us-east-1:941377112071:project/malicious-project-1775701380
2026-04-08 21:25:38,708 - INFO - SUCCESS: Detected our malicious CodeBuild project creation!
2026-04-08 21:25:38,708 - INFO - HYPOTHESIS VERIFIED: Detective controls successfully detected malicious CodeBuild project creation
[32m[2026-04-08 21:25:38 INFO] Steady state hypothesis is met!
```
**Justification**: The PROBE successfully detected the malicious CodeBuild project creation. The evidence shows:
1. The EventBridge rule was confirmed as ENABLED
2. Log streams were found in the detection log group
3. A `CreateProject` event was specifically found for the malicious project ARN
4. The hypothesis was verified confirming the detective controls worked as expected
5. The Chaos Toolkit confirmed "Steady state hypothesis is met!"

This provides complete verifiable evidence that the detective probe successfully identified the attack activity.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × [100] + 0.50 × [100]**
Q_post = 100.00

**Threshold**: 100
**Result**: Q_post >= 100

## DECISION

**VALID EXECUTION**

---

## Recommendations

The experiment executed successfully with full marks for both factors. Some minor observations for potential future improvements:

1. **Event propagation timing**: The experiment waited 60 seconds for event propagation. Consider documenting whether this is the minimum required time or if it could be optimized.

2. **Rollback verification**: While rollback was executed, consider adding explicit verification that all resources were deleted to ensure complete cleanup.

3. **Additional detection metadata**: Consider capturing and logging additional metadata about the detected event (e.g., timestamp, user identity, source IP) to enhance forensic capabilities.

4. **Multiple detection channels**: Consider verifying detection through additional channels (e.g., CloudTrail, Security Hub) to test defense-in-depth.