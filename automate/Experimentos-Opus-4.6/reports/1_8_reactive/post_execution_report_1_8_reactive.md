# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2, 1.7
- **Evaluation Date**: 2026-04-20

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-20 15:57:56,538 [INFO] STEP 1.2: ec2:DescribeInstances (T1580)
2026-04-20 15:57:57,198 [INFO]   SUCCEEDED: {'HttpTokens': 'required', 'HopLimit': 1}
2026-04-20 15:57:59,199 [INFO] STEP 1.7: ec2:ModifyInstanceMetadataOptions (T1562.001)
2026-04-20 15:57:59,874 [INFO]   SUCCEEDED (IMDS downgraded): {'HttpTokens': 'optional', 'HopLimit': 2}
```

**Justification**: Both attack steps executed successfully with verifiable evidence. Step 1.2 (DescribeInstances for IMDS enumeration, MITRE T1580) confirmed the initial secure state (`HttpTokens=required`, `HopLimit=1`). Step 1.7 (ModifyInstanceMetadataOptions, MITRE T1562.001) successfully downgraded IMDS from v2 to v1 (`HttpTokens=optional`, `HopLimit=2`). The attack results are structured, explicit, and fully verifiable. The attacker role was successfully assumed and used to execute both actions against the target EC2 instance.

---

## Factor 2: PROBE Capability
**Score**: 0

**Log Excerpts**:
```
2026-04-20 16:11:39,247 [INFO] --- Poll (981s remaining) checks={'imds_restored': False, 'role_denied': False, 'sns_notification': False} ---
[2026-04-20 16:16:48 ERROR]   => failed: botocore.exceptions.ConnectTimeoutError: Connect timeout on endpoint URL: "https://ec2.us-east-1.amazonaws.com/"
[2026-04-20 16:16:48 WARNING] Probe terminated unexpectedly, so its tolerance could not be validated
[2026-04-20 16:16:48 CRITICAL] Steady state probe 'Verify IMDS restored to required and hop-limit 1, attacker role denied, and remediation notification received on SQS' is not in the given tolerance so failing this experiment
```

**Justification**: The probe failed to return a verifiable result regarding defense behavior. Throughout approximately 14 minutes of polling (from 15:57:59 to 16:11:39), none of the three remediation checks transitioned to `True`: IMDS was never restored, the attacker role was never denied, and no SNS notification was received. The probe then terminated unexpectedly due to a `ConnectTimeoutError` to the EC2 API endpoint, meaning it could not even complete its polling cycle. While the experiment correctly identified a "deviated" state (indicating a potential weakness — the automated remediation pipeline failed), the probe itself did not produce a verifiable, complete measurement of defense behavior. The probe crashed rather than reaching a definitive conclusion through its own logic. The lack of any observed defensive response combined with the abnormal termination means we cannot distinguish between "the defense didn't work" and "the probe infrastructure failed before it could observe the defense."

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × 100 + 0.50 × 0**
Q_post = 50.00

**Threshold**: 80
**Result**: Q_post < 80

## DECISION

**INVALID EXECUTION**

---

## Recommendations

1. **Probe Resilience**: The probe should implement retry logic and exception handling for transient network failures (ConnectTimeoutError). A single API timeout should not terminate the entire verification loop.

2. **CloudTrail/EventBridge Latency**: The 30-second stabilization wait after CloudTrail/EventBridge setup may be insufficient. CloudTrail can take up to 15 minutes to deliver events. Consider extending the stabilization period or verifying that the EventBridge rule is actively receiving events before executing the attack.

3. **Lambda Function Verification**: Before executing the attack, add a pre-flight check to confirm the Lambda remediation function is properly deployed, has correct permissions, and can be invoked. Check CloudWatch Logs for any Lambda invocation errors during the polling window.

4. **EventBridge Rule Validation**: Verify the EventBridge rule pattern matches the `ModifyInstanceMetadataOptions` API call event structure. A misconfigured event pattern would silently prevent remediation.

5. **Timeout Strategy**: The 1800-second (30-minute) timeout is generous, but the probe crashed at ~981s remaining (~14 minutes in). Implement network-level retries and consider shorter polling intervals with exponential backoff.

6. **Diagnostic Logging**: Add intermediate diagnostics during polling — check Lambda CloudWatch logs, EventBridge rule metrics, and CloudTrail event delivery status to pinpoint where the remediation pipeline breaks down.