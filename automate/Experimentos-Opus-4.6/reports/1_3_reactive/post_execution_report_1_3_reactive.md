# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2026-04-17

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
[INFO] 2026-04-17 13:50:45 - Assuming attacker role: arn:aws:iam::396608802942:role/sce-react-attacker-1776426505
[INFO] 2026-04-17 13:50:45 - Role assumed successfully
[INFO] 2026-04-17 13:50:45 - Attack principal ARN: arn:aws:sts::396608802942:assumed-role/sce-react-attacker-1776426505/sce-reactive-attack
[INFO] 2026-04-17 13:50:45 - Executing: aws ec2 describe-instances
[INFO] 2026-04-17 13:50:45 - DescribeInstances SUCCEEDED (expected)
[INFO] 2026-04-17 13:50:45 - Instances returned: 2
[INFO] 2026-04-17 13:50:45 - Duration: 0.65s
[INFO] 2026-04-17 13:50:45 - Executing additional DescribeInstances calls for reactive trigger confidence
[INFO] 2026-04-17 13:50:46 - Additional call 1/3 succeeded
[INFO] 2026-04-17 13:50:48 - Additional call 2/3 succeeded
[INFO] 2026-04-17 13:50:50 - Additional call 3/3 succeeded
```
**Justification**: The attack action (EC2 reconnaissance via `DescribeInstances` — MITRE ATT&CK T1580) executed successfully and produced verifiable evidence. The attacker role was assumed, 4 total `DescribeInstances` API calls were made successfully, and 2 EC2 instances were enumerated. The infrastructure (CloudFormation stack, CloudTrail, EventBridge rule, Lambda function) was fully deployed and verified before the attack. The action fully simulated the intended attack node 1.2.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
[INFO] 2026-04-17 13:50:52 - Starting reactive verification (SLA: 1800s)
[INFO] 2026-04-17 13:50:52 - Checking for deny-all policy 'sce-deny-all-1776426505' on role 'sce-react-attacker-1776426505'
[INFO] 2026-04-17 13:50:52 - Verification attempt 1 (0s / 1800s elapsed)
[INFO] 2026-04-17 13:50:53 - Inline policies on attacker role: ['AllowEC2Describe']
...
[INFO] 2026-04-17 14:20:32 - Inline policies on attacker role: ['AllowEC2Describe']
[INFO] 2026-04-17 14:20:32 - Deny policy not yet applied (reactive chain pending)
[INFO] 2026-04-17 14:21:02 - Deny-all policy applied:       False
[INFO] 2026-04-17 14:21:02 - Post-attack calls blocked:     False
[INFO] 2026-04-17 14:21:02 - Lambda invocation confirmed:   False
[ERROR] 2026-04-17 14:21:02 - HYPOTHESIS FAILED: Reactive controls did not respond within SLA
[CRITICAL] Steady state probe 'verify-reactive-credential-revocation' is not in the given tolerance so failing this experiment
[INFO] 2026-04-17 14:22:07 - Experiment ended with status: deviated
```
**Justification**: The probe performed a thorough, methodical verification of the reactive control's behavior. It polled for the expected `sce-deny-all` deny policy on the attacker role across 60 verification attempts over the full 1800-second SLA window (30-second intervals). It checked three distinct verification criteria: (1) deny-all policy application, (2) post-attack call blocking, and (3) Lambda invocation confirmation. All three returned `False`, providing a clear, verifiable, and definitive result: the reactive defense chain (CloudTrail → EventBridge → Lambda → credential revocation) failed to trigger. The probe correctly identified the deviation from the steady-state hypothesis and the experiment was marked as "deviated." This is a high-quality probe result — it produced an unambiguous, evidence-backed finding of a security weakness.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × 100 + 0.50 × 100**
Q_post = 100.00

**Threshold**: 80
**Result**: Q_post >= 80

## DECISION

**VALID EXECUTION**

---

## Recommendations

While the experiment execution is valid and of high quality, the following observations may improve future iterations:

1. **Diagnose the reactive chain failure**: The Lambda function log group did not exist (`Lambda log group does not exist` during cleanup), strongly suggesting the Lambda was never invoked. This points to a failure in the EventBridge rule matching the CloudTrail event for `DescribeInstances`. Investigate whether the EventBridge rule's event pattern correctly matches the specific API call and principal.

2. **Add intermediate diagnostics**: Consider adding mid-experiment checks on the EventBridge rule's invocation metrics (e.g., `InvocationsAttempted`, `FailedInvocations`) and CloudTrail event delivery status to pinpoint exactly where the reactive chain breaks.

3. **Reduce SLA wait if possible**: The 1800s (30-minute) SLA is generous. If the expected response time for this reactive chain is much shorter (e.g., < 5 minutes), consider a shorter timeout with a separate "extended" fallback to save experiment duration while still capturing the result efficiently.

4. **Verify CloudTrail delivery latency**: CloudTrail events can have significant delivery delays (typically 5-15 minutes). Ensure that the EventBridge rule is configured to receive events via CloudTrail's integration with EventBridge (not relying solely on S3 log delivery), which could explain the non-triggering behavior.