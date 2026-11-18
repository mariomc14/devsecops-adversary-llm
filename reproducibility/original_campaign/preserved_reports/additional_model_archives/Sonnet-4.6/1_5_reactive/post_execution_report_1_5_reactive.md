# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.5
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2026-04-09 15:23:48 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 0
**Log Excerpts**:
```
[2026-04-09 15:23:48 ERROR]   => failed: RuntimeError: Stack sce-experiment-1775740830 reached terminal state ROLLBACK_IN_PROGRESS. Recent reasons: ['', '', '', '', '']
[2026-04-09 15:23:48 ERROR]   => failed: KeyError: 'instance_id'
2026-04-09 15:23:48,489 [INFO] sce.1_5.reactive — === attack() — Downgrade IMDS to IMDSv1 ===
2026-04-09 15:23:48,490 [WARNING] sce.1_5.reactive — Attack did not succeed (possibly blocked by a preventive control).
```
**Justification**: The attack action (Attack Node 1.2 — `ModifyInstanceMetadataOptions` to downgrade IMDS to IMDSv1) **did not execute**. The CloudFormation stack provisioning failed, entering `ROLLBACK_IN_PROGRESS` state before the target EC2 instance could be created. As a direct consequence, no `instance_id` was available in the experiment state, causing the attack action to fail with a `KeyError: 'instance_id'`. There is no verifiable evidence that the `ModifyInstanceMetadataOptions` API call was ever issued against any EC2 instance. The attack was never attempted in any meaningful sense — the failure is infrastructural, not a security control blocking the attack. No API call evidence, no instance modification record, no attacker role assumption confirmation exists in the logs.

---

## Factor 2: PROBE Capability
**Score**: 0
**Log Excerpts**:
```
2026-04-09 15:23:48,490 [WARNING] sce.1_5.reactive — Attack did not succeed (possibly blocked by a preventive control). Reactive probe is vacuously satisfied — returning True to indicate the system is in a safe state.
[2026-04-09 15:23:48 INFO] Steady state hypothesis is met!
```
**Justification**: The reactive probe is designed to verify that **after** an IMDS downgrade attack, the defensive controls (Lambda auto-remediation, EventBridge rule, SSM flag) restore `HttpTokens=required` and revoke attacker credentials. Since the attack never executed (no EC2 instance was created, no downgrade was attempted), the probe's "vacuously satisfied" return is explicitly acknowledged in the log as a logical fallback — not a genuine observation of defense behavior. The probe did **not** observe any remediation Lambda invocation, any EventBridge event triggered, any `ModifyInstanceMetadataOptions` restoration call, or any attacker credential revocation. The steady-state hypothesis being "met" is a vacuous truth — it carries zero evidentiary value regarding actual reactive defense capability. No verifiable defensive behavior was observed or measured.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × 0 + 0.50 × 0**

Q_post = 0.00

**Threshold**: 80
**Result**: Q_post < 80

## DECISION

**INVALID EXECUTION**

---

## Recommendations

### Root Cause: CloudFormation Stack Provisioning Failure
The experiment collapsed at its foundation — the infrastructure stack never successfully deployed. The log shows `ROLLBACK_IN_PROGRESS` with **empty reason strings** (`['', '', '', '', '']`), which indicates the failure root cause was not captured. Address this first:

1. **Diagnose the CloudFormation failure**: Inspect the AWS CloudFormation console or use `aws cloudformation describe-stack-events` for stack `sce-experiment-1775740830` to retrieve the actual resource-level failure reason (e.g., IAM permission denied, Lambda deployment package missing, EC2 quota exceeded, invalid AMI in region).

2. **Improve error logging**: The empty reason strings suggest the stack event polling logic is not correctly extracting `ResourceStatusReason` from CloudFormation events. Fix the event parsing to surface actionable error messages directly in the log.

3. **Validate the AMI**: AMI `ami-0e10497160c48e829` was resolved — confirm it is valid and accessible in `us-east-1` with the executing IAM principal.

4. **Pre-flight IAM validation**: Add a pre-experiment check verifying the executing role has all required permissions: `cloudformation:CreateStack`, `ec2:RunInstances`, `iam:CreateRole`, `lambda:CreateFunction`, `events:PutRule`, `ssm:PutParameter`.

5. **Add explicit state guards**: The attack action should explicitly check for a valid `instance_id` in state and fail with a clear, informative error rather than a bare `KeyError`. This will improve diagnosability.

6. **Re-execute after infrastructure fix**: Once the CloudFormation stack deploys successfully (`CREATE_COMPLETE`), re-run the experiment to obtain genuine f1 and f2 evidence — the attack must actually call `ModifyInstanceMetadataOptions` and the probe must observe Lambda-driven remediation.