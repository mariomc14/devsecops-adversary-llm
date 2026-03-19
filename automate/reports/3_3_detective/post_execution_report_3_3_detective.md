# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 3.3
- **Probe Type**: Detective
- **Attack Nodes**: 1.2, 2.2, 3.2
- **Evaluation Date**: 2026-03-17 18:58:24 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 0
**Log Excerpts**:
```
[2026-03-17 18:58:24 ERROR]   => failed: TimeoutError: Stack 'sce-experiment-1773769094' did not reach CREATE_COMPLETE within 1200s
[2026-03-17 18:58:24 INFO] Action: execute-attack-1.2-modify-imds-2.2-harvest-credentials-3.2-lateral-movement-via-exfil-role
[2026-03-17 18:58:24 ERROR]   => failed: KeyError: 'instance_id'
```
**Justification**: The ACTION failed at two distinct points, yielding zero verifiable evidence of attack execution:

1. **CloudFormation Stack Timeout**: The provisioning action (`provision-vpc-ec2-cloudtrail-config-flowlogs-alarms-lambdas-iam-s3-ecr-ssm-via-cloudformation`) failed with a `TimeoutError` after 1200 seconds (~20 minutes). The stack `sce-experiment-1773769094` never reached `CREATE_COMPLETE`, meaning the underlying infrastructure (EC2 instance, VPC, CloudTrail, AWS Config, Flow Logs, CloudWatch Alarms) was never successfully instantiated.

2. **Attack Execution Failure**: Because the stack never completed provisioning, the subsequent attack action (`execute-attack-1.2-modify-imds-2.2-harvest-credentials-3.2-lateral-movement-via-exfil-role`) failed immediately with `KeyError: 'instance_id'`. This confirms that no EC2 instance was available in the stack outputs, so none of the three attack steps (T1578 IMDS weakening, T1552.005 credential harvesting, T1078.004 lateral movement) were executed. There is no verifiable evidence that any attack was performed against a live target.

---

## Factor 2: PROBE Capability
**Score**: 0
**Log Excerpts**:
```
[2026-03-17 18:58:24 ERROR]   => failed: KeyError: 'instance_id'
[2026-03-17 18:58:24 WARNING] Probe terminated unexpectedly, so its tolerance could not be validated
[2026-03-17 18:58:24 CRITICAL] Steady state probe 'verify-cloudtrail-config-flowlogs-and-trail-alarm-detect-imds-weakening-harvest-and-lateral-movement' is not in the given tolerance so failing this experiment
[2026-03-17 18:58:24 INFO] Experiment ended with status: deviated
```
**Justification**: The detective probe (`verify-cloudtrail-config-flowlogs-and-trail-alarm-detect-imds-weakening-harvest-and-lateral-movement`) also failed to return any verifiable result:

1. **Probe terminated unexpectedly**: The probe encountered the same `KeyError: 'instance_id'` as the attack action. Since the CloudFormation stack never completed, the probe could not resolve the EC2 instance ID necessary to query CloudTrail events, VPC Flow Logs metric filter alarms, AWS Config NON_COMPLIANT evaluations, or CloudWatch Trail alarms.

2. **Tolerance not validated**: The Chaos Toolkit explicitly logged `"Probe terminated unexpectedly, so its tolerance could not be validated"`. This means none of the four detection mechanisms (CloudTrail, VPC Flow Logs, AWS Config, CloudWatch Alarms) were checked against expected detection windows for the T1578 + T1552.005 + T1078.004 attack chain.

3. **Deviated status is misleading**: The experiment status `deviated` and the `CRITICAL` log entry do not indicate that a genuine security weakness was discovered — they reflect an infrastructure provisioning failure cascading into probe failure, not a meaningful detection gap finding.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × 0 + 0.50 × 0**

Q_post = 0.00

**Threshold**: 100
**Result**: Q_post < 100

## DECISION

**INVALID EXECUTION**

---

## Recommendations

### 1. Resolve CloudFormation Stack Timeout
- **Increase the provisioning timeout**: The stack timed out at 1200s (~20 min). Audit the CloudFormation template for resources that may be taking excessive time — likely candidates include EC2 instance initialization, Lambda deployment packages, SSM parameter propagation, or ECR image pushes. Increase the timeout to 1800–2400s or split the stack into nested stacks.
- **Investigate lingering resources**: Check whether the stack `sce-experiment-1773769094` left orphaned resources in a partial `CREATE_IN_PROGRESS` state. Ensure cleanup/rollback completes before re-running.
- **Pre-validate AMI**: Confirm `ami-02dfbd4ff395f2a1b` is available in the target region and supports the required instance type without extended initialization delays.

### 2. Decouple Infrastructure Provisioning from the Experiment Run
- Consider provisioning the baseline infrastructure (VPC, EC2, CloudTrail, AWS Config, Flow Logs, Alarms) as a **pre-experiment fixture** rather than inline during the experiment method. This separates environment readiness concerns from experiment execution.

### 3. Add Pre-Flight Stack Readiness Check
- Before proceeding to the attack action, add an explicit probe that verifies `instance_id` is available in stack outputs. If absent, fail fast with a descriptive error rather than propagating a `KeyError` through all subsequent steps.

### 4. Implement Graceful KeyError Handling
- The `KeyError: 'instance_id'` should be caught and surfaced as a meaningful pre-condition failure (e.g., `PreConditionError: EC2 instance not provisioned`), not an unhandled exception. This improves debuggability and prevents misleading `deviated` experiment outcomes.

### 5. Validate Detective Controls Independently
- Once provisioning is stable, verify each detection mechanism independently before running the full chain:
  - CloudTrail: confirm `ModifyInstanceAttribute` events are logged for IMDS changes (T1578).
  - VPC Flow Logs + metric filter: confirm the alarm fires on anomalous outbound traffic patterns (T1552.005).
  - AWS Config: confirm NON_COMPLIANT evaluation triggers on IMDSv1-enabled instances (T1578).
  - CloudWatch Alarm: confirm the trail alarm fires on `AssumeRole` calls with the exfiltration role (T1078.004).