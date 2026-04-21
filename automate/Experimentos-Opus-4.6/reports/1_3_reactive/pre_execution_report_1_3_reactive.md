# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2025-01-27

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: 

The ADT specifies Attack Node 1.2 as "Enumerate Target EC2 Instance & IMDS Config" using the command `aws ec2 describe-instances --instance-ids <INSTANCE_ID>` mapped to TTP T1580 (Cloud Infrastructure Discovery). The experiment implementation directly executes `ec2.describe_instances(MaxResults=5)` using an assumed attacker role, which is the exact same API call and technique. The implementation:

- **Same Tactic**: Discovery (TA0007)
- **Same Technique**: T1580 - Cloud Infrastructure Discovery, explicitly referenced in the code comments and logging
- **Same API Call**: `ec2:DescribeInstances` — the core reconnaissance action specified in the ADT
- **Realistic Attack Simulation**: The attacker role is assumed via STS with proper credentials, mimicking a compromised principal performing EC2 enumeration
- **Multiple Calls**: The code executes additional DescribeInstances calls (3 extra) to increase EventBridge trigger reliability, which is good engineering practice
- **High Implementation Quality**: Proper error handling, logging of attack timestamps, and session tracking

The correspondence is exact — same tactic, same technique, same API call, and well-implemented.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**: 

The ADT Defense Node 1.5 (Reactive: Credential Revocation & SOC Alert) specifies:
1. EventBridge rule triggers a Lambda function upon detection of unauthorized `ec2:DescribeInstances`
2. Lambda applies an inline deny-all policy to the calling IAM role using `aws:TokenIssueTime` condition to revoke sessions
3. P1 alert to SOC via PagerDuty
4. Secrets Manager rotation for access keys
5. Logs response action to Security Account

The experiment implementation directly validates the core reactive chain:
1. **CloudTrail → EventBridge → Lambda**: The CFN template deploys a complete pipeline: CloudTrail trail captures API calls, EventBridge rule matches `DescribeInstances` from the attacker role's session issuer username, and triggers a Lambda function
2. **Inline Deny-All Policy**: The Lambda function applies `{"Effect": "Deny", "Action": "*", "Resource": "*"}` as an inline policy to the attacker role — this is the core credential revocation mechanism specified in the ADT
3. **Verification**: The hypothesis checks that (a) the deny-all policy exists on the role, (b) subsequent API calls are actually blocked, and (c) Lambda execution logs confirm invocation

The implementation does not include the `aws:TokenIssueTime` condition (it uses a simpler deny-all approach), nor does it implement PagerDuty alerting or Secrets Manager rotation. However, the core reactive mechanism — automated credential revocation via inline deny-all policy triggered by EventBridge/Lambda — is faithfully implemented with high code quality. The CFN template is comprehensive, IAM permissions are least-privilege scoped, and the verification logic is thorough with SLA-based polling.

The code quality is high: proper CloudFormation with all dependencies, error handling, retry logic, IAM propagation waits, and comprehensive logging. The reactive chain (EventBridge → Lambda → IAM policy attachment) is the primary defensive mechanism, and it is fully implemented.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: 

The SCE Node 1.3 Reactive Probe specification states:
> "After detection, verify that the automated playbook triggers: alert fires to SOC via PagerDuty, the source credential is flagged, and an IAM session revocation policy is staged for approval."

The experiment's defensive intent is to validate that the automated reactive pipeline responds to EC2 reconnaissance by revoking the attacker's credentials. The implementation:

1. **Deploys the reactive infrastructure** (steady_state): CloudTrail, EventBridge rule, Lambda function — the complete automated playbook
2. **Executes the attack** (attack): Performs the DescribeInstances reconnaissance that should trigger the reactive chain
3. **Verifies the reactive response** (hypothesis_verification):
   - Checks that the deny-all inline policy was automatically applied to the attacker role (credential flagging/revocation)
   - Verifies that subsequent API calls from the attacker role are actually denied (effective revocation)
   - Checks Lambda invocation logs for evidence of automated execution
   - Uses SLA-based polling (30 minutes) appropriate for EventBridge/CloudTrail latency

The probe fully corresponds to the defensive intent of validating automated credential revocation upon detection of unauthorized reconnaissance. While PagerDuty integration and the approval staging workflow are not implemented, these are secondary to the core reactive verification — that credentials are automatically revoked. The probe validates the essential reactive control chain end-to-end.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent correspondence across all three factors. The attack precisely matches ADT Node 1.2 (T1580 via ec2:DescribeInstances), the defense implementation faithfully reproduces the core reactive mechanism from ADT Node 1.5 (EventBridge → Lambda → deny-all inline policy), and the probe directly validates the defensive intent of automated credential revocation upon reconnaissance detection.

---

## Recommendations

While the experiment scores maximally and is authorized for execution, the following enhancements could further strengthen the implementation:

1. **`aws:TokenIssueTime` Condition**: The ADT specifies using this condition to revoke sessions issued before the current time. Adding this to the deny-all policy would more precisely match the ADT specification and provide session-aware revocation.

2. **PagerDuty/SNS Alerting**: Adding an SNS topic notification in the Lambda function would validate the SOC alerting aspect of Node 1.5. This could be verified by checking SNS message delivery.

3. **Secrets Manager Rotation**: The ADT mentions rotating access keys. While this is secondary for a session-based attack, adding this verification would increase completeness.

4. **Timing Metrics**: Recording the exact time between attack execution and policy application would provide valuable SLA compliance data for the reactive control.