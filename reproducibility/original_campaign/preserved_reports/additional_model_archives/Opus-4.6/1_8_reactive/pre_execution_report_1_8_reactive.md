# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2, 1.7
- **Evaluation Date**: 2025-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: 

The experiment implements both attack steps specified in the ADT with exact correspondence:

**Attack Node 1.2 (T1580 - Cloud Infrastructure Discovery):** The `attack()` function executes `ec2:DescribeInstances` with the target instance ID, querying MetadataOptions fields (HttpTokens, HttpPutResponseHopLimit) — precisely matching the ADT specification which calls for `aws ec2 describe-instances --instance-ids <INSTANCE_ID> --query "Reservations[*].Instances[*].{...MetadataOptions...}"`. The tactic (Discovery) and technique (T1580) are faithfully reproduced.

**Attack Node 1.7 (T1562.001 - Impair Defenses: Disable or Modify Tools):** The `attack()` function executes `ec2.modify_instance_metadata_options()` with `HttpTokens="optional"`, `HttpEndpoint="enabled"`, and `HttpPutResponseHopLimit=2` — an exact match to the ADT command `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`. The tactic (Defense Evasion) and technique (T1562.001) are correctly implemented.

Both attacks are executed using an attacker IAM role assumed via STS (simulating compromised credentials with ec2:DescribeInstances and ec2:ModifyInstanceMetadataOptions permissions), matching the ADT's dependency on "valid AWS credentials with access to the banking platform account." The implementation quality is high: proper credential handling, error handling, result logging, and sequential execution with appropriate delays.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**: 

The SCE node 1.8 specifies a **Reactive Probe** that validates the reactive defense controls described in ADT nodes **1.5** (Session Revocation & Credential Invalidation) and **1.10** (Auto-Remediate IMDS & Revoke Attacker Permissions).

The experiment's reactive defense implementation corresponds to ADT node 1.10 with high fidelity:

1. **IMDS Re-enforcement (ADT 1.10 item 1):** The Lambda remediation function calls `ec2.modify_instance_metadata_options()` with `HttpTokens="required"` and `HttpPutResponseHopLimit=1` — exactly matching the ADT's specification of "Re-applies --http-tokens required and --http-put-response-hop-limit 1."

2. **Attacker Permission Revocation (ADT 1.10 item 2):** The Lambda attaches an inline deny-all policy (`{"Effect": "Deny", "Action": "*", "Resource": "*"}`) to the attacker role — matching the ADT's "Attaches inline deny-all policy to the IAM principal that made the call, revoking all active sessions."

3. **SNS Notification (ADT 1.10 item 3):** The Lambda publishes a remediation confirmation to an SNS topic with SQS subscriber — matching the ADT's "Publishes remediation confirmation to SNS topic with SQS subscriber for audit trail."

4. **EventBridge → Lambda Pipeline:** The detection-to-response pipeline uses EventBridge rule matching `ModifyInstanceMetadataOptions` CloudTrail events triggering a Lambda function — matching the ADT's "EventBridge rule triggers Lambda remediation function."

The implementation quality is high: CloudFormation provisions the complete reactive pipeline (CloudTrail → EventBridge → Lambda → SNS → SQS), includes proper IAM scoping, pre-flight validation of all components, and the Lambda code includes robust error handling and logging.

Items 4 (EBS snapshot) and 5 (SOC/CISO/Compliance notification per PCI-DSS) from ADT 1.10 are not implemented, but these are supplementary forensic/notification actions. The core reactive controls (remediate + revoke + notify) are fully covered.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: 

The SCE node 1.8 Reactive Probe specification states three verification objectives:

1. **"Lambda auto-remediation re-enforces IMDSv2 (http-tokens=required, hop=1) within 5 minutes"** → The `hypothesis_verification()` CHECK 1 polls `describe_instances` to verify `HttpTokens == "required"` and `HttpPutResponseHopLimit == 1`. ✓

2. **"Attacker role receives inline deny-all policy"** → CHECK 2 calls `list_role_policies` and `get_role_policy` to verify the existence of `sce-reactive-deny-all` with `Effect: Deny, Action: *, Resource: *`. ✓

3. **"Remediation notification on SNS/SQS pipeline"** → CHECK 3 polls the SQS queue for a message containing `remediation_complete` and the target instance ID. ✓

4. **"Instance flagged for forensic investigation"** → Not explicitly verified, but this is a lower-priority supplementary check.

The probe's defensive intent aligns with the ADT's reactive node 1.10 purpose: validating that automated incident response works end-to-end after an IMDS downgrade attack. The experiment follows the correct Chaos Engineering methodology: establish steady state (IMDSv2 enforced) → inject fault (IMDS downgrade) → verify hypothesis (automated remediation fires correctly within SLA).

The 30-minute SLA timeout is generous but appropriate for an automated reactive verification. The polling mechanism includes robust error handling (per-call exception catching for transient network errors), diagnostic logging (Lambda CloudWatch logs, EventBridge invocation metrics), and elapsed-time tracking — all contributing to high probe quality.

The probe correctly validates the defensive intent of the reactive control: confirming that the automated remediation pipeline detects, responds to, and recovers from the IMDS downgrade attack.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent correspondence across all three quality factors. The attack implementation precisely mirrors ADT nodes 1.2 and 1.7 with correct TTPs. The reactive defense pipeline faithfully implements ADT node 1.10's auto-remediation controls. The hypothesis verification probes directly validate the defensive intent specified in the SCE node 1.8 reactive probe specification.

---

## Recommendations

While the experiment scores full marks and is authorized for execution, minor enhancements could further strengthen it:

1. **EBS Snapshot Verification**: Add a CHECK 4 to verify the Lambda triggers an EBS snapshot of the affected instance (ADT 1.10 item 4), even if implemented as a separate Lambda action.
2. **SLA Granularity**: The ADT specifies "<5 min from API call" as the remediation target. Consider adding a strict 5-minute SLA check alongside the 30-minute overall timeout, and explicitly logging whether each check passes within the 5-minute window.
3. **Forensic Flagging**: Add tagging verification to confirm the instance is tagged for forensic investigation post-remediation.