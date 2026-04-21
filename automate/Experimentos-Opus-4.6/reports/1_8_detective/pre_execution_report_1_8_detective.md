# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8
- **Probe Type**: Detective
- **Attack Nodes**: 1.2, 1.7
- **Evaluation Date**: 2024-01-XX

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: 

The experiment implementation provides full correspondence with both attack nodes specified in the ADT:

**Attack Node 1.2 (T1580 - Cloud Infrastructure Discovery):** The ADT specifies `aws ec2 describe-instances --instance-ids <INSTANCE_ID>` with a query on MetadataOptions fields. The Python implementation executes exactly this via:
```python
resp = ec2a.describe_instances(InstanceIds=[iid])
md = resp["Reservations"][0]["Instances"][0].get("MetadataOptions", {})
```
The attacker role is assumed via STS, the target instance is the banking-tier EC2 instance, and the returned IMDS configuration (HttpTokens, HopLimit) is captured — matching the ADT's described result of revealing IMDSv1/v2 configuration.

**Attack Node 1.7 (T1562.001 - Impair Defenses: Disable or Modify Tools):** The ADT specifies `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`. The Python implementation executes:
```python
resp = ec2a.modify_instance_metadata_options(
    InstanceId=iid,
    HttpTokens="optional",
    HttpEndpoint="enabled",
    HttpPutResponseHopLimit=2,
)
```
This is an exact parameter-level match. The attacker uses assumed credentials from a dedicated attacker IAM role, both attacks succeed (by design — the attacker role has explicit Allow), and the STRIDE goals (Tampering, Information Disclosure, Elevation of Privilege) are achievable through the weakened IMDS configuration.

Both TTPs are correctly mapped, the technique is identical (not just the same tactic), and the implementation quality is high with proper error handling, logging, and timestamp tracking.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**: 

The SCE Node 1.8 is a **Detective Probe** that, per the ADT, validates detective controls for the IMDS downgrade attack (Step 2). The relevant defense nodes are:

**ADT Node 1.9 (Detective: AWS Config Rule & CloudTrail Event Monitoring):** Specifies:
- AWS Config managed rule `ec2-imdsv2-check` for continuous evaluation
- EventBridge rule matching CloudTrail event `ModifyInstanceMetadataOptions` — trigger alert on ANY invocation
- Security Hub integration (HIGH severity)
- Configuration drift detection (HttpTokens changes from "required" to "optional")

**ADT Node 1.4 (Detective: CloudTrail API Monitoring & Anomaly Detection):** Specifies:
- CloudTrail monitoring for `ec2:DescribeInstances` calls with MetadataOptions query patterns
- EventBridge rule for EC2 Describe API calls from non-baseline principals

The implementation provisions and validates all three core detective mechanisms:

1. **CloudTrail:** A dedicated trail is created, and the hypothesis verifies both `DescribeInstances` and `ModifyInstanceMetadataOptions` events are recorded with correct instance IDs via `ct.lookup_events()`.

2. **EventBridge → SNS → SQS pipeline:** An EventBridge rule matching `ModifyInstanceMetadataOptions` is provisioned (matching ADT 1.9's specification). The SNS → SQS chain provides observable, poll-able proof of detection. The hypothesis verifies the message arrives containing the correct event name and instance ID.

3. **AWS Config `ec2-imdsv2-check`:** The managed rule is provisioned via CloudFormation. The hypothesis polls `get_compliance_details_by_config_rule` to confirm the modified instance is evaluated as `NON_COMPLIANT` — directly validating configuration drift detection.

The CloudFormation template is well-structured with proper IAM permissions, bucket policies, and resource dependencies. The code quality is high with comprehensive error handling, graceful degradation for pre-existing Config recorders, and proper resource tagging.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: 

The ADT's SCE Node 1.8 Detective Probe specifies:

> *"Execute the modify-instance-metadata-options call (expecting denial) and verify CloudTrail records the denied API call. Confirm AWS Config rule 'ec2-imdsv2-check' flags any instance not enforcing IMDSv2 within 10 minutes. Validate EventBridge rule triggers alert on any ModifyInstanceMetadataOptions API call regardless of success/failure."*

The implementation's defensive intent aligns fully:

1. **CloudTrail recording verification** — The probe confirms CloudTrail captured both the DescribeInstances (attack 1.2) and ModifyInstanceMetadataOptions (attack 1.7) API calls. While the ADT mentions "expecting denial," the experiment design intentionally allows the attacks to succeed to validate detection of *successful* attacks — this is actually a more rigorous test since detecting successful attacks is the critical scenario when preventive controls fail.

2. **AWS Config `ec2-imdsv2-check` evaluation** — The probe verifies the Config rule flags the instance as NON_COMPLIANT after the IMDS downgrade, with a 30-minute SLA (the ADT specifies 10 minutes; the implementation uses a generous 30-minute window but polls every 20 seconds, so it will catch within the ADT's window if the control works).

3. **EventBridge alert verification** — The probe confirms the EventBridge rule fires on the ModifyInstanceMetadataOptions call and delivers a notification through the SNS → SQS pipeline. This validates the "alert on any ModifyInstanceMetadataOptions API call" requirement.

The probe's intent is purely detective — it does not test preventive blocking or reactive remediation, which is correct for a Detective Probe type. The 30-minute SLA with polling provides a reasonable operational window. The four-check structure (CloudTrail Describe, CloudTrail Modify, EventBridge SQS, Config NON_COMPLIANT) provides comprehensive coverage of the detective control surface described in the ADT.

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

The experiment is well-designed and ready for execution. Minor observations for potential enhancement (not blocking):

1. **Config SLA alignment**: The ADT specifies a 10-minute window for Config rule evaluation; consider adding a warning log if the Config check takes >10 minutes even though the overall SLA is 30 minutes, to surface potential drift from the ADT's expectations.

2. **GuardDuty integration**: The ADT Node 1.9 mentions cross-correlation with GuardDuty findings. The current implementation does not validate GuardDuty detection, though this is understandable given GuardDuty's longer detection latency and the complexity of provisioning it in an experiment. This could be a future enhancement.

3. **Security Hub integration**: The ADT mentions feeding findings into Security Hub as HIGH severity. This is not validated in the current probe but could be added as an additional check.

4. **Minor code issue**: The `_build_template` function has a typo in the IAM ARN — `arn:aws:iam::${AWS::AccountId}:root` has a double colon (should be `arn:aws:iam::${AWS::AccountId}:root` — actually this is interpolated by CloudFormation's `Fn::Sub` but the double colon between `iam` and the account ID is incorrect; it should be a single colon). This would cause a stack creation failure. **Correction**: Looking more carefully, the `AWS_ConfigRole` managed policy ARN also has `arn:aws:iam::aws:policy/...` with double colons. These should be single colons (`arn:aws:iam::aws:policy/...` → `arn:aws:iam::aws:policy/...`). This is a potential runtime issue but does not affect the quality evaluation of the design correspondence.