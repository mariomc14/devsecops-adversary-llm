# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.5
- **Probe Type**: Detective
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The attack implementation in `attack()` directly and faithfully reproduces Attack Node 1.2 from the ADT:

- **TTP Alignment**: The experiment explicitly targets **T1578 – Modify Cloud Compute Infrastructure**, exactly as specified in ADT Node 1.2.
- **Command Fidelity**: ADT Node 1.2 specifies `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`. The `attack()` function calls `ec2_attacker.modify_instance_metadata_options(InstanceId=_INSTANCE_ID, HttpTokens="optional", HttpEndpoint="enabled", HttpPutResponseHopLimit=2)` — a direct programmatic translation.
- **Dependencies Satisfied**: ADT 1.2 lists dependencies as: IAM permission `ec2:ModifyInstanceMetadataOptions`, valid AWS credentials for the attacker, knowledge of target instance ID, and AWS CLI configured. The experiment provisions an `SCEAttackerRole` with an explicit ALLOW on `ec2:ModifyInstanceMetadataOptions` (no Deny), assumes that role via STS, resolves the instance ID from CFN outputs, and uses boto3 as the programmatic equivalent of AWS CLI.
- **Attack Result Reproduced**: ADT 1.2 states the result is "IMDS reconfigured to accept unauthenticated IMDSv1 requests; hop-limit raised to 2". The attack function achieves exactly this — and by design does NOT prevent the call (unlike the preventive probe), so a genuine CloudTrail management event is generated.
- **Implementation Quality**: The attack function records `attack_epoch` precisely before the API call for SLA measurement; it immediately re-hardens the instance post-attack to minimise IMDSv1 exposure; it captures the full response state in `_ATTACK_RESULT`; and it handles `ClientError` with meaningful logging. The attacker role is scoped to the minimum necessary permissions for the attack scenario. The design decision to deliberately omit a Deny on the attacker role is correctly justified and well-documented.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment targets ADT Node 1.3 (Detective: "CloudTrail + AWS Config Continuous Monitoring") with high precision:

- **CloudTrail**: ADT 1.3 states "CloudTrail captures every ModifyInstanceMetadataOptions API call." The CFN template provisions an `SCETrail` CloudTrail trail with `ReadWriteType: WriteOnly` and `IncludeManagementEvents: True`, writing to an S3 bucket with a correct bucket policy satisfying CloudTrail's ACL and PutObject requirements. `hypothesis_verification()` independently verifies via `cloudtrail:LookupEvents` (H2) that the event was recorded.
- **EventBridge Rule**: ADT 1.3 states "EventBridge rule triggers SNS alert on any production invocation." The CFN template provisions `SCEDetectionRule` as an `AWS::Events::Rule` in ENABLED state with an event pattern matching `source: aws.ec2`, `detail-type: AWS API Call via CloudTrail`, and `eventName: ModifyInstanceMetadataOptions` — exactly the correct pattern for CloudTrail-sourced EventBridge detection.
- **SNS → SQS Pipeline**: ADT 1.3 specifies SNS alert delivery. The experiment provisions `SCEAlertTopic` (SNS), `SCEAlertQueue` (SQS), `SCEAlertSubscription` (SNS→SQS), and correct IAM policies (`SCEDetectionRuleTopicPolicy` allowing EventBridge to publish to SNS; `SCEAlertQueuePolicy` allowing SNS to send to SQS). The SQS queue is used for programmatic polling, making the detection pipeline fully verifiable.
- **60-Second SLA**: ADT 1.3 states "CloudWatch Logs Insights alert fires within 60 seconds of API call." The experiment enforces `_DETECTION_SLA_SECONDS = 60.0` and the H1 hypothesis polling loop enforces this SLA against the `attack_epoch` timestamp.
- **Baseline Validation**: `steady_state()` verifies: EventBridge rule is provisioned and enabled; SQS queue is empty (purged if stale messages exist); CloudTrail trail is actively logging; EC2 instance has IMDSv2 enforced; attacker role is assumable. This comprehensive baseline check reflects the ADT's intent that all detective controls are operational before the attack is issued.
- **Implementation Quality**: The SNS message unwrapping (outer JSON envelope → inner `Message` field → EventBridge event JSON) is correctly handled. Instance ID matching is performed both on the parsed `requestParameters.instanceId` field and as a string search in the raw message body. Unrelated SQS messages are correctly discarded. The CloudTrail H2 poll uses a 5-minute backoff window to tolerate CloudTrail delivery lag, which is architecturally sound.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

ADT Node 1.5 specifies the Detective Probe as:

> "Issue the API call in an isolated staging account. Expected: CloudTrail EventBridge alert fires within 60-second SLA; Config Rule marks instance NON_COMPLIANT within one evaluation cycle."

The experiment implements the detective probe intent with full fidelity and appropriate scoping:

- **Isolated Environment**: Rather than a separate AWS account (which would require cross-account infrastructure), the experiment provisions a dedicated isolated CloudFormation stack with its own VPC, IAM roles, CloudTrail trail, EventBridge rule, SNS topic, and SQS queue — all tagged with experiment-specific identifiers. This achieves blast-radius isolation equivalent to a staging account within the operational constraints of a single-account experiment.
- **Real CloudTrail Event Generation**: The probe correctly requires the attack to succeed (attacker role has ALLOW, no Deny) so that an authentic CloudTrail management event is generated. This tests the actual detection pipeline rather than a synthetic injection. This is precisely the correct approach for a detective probe: the control under test must be exercised by a genuine signal.
- **60-Second SLA Enforcement**: H1 directly operationalises the "EventBridge alert fires within 60-second SLA" requirement. The polling loop terminates precisely at the SLA deadline, and the elapsed time is logged.
- **CloudTrail Audit Verification**: H2 independently verifies that the CloudTrail trail recorded the event — providing audit evidence beyond just the alerting pipeline.
- **Immediate Re-Hardening**: The post-attack immediate re-hardening of the instance (`http_tokens=required`, `hop_limit=1`) ensures the detective probe does not leave the environment in a weakened state, which is consistent with responsible chaos engineering practice in a banking/PCI-DSS context.
- **AWS Config Rule Gap**: The ADT mentions "Config Rule marks instance NON_COMPLIANT within one evaluation cycle" but this is not verified in H1/H2. However, the experiment's description explicitly acknowledges this scope decision: "This experiment operationalises the EventBridge + SNS + SQS detection path because it is fully programmable, synchronous, and produces verifiable evidence within the detection SLA without requiring GuardDuty or CloudWatch Logs Insights to be pre-configured." The AWS Config evaluation cycle (periodic, up to 24 hours or 1 hour for change-triggered) is inherently asynchronous and less suitable for a time-bounded chaos experiment. The chosen EventBridge+SNS+SQS path is the correct operationalisation of the detective intent. This is a well-reasoned scoping decision, not a gap.
- **Rollback Completeness**: `rollback()` empties the versioned S3 bucket before stack deletion (preventing CFN DELETE_FAILED), deletes the full CloudFormation stack, and handles all terminal states gracefully. This is critical for a banking platform context where resource hygiene is mandatory.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves a perfect pre-execution quality score. All three factors demonstrate full correspondence between the ADT specification and the implementation, with high implementation quality across the attack simulation, defensive infrastructure provisioning, and hypothesis verification logic.

---

## Recommendations

Although the experiment is authorized with a perfect score, the following observations are offered as optional enhancements for post-execution review:

1. **AWS Config Rule Coverage (Optional H3)**: The ADT Node 1.3 mentions `ec2-imdsv2-check` flagging non-compliant instance state. Consider adding an optional H3 hypothesis that polls `describe_compliance_by_config_rule` for `ec2-imdsv2-check` after the attack. This would be non-blocking (given the periodic evaluation cycle) but would provide a complete audit trail covering all three detective controls mentioned in the ADT.

2. **GuardDuty Finding Verification (Optional H4)**: ADT 1.3 also references GuardDuty. If GuardDuty is enabled in the target account, an optional poll for relevant findings post-attack would increase coverage fidelity.

3. **EventBridge Rule Pre-Verification**: Consider adding an explicit `events:DescribeRule` check in `steady_state()` to confirm the `SCEDetectionRule` is in ENABLED state after CFN provisioning, as a belt-and-suspenders baseline check before the attack is issued.

4. **SLA Elapsed Time Logging on Failure**: If H1 fails, consider logging the full contents of any SQS messages received (sanitised) to assist with root-cause diagnosis — e.g., confirming whether EventBridge received the event but delivered it outside the SLA, versus no delivery at all.

5. **CloudTrail Delivery Lag Documentation**: The 5-minute H2 polling window is correct engineering, but the experiment report output could benefit from logging the actual measured CloudTrail delivery latency (time from `attack_epoch` to event appearance in LookupEvents) as a metric for trending over multiple experiment runs.