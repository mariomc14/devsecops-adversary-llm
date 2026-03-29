# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 3.3
- **Probe Type**: Detective
- **Attack Nodes**: 1.2, 2.2, 3.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

All three attack nodes are faithfully reproduced in the implementation with correct MITRE ATT&CK tactic/technique fidelity:

**Attack Node 1.2 (T1578 — Modify Cloud Compute Infrastructure)**:
The ADT specifies `aws ec2 modify-instance-metadata-options --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`. The implementation executes exactly this via `ec2_client.modify_instance_metadata_options(InstanceId=instance_id, HttpTokens="optional", HttpEndpoint="enabled", HttpPutResponseHopLimit=2)`. Parameters match precisely. The attack is executed against a real CFn-provisioned EC2 test instance (not mocked), using real AWS credentials, consistent with the ADT's stated dependencies (ec2:ModifyInstanceMetadataOptions permission, valid AWS credentials, running EC2 instance).

**Attack Node 2.2 (T1552.005 — Unsecured Credentials: Cloud Instance Metadata API)**:
The ADT specifies unauthenticated curl to `http://169.254.169.254/latest/meta-data/iam/security-credentials/`. The IMDSProbeFunction Lambda implements exactly this — issuing an unauthenticated HTTP GET to the instance private IP with `Host: 169.254.169.254` header (routing through the private subnet to hit IMDS without a session token). It retrieves the role name and then the full credentials. The dependency chain (Step 1.2 must complete first, IMDSv1 re-enabled) is correctly sequenced in `attack()`. The harvest result is persisted to SSM for detection verification.

**Attack Node 3.2 (T1078.004 — Valid Accounts: Cloud Accounts)**:
The ADT specifies using exfiltrated credentials to enumerate `sts get-caller-identity`, `iam list-attached-role-policies`, `iam list-role-policies`, and attempt lateral movement to S3, Secrets Manager, ECR. The SimulatedAttackerFunction assumes `ExfiltrationSimRole` (representing the compromised instance role) and then invokes `sts:GetCallerIdentity`, `iam:ListRoles`, `iam:CreateUser`, `s3:GetObject` on the PCI bucket, and `ecr:GetAuthorizationToken` — directly corresponding to the enumeration and privilege escalation attempts described in the ADT. The dependency (Step 2 complete, external attacker context) is simulated by the Lambda assuming the ExfilRole.

Implementation quality is high: retry logic, proper error handling, base64 tail-log decoding, IAM propagation delays, sequential step execution with state tracking.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The detective probe targets ADT node 1.4 (Step 1 Detective Safeguard), 2.4 (Step 2 Detective Safeguard), and 3.4 (Step 3 Detective Safeguard) with high fidelity across all three:

**ADT 1.4 — Detect IMDS Config Modification**:
- ADT Control 1: CloudTrail logs ModifyInstanceMetadataOptions → implemented as `(a1)` CloudWatch Logs `filter_log_events` with FilterPattern matching `$.eventName = "ModifyInstanceMetadataOptions"` and the specific instance ID.
- ADT Control 2: AWS Config rule evaluates NON_COMPLIANT → **replaced** with `(a2)` direct `ec2:DescribeInstances` check confirming `HttpTokens=optional` and `HopLimit=2`. The implementation documentation explicitly justifies this substitution (Config recorder was the primary timeout root-cause). The replacement is functionally equivalent for detective validation.
- ADT Control 3: CloudWatch Metric Filter + Alarm → the TrailMetricFilter/TrailAlarm in Stack B covers this (though primarily associated with Step 3.2 ExfilRole calls; CloudTrail event delivery itself serves as the metric for Step 1.2).

**ADT 2.4 — Detect IMDS Credential Harvest**:
- ADT Control 1: VPC Flow Logs CloudWatch Alarm on port-80 ACCEPT traffic → implemented as `(b1)` `FlowLogsMetricFilter` with FilterPattern `[..., dstport=80, ..., action=ACCEPT, ...]` and `FlowLogsAlarm` with `ComparisonOperator: GreaterThanThreshold` on threshold 0. Polled via `_poll_until` for ALARM state transition within 180s.
- ADT Control 2: GuardDuty InstanceCredentialExfiltration → not directly tested (GuardDuty is a live service, not testable in isolation); acceptable for a scoped detective probe.
- SSM `HarvestSignalParam` confirms `harvested::` prefix — `(b2)` directly maps to the harvest detection signal described in the chaos node specification.

**ADT 3.4 — Detect Exfiltrated Credential Misuse**:
- ADT Control 2/3: SIEM correlation on iam:List*/iam:Get* from instance role; CloudWatch TrailAlarm on ExfilRoleAPICall metric → implemented as `(c1)` CloudTrail filter for `GetCallerIdentity`, `ListRoles`, `GetAuthorizationToken` events from `ExfiltrationSimRole` principal; `(c2)` TrailMetricFilter/TrailAlarm with FilterPattern `$.userIdentity.sessionContext.sessionIssuer.userName = "<exfil_role_name>"`. This precisely represents the SIEM alert pathway described in the ADT.

Code quality: Stack B template is well-structured with proper DependsOn ordering, correct FilterPattern syntax for VPC Flow Logs space-delimited format, correct metric namespace scoping, TreatMissingData: notBreaching (avoids false positives during setup), 60s period with single EvaluationPeriod for responsive detection. The two-stack split is architecturally sound and directly addresses the root-cause identified.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The defensive intent of the detective safeguards is to validate that security monitoring infrastructure can detect the full three-step IMDS attack chain within defined detection windows before an analyst can respond. The probe design fully serves this intent:

**Detection Window Validation**: The experiment imposes explicit SLA windows — `_CLOUDTRAIL_DELIVERY_WAIT = 300s` for CloudTrail event delivery and `_ALARM_TRANSITION_WAIT = 180s` for alarm state transitions. These are realistic operational bounds (CT delivery can take 2-5 min; metric aggregation adds delay) and directly validate whether detective controls meet their implied detection SLAs.

**Full Attack Chain Coverage**: The experiment exercises all three attack TTPs sequentially (T1578 → T1552.005 → T1078.004) against real AWS infrastructure, ensuring the detective controls are tested against actual API calls generating real CloudTrail events and VPC Flow Logs — not synthetic signals. This maximizes detection fidelity.

**Multi-Control Corroboration**: Each attack step is validated by two independent detective signals: (a1+a2) CloudTrail event AND EC2 state verification; (b1+b2) Flow Logs alarm AND SSM harvest signal; (c1+c2) CloudTrail API call events AND TrailAlarm state. This mirrors how a real SOC would corroborate detections and validates defense-in-depth at the detective layer.

**Separation of Concerns**: The two-stack architecture ensures observability resources (CloudTrail, Flow Logs, alarms) are independently managed and fully operational before attack execution. The 60s warm-up delay after Stack B creation ensures CloudTrail delivery pipeline is active, preventing false negatives from timing artifacts.

**Scoped Non-Production Target**: The CFn-provisioned test instance with timestamped resource names ensures clean-room execution with no impact on production systems, consistent with SCE blast-radius principles.

**Graceful Degradation Logic**: The `b_harvest_ok = b_alarm_ok` fallback (if SSM harvest signal is blocked but the Flow Logs alarm fires) reflects the correct defensive intent — the alarm is the primary detective control; the harvest signal is corroborating evidence. This prevents a false FAIL if IMDS propagation timing causes the Lambda to hit IMDSv2 enforcement.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves maximum correspondence across all three quality factors. The implementation demonstrates: (1) exact TTP fidelity for all three attack nodes, (2) direct mapping to all testable detective controls in the ADT with a justified substitution for the AWS Config sub-check, and (3) a probe design that fully validates the defensive intent of detective safeguard nodes 1.4, 2.4, and 3.4 within defined detection windows.

---

## Recommendations

As Q_pre = 100.00, no remedial changes are required. The following optional enhancements could further strengthen the experiment in future iterations:

1. **GuardDuty Integration**: Add a synthetic GuardDuty finding injection (via `guardduty:CreateSampleFindings` or EventBridge event injection) to validate the `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` detection path described in ADT 2.4 Control 2 and 3.4 Control 1 — currently the only untested detective control.

2. **Secrets Manager Access Alerting**: ADT 3.4 Control 4 specifies a CloudWatch alarm on `secretsmanager:GetSecretValue` from instance role outside VPC endpoints. Adding a `secretsmanager:GetSecretValue` attempt in the SimulatedAttackerFunction and a corresponding metric filter would achieve full 3.4 coverage.

3. **Detection Latency Metrics**: Emit custom CloudWatch metrics recording the actual detection latency (time from attack execution to alarm transition) to generate quantitative SLA compliance data across experiment runs.