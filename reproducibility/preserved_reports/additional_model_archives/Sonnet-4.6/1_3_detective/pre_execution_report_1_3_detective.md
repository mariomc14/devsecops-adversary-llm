# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3
- **Probe Type**: Detective
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The `attack()` function in the Python implementation directly and precisely mirrors Attack Node 1.2 as specified in the ADT:

| ADT Specification (Node 1.2) | Implementation (`attack()`) |
|---|---|
| `aws ec2 modify-instance-metadata-options` | `ec2.modify_instance_metadata_options(...)` |
| `--instance-id <INSTANCE_ID>` | `InstanceId=instance_id` (from `_STATE["instance_id"]`) |
| `--http-tokens optional` | `HttpTokens="optional"` |
| `--http-endpoint enabled` | `HttpEndpoint="enabled"` |
| `--http-put-response-hop-limit 2` | `HttpPutResponseHopLimit=2` |
| TTP: T1578 — Modify Cloud Compute Infrastructure | Explicitly noted in log message: `"(TTP: T1578)"` |

The attack is scoped strictly to the EC2 instance provisioned by `steady_state()` (not a pre-existing production instance), preventing blast radius. The function records both `attack_time_monotonic` and `attack_time_utc` for MTTD measurement, which demonstrates high implementation quality. The dependency conditions from the ADT (valid EC2 instance, appropriate IAM permissions on the test role, AWS CLI/SDK available) are all satisfied by the `steady_state()` CFN stack provisioning. The attack correctly simulates the adversary action of downgrading IMDS to IMDSv1-optional with hop-limit=2 to enable credential harvesting from co-resident containers. No deviations from the specified tactic or technique are present.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment's detective probe maps precisely to Detective Safeguard Node 1.4 ("CloudTrail Alerting on IMDS Weakening API Calls") from the ADT. All three detection channels specified in Node 1.3 (SCE Chaos Node) and grounded in Node 1.4 are implemented:

**Signal A — CloudTrail → CloudWatch Logs** (maps directly to Node 1.4: *"CloudTrail captures every ModifyInstanceMetadataOptions API call"* and *"SIEM ingestion within <2 min"*):
- The CFN template creates a CloudTrail trail with CW Logs delivery, a CW Logs IAM role, and a metric filter with the correct pattern `{ $.eventName = "ModifyInstanceMetadataOptions" }`.
- `hypothesis_verification()` polls the log group with an instance-scoped structured filter pattern that prevents false positives in shared accounts.

**Signal B — EventBridge Rule Invocation** (maps to Node 1.4: *"EventBridge rule pattern fires SNS alert"*):
- The CFN template creates an EventBridge rule with the exact pattern from Node 1.4: `source: ["aws.ec2"]`, `detail-type: ["AWS API Call via CloudTrail"]`, `detail.eventName: ["ModifyInstanceMetadataOptions"]`.
- Verification polls `AWS/Events Invocations` metric with a 40-minute lookback window covering the full SLA.

**Signal C — CloudWatch Alarm** (maps to Node 1.4: *"AWS Config rule ... NON_COMPLIANT finding"* — proxied via CW Alarm since Config rule evaluation is account-wide and not sandbox-safe):
- The CFN template creates a `CloudWatch::Alarm` on the metric filter output (`SCE/{suffix}/IMDSWeakeningAttempts`), `GreaterThanOrEqualToThreshold=1`, `Period=60`, `EvaluationPeriods=1`.
- The alarm transitions to `ALARM` state within one 60-second evaluation window, which is a faithful proxy for the Security Hub NON_COMPLIANT signal.

**Additional quality markers**:
- SNS topic policy correctly grants `events.amazonaws.com` and `cloudwatch.amazonaws.com` publish permissions.
- The S3 bucket policy for CloudTrail uses the required `s3:x-amz-acl: bucket-owner-full-control` condition.
- MTTD is measured per-signal and reported against the <15-minute KPI from the ADT.
- The 30-minute SLA window (`timeout_s=1800`) in `_wait_until()` matches the experiment manifest SLA specification.
- The `SCECWLogsRole` IAM role correctly scopes the `logs:CreateLogStream` / `logs:PutLogEvents` permission to the specific log group ARN.

One minor gap: Node 1.4 references GuardDuty (`UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration`) and VPC Flow Logs as additional detection vectors. These are not implemented as verification signals. However, this is appropriate for the scope of a detective probe focused on Attack Node 1.2 only — GuardDuty requires actual credential use outside the VPC (Step 2 territory, not Step 1), and VPC Flow Logs anomalies similarly belong to downstream attack steps. The three implemented signals are the correct and complete set for Step 1 detection.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The probe's defensive intent is to validate that the organization's detective controls for IMDS weakening are operationally effective — specifically that a `ModifyInstanceMetadataOptions` API call is detected through multiple channels within the SLA window. The implementation achieves this with high fidelity:

**Alignment with Node 1.3 Detective Probe specification**:
> *"Issue a permitted ModifyInstanceMetadataOptions call in a sandbox account. Confirm CloudTrail event appears in SIEM within 2 minutes, Security Hub marks instance NON_COMPLIANT, and on-call engineer receives SNS/PagerDuty alert within SLA (<15 min MTTD)."*

- ✅ **Sandbox isolation**: All resources are created in a clean CFN stack with unique timestamp suffix. The attack targets only the provisioned instance, never a production resource.
- ✅ **Permitted call**: The attack uses the caller's own IAM credentials (not a blocked role), representing a permitted call in the sandbox context — this correctly tests detection, not prevention.
- ✅ **CloudTrail → SIEM proxy**: Signal A confirms CloudWatch Logs delivery within the SLA (CW Logs is the SIEM ingestion pipeline as configured in the trail).
- ✅ **Security Hub NON_COMPLIANT proxy**: Signal C (CloudWatch Alarm on metric filter) faithfully proxies the Security Hub finding in a way that is measurable and automatable.
- ✅ **SNS alert proxy for PagerDuty**: The SNS topic receives both EventBridge and CloudWatch Alarm notifications — Signal B validates the EventBridge → SNS path.
- ✅ **MTTD measurement**: `attack_time_monotonic` is recorded at attack completion; per-signal elapsed time is logged and compared against the <15-minute KPI.
- ✅ **All-or-nothing verdict**: `hypothesis_verification()` returns `True` only when all three signals are confirmed, enforcing the requirement that the full detection chain is functional.
- ✅ **Guaranteed rollback**: The `rollback()` function is called in the `finally` block of `_run_experiment()`, ensuring no orphaned resources regardless of experiment outcome.
- ✅ **Steady-state fidelity**: The pre-attack baseline verifies `HttpTokens=required`, `HopLimit=1`, `State=applied` — confirming the instance starts from the correct secure configuration before the attack degrades it.

The probe correctly distinguishes its scope from the preventive and reactive probes (also specified in Node 1.3) by focusing exclusively on detection signal confirmation, not blocking or remediation verification. The implementation correctly does not invoke the reactive Lambda or SSM remediation, avoiding interference with the detection timing measurements.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves a perfect quality score across all three factors. The implementation demonstrates complete fidelity to the ADT specification for Attack Node 1.2 and Detective Safeguard Node 1.4, with production-grade implementation quality including proper error handling, idempotent rollback, MTTD measurement, sandbox isolation, and SLA enforcement.

---

## Recommendations

The experiment meets or exceeds all quality thresholds. The following optional enhancements could increase defense-in-depth of the experiment itself (not required for authorization):

1. **GuardDuty Signal (Optional Extension)**: Consider adding a fourth verification signal that checks for GuardDuty finding `UnauthorizedAccess:EC2/MetadataDNSRebind` or equivalent, to validate the full detection stack described in Node 1.4. This would require enabling GuardDuty in the sandbox account.

2. **CloudTrail Delivery Latency Assertion**: The current Signal A polls with a 30-second interval. Adding an assertion that the first detection occurs within 120 seconds (2-minute SLA from Node 1.4) would make the MTTD SLA enforcement explicit and machine-verifiable rather than just logged.

3. **Concurrent Signal Polling**: The three signals are currently polled sequentially (A, then B, then C), each with a full 1800-second timeout. Parallel polling using `threading` or `concurrent.futures` would reduce total experiment wall-clock time in failure scenarios and provide more accurate relative MTTD measurements between signals.

4. **EventBridge Rule Warm-up**: Consider adding a 10-second sleep between `steady_state()` and `attack()` in `_run_experiment()` to ensure the EventBridge rule and CloudTrail → CW Logs delivery pipeline are fully propagated after CFN stack creation completes.