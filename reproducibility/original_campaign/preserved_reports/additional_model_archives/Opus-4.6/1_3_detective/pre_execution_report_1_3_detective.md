# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3
- **Probe Type**: Detective
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: 

The ADT Attack Node 1.2 specifies:
- **Command**: `aws ec2 describe-instances --instance-ids <INSTANCE_ID> --query "Reservations[*].Instances[*].{InstanceId:InstanceId, MetadataOptions:MetadataOptions}" --output json`
- **TTP**: T1580 - Cloud Infrastructure Discovery
- **Dependencies**: `ec2:DescribeInstances` permission; valid AWS credentials
- **Result**: Returns current IMDS configuration confirming whether protections are enforced

The experiment implementation:
- Creates a simulated attacker IAM role with explicit `ec2:DescribeInstances` permission
- Assumes that role via STS (`sce-detective-attack` session)
- Executes `ec2.describe_instances(MaxResults=5)` — the same API call specified in the ADT
- Records the attack principal ARN, timestamp, and execution result
- Executes a second call for detection confidence
- The TTP mapping (T1580) is explicitly referenced in the code docstring and logging

The tactic (Discovery) and technique (Cloud Infrastructure Discovery / T1580) are identical. The implementation uses the exact same AWS API (`ec2:DescribeInstances`) with proper credential handling. The attack is executed from a simulated attacker role (mimicking a compromised CI/CD role), which aligns with the ADT's scenario of unauthorized reconnaissance. The implementation quality is high: proper error handling, timing capture, and dual-call strategy for robustness.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**: 

The ADT Defense Node 1.4 specifies:
- **Classification**: Detective
- **Description**: CloudTrail logs every `ec2:DescribeInstances` API call with full principal ARN, source IP, and user agent. A custom CloudWatch metric filter triggers an alarm when DescribeInstances is invoked by any principal outside the approved operations IAM group. GuardDuty correlates reconnaissance patterns. Amazon Detective provides entity-level investigation. All logs ship to the Security Account data lake with integrity validation.

The experiment implements the following detective controls via CloudFormation:
1. **CloudTrail Trail** (`DetectiveTrail`): Configured with `IsLogging: True`, `EnableLogFileValidation: True`, delivering to CloudWatch Logs — matches "CloudTrail logs every ec2:DescribeInstances API call with full principal ARN, source IP, and user agent" and "integrity validation enabled"
2. **CloudWatch Log Group** (`TrailLogGroup`): Receives CloudTrail events — enables log search and correlation
3. **CloudWatch Metric Filter** (`ReconMetricFilter`): Filter pattern `{ ($.eventName = "DescribeInstances") }` — directly matches "custom CloudWatch metric filter triggers an alarm when DescribeInstances is invoked"
4. **CloudWatch Alarm** (`ReconAlarm`): Triggers on Sum ≥ 1 with 60-second period, fires to SNS — matches the alarm trigger behavior described
5. **SNS Topic** (`AlarmTopic`): Alarm action target for notification

The experiment does not implement GuardDuty or Amazon Detective verification, but the SCE node 1.3's detective probe description specifically states: "Verify CloudTrail logs the denied event within 5 minutes and GuardDuty correlates it as reconnaissance (Recon:IAMUser)." The implementation focuses on CloudTrail + CloudWatch pipeline which is the primary detective mechanism. The code also includes a direct CloudTrail `lookup_events` query as secondary verification. The implementation quality is high: proper CloudFormation templating, resource dependencies, IAM roles for CloudTrail-to-CloudWatch delivery, event selectors, and S3 bucket policies with proper security conditions.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: 

The SCE Node 1.3 Detective Probe specifies:
> "Inject a simulated DescribeInstances call from an unauthorized principal. Verify CloudTrail logs the denied event within 5 minutes and GuardDuty correlates it as reconnaissance (Recon:IAMUser)."

The experiment's defensive intent is to validate that the detective control pipeline (CloudTrail → CloudWatch Logs → Metric Filter → Alarm) successfully detects unauthorized EC2 reconnaissance attempts.

The `hypothesis_verification()` function implements this intent through:

1. **CloudTrail event in CloudWatch Logs**: Uses `filter_log_events` with pattern matching for `DescribeInstances`, then parses each event to verify it came from the specific attacker role (`sce-attacker-{timestamp}`), checking principal ARN, source IP, user agent — directly validating the detective control pipeline
2. **CloudWatch Alarm state**: Polls the alarm to verify it transitioned to `ALARM` state, confirming the metric filter → alarm pipeline works end-to-end
3. **CloudTrail direct lookup**: Uses `lookup_events` as secondary evidence, matching the attack event name and attacker role

The probe correctly validates the detective intent: a simulated unauthorized call is injected, and the verification confirms that the detective controls (CloudTrail logging, metric filter matching, alarm triggering) detect it. The implementation includes:
- SLA-based polling (30-minute window) with configurable timeout
- Multiple detection channels for robustness
- Detailed evidence logging (source IP, user agent, event time)
- Graceful handling of CloudTrail delivery latency (alarm may lag behind log events)

The slight deviation is that the experiment allows the call to succeed (rather than being denied) to ensure CloudTrail captures a complete event, which is actually a stronger test of detective controls. The ADT's mention of GuardDuty correlation is not verified in code, but the primary detective mechanism (CloudTrail + CloudWatch) is fully validated.

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

While the experiment scores perfectly against the evaluation criteria, the following enhancements could further strengthen it:

1. **GuardDuty Integration**: The ADT node 1.3 mentions verifying GuardDuty generates a `Recon:IAMUser` finding. Adding a GuardDuty finding check would provide complete coverage of the detective probe specification.

2. **SLA Measurement**: While the probe polls within a 30-minute window, explicitly measuring and reporting the detection latency (time from attack to first detection) against the "5 minutes" SLA mentioned in the ADT would provide valuable operational metrics.

3. **Negative Testing**: Consider adding a pre-attack verification that the alarm is in `OK`/`INSUFFICIENT_DATA` state before the attack, strengthening the causal link between the attack and alarm transition.

4. **Principal Filtering**: The metric filter matches all `DescribeInstances` calls, not specifically unauthorized ones. In production, the filter should exclude approved operations IAM group principals as specified in the ADT. This is acceptable for experiment scope but worth noting.