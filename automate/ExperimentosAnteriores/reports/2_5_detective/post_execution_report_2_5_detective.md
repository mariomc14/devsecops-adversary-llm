# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.5
- **Probe Type**: Detective
- **Attack Nodes**: 1.2, 2.2
- **Evaluation Date**: 2026-03-17 14:18:31 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-03-17T14:11:02Z [INFO] sce.2_5.detective - Step 1: Assumed AttackerRole session: AROAVYV52CB7AFPYQWFL2:sce-attack-1-1773752860-03b79511
2026-03-17T14:11:03Z [INFO] sce.2_5.detective - Step 1: ModifyInstanceMetadataOptions succeeded (HTTP 200). CloudTrail event generated.
2026-03-17T14:11:04Z [INFO] sce.2_5.detective - Step 1: Instance i-09ecebc70662005f0 re-hardened to IMDSv2 (http_tokens=required, hop_limit=1).
2026-03-17T14:11:12Z [INFO] sce.2_5.detective - SSM command 41779ce8-f220-418f-a144-5a015debf5a2: status=Success rc=0 stdout='HTTP_CODE:401'
2026-03-17T14:11:12Z [INFO] sce.2_5.detective - Step 2: IMDS curl completed. SSM status=Success HTTP code='401'
...
'attack_epoch': 1773753062.2866058, 'step1_http_status': 200, 'step1_rehardened': True, 'step2_stdout': 'HTTP_CODE:401'
```

**Justification**:
Both attack steps executed successfully and produced verifiable evidence:

- **Attack Node 1.2 (T1578 – Modify Instance Metadata Options)**: The attacker role (`sce-attacker-role-1773752860-03b79511`) was successfully assumed (session `AROAVYV52CB7AFPYQWFL2:sce-attack-1-1773752860-03b79511`). The `ec2:ModifyInstanceMetadataOptions` API call was issued against target instance `i-09ecebc70662005f0`, downgrading IMDS to IMDSv1 (`http_tokens=optional`, `hop_limit=2`), and received HTTP 200 confirmation. A CloudTrail event was generated. The target was subsequently re-hardened to IMDSv2 as designed.

- **Attack Node 2.2 (T1552.005 – Unsecured Credentials: Cloud Instance Metadata API)**: An SSM Run Command (`41779ce8-f220-418f-a144-5a015debf5a2`) was successfully submitted to and executed on probe instance `i-067fd2c6a03fb2b35`, issuing `curl` requests to `169.254.169.254`. The command returned `status=Success`, `rc=0`, and `HTTP_CODE:401` — confirming actual network traffic was generated toward the IMDS endpoint (the 401 is the expected response since IMDSv2 was in force on the probe instance, but the TCP connection and HTTP request to 169.254.169.254 were still made and would be visible to flow log capture).

Both attack steps have concrete, timestamped, machine-verifiable evidence of execution in the log.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-03-17T14:11:28Z [INFO] sce.2_5.detective - [H1] CloudTrail event found. EventTime=2026-03-17 14:11:04+01:00 Actor=arn:aws:iam::396608802942:user/ChaosXploit-Labs InstanceId=
2026-03-17T14:11:28Z [INFO] sce.2_5.detective - [H1] PASS -- CloudTrail recorded ModifyInstanceMetadataOptions for instance i-09ecebc70662005f0.

2026-03-17T14:16:43Z [ERROR] sce.2_5.detective - [H2] FAIL -- VPC Flow Logs did NOT capture traffic to 169.254.169.254 within 300-second polling window. Elapsed: 340.8s.

2026-03-17T14:16:43Z [INFO] sce.2_5.detective - [H3] Remaining SLA for EventBridge notification: 10s.
2026-03-17T14:16:43Z [INFO] sce.2_5.detective - [H3] PASS -- EventBridge notification received 341.7s after attack. Event: ModifyInstanceMetadataOptions Instance: i-09ecebc70662005f0
2026-03-17T14:16:43Z [ERROR] sce.2_5.detective - hypothesis_verification() -> FAIL. One or more detective hypotheses were not satisfied.
```

**Justification**:
The probe successfully interrogated all three detective hypotheses and returned definitive, verifiable verdicts for each:

- **H1 (CloudTrail)**: PASS — The probe queried CloudTrail `LookupEvents` and retrieved a real, timestamped event (`2026-03-17 14:11:04+01:00`) matching `ModifyInstanceMetadataOptions` on the correct instance. This constitutes clear positive evidence that the CloudTrail detection control is functioning.

- **H2 (VPC Flow Logs)**: FAIL — The probe ran a CloudWatch Logs Insights query against the flow log group `/sce/flowlogs/1773752860-03b79511` for 300 seconds (polling elapsed: 340.8s) without finding matching traffic to `169.254.169.254`. This is a conclusive, verifiable negative result — the probe exhausted its polling window and explicitly reported the failure with elapsed time and the target log group. This represents a genuine weakness finding: VPC Flow Logs either have a delivery delay exceeding 300s in this environment, or IMDS traffic (link-local, 169.254.169.254) is not captured by VPC Flow Logs at all (which is a known AWS limitation — link-local/instance metadata traffic is not included in VPC Flow Logs).

- **H3 (EventBridge / SQS SLA)**: PASS on detection, but FAIL on the 60-second SLA — The EventBridge rule did deliver a notification to SQS (confirmed by message retrieval containing `ModifyInstanceMetadataOptions` and instance `i-09ecebc70662005f0`), but at 341.7 seconds post-attack, vastly exceeding the 60-second SLA threshold. The probe correctly measured and reported this latency.

The probe produced verifiable, differentiated, and actionable results across all three hypotheses. The overall experiment outcome of `deviated` is well-supported by the probe's findings: two of three detective controls either failed outright (H2) or failed their SLA (H3). This is exactly the purpose of a detective probe in SCE — the probe capability is fully demonstrated.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × 100 + 0.50 × 100**

Q_post = 100.00

**Threshold**: 100
**Result**: Q_post >= 100

## DECISION

**VALID EXECUTION**

---

## Recommendations

Although the experiment is VALID, the findings reveal two actionable weaknesses that should be addressed:

### H2 – VPC Flow Logs Cannot Capture IMDS Traffic
- **Root Cause**: AWS VPC Flow Logs by design do **not** capture traffic to link-local addresses (`169.254.169.254`). This is a fundamental AWS platform limitation, not a configuration defect.
- **Recommendation**: Replace H2 with a detective control that *can* observe IMDS access. Options include:
  - **IMDSv2 enforcement monitoring**: Use AWS Config rule `ec2-imdsv2-check` to flag instances where `HttpTokens ≠ required`.
  - **Host-based logging**: Deploy the CloudWatch Agent or an EDR/HIDS on EC2 instances to capture outbound HTTP connections to 169.254.169.254 at the OS level.
  - **CloudTrail Data Events on SSM**: Capture SSM `SendCommand` events in CloudTrail to detect unauthorized remote execution of IMDS queries.
  - **GuardDuty**: Enable GuardDuty finding `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` for credential abuse detection.

### H3 – EventBridge Notification SLA Exceeded (341.7s vs. 60s target)
- **Root Cause**: CloudTrail event delivery to EventBridge can take up to ~15 minutes in standard configurations. The 60-second SLA is not achievable with CloudTrail-sourced EventBridge rules under normal conditions.
- **Recommendations**:
  - **Revise the SLA**: Adjust the EventBridge detection SLA to 900 seconds (15 minutes) to match AWS CloudTrail delivery guarantees, and document this as the accepted detection latency.
  - **Use CloudTrail Lake or real-time streaming**: Consider enabling CloudTrail Lake with near-real-time query capability, or streaming CloudTrail events via Kinesis Data Streams for sub-minute detection latency.
  - **Supplement with AWS Config**: AWS Config can detect `ModifyInstanceMetadataOptions` changes more quickly than CloudTrail-sourced EventBridge in some configurations.
  - **Document as a weakness**: The 341.7s delivery latency should be formally registered as a detection gap: an adversary has a ~5-minute window after executing `ModifyInstanceMetadataOptions` before an alert fires.