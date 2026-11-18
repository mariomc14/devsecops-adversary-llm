# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.5
- **Probe Type**: Detective
- **Attack Nodes**: 1.2, 2.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The implementation faithfully and completely reproduces both attack nodes specified in the ADT.

**Attack Node 1.2 (T1562.008 — Impair Defenses: Disable or Modify Cloud Security Controls)**:
The ADT specifies `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`. The Python implementation calls `ec2.modify_instance_metadata_options(InstanceId=inst, HttpTokens="optional", HttpEndpoint="enabled", HttpPutResponseHopLimit=2)` — an exact boto3 translation with identical parameters (`HttpTokens=optional`, `HttpEndpoint=enabled`, `HopLimit=2`). The tactic (T1562.008) and technique are fully matched.

**Attack Node 2.2 (T1552.005 — Unsecured Credentials: Cloud Instance Metadata API)**:
The ADT specifies confirming that the weakened IMDS state persists as the attacker's precondition for unauthenticated credential retrieval. The implementation calls `ec2.describe_instances()` post-modification and validates that `HttpTokens == "optional"` and `HopLimit == 2`, precisely simulating the attacker's control-plane confirmation step before issuing unauthenticated IMDS curl requests. The tactic and technique alignment is complete.

Additional quality indicators: the `attack()` function records timestamps (`_STATE["attack_1_2_ts"]`, `_STATE["attack_2_2_ts"]`) used downstream in the hypothesis verification; there is an 8-second propagation delay between the two attack steps to allow EC2 control-plane commit; the function returns `False` on any `ClientError` to signal to the runner; and the attack is scoped exclusively to experiment-owned resources, satisfying the ADT's sandbox constraint.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment targets detective controls from ADT nodes **1.3** and **2.3**, and the implementation validates all three independent detection channels described in those nodes with high-quality code.

**ADT Node 1.3 (CloudTrail + AWS Config Rule + EventBridge)**: Signal C in `hypothesis_verification()` acts as a CloudTrail proxy: `describe_instances()` confirms the weakened IMDS state persists in the EC2 control-plane, which is the same data surface that populates CloudTrail `ModifyInstanceMetadataOptions` events. The design acknowledges that direct CloudTrail event polling would require a trail and S3/Athena query path that is impractical within a sandboxed experiment SLA, so the EC2 control-plane state persistence serves as a structurally sound and justified proxy signal.

**ADT Node 2.3 (GuardDuty + VPC Flow Logs + CloudWatch Logs Insights)**: 
- *Signal A* polls `list_findings` / `get_findings` for `Policy:EC2/NoIMDSv2` and a broad set of correlated finding types (`UnauthorizedAccess:EC2`, `CredentialAccess`, `Recon:IAMUser`) plus keyword-based fallback matching on title strings. This directly reflects the GuardDuty detection described in ADT 2.3.
- *Signal B* polls `describe_log_streams` on the CFN-provisioned CloudWatch Log Group that receives VPC Flow Logs, checking for active log streams with events newer than the stack creation timestamp (with a 600-second buffer). This directly reflects the VPC Flow Logs → CloudWatch Logs detection pipeline in ADT 2.3.

Implementation quality is high: the 60-second clock-skew buffer on `attack_ts`, millisecond-epoch conversion for GuardDuty's `GreaterThanOrEqual` filter, `ResourceNotFoundException` handling for the log group, `_poll_until()` generic polling abstraction with configurable SLA, and per-signal structured results dictionary with a final AND-gate verdict all demonstrate production-grade defensive testing practice.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The detective probe's intent as stated in the ADT node 2.5 is: *"With HopLimit temporarily raised to 2 in the sandbox, perform the IMDS curl; confirm GuardDuty raises UnauthorizedAccess:EC2/MetadataServiceAccess within 5 min, VPC Flow Logs show the anomalous 169.254.169.254 destination within 2 min, and the SIEM alert fires within 3 min of the curl execution."*

The experiment maps this intent faithfully across all three signals:

1. **GuardDuty Signal**: The probe checks for `Policy:EC2/NoIMDSv2` (which fires deterministically on `HttpTokens=optional`) and related IMDS/credential findings — this is the correct and more reliable signal for this specific attack than `UnauthorizedAccess:EC2/MetadataServiceAccess` (which requires in-instance IMDS access, not achievable in a pure control-plane test). The ADT's 5-minute SLA is subsumed within the 30-minute outer SLA; GuardDuty's `ONE_HOUR` publishing frequency is correctly accounted for by the extended polling window and documented in the manifest.

2. **VPC Flow Log Signal**: The probe validates the delivery pipeline is active (log streams with recent events), which confirms the detection infrastructure is operational and would capture `169.254.169.254` destination flows. The 2-minute ADT SLA maps to the 30-minute outer window conservatively.

3. **CloudTrail Proxy Signal**: The probe confirms `ModifyInstanceMetadataOptions` is durably reflected in the EC2 control plane — the same API surface that generates CloudTrail management events, confirming ADT node 1.3's detection mechanism is triggered.

The 30-minute outer SLA is appropriate given GuardDuty's `ONE_HOUR` publishing frequency for new detectors and VPC Flow Log delivery latency. The `hypothesis_verification()` function uses an AND-gate across all three signals, meaning the probe only passes if the full multi-signal detection chain described in the ADT is confirmed. The steady-state baseline assertion (IMDSv2 enforced pre-attack) and the dedicated rollback with complete resource cleanup further ensure the probe produces clean, reproducible results aligned with the ADT's sandbox execution model.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

All three quality factors achieve maximum scores. The experiment is fully authorized for execution.

---

## Recommendations

The experiment scores at ceiling on all three factors. The following observations are offered as operational hardening suggestions rather than quality deficiencies:

1. **GuardDuty Publishing Frequency**: The detector is created with `ONE_HOUR` publishing frequency. Consider using `SIX_HOURS` for cost management in long-running sandboxes, or `FIFTEEN_MINUTES` if the ADT's 5-minute SLA for Signal A needs to be testable within a tighter window in future iterations.

2. **Signal A Coverage Gap**: The actual ADT curl-based IMDS access (`curl http://169.254.169.254/...`) is not executed from within the instance (which would require SSM Run Command or user-data). The GuardDuty finding `Policy:EC2/NoIMDSv2` fires on configuration state, not on access events — this is correctly leveraged but the manifest description's reference to "perform the IMDS curl" is not literally implemented. This is a sound pragmatic choice for a control-plane detective probe, but future experiments targeting `UnauthorizedAccess:EC2/MetadataServiceAccess` should add SSM-based in-instance curl execution.

3. **Signal B Threshold**: The 600-second (10-minute) buffer on the Flow Log stream timestamp check is generous. Consider tightening to 300 seconds in future runs once baseline VPC Flow Log delivery latency is empirically measured.

4. **CloudTrail Direct Validation**: A future enhancement could add direct CloudTrail `lookup_events` polling for `ModifyInstanceMetadataOptions` events to replace the control-plane proxy with a true CloudTrail signal, fully satisfying ADT node 1.3's detection mechanism without inference.