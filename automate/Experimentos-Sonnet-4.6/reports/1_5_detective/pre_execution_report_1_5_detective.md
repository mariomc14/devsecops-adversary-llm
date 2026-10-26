# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.5
- **Probe Type**: Detective
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2026-04-08T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The `attack()` function in the Python implementation directly and precisely mirrors Attack Node 1.2 as specified in the ADT.

**Tactic alignment**: The ADT specifies T1578 — Modify Cloud Compute Infrastructure. The implementation calls `ec2_client.modify_instance_metadata_options()` with `HttpTokens="optional"`, `HttpEndpoint="enabled"`, and `HttpPutResponseHopLimit=2` — exactly the parameters listed in the ADT attack command:
```
aws ec2 modify-instance-metadata-options \
  --http-tokens optional \
  --http-endpoint enabled \
  --http-put-response-hop-limit 2
```

**Technique alignment**: The specific technique (weakening IMDS protections by re-enabling IMDSv1 and raising hop limit) is implemented with full fidelity. The steady-state baseline correctly establishes `HttpTokens=required` and `HopLimit=1` via the CloudFormation template (`MetadataOptions: HttpTokens: required, HttpEndpoint: enabled, HttpPutResponseHopLimit: 1`), then the attack transitions to `optional`/`2` — matching the ADT's stated result ("IMDSv1 re-enabled; hop limit raised to 2").

**Implementation quality**: High. The attack function includes retry logic with exponential backoff (5 retries, starting at 5s, capped at 60s), timestamps the attack both in UTC wall-clock and monotonic time for latency measurement, records `attack_success` in shared state, and logs the resulting metadata options from the API response. The `_verify_baseline_imdsv2()` function confirms the pre-attack steady state is correctly established before the attack fires. The attack precisely targets the provisioned experiment instance (not a production resource).

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The implementation corresponds fully to Detective Safeguard 1.3 as specified in the ADT, and achieves high implementation quality across all detective control layers.

**ADT Detective Safeguard 1.3 specifies**:
1. CloudTrail recording of `ModifyInstanceMetadataOptions` as a management event ✅ — CloudTrail trail created via `_create_cloudtrail_trail()` as a post-stack boto3 call
2. EventBridge rule triggering on `eventName=ModifyInstanceMetadataOptions`, scoped to specific instance ID, routing to SNS topic and SQS queue within 60s ✅ — CFN stack deploys `ImdsModificationRule` EventBridge rule; `_narrow_eventbridge_rule()` post-deploy scopes it to the specific instance ID with `httpTokens=optional` filter
3. CloudWatch metric filter on CloudTrail log group counting events and triggering Alarm ✅ — `ImdsMetricFilter` and `ImdsModificationAlarm` in CFN template, wired to the trail log group
4. AWS Config Rule `ec2-imdsv2-check` marking instance NON_COMPLIANT ✅ — `_create_config_rule()` creates `EC2_IMDSV2_REQUIRED` managed rule via boto3; pre-flight checks for active recorder

**Control hierarchy fidelity**: The implementation correctly implements the ADT's tiered detective architecture — primary (EventBridge/SQS), secondary (Config NON_COMPLIANT), tertiary (CloudWatch Alarm). The conditional/mandatory classification mirrors the ADT's note that "all optional component failures are non-fatal to the primary EventBridge/SQS chain."

**Implementation quality**: High. The decoupling of CloudTrail and Config Rule from the CFN stack (post-stack boto3 calls) is architecturally sound — it prevents optional component failures from rolling back the primary detection infrastructure. The `_create_cloudtrail_trail()` function handles bucket creation, IAM role creation with CW Logs write policy, IAM propagation delay (15s), and trail creation with appropriate error handling. The `_verify_controls_armed()` pre-flight function validates EventBridge rule state, alarm existence, and SQS reachability before the attack is fired. The EventBridge rule narrowing with `httpTokens: ["optional"]` in the event pattern is a particularly precise implementation detail matching the ADT's "scoped post-deploy to the specific instance ID" specification.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The `hypothesis_verification()` function fully corresponds to the detective probe intent specified in ADT Node 1.5.

**ADT SCE Node 1.5 Detective Probe specifies**:
> "Execute ModifyInstanceMetadataOptions with httpTokens=optional in a controlled CloudFormation-provisioned stack (minimal stable core: EC2, EventBridge, SNS, SQS, CW Logs, metric filter, Alarm). Verify EventBridge alert fires and reaches SQS queue within 1800 s SLA. Confirm Config Rule marks instance NON_COMPLIANT if recorder active. Confirm CloudWatch Alarm enters ALARM state if CloudTrail trail was provisioned. Measure and log detection latency from attack_ts_mono to SQS message arrival."

**Implementation correspondence**:

| ADT Requirement | Implementation | Status |
|---|---|---|
| EventBridge fires and reaches SQS within 1800s | `_poll_until(_check_sqs_for_imds_event, sla=1800)` as Sub-check A (PRIMARY/mandatory) | ✅ Full |
| Config Rule marks NON_COMPLIANT if recorder active | Sub-check B conditional on `config_available`, with `start_config_rules_evaluation()` trigger | ✅ Full |
| CloudWatch Alarm enters ALARM state if trail provisioned | Sub-check C conditional on `trail_name` presence | ✅ Full |
| Measure and log detection latency from attack_ts_mono | `latency = time.monotonic() - _STATE["attack_ts_mono"]` recorded as `detection_latency_seconds` | ✅ Full |
| 1800s SLA window | `_SLA_SECONDS = 1800` used throughout | ✅ Full |

**Pass/fail logic fidelity**: The hypothesis correctly implements the ADT's pass condition: "The probe passes if A succeeds and neither B nor C is a confirmed failure." The three-valued logic (`True`/`False`/`None`) correctly distinguishes between confirmed failure and inconclusive (skipped due to absent prerequisites), exactly matching the ADT's conditional language ("if recorder active," "if CloudTrail trail was provisioned").

**SQS message parsing**: `_check_sqs_for_imds_event()` correctly handles the SNS-wrapped SQS message format (outer JSON with `Message` field containing inner JSON), searches for both `modifyinstancemetadataoptions` and the specific instance ID in the message body, and deletes matched messages to prevent double-counting. The 60s advisory latency threshold is also logged against the primary 1800s SLA, matching the ADT's "60-second SLA target for the EventBridge alert chain" reference.

**Rollback fidelity**: The `rollback()` function's dependency-ordered teardown (trail → Config rule → S3 bucket with paginator → IAM role → CFN stack) matches the ADT's specification: "Verify rollback empties and deletes trail S3 bucket" — implemented with `list_objects_v2` paginator before `delete_bucket`.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves maximum correspondence across all three quality factors. The implementation faithfully represents Attack Node 1.2 (T1578 IMDS weakening), fully implements Detective Safeguard 1.3's layered detection chain, and the probe verification logic precisely matches the detective intent specified in SCE Node 1.5. The experiment is authorized for execution.

---

## Recommendations

All three factors scored at maximum. No corrective actions required. The following observations are offered as optional enhancements for future iterations:

1. **Detection latency SLA refinement**: The code logs a "60-second ideal target" advisory but the ADT specifies the EventBridge chain should route to SQS "within 60 s." Consider making the 60s advisory a formal sub-pass criterion (non-blocking) to generate richer telemetry about control performance degradation over time.

2. **SQS long-polling efficiency**: `WaitTimeSeconds=5` in `receive_message` combined with a 20s poll interval means the effective polling granularity is ~25s. Since the ADT targets 60s ideal detection, reducing `_POLL_INTERVAL` to 10s would improve detection latency measurement precision without meaningfully increasing API costs.

3. **Config evaluation race condition**: `start_config_rules_evaluation()` is called immediately after the attack, but Config may not have discovered the instance state change yet. Adding a brief 30s delay before triggering the evaluation (or retrying on `ResourceInUseException`) would reduce false-negative inconclusive results in environments where Config is active.

4. **CloudTrail event delivery lag**: CloudTrail management events typically arrive at EventBridge within 15 minutes. The 1800s SLA window accommodates this, but documenting the expected P50/P99 delivery latency in the experiment manifest would strengthen the evidence base for the 60s "ideal" vs. 1800s "maximum" SLA distinction.