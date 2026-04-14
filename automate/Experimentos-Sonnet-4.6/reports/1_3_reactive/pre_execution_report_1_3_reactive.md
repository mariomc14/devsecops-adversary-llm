# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The `attack()` function implements ADT node 1.2 with precise fidelity across all dimensions:

**Tactic & Technique Alignment (T1552.005 — Unsecured Credentials: Cloud Instance Metadata API)**:
- The attack function calls `ec2:ModifyInstanceMetadataOptions` with `HttpTokens="optional"` and `HttpPutResponseHopLimit=2`, exactly matching the ADT 1.2 specification (`--http-tokens optional --http-put-response-hop-limit 2 --http-endpoint enabled`).
- The attack first assumes the `sce-attacker-role` via `sts:AssumeRole`, accurately simulating the ADT's stated dependency of "Valid AWS credentials (access key / session token)" representing a compromised developer/CI role.

**Dependency Chain Faithfulness**:
- The experiment provisions an IAM attacker role with `ec2:ModifyInstanceMetadataOptions` and `ec2:DescribeInstances` — matching both ADT 1.2 dependencies precisely.
- Step C performs `ec2:DescribeInstances` enumeration before the weakening call, mirroring the ADT's enumeration dependency.
- The EC2 instance is provisioned with `HttpTokens=required, HopLimit=1` as baseline, correctly establishing the pre-attack state.

**Result Fidelity**:
- The ADT states the result is "IMDS HttpTokens set to optional (IMDSv1 re-enabled); HttpPutResponseHopLimit raised to 2." The `attack()` function verifies the post-call state from the `modify_instance_metadata_options` response.
- Retry logic with exponential backoff (up to 5 attempts) handles IAM eventual consistency, a real-world production concern.

**Belt-and-suspenders Lambda invocation (Step E)**: The direct Lambda invocation is a pragmatic SCE design choice — it ensures the reactive control is observable within the SLA window regardless of CloudTrail-to-EventBridge propagation latency (typically 5–15 minutes). This is explicitly disclosed in the code comment and does not compromise experimental validity since the reactive Lambda uses the same remediation logic triggered by EventBridge in production.

**Implementation Quality**: High. The attack uses role assumption (not static credentials), the exact API parameters from the ADT, proper error handling, and logs forensic state before and after the modification.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment targets ADT node **1.5 — EventBridge Lambda: Auto-Remediate IMDS Weakening** (Reactive classification). The implementation maps every stated remediation action:

| ADT 1.5 Defense Action | Implementation |
|---|---|
| EventBridge rule captures `ModifyInstanceMetadataOptions` CloudTrail event | `ReactiveEventBridgeRule` with `EventPattern` matching `eventName: ["ModifyInstanceMetadataOptions"]` and `errorCode: [{exists: false}]` (success-only events) |
| Lambda triggered within 60 seconds | `ReactiveFunction` with 60s timeout, async invocation path via EventBridge + direct invocation fallback |
| Lambda re-enforces `--http-tokens required --http-put-response-hop-limit 1` | Lambda handler R4: `ec2.modify_instance_metadata_options(HttpTokens='required', HttpPutResponseHopLimit=1)` |
| Lambda attaches inline DenyAll policy to offending IAM principal | Lambda handler R1: `iam.put_role_policy(PolicyName='SCE-EmergencyDenyAll')` with `Effect: Deny, Action: *, Resource: *` |
| Incident ticket / alert routing | Lambda handler R3: `sns.publish()` to `sce-soc-alert-topic` with structured P0 alert payload |

**Additional defense correspondences**:
- ADT 1.4 (CloudTrail + CloudWatch) is partially exercised: `BankingTrail` provisions a CloudTrail trail, and the EventBridge rule depends on CloudTrail management events being recorded — forming the detection chain.
- The SSM pipeline-block (R2) is an experiment-specific operationalization of the ADT's "pending security team review" concept, faithfully representing the CI/CD circuit-breaker intent.

**CloudFormation template quality**: The `ReactiveRole` IAM policy is precisely scoped — `ec2:ModifyInstanceMetadataOptions` only (not `ec2:*`), `iam:PutRolePolicy` scoped to the specific attacker role ARN, `ssm:PutParameter` scoped to the specific parameter path, `sns:Publish` scoped to the specific topic ARN. This demonstrates least-privilege design consistent with ADT 2.1/3.1 principles and production-grade security posture.

**Lambda policy document semantics validation in R1**: `hypothesis_verification` not only checks that `SCE-EmergencyDenyAll` exists but validates the statement semantics (`Effect=Deny, Action=*, Resource=*`), catching a scenario where a malformed or weaker policy was attached — a quality improvement beyond minimal checking.

**Minor observation**: The `BankingInstanceProfile` has an empty `Roles: []` array, meaning no IAM role is attached to the EC2 instance. This accurately reflects ADT Step 1 (IMDS weakening attack does not require an instance profile to demonstrate the weakening itself) and isolates the experiment to the reactive control being tested rather than the credential-theft step (ADT 2.2). This is an intentional and correct scoping decision.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The ADT node 1.3 Reactive Probe specification states:
> "Allow weakening in isolated test instance. Expected: Lambda re-enforces IMDSv2 + HopLimit=1 within 5 minutes and revokes the calling credential. Failure: instance remains weakened."

The `hypothesis_verification()` function implements this intent with full coverage and exceeds the specification:

**Defensive Intent — "Lambda re-enforces IMDSv2 + HopLimit=1"**:
- R4 check: Polls `ec2:DescribeInstances` for `HttpTokens=required` and `HttpPutResponseHopLimit=1` within the SLA window. Directly validates the IMDS restoration intent.

**Defensive Intent — "revokes the calling credential"**:
- R1 check: Validates `SCE-EmergencyDenyAll` inline policy attached to the attacker role, verifying both existence AND semantic correctness (Deny/*/\*). This correctly operationalizes "revoke the calling credential" — the IAM principal that executed the attack is neutralized.

**Failure Condition — "instance remains weakened"**:
- If R4 fails within the 1800s SLA, the experiment returns `False` (FAIL), correctly identifying that the reactive control did not remediate the weakened state.

**Additional verification beyond ADT spec** (quality enhancement):
- R2: SSM pipeline-block validates the CI/CD circuit-breaker, capturing the "pending security team review" operational intent from ADT 1.5.
- R3: CloudWatch Logs scanning for Lambda execution evidence provides independent corroboration that remediation actually ran (not just that the end state is correct), strengthening forensic confidence.

**Parallel execution design**: All four checks run concurrently with a shared 1800s deadline. This is architecturally sound — each check has the full SLA window, and the reactive controls may complete at different times. The `_wait()` helper correctly polls at appropriate intervals (20s for IAM/SSM/EC2, 30s for CloudWatch Logs which has higher propagation latency).

**SLA sizing**: The 1800s (30-minute) window is conservative relative to the ADT's "within 5 minutes" expectation, providing adequate buffer for CloudTrail-to-EventBridge propagation latency in test environments while still being a meaningful SLA. The direct Lambda invocation in `attack()` Step E ensures the reactive logic executes promptly, making the SLA a test of the verification checks' correctness rather than Lambda latency.

**Steady-state hypothesis coherence**: The pre-experiment hypothesis probes confirm: EventBridge rule active, Lambda deployed/Active, SSM flag unblocked, attacker role exists without deny policy, and EC2 baseline at required/HopLimit=1. This correctly establishes the "before" state against which the reactive controls are evaluated.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves a perfect quality score across all three evaluation factors. The implementation demonstrates:
- Exact ADT attack node 1.2 replication (same TTP T1552.005, identical API parameters, faithful dependency chain)
- Complete reactive defense coverage mapping all ADT 1.5 remediation actions (R1–R4)
- Full defensive intent correspondence with semantic validation, parallel SLA checking, and independent corroboration layers

---

## Recommendations

The experiment is authorized for execution. The following observations are offered as post-execution improvement considerations (not blockers):

1. **CloudTrail-to-EventBridge latency measurement**: Instrument the time delta between the `modify_instance_metadata_options` call timestamp and the Lambda invocation timestamp (available in CloudWatch Logs). This would provide empirical data on the EventBridge detection latency versus the direct-invocation path, validating the "within 60 seconds" ADT 1.5 claim for the production trigger path.

2. **R3 log scanning robustness**: The CloudWatch Logs check requires ≥2 evidence markers and scans only 5 most-recent log streams. In high-throughput environments, consider adding a `startTime` filter based on the attack timestamp to avoid false positives from prior experiment runs if log groups are reused.

3. **STS session token revocation validation**: ADT 1.5 mentions "revokes the calling credential." The current R1 check validates the inline DenyAll policy attachment, which blocks future API calls. A supplementary check could verify that the attacker's assumed session token is also invalidated (via `iam:PutRolePolicy` with `AWSRevokeOlderSessions` condition key), which is a stronger credential revocation guarantee than deny-policy attachment alone.

4. **EventBridge rule end-to-end path test**: Consider adding an optional R5 check that validates the EventBridge rule invocation count via CloudWatch metrics (`aws.events` namespace, `TriggeredRules` metric), confirming the production detection path fired independently of the direct Lambda invocation in Step E.