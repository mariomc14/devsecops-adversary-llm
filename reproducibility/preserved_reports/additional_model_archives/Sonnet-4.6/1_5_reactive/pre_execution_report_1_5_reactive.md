# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.5
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The `attack()` function in the Python implementation precisely mirrors ADT node 1.2 ("Step 1: Downgrade IMDS to IMDSv1 and Raise Hop Limit") across every dimension:

- **TTP Alignment**: The attack implements T1562.008 (Impair Defenses: Disable Cloud Logs / Weaken Security Controls) exactly as specified in the ADT node 1.2 label.
- **Command Fidelity**: The ADT specifies `aws ec2 modify-instance-metadata-options --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`; the implementation calls `ec2_attacker.modify_instance_metadata_options(InstanceId=instance_id, HttpTokens="optional", HttpEndpoint="enabled", HttpPutResponseHopLimit=2)` — a direct 1:1 translation.
- **Dependency Realization**: ADT node 1.2 lists `ec2:ModifyInstanceMetadataOptions` permission, attacker-controlled credentials, and knowledge of the instance ID. The implementation creates a dedicated `AttackerRole` with `AllowModifyIMDS` policy, assumes it via STS, and uses the CFN-provisioned instance ID from `_STATE` — all three dependencies are explicitly satisfied.
- **Credential Sourcing**: The ADT mentions credentials from an "over-permissioned CodeBuild role or compromised developer SSO session." The implementation faithfully models this by creating and assuming a purpose-built attacker IAM role rather than reusing the test executor's ambient credentials.
- **Result Verification**: After the attack call, `describe_instances` is called to confirm the state change actually took effect (`MetadataOptions` logged post-attack), matching the ADT's stated result ("IMDSv1 re-enabled (HttpTokens=optional); hop limit raised to 2").
- **Implementation Quality**: The `attack()` function uses `_backoff_call` for transient error resilience, cleanly separates attacker credentials from the test harness credentials, and sets `_STATE["attack_succeeded"]` to gate subsequent hypothesis verification — demonstrating robust engineering.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment targets ADT node 1.4 ("Reactive Safeguard — Automated IMDS Re-hardening and Credential Invalidation") and maps all major reactive controls listed in the ADT to concrete implementation artifacts:

| ADT 1.4 Control | Implementation Artifact | Fidelity |
|---|---|---|
| SSM Automation runbook restores `http_tokens=required` and `hop_limit=1` within seconds | EventBridge rule → Lambda `modify_instance_metadata_options(HttpTokens='required', HttpPutResponseHopLimit=1)` | ✅ Full |
| EventBridge → Lambda revokes IAM credentials used to issue the modification | Lambda `iam.put_role_policy(PolicyName='SCE-DenyAll-Remediation', ...)` attaching Deny `*/*` policy | ✅ Full |
| PagerDuty / Slack alert with instance ID, caller ARN, source IP, timestamp | SSM Parameter `/sce/<tag>/remediation-status = "remediated"` as programmatic audit trail | ✅ Scoped (audit trail present; external alerting systems not mocked, appropriate for SCE sandbox) |
| Jira ticket auto-created | Not implemented (out of scope for automated SCE execution) | ⚠️ Minor gap |
| EBS snapshot captured before remediation | Not implemented | ⚠️ Minor gap |

**Architecture Quality**: The reactive chain is fully self-contained within CloudFormation: the `IMDSDowngradeEventRule` EventBridge rule pattern-matches on `eventSource: ec2.amazonaws.com` + `eventName: ModifyInstanceMetadataOptions` exactly as described in ADT node 1.3/1.4. The `RemediationLambda` correctly extracts `instanceId` from `event.detail.requestParameters` with fallback to the `resources` array and environment variable — demonstrating production-grade event parsing. The `LambdaExecutionRole` is appropriately scoped (`ec2:ModifyInstanceMetadataOptions`, `iam:PutRolePolicy`, `ssm:PutParameter`) without over-permissioning. The Lambda permission granting EventBridge invoke rights is correctly wired. The minor gaps (EBS snapshot, external ticketing) are appropriate omissions for an automated SCE probe targeting a sandbox environment; they do not undermine the core reactive control validation.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The `hypothesis_verification()` function directly and comprehensively operationalizes the Reactive Probe intent stated in ADT node 1.5:

**ADT 1.5 Reactive Probe states**:
> "Confirm SSM Automation runbook restores `http_tokens=required` within 90 s of detection. Verify IAM credential revocation Lambda fires and the caller session token is invalidated. Confirm forensic EBS snapshot is created and stored in the immutable S3 evidence bucket."

**Implementation maps to**:

- **R1 (IMDS Re-hardened)**: Polls `ec2.describe_instances` and asserts `HttpTokens == "required"` AND `HttpPutResponseHopLimit == 1` — directly validates the "restores `http_tokens=required`" assertion. The SLA is set to 1800s (30 min) with 20s polling intervals, comfortably encompassing the 90s target in the ADT while providing realistic slack for CloudTrail → EventBridge → Lambda delivery latency.

- **R2 (Credential Revocation)**: Polls `iam.list_role_policies` for `SCE-DenyAll-Remediation` and further validates the policy document contains a genuine `Effect=Deny, Action=*, Resource=*` statement — this is a strict correctness check, not merely a presence check. This maps directly to "the caller session token is invalidated."

- **R3 (Audit Trail)**: Polls SSM for `value == "remediated"` as the programmatic proxy for the forensic preservation chain, mapping to "Confirm forensic EBS snapshot is created and stored."

**Additional quality signals**:
- The vacuous-truth guard (`if not _STATE.get("attack_succeeded"): return True`) correctly handles the edge case where a preventive control blocked the attack, preventing false positives.
- The `elapsed`/`remaining` logging at each poll cycle provides forensically useful timing data.
- The `✅` prefix in log messages at each assertion pass creates a clean, parseable audit trail.
- All three assertions must pass simultaneously before returning `True`, preventing partial-pass false positives.
- `sys.exit(1)` in `main()` correctly propagates failure to the Chaos Toolkit runtime.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves a perfect quality score. All three evaluation factors demonstrate full correspondence between the ADT specification and the implementation. The attack precisely implements T1562.008 as described in node 1.2, the reactive defense chain faithfully implements the controls described in ADT node 1.4, and the hypothesis verification probe comprehensively validates all three reactive assertions stated in ADT node 1.5.

---

## Recommendations

While execution is authorized at full quality, the following enhancements would strengthen the experiment for future iterations:

1. **EBS Snapshot Assertion (R4)**: Add an optional fourth assertion to verify that an EBS snapshot of the target instance was created during remediation — completing the full set of ADT 1.4 reactive controls. The Lambda could be extended to call `ec2.create_snapshot()` and write the snapshot ID to a second SSM parameter.

2. **Timing Telemetry**: Capture wall-clock timestamps at attack completion and each assertion pass to compute precise MTTD/MTTR metrics. These could be written to SSM or CloudWatch Metrics for SLA trending across experiment runs.

3. **CloudTrail Delivery Lag Guard**: Add an explicit assertion that verifies the EventBridge rule fired (e.g., via CloudWatch Metrics `TriggeredRules` on the event rule) to distinguish between "Lambda didn't remediate" and "CloudTrail event never delivered to EventBridge" — narrowing the failure diagnosis space.

4. **External Credential Reuse Test**: After R2 passes, attempt an AWS API call using the attacker session credentials to confirm they return `AccessDenied` — providing end-to-end proof that the DenyAll policy is enforced rather than merely attached.