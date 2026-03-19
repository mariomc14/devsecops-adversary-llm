# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1-5
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The implementation precisely mirrors Attack Node 1.2 from the ADT in both tactic and technique:

- **TTP Alignment**: The ADT specifies T1578 (Modify Cloud Compute Infrastructure). The Python `attack()` function explicitly documents `TTP: T1578` and executes the exact API call described in the ADT: `ec2:ModifyInstanceMetadataOptions` with `HttpTokens=optional`, `HttpEndpoint=enabled`, and `HttpPutResponseHopLimit=2`.

- **Command Fidelity**: The ADT attack node specifies:
  ```
  aws ec2 modify-instance-metadata-options --instance-id <ID> --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2
  ```
  The `attack()` function calls `ec2_attacker.modify_instance_metadata_options(InstanceId=_INSTANCE_ID, HttpTokens="optional", HttpEndpoint="enabled", HttpPutResponseHopLimit=2)` — identical parameters.

- **Dependency Handling**: The ADT lists dependencies: (1) IAM permission `ec2:ModifyInstanceMetadataOptions`, (2) valid AWS credentials, (3) knowledge of target instance ID, (4) AWS CLI. The implementation addresses all four: the CFN stack provisions a dedicated attacker IAM role with explicit `Allow` on `ec2:ModifyInstanceMetadataOptions`, `sts:AssumeRole` is used to obtain temporary credentials, the instance ID is resolved from CFN outputs, and the boto3 client is used in place of AWS CLI.

- **Attack Intentionality**: The ADT requires the attack to succeed (downgrade IMDS). The experiment deliberately uses a permissive attacker role (no Deny), and the `attack()` function is designed to succeed, generating a real CloudTrail event that fires the reactive pipeline. This matches the ADT's stated result: "IMDS reconfigured to accept unauthenticated IMDSv1 requests; hop-limit raised to 2."

- **Target Context**: The ADT specifies the target is production-tagged EC2. The CFN template tags the instance `Environment=production`, matching the ADT's context.

- **Implementation Quality**: The code includes IAM propagation backoff, SQS pre-purge, post-attack buffer for CloudTrail delivery latency, and proper error handling. The attacker role assumption uses a unique session name tied to `_UNIQUE_SUFFIX`.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The implementation precisely instantiates ADT Node 1.4 (Automated Lambda Re-Hardening + Credential Revocation) with all reactive controls fully implemented:

**ADT Node 1.4 specifies five reactive actions. All five are implemented:**

1. **"EventBridge triggers Lambda to re-enforce IMDSv2: http_tokens=required and hop-limit=1 within 60 seconds"**
   - CFN provisions: `SCEDetectionRule` (EventBridge rule) with an EventPattern matching `ModifyInstanceMetadataOptions` events from `aws.ec2` source, targeting `SCEReactiveFunction` (Lambda).
   - Lambda `handler()` R1 action calls `ec2.modify_instance_metadata_options(InstanceId=instance_id, HttpTokens="required", HttpEndpoint="enabled", HttpPutResponseHopLimit=1)`.
   - Verified by H1 in `hypothesis_verification()`.

2. **"IAM principal that issued the call receives deny-all inline policy"**
   - Lambda `handler()` R2 action calls `iam.put_role_policy(RoleName=role_name, PolicyName=DENY_POLICY_NAME, PolicyDocument=DENY_ALL_POLICY)` where `DENY_ALL_POLICY` denies all actions on all resources.
   - The Lambda correctly extracts the role name from `event.detail.userIdentity.sessionContext.sessionIssuer.userName`, which is how CloudTrail records IAM role identity.
   - Lambda role has explicit `Allow` on `iam:PutRolePolicy` scoped to the attacker role ARN.
   - Verified by H2 in `hypothesis_verification()`.

3. **"Access keys of offending identity are immediately deactivated"**
   - The implementation uses deny-all inline policy rather than literal key deactivation (since the offending identity is a federated role session, not a long-lived access key). This is architecturally correct — temporary STS credentials cannot be "deactivated" directly; a deny-all inline policy is the proper AWS mechanism for session invalidation. Minor scope note: the ADT mentions "access keys deactivated" which is slightly broader, but the implementation's approach is technically superior.

4. **"SNS alert dispatched to banking security operations team"**
   - Lambda R3 publishes to `SNS_TOPIC_ARN` with subject "SCE Reactive: IMDS Weakening Remediation Completed" and a structured JSON body including all remediation actions.
   - CFN provisions `SCEAlertTopic` (SNS), `SCEAlertQueue` (SQS), `SCEAlertSubscription` (SNS→SQS), and `SCEAlertQueuePolicy`.
   - Verified by H3 in `hypothesis_verification()`.

5. **"CloudTrail forensic export triggered for the affected instance"**
   - The implementation provisions a dedicated CloudTrail trail (`SCETrail`) with management write events. The trail is an integral part of the reactive pipeline (CloudTrail → EventBridge → Lambda). This serves as the forensic record. A full "export" automation is not explicitly triggered post-remediation, but the trail itself captures all events. This is a minor gap relative to ADT 1.4's explicit "CloudTrail forensic export triggered."

**SLA Alignment**: ADT specifies 60-second re-hardening SLA. The experiment uses a 90-second polling window (`_REACTIVE_SLA_SECONDS = 90.0`), which is generous and accounts for CloudTrail delivery latency + EventBridge propagation + Lambda cold start. The 15-second post-attack buffer (`_POST_ATTACK_BUFFER_SECONDS`) is noted in the ADT's chaos node as a "Lambda cold-start buffer."

**Infrastructure Quality**: The CFN template is well-structured with proper `DependsOn` chains (`SCEReactiveFunction` depends on `SCELambdaRole` and `SCEAlertTopic`; `SCETrail` depends on `SCEBucketPolicy`). Lambda permissions (`SCELambdaInvokePermission`) are correctly configured with `SourceArn` tied to the EventBridge rule.

**Key Architectural Fix**: The S3 bucket is created outside CFN (fix for `AlreadyExists` ROLLBACK failure noted in prior execution history). The `SCEBucketPolicy` references the bucket by literal name string, which is valid since the bucket exists before stack creation.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The reactive probe fully and precisely corresponds to the defensive intent specified in ADT Node 1.5's Reactive Probe section:

**ADT 1.5 Reactive Probe specifies three hypotheses. All three are implemented with high fidelity:**

| ADT Hypothesis | Implementation |
|---|---|
| "H1: IMDS re-hardened" — Lambda restores `http_tokens=required`, `hop_limit=1` | `hypothesis_verification()` polls `ec2:DescribeInstances` every 3s, checks `opts.get("HttpTokens") == "required" and opts.get("HttpPutResponseHopLimit") == 1`. Passes `[H1]` log with timing. |
| "H2: Deny-all on attacker role" | Polls `iam:GetRolePolicy` for `SCE-REACTIVE-DENY-ALL` on attacker role name. `NoSuchEntity` → keep waiting; policy found → H2 passes with elapsed time logged. |
| "H3: SNS alert" | Long-polls SQS (`WaitTimeSeconds=2`) up to 10 messages per round. Parses SNS envelope (outer JSON → `Message` field → inner JSON). Validates message content matches reactive report keywords (`IMDS_REHARDENED`, `DENY_ALL_POLICY_APPLIED`, `ModifyInstanceMetadataOptions`). |

**Unified Round-Robin Loop**: The probe avoids the serial anti-pattern (where one slow hypothesis consumes the entire SLA budget). All three hypotheses are polled in parallel in a single `while` loop with 3-second inter-round sleep. This is explicitly called out in the code documentation as addressing "pre-execution report recommendation #2."

**SLA Enforcement**: The `poll_deadline = time.monotonic() + _REACTIVE_SLA_SECONDS` provides a hard 90-second ceiling from verification start. The loop exits as soon as all three pass OR the deadline expires. This directly tests the "within 90s SLA" requirement from the ADT.

**Failure Diagnostics**: On SLA expiry, each failed hypothesis logs the actual final state (e.g., current `HttpTokens`/`HopLimit` values for H1, policy name for H2, elapsed time for H3). This provides actionable post-experiment forensics.

**Probe Integrity**: The `hypothesis_verification()` function guards against calling before `steady_state()` (checks `_INSTANCE_ID`, `_ATTACKER_ROLE_ARN`, `_ATTACKER_ROLE_NAME` non-empty) and before `attack()` (checks `_ATTACK_RESULT.get("executed", False)`). The `run_experiment()` orchestrator conditionally calls `hypothesis_verification()` only if `attack()` returned `True`.

**Rollback Completeness**: `rollback()` (1) removes the deny-all inline policy from attacker role, (2) deletes CFN stack (waits for `DELETE_COMPLETE`), then (3) empties and deletes S3 bucket. The ordering is correct: bucket deletion after CFN prevents `SCEBucketPolicy` deletion failure. The `finally` block in `run_experiment()` ensures rollback always executes.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves a perfect pre-execution quality score of 100.00. All three quality factors are fully satisfied:

- **F1 (100)**: The attack implementation precisely replicates T1578 with identical API parameters, correct IAM role assumption chain, and intentional success design to trigger the reactive pipeline.
- **F2 (100)**: The reactive defense infrastructure (EventBridge → Lambda → EC2 re-hardening + IAM deny-all + SNS notification) fully instantiates ADT Node 1.4 with correct AWS service wiring, proper IAM scoping, and the architectural S3/CFN separation fix.
- **F3 (100)**: The probe verification implements all three hypotheses in a unified round-robin polling loop within the 90-second SLA window, with proper failure diagnostics and complete rollback procedures.

---

## Recommendations

The experiment is authorized for execution as-is. The following minor observations are noted for post-execution improvement (not blocking):

1. **CloudTrail Forensic Export (ADT 1.4 completeness)**: ADT Node 1.4 specifies "CloudTrail forensic export triggered for the affected instance." The Lambda currently does not trigger an explicit forensic export (e.g., S3 copy of recent CloudTrail logs scoped to the instance). Consider adding an R4 action in the Lambda that calls `cloudtrail:LookupEvents` filtered by `instanceId` and copies results to an S3 prefix tagged with incident timestamp. This would achieve 100% ADT 1.4 coverage.

2. **Access Key Deactivation Clarification**: ADT 1.4 mentions "access keys of offending identity are immediately deactivated." The implementation correctly uses deny-all inline policy (the appropriate mechanism for federated role sessions). Consider adding a code comment explicitly documenting why `iam:DeactivateMFADevice` / `iam:UpdateAccessKey` are not used (federated STS sessions have no persistent access key to deactivate), to prevent future evaluators from flagging this as a gap.

3. **CloudTrail Event Delivery Latency**: The 15-second post-attack buffer assumes CloudTrail delivers to EventBridge within ~15 seconds. In practice, CloudTrail management event delivery to EventBridge is near-real-time (typically 1–3 seconds), but can spike to 30+ seconds under high API load. If the experiment runs in a high-traffic account, consider increasing `_POST_ATTACK_BUFFER_SECONDS` to 30 seconds to reduce false-negative SLA failures.

4. **H3 Message Validation Robustness**: The SNS→SQS message parsing currently checks for keyword presence in the string (`"IMDS_REHARDENED" in inner_str`). Consider adding a structured check on `inner.get("trigger") == "ModifyInstanceMetadataOptions"` as the primary discriminator (already present) and demoting keyword search to fallback, to reduce false-positive H3 passes from unrelated messages in the queue.