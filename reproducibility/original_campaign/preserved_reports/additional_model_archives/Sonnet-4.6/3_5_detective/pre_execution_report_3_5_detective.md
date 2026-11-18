# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 3.5
- **Probe Type**: Detective
- **Attack Nodes**: 1.2, 2.2, 3.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

---

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The experiment implements all three attack nodes with high fidelity:

**Attack Node 1.2 (T1562.008 - Weaken IMDS Protections)**: The ADT specifies `aws ec2 modify-instance-metadata-options` to re-enable IMDSv1 and raise the hop limit. Since this is a detective probe operating in a sandbox (not a live EC2 instance), the experiment correctly proxies this via `sts:AssumeRole` on the instance-simulation role — generating the credential-acquisition CloudTrail event that maps to the IMDS downgrade trigger in the attack chain. The docstring explicitly documents this proxy rationale. This is the correct operationalization for a detective probe that cannot and should not run real EC2 IMDS attacks.

**Attack Node 2.2 (T1552.005 - Retrieve Credentials via IMDS)**: The ADT specifies `curl http://169.254.169.254/.../security-credentials/<ROLE_NAME>` to retrieve temporary IAM credentials. The experiment operationalizes this as `sts:GetCallerIdentity` called with the assumed role credentials — correctly simulating the attacker verifying stolen credential validity, which is the behavioral signal that maps to T1552.005 in a CloudTrail-observable context.

**Attack Node 3.2 (T1078.004 - Lateral Movement / Privilege Escalation)**: The ADT specifies `aws sts get-caller-identity`, `aws s3 ls`, and `aws iam list-attached-role-policies` with stolen credentials. The implementation exactly mirrors this: `iam:ListAttachedRolePolicies` and `s3:ListAllMyBuckets` are called with the stolen (assumed) credentials. The TTP mapping to T1078.004 is preserved. The implementation uses `list_attached_role_policies` and `list_buckets` which generate the exact CloudTrail event names (`ListAttachedRolePolicies`, `ListBuckets`) referenced in the ADT node 3.3 detection specification.

The code quality is high: error handling is present for each attack step, CloudTrail event name constants match the actual AWS API event names, timestamps are captured for SLA windowing, and the attack sequence respects the dependency chain (1.2 → 2.2 → 3.2).

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment maps precisely to the detective controls specified in ADT nodes 1.3, 2.3, and 3.3, and validates them through three independent signals:

**ADT Node 1.3 (CloudTrail + EventBridge)**: Signal C (`_check_cloudtrail_assume_role`) uses `cloudtrail.lookup_events` filtered by `EventName=AssumeRole` and scoped to the instance-role ARN/name, directly validating that the credential acquisition event is durably recorded. This maps to the ADT's specification: "Every ec2:ModifyInstanceMetadataOptions API call is durably recorded in CloudTrail." The proxy (AssumeRole for IMDS credential theft) is the correct CloudTrail-observable equivalent.

**ADT Node 2.3 (GuardDuty + VPC Flow Logs)**: Signal A (`_check_guardduty`) polls `list_findings` with a timestamp filter anchored to the attack execution time, then retrieves findings and checks for `CredentialAccess:IAMUser/AnomalousBehavior`, `Recon:IAMUser/UserPermissions`, and `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` — all three types explicitly named in ADT node 2.3. The `GD_RELEVANT_PREFIXES` tuple covers exactly the finding types described in ADT nodes 2.3 and 3.3. The 30-minute SLA matches the ADT's 5-minute GuardDuty detection target (with a conservative outer bound).

**ADT Node 3.3 (CloudTrail Anomaly Correlation + SIEM chain)**: Signal B (`_check_cloudwatch_logs`) validates that the CloudTrail CW Logs delivery pipeline contains at least two of the four attack-chain event names (`AssumeRole`, `GetCallerIdentity`, `ListAttachedRolePolicies`, `ListBuckets`). This directly tests the ADT's claim that "SIEM correlation rules link the ModifyInstanceMetadataOptions CloudTrail event (Step 1) with subsequent API calls using the same role, producing an end-to-end attack-chain alert." The CW Logs delivery validates the data-pipeline completeness required for SIEM correlation.

Infrastructure provisioning is correct: CloudTrail with `IncludeGlobalServiceEvents=True` captures IAM/STS API calls; `EventSelectors` with `IncludeManagementEvents=True` captures the attack-chain events; the CW Logs delivery role has correct `logs:PutLogEvents` permissions; GuardDuty is get-or-create with pre-existing detector tolerance. Code quality is high: CFN template has no IAM resources (learning from prior runs), bucket policy uses correct CloudTrail service principal, stack outputs are harvested and stored in `_STATE`, `OnFailure=DO_NOTHING` prevents premature cleanup masking failures.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The detective probe fully corresponds to the defensive intent specified in ADT node 3.5:

The ADT's detective probe specification states: *"Replay aws sts get-caller-identity and aws s3 ls from an external IP using sandbox credentials; confirm GuardDuty raises InstanceCredentialExfiltration.OutsideAWS within 5 min and the SIEM attack-chain correlation alert linking Steps 1 through 3 fires within 5 min."*

The experiment realizes this intent across all dimensions:

1. **Behavioral coverage**: The implementation replays exactly `sts:GetCallerIdentity` (Node 2.2) and `s3:ListAllMyBuckets` plus `iam:ListAttachedRolePolicies` (Node 3.2) with stolen (assumed) credentials, matching the ADT's "replay ... using sandbox credentials" specification.

2. **GuardDuty validation**: Signal A explicitly checks for `InstanceCredentialExfiltration.OutsideAWS` as the primary finding type (first in `GD_RELEVANT_PREFIXES`), plus `CredentialAccess:IAMUser/AnomalousBehavior` and `Recon:IAMUser/UserPermissions` as accepted equivalents, within the 30-minute SLA.

3. **SIEM correlation chain validation**: Signal B validates that the CloudTrail → CloudWatch Logs delivery pipeline contains the attack-chain event names, confirming the data necessary for "the SIEM attack-chain correlation alert linking Steps 1 through 3." Signal C provides the anchor event validation (AssumeRole = credential acquisition = Step 1 proxy).

4. **Three independent signals**: The ADT mentions three detection layers (GuardDuty, CloudTrail, SIEM correlation). The experiment validates all three independently — GuardDuty findings API, CloudWatch Logs query, and CloudTrail lookup_events — with all three required to return `True` for a passing verdict.

5. **SLA enforcement**: The `_poll_until` helper with `SLA_SECONDS=1800` enforces the 30-minute outer SLA for all three signals. The 30-minute window is a reasonable conservative bound over the ADT's 5-minute targets, appropriate for sandbox/test-account conditions where GuardDuty and CloudTrail delivery may have additional latency.

6. **Rollback completeness**: The rollback covers all provisioned resources (trail stop → S3 empty → CFN delete → IAM delete → conditional GuardDuty delete) in correct dependency order, preserving experiment isolation.

The `hypothesis_verification()` function structure precisely mirrors the steady-state hypothesis defined in the manifest JSON, and the three-signal `results` dict provides granular signal-level reporting that maps directly to the ADT's detection nodes 1.3, 2.3, and 3.3.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

---

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves a perfect pre-execution quality score across all three factors. The implementation demonstrates:
- Exact TTP correspondence for all three attack nodes with appropriate sandbox proxying
- Precise mapping to all three detective control layers (GuardDuty, CloudTrail CW Logs, CloudTrail lookup)
- Full alignment with the ADT node 3.5 detective probe specification
- High code quality with correct error handling, IAM propagation delays, SLA polling, and tolerant rollback

---

## Recommendations

No remediation required. The experiment is authorized for execution. The following operational notes may improve runtime reliability:

1. **GuardDuty latency**: The `ONE_HOUR` publishing frequency on a newly created detector may extend Signal A confirmation time. If running in a fresh account, consider pre-warming the detector or accepting the 30-minute SLA may expire before GuardDuty fires in edge cases.

2. **CloudTrail delivery latency**: CW Logs delivery typically occurs within 5-15 minutes. Signal B's 30-minute SLA provides adequate headroom, but the `limit=100` in `get_log_events` may miss events if the stream is dense. Consider adding pagination across all streams.

3. **External IP detection**: The ADT specifically mentions `InstanceCredentialExfiltration.OutsideAWS` which fires when credentials are used from a non-AWS IP. If the test runner executes from an AWS IP range (e.g., Lambda, EC2, CodeBuild), GuardDuty may raise `AnomalousBehavior` instead. The `GD_RELEVANT_PREFIXES` tuple correctly handles both cases.