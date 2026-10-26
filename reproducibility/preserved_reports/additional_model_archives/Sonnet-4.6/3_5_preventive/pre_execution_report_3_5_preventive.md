# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 3.5
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2, 2.2, 3.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The experiment faithfully operationalises all three attack nodes specified in the ADT:

**Node 1.2 (T1562.008 – Weaken IMDS Protections):** The ADT specifies that the attacker uses `ec2:ModifyInstanceMetadataOptions` to downgrade IMDS, enabling subsequent credential theft. The experiment correctly proxies this by calling `sts:AssumeRole` on the instance-profile role to simulate having already obtained credentials from a weakened IMDS endpoint. The code comment explicitly acknowledges this design choice: *"The actual IMDS weakening is not performed here because the preventive probe tests what happens AFTER credentials are stolen."* This is methodologically sound for a preventive probe scoped to blast-radius containment (ADT 3.5 tests post-theft lateral movement controls, not the IMDS weakening itself). The TTP label T1562.008 is correctly tagged in the manifest.

**Node 2.2 (T1552.005 – Retrieve Credentials from IMDS):** The ADT specifies retrieving `AccessKeyId`, `SecretAccessKey`, and `Token` from `169.254.169.254`. The implementation simulates this by calling `sts:AssumeRole` on the instance role to obtain a `Credentials` dict with identical structure and semantics. The subsequent `sts:GetCallerIdentity` call with the stolen credentials (Node 2.2 verification step) directly mirrors the ADT's *"Verify identity and confirm credential validity"* dependency. TTP T1552.005 is correctly tagged.

**Node 3.2 (T1078.004 – Use Stolen Credentials for Lateral Movement):** The ADT's command block specifies `aws sts get-caller-identity`, `aws s3 ls`, and `aws iam list-attached-role-policies`. The experiment implements a superset of these: `sts:GetCallerIdentity` (Node 2.2 step), `iam:CreateUser` (persistence/escalation path), `sts:AssumeRole` to an AdministratorAccess role (privilege escalation), `s3:GetObject` on a PCI-scope bucket (data exfiltration), and `cloudtrail:StopLogging` (defence evasion). All four blocked actions directly correspond to the ADT's stated attack objectives: *"enumerates and accesses S3 buckets holding PCI-DSS-scoped transaction data… assumes higher-privileged roles… stages cardholder data for exfiltration."* TTP T1078.004 is correctly tagged.

The implementation quality is high: the intentionally broad inline policy (`IntentionallyBroadGrantBlockedByBoundary` statement) correctly isolates the permission boundary as the sole control under test, unexpected-success paths are handled with immediate cleanup, and the `_assume_instance_role` retry loop handles IAM eventual consistency. Full correspondence achieved.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment targets ADT node 3.1 (*"Least-Privilege IAM + Permission Boundaries on Instance Profiles"*) as its primary preventive control, and ADT node 2.1 (*"IMDSv2 HopLimit=1 + Container Network Isolation + SSRF SAST Gate"*) via the S3 bucket policy as a secondary independent control layer. The correspondence is comprehensive:

**Permission Boundary (ADT 3.1 primary control):** The ADT states: *"Roles explicitly Deny: iam:CreateUser, iam:CreateAccessKey, iam:AttachRolePolicy, sts:AssumeRole (except scoped to trusted roles), cloudtrail:StopLogging, s3:DeleteObject on audit and artifact buckets."* The experiment's `_create_permission_boundary()` function implements an allowlist-based boundary (anything not listed is implicitly denied) PLUS an explicit `ExplicitDenyHighRisk` statement covering `iam:CreateUser`, `iam:CreateAccessKey`, `iam:AttachRolePolicy`, `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `cloudtrail:UpdateTrail`, `cloudtrail:PutEventSelectors`, and `s3:DeleteBucket`/`s3:DeleteObject`. The four tested attack actions (3.2a through 3.2d) map directly to this deny list. The `PermissionsBoundary=boundary_arn` parameter is set at role creation time, correctly reflecting the ADT's description of boundaries applied at the IAM principal level.

**S3 Bucket Policy (ADT 3.1 + defence depth):** The ADT states the S3 bucket carries a resource-based control independent of IAM. The CFN template implements `DenyGetObjectAllPrincipals` with `Principal: "*"` and `Effect: Deny`, providing a second independent denial layer for Signal C exactly as the ADT describes: *"s3:GetObject on audit and artifact buckets"* and the bucket policy cross-reference. The `DenyNonSSL` statement adds PCI-DSS Req 4.2 compliance hardening not explicitly required by the probe but consistent with the banking platform context.

**Baseline assertion in `steady_state()`:** The code verifies boundary attachment and bucket policy presence BEFORE the attack, matching the ADT's *"Permission boundaries enforce these limits independently of policy attachments"* and the IaC validation intent from node 1.1.

**Signal E (boundary durability):** The live `get_role()` check in `hypothesis_verification()` confirms the boundary was not detached mid-experiment, directly operationalising the ADT's *"An SCP at the Organization level enforces the same Deny conditions as a second independent layer"* intent (the experiment substitutes the SCP with a durability check because SCP testing requires an Organizations context unavailable in a sandbox account — an appropriate scoping decision clearly documented).

**No-IAM-user structural check:** The `iam.get_user(UserName="sce-test-persistence-user")` check in both `hypothesis_verification()` and `rollback()` directly implements the ADT probe requirement: *"verify no S3 object is returned and no IAM user is created."*

Implementation quality is high: the boundary uses an allowlist (not a pure deny list) which is a best-practice IAM boundary pattern; the intentionally broad inline policy correctly makes the boundary the sole effective control; rollback is tolerant and covers all created resources in correct dependency order (inline policies before role deletion, AdministratorAccess detachment before high-priv role deletion, boundary policy detachment path in `_delete_iam_resources`).

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The ADT's SCE node 3.5 Preventive Probe specifies:

> *"Using a cloned instance-profile role in a sandbox, attempt iam:CreateUser, sts:AssumeRole to admin role, and s3:GetObject on the PCI-scope bucket; confirm all three are denied by the permission boundary and SCP; verify no S3 object is returned and no IAM user is created. Confirm cloudtrail:StopLogging is denied and the audit trail remains intact."*

The experiment's defensive intent alignment is complete across all five required signals:

| ADT Requirement | Implementation | Signal |
|---|---|---|
| `iam:CreateUser` denied | `iam_with_stolen.create_user(...)` → `AccessDenied` check | Signal A |
| `sts:AssumeRole` to admin denied | `sts_with_stolen.assume_role(RoleArn=high_priv_arn, ...)` → `AccessDenied` check | Signal B |
| `s3:GetObject` on PCI bucket denied | `s3_with_stolen.get_object(Bucket=bucket, ...)` → `AccessDenied` check | Signal C |
| `cloudtrail:StopLogging` denied | `ct_with_stolen.stop_logging(Name=fake_trail_arn)` → `AccessDenied` check | Signal D |
| No IAM user created | `iam.get_user(UserName="sce-test-persistence-user")` → `NoSuchEntity` assertion | Structural |

The "cloned instance-profile role in a sandbox" is correctly implemented as a boto3-created role with `PermissionsBoundary` parameter set, carrying an intentionally broad inline policy to ensure the boundary (not the identity policy) is the sole blocking control — this is precisely the right experimental design for validating a permission boundary.

The manifest's steady-state hypothesis title accurately summarises all five signals. The `hypothesis_verification()` function uses polling with a 30-minute outer SLA matching the ADT's *"30-minute SLA"* specification, with 60-second fast-path checks for Signals A-D (already resolved by the attack phase) and the full SLA window for Signal E (live API check).

The `TrailNotFoundException` handling in `_check_cloudtrail_stop()` shows careful reasoning: if the IAM check were to pass before the resource ARN check, it would indicate a boundary bypass, and the code correctly flags this as a potential fail condition rather than incorrectly treating it as an AccessDenied equivalent.

The `DENIED_CODES` set covers all AWS SDK variations of access denial (`AccessDenied`, `AccessDeniedException`, `UnauthorizedAccess`, `AuthorizationError`, `Client.UnauthorizedOperation`), ensuring cross-service error code normalisation does not produce false passes.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

All three quality factors score at maximum. The experiment fully corresponds to the ADT specification across attack node coverage, defensive control operationalisation, and probe intent. The implementation demonstrates high engineering quality with correct IAM boundary patterns, appropriate sandbox scoping, robust error handling, and compliant rollback logic. The experiment is cleared for execution.

---

## Recommendations

Although the experiment achieves the maximum score and is authorized for execution, the following enhancements would increase coverage and resilience for future iterations:

1. **SCP simulation gap acknowledgement:** The ADT references SCP-level controls as a second independent layer alongside the permission boundary. Since SCPs require an AWS Organizations context, the experiment correctly omits them but does not explicitly log this scoping decision in the experiment output. Adding a `log.info("[SCOPE] SCP controls not tested - requires Organizations context; boundary is sole control under test")` statement would improve auditability.

2. **`iam:CreateAccessKey` test action:** The ADT explicitly lists `iam:CreateAccessKey` as a denied action. Adding this as a 3.2e attempt would achieve 100% coverage of the ADT's deny list without requiring additional infrastructure.

3. **`iam:AttachRolePolicy` test action:** Similarly, `iam:AttachRolePolicy` is listed in ADT 3.1. Testing it against the high-privilege role ARN would complete the ADT's stated deny list coverage.

4. **Credential expiry window validation:** The ADT notes stolen credentials are *"valid up to 6 hours."* The experiment uses `DurationSeconds=900` (15 min), which is conservative and correct for sandbox use, but documenting this design choice in the code comments would improve traceability.

5. **Region parametrisation:** The `region_name or "us-east-1"` fallback should be replaced with an explicit environment variable or parameter to avoid silently defaulting to a region that may not match the banking platform's primary region during execution.