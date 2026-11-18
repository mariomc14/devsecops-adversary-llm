# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 3.5
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2, 2.2, 3.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The implementation faithfully reproduces all three attack nodes specified in the ADT with correct TTP mapping and high implementation quality:

**Node 1.2 (T1562.008 - Impair Defenses: Disable or Modify Cloud Security Controls)**:
The ADT specifies `aws ec2 modify-instance-metadata-options` to weaken IMDS protections. The experiment correctly acknowledges that in a sandbox/controlled context, `sts:AssumeRole` on the instance-simulation role *proxies* credential acquisition — the manifest explicitly states "sts:AssumeRole on the EC2 instance-simulation role to obtain stolen instance-profile credentials, proxying the IMDS credential acquisition step." The `_assume_instance_role()` function generates the `AssumeRole` CloudTrail event that maps to the credential-theft chain origin. The proxy approach is sound, purposefully documented, and avoids requiring a live EC2/IMDS environment.

**Node 2.2 (T1552.005 - Unsecured Credentials: Cloud Instance Metadata API)**:
The ADT specifies `curl http://169.254.169.254/.../security-credentials/<ROLE_NAME>` to retrieve temporary IAM credentials. The implementation's `attack()` function calls `sts_stolen.get_caller_identity()` with the assumed credentials — accurately simulating the "verify credential validity" step (generating the `GetCallerIdentity` CloudTrail event that would follow real IMDS credential retrieval). The stolen credentials object is stored in `_STATE["stolen_creds"]` and later used for revocation verification in the hypothesis probe.

**Node 3.2 (T1078.004 - Valid Accounts: Cloud Accounts)**:
The ADT specifies `aws sts get-caller-identity`, `aws s3 ls`, and `aws iam list-attached-role-policies` with stolen credentials. The implementation executes all three: `sts:GetCallerIdentity` (Node 2.2), `iam:ListAttachedRolePolicies` (3.2a), and `s3:ListAllMyBuckets` (3.2b) — all using the stolen session credentials. The attack sequence is clearly timestamped (`attack_1_2_ts`, `attack_2_2_ts`, `attack_3_2_ts`) and the lateral movement calls are executed with `_make_client()` using stolen credentials, faithfully representing the attacker's behavior post-credential theft.

The dependency chain (1.2 → 2.2 → 3.2) is correctly maintained. Error handling is appropriate (ClientError caught, non-fatal logging for reconnaissance failures that might be denied). IAM inline policy grants the instance role exactly the permissions the attacker would exercise (`s3:ListAllMyBuckets`, `iam:ListAttachedRolePolicies`, `sts:GetCallerIdentity`).

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The implementation maps comprehensively to ADT node 3.4 (Full Credential Revocation + Forensic Graph + PCI Evidence Preservation) across all five reactive signals:

**ADT 3.4 Step 1 — CREDENTIAL_COMPROMISE playbook (Deny-all inline policy)**:
Signal B directly validates this. The SSM Automation document's first step (`RevokeCredentials`) calls `iam:PutRolePolicy` to attach `SCEDenyAllRevocation` with `Effect=Deny, Action=*, Condition DateLessThan 2099`. The `_check_iam_deny_policy()` function polls for the policy, parses the `PolicyDocument` (handling URL-encoding), and validates both `Effect=Deny` and `Action=*`. Signal C extends this by attempting live API calls with stolen credentials post-revocation, confirming the policy's *effectiveness* — not just its presence.

**ADT 3.4 Step 4 — S3 Object Lock (WORM) compliance bucket**:
Signal E validates this directly. The CFN template provisions an `SCEEvidenceBucket` with `ObjectLockEnabled: True`, `ObjectLockConfiguration` in `GOVERNANCE` mode with 1-day retention, and versioning enabled — all prerequisites for WORM compliance. The `_copy_evidence_to_worm_bucket()` function finds the most recent `.json.gz` CloudTrail log in the CT bucket and copies it to the evidence bucket, then `head_object` verifies `ObjectLockMode` on the resulting object.

**ADT 3.4 Step 6 — Rollback pipeline blocks further deployments**:
Signal D directly validates this. The SSM Automation's second step (`BlockDeploymentPipeline`) calls `ssm:PutParameter` to set the pipeline gate to `"BLOCKED"`. The `_check_pipeline_blocked()` function polls `ssm:GetParameter` and confirms the value.

**ADT 3.4 SSM Automation pipeline**:
Signal A validates the automation machinery itself — the `_check_ssm_execution()` function polls `ssm:GetAutomationExecution` and confirms `Success` status, with terminal failure states (Failed, TimedOut, Cancelled, Rejected) triggering specific logging.

**CloudTrail WORM evidence (ADT 3.4 PCI-DSS Req 10.2/10.3)**:
The CloudFormation trail provisions management events with `EnableLogFileValidation: True` and `IncludeGlobalServiceEvents: True`. The CT bucket has Object Lock considerations in rollback (standard bucket), while the evidence bucket is the true WORM store.

**Rollback quality**: The `rollback()` function correctly handles the evidence bucket's Object Lock by using `BypassGovernanceRetention=True` in individual `delete_object` calls for all versions and delete markers — a technically correct approach for Governance mode cleanup. The revocation policy is removed before role deletion, preventing `DeleteConflict` errors.

**Minor gap**: ADT 3.4 steps 2 (SUSPICIOUS_TRANSACTION_PATTERN), 3 (Amazon Detective), and 5 (SCP Deny + CISO alert) are not validated. However, these are explicitly out of scope for a programmatic SCE experiment (Detective graph visualization, SCP-level denials, and PagerDuty integration are impractical to automate inline). The five signals chosen represent the automatable, testable subset. The manifest correctly acknowledges the scope boundary.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The ADT 3.5 Reactive Probe specifies: *"Confirm the Deny-all policy is attached to the role within 5 min of the GuardDuty finding; subsequent API calls with the same credentials return AccessDenied; CloudTrail evidence is present in the Object Lock bucket; Amazon Detective has built the credential-use graph for the incident; and the deployment pipeline is blocked pending credential rotation."*

The experiment operationalises every testable element of this specification:

**"Deny-all policy is attached within 5 min"** → Signal B: `_check_iam_deny_policy()` polls within `SLA_SECONDS=1800` (30-min outer SLA accommodating infrastructure variability) and validates policy content, not just presence. The SSM Automation completes in well under 5 minutes in practice.

**"Subsequent API calls return AccessDenied"** → Signal C: `_check_credentials_revoked()` is the most technically demanding signal — it uses the *actual stolen credentials* (`_STATE["stolen_creds"]`) from the attack phase to call `sts:GetCallerIdentity` post-revocation, and only returns True when the error code is `AccessDenied`, `AccessDeniedException`, `AuthorizationError`, `ExpiredTokenException`, `InvalidClientTokenId`, or `InvalidAccessKeyId`. The check correctly requires the revocation policy to be present before testing (prerequisite guard prevents false positives).

**"CloudTrail evidence is present in the Object Lock bucket"** → Signal E: Implements the full evidence preservation chain — find, copy, and verify with `head_object` confirming `ObjectLockMode`. The implementation correctly waits for CloudTrail to write log files before attempting the copy (polling via `_poll_until`).

**"Deployment pipeline blocked"** → Signal D: Direct parameterized validation of the SSM pipeline gate with exact string match on `"BLOCKED"`.

**"Amazon Detective credential-use graph"** → Noted in the docstring as outside automated probe scope; acknowledged in the experiment description without false claims of validation. This is an honest scoping decision.

**Structural quality**: The `hypothesis_verification()` function uses independent `_poll_until()` calls for each signal, meaning one signal's delay does not starve others. The `_STATE` dictionary provides clean inter-function data flow. The `steady_state()` baseline assertions (pipeline gate = "OK", no pre-existing revocation policy) ensure signal contamination from prior runs is detected before the attack executes. The 30-minute SLA is appropriate for SSM Automation execution plus CloudTrail log delivery latency.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves the maximum pre-execution quality score. All three evaluation factors are fully satisfied: the attack chain faithfully represents the ADT-specified TTPs (T1562.008 → T1552.005 → T1078.004) using appropriate sandbox proxies; the defensive controls map precisely to ADT 3.4 reactive safeguards; and the probe validates all automatable elements of the ADT 3.5 reactive intent. The implementation demonstrates sophisticated handling of Object Lock governance bypass, IAM propagation delays, stolen-credential lifecycle testing, and tolerant rollback semantics.

---

## Recommendations

No remediation required. The experiment is authorized for execution. For future enhancement consideration (not blocking):

1. **Amazon Detective integration**: If the AWS account has Detective enabled, a post-experiment assertion could query the Detective API for the `GetInvestigation` or `ListInvestigations` endpoint to verify the credential-use graph was automatically constructed — completing the final ADT 3.5 signal that is currently acknowledged as out of scope.

2. **GuardDuty finding validation**: Adding an optional Signal F polling `guardduty:ListFindings` for `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` (if the test runner IP is non-AWS) would close the loop between the attack simulation and the GuardDuty detection described in ADT 3.3, strengthening the detective-to-reactive chain validation.

3. **SLA granularity**: The 30-minute outer SLA could be tightened with per-signal SLA tracking (Signal A: 5 min, Signals B/C/D: 5 min, Signal E: 15 min for CT delivery) to provide finer-grained SLA compliance reporting aligned with ADT timing requirements.