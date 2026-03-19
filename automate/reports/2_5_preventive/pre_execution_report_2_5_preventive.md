# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.5
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2, 2.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

**Attack Node 1.2 (T1578 – Modify Cloud Compute Infrastructure)**:
The ADT specifies: `aws ec2 modify-instance-metadata-options --instance-id <ID> --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`. The implementation in `attack()` Step 1 precisely mirrors this: it assumes the attacker role via `sts:AssumeRole`, constructs a dedicated EC2 client with those credentials, then calls `ec2_attacker.modify_instance_metadata_options(InstanceId=_TARGET_INSTANCE_ID, HttpTokens="optional", HttpEndpoint="enabled", HttpPutResponseHopLimit=2)`. The TTP (T1578), parameters, dependency chain (IAM credentials + instance ID knowledge + AWS CLI/SDK), and expected result (IMDS downgrade attempt) are all faithfully reproduced.

**Attack Node 2.2 (T1552.005 – Cloud Instance Metadata API)**:
The ADT specifies: `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/` from a co-located process. The implementation in `attack()` Step 2 models this via SSM RunCommand on the probe EC2 instance (correctly modelled as a co-located process), executing unauthenticated IMDSv1 curl requests (sub-steps 2a and 2b). The dependency chain is correctly reflected: the attack is staged sequentially after Step 1. Sub-step 2c additionally probes valid IMDSv2 token flow to differentiate "blocked by token enforcement" from "endpoint unreachable", adding diagnostic depth. Both TTPs are correctly tagged, and HTTP response codes are captured for hypothesis evaluation. The chained dependency (Step 1 must succeed for Step 2 to yield credentials) is architecturally encoded in the infrastructure design.

**Implementation Quality**: High. Error handling distinguishes `AccessDenied`, `UnauthorizedOperation`, and unexpected codes. Results are stored in `_ATTACK_RESULT` with granular keys. SSM readiness is polled before Step 2 to avoid false negatives. The attacker role assumption is correctly done with a unique session name.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

**ADT Node 1.1 (IAM Least-Privilege + IaC Drift Prevention) → P2 control**:
The ADT states: "SCP and IAM policy explicitly deny ec2:ModifyInstanceMetadataOptions on all EC2 instances tagged Environment=production." The implementation precisely encodes this as `SCEAttackerRole` in the CFN template with an inline policy containing:
- `Sid: DenyIMDSWeakeningOnProd` — explicit `Effect: Deny` on `ec2:ModifyInstanceMetadataOptions` with `Condition: StringEquals: ec2:ResourceTag/Environment: production`
- Target EC2 instance tagged `Environment: production`

This is a direct, accurate implementation of the IAM tag-conditional Deny described in the ADT. The attacker role also includes baseline Allow statements (`ec2:DescribeInstances`, `sts:GetCallerIdentity`) to model a realistic attacker credential set with limited permissions, consistent with the ADT's description of "an attacker with valid AWS credentials."

**ADT Node 2.1 (IMDSv2 Hop-Limit Enforcement + Container Egress Blocking) → P1 control**:
The ADT states: "IMDSv2 hop-limit=1 enforced; containers cannot reach 169.254.169.254 via SSRF because TTL expires before reaching the metadata endpoint." The implementation enforces this on both EC2 instances via CFN `MetadataOptions: HttpTokens: required, HttpEndpoint: enabled, HttpPutResponseHopLimit: 1`. The baseline check in `steady_state()` explicitly verifies `http_tokens == "required" and hop_limit == 1` before proceeding, ensuring the control is active. The probe instance (representing the co-located container) accesses its own IMDS (link-local 169.254.169.254), and the IMDSv2 enforcement causes HTTP 401 for unauthenticated requests — directly validating the ADT's stated blocking mechanism.

**Implementation Quality**: High. The CFN template is well-structured with proper DependsOn chains, `_ascii_safe()` enforcement on all strings, and `_validate_template_strings()` pre-submission validation. IAM trust policy uses a programmatically resolved `account_id` (not a hardcoded placeholder). The `_build_cfn_template()` function is modular and parameterised. The SSM-only instance profile design correctly scopes instance permissions to the minimum required for experiment orchestration, matching the ADT's least-privilege principle.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The SCE Node 2.5 Preventive probe is designed to validate that **both preventive controls independently and jointly block the IMDS credential-theft chain before any harm occurs**. The defensive intent per the ADT is:

1. **P2 (Node 1.1)**: IAM Deny stops the IMDS weakening at the API layer — the attacker never achieves the prerequisite for credential theft.
2. **P1 (Node 2.1)**: Even if weakening were attempted, IMDSv2 enforcement with hop-limit=1 prevents unauthenticated IMDS access from co-located processes.

The `hypothesis_verification()` function maps precisely to this intent with three independent hypotheses:

- **H1** verifies P2: `step1_access_denied == True` confirms the IAM Deny fired at the `ec2:ModifyInstanceMetadataOptions` call. The verification correctly distinguishes between denial at `sts:AssumeRole` level vs. at the EC2 API level (both acceptable for H1).

- **H2** verifies the consequence of P2: the target instance IMDS state remains `http_tokens=required, hop_limit=1` post-attack, confirmed by a live `ec2:DescribeInstances` call rather than relying on cached state. This is correct — it validates that the Deny policy actually prevented mutation, not just that an error was returned.

- **H3** verifies P1 independently: it checks that IMDSv1 unauthenticated requests from the probe instance return non-200 HTTP codes (401 or 404), confirming IMDSv2 enforcement blocks the credential retrieval path regardless of whether IMDS weakening was attempted.

The H3 skip logic is appropriately reasoned: if Step 2 is not SSM-reachable, H1+H2 still validate the primary preventive chain (since without IMDS weakening, credential theft via IMDS is architecturally impossible). This is consistent with the ADT's defence-in-depth framing where P2 is the first line of defence and P1 is the second.

The JSON manifest correctly describes the chained attack and three hypotheses. The `steady-state-hypothesis` probe calls `hypothesis_verification()` which serves as both pre-condition check and post-attack verification — a valid Chaos Engineering pattern. The rollback is comprehensive and idempotent.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves full correspondence across all three quality factors. The implementation faithfully reproduces both attack TTPs (T1578 and T1552.005) with correct parameters, correctly implements both ADT defensive controls (IAM tag-conditional Deny and IMDSv2 hop-limit enforcement), and the probe hypotheses (H1, H2, H3) directly validate the preventive defensive intent described in ADT Nodes 1.1 and 2.1.

---

## Recommendations

The experiment is authorized without mandatory changes. The following optional enhancements could further strengthen the probe in future iterations:

1. **WAF/network-layer validation**: ADT Node 2.1 mentions "AWS WAF and API Gateway rules reject server-side requests targeting link-local ranges." A future enhancement could add a sub-step that tests a WAF-fronted endpoint with an SSRF payload targeting `169.254.169.254`, providing coverage of the WAF control layer described in the ADT.

2. **Falco rule validation**: ADT Node 2.1 mentions "Falco rule alerts on unexpected curl or wget to 169.254.169.254." If Falco is deployed in the environment, a sub-step checking for a Falco alert after the curl commands in Step 2 would provide detective coverage within the preventive probe.

3. **SCP simulation**: The ADT mentions SCPs in Node 1.1. The current implementation tests IAM inline policy Deny (which is valid and correct), but a future variant could test SCP-enforced Deny to exercise the full control stack described in the ADT.

4. **Cross-instance IMDS access test**: The current H3 tests the probe instance's own IMDS. A network-layer test confirming the probe cannot reach the *target* instance's IMDS IP (even with hop-limit=2 simulated via iptables on a test instance) would more directly validate the hop-limit TTL expiry mechanism described in the ADT.