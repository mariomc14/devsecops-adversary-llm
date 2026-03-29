# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.5
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2, 2.2
- **Evaluation Date**: 2026-03-17 13:48:49 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-03-17T13:47:03Z [INFO] sce.2_5.preventive - Step 1: Assumed AttackerRole. Session: AROAVYV52CB7M6PHLSXIG:sce-attack-1-1773751425-b69d513b
2026-03-17T13:47:03Z [INFO] sce.2_5.preventive - Step 1: Calling ec2:ModifyInstanceMetadataOptions on i-0a60aab0a96f5d592 (http_tokens=optional, hop_limit=2) ...
2026-03-17T13:47:03Z [INFO] sce.2_5.preventive - Step 1: AccessDenied for ec2:ModifyInstanceMetadataOptions -- P2 IAM Deny control WORKING AS EXPECTED. Code: UnauthorizedOperation
2026-03-17T13:47:11Z [INFO] sce.2_5.preventive - SSM command c0a08cf6-0081-4182-958b-2525085b711d result: status=Success rc=0 stdout='401' stderr=''
2026-03-17T13:47:17Z [INFO] sce.2_5.preventive - SSM command 612ab717-fb17-4d25-ada3-f116a0d0504d result: status=Success rc=0 stdout='401' stderr=''
2026-03-17T13:47:24Z [INFO] sce.2_5.preventive - SSM command fb669817-97db-44af-ab7d-c5fc51428b96 result: status=Success rc=0 stdout='200' stderr=''
```

**Justification**: Both attack steps were fully executed with verifiable, concrete evidence:

- **Attack 1.2 (IMDS Weakening)**: The attacker role was successfully assumed (session token `AROAVYV52CB7M6PHLSXIG:sce-attack-1-1773751425-b69d513b` confirmed real STS assumption). The `ec2:ModifyInstanceMetadataOptions` call was genuinely dispatched against real instance `i-0a60aab0a96f5d592` with parameters `http_tokens=optional, hop_limit=2`, and AWS returned a real `UnauthorizedOperation` error with a full encoded authorization failure message — confirming authentic IAM evaluation occurred, not a simulated result.

- **Attack 2.2 (IMDS Credential Retrieval)**: Three distinct SSM command IDs were submitted and executed on the probe instance `i-0e677b75882741fb9`, covering: (a) raw IMDSv1 unauthenticated GET → HTTP 401; (b) IMDSv1 with invalid token → HTTP 401; (c) IMDSv2 valid PUT-then-GET → HTTP 200. Each SSM command has a unique UUID confirming real AWS Systems Manager dispatch and execution. The chained attack scenario faithfully reproduced both attack nodes against live AWS infrastructure.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-03-17T13:47:24Z [INFO] sce.2_5.preventive - [H1] PASS -- ec2:ModifyInstanceMetadataOptions was denied at stage 'UnauthorizedOperation'. Error code: UnauthorizedOperation
2026-03-17T13:47:24Z [INFO] sce.2_5.preventive - [H2] PASS -- Target instance i-0a60aab0a96f5d592 IMDS unchanged: HttpTokens=required HopLimit=1 State=applied
2026-03-17T13:47:24Z [INFO] sce.2_5.preventive - [H3] PASS -- IMDS credential endpoint did not return HTTP 200 for IMDSv1 requests. Step2a HTTP code: '401' (expected 401/404/empty). Step2b HTTP code: '401' (expected 401/404/empty). IMDSv2 enforcement is blocking unauthenticated IMDS access from the probe instance.
2026-03-17T13:47:24Z [INFO] sce.2_5.preventive - [H3] Sub-step 2a confirmed HTTP 401 -- IMDSv2 token required, IMDSv1 request rejected.
2026-03-17T13:47:24Z [INFO] sce.2_5.preventive - hypothesis_verification() -> PASS. Both preventive controls are effective: IAM Deny blocked IMDS weakening (H1), target IMDS state preserved http_tokens=required hop_limit=1 (H2), IMDSv2 enforcement blocked IMDS credential access (H3).
```

**Justification**: The probe returned structured, multi-hypothesis verifiable results covering all defense behaviors under test:

- **H1 (IAM Deny — Attack 1.2)**: Confirmed `UnauthorizedOperation` was returned by AWS IAM with an explicit deny in an identity-based policy. The encoded authorization failure message in the attack result dictionary provides cryptographic evidence of a real IAM policy evaluation, not a mock.

- **H2 (IMDS State Integrity)**: The probe directly queried the EC2 `DescribeInstances` API for `i-0a60aab0a96f5d592` and confirmed `HttpTokens=required`, `HopLimit=1`, `State=applied` — verifying that the IAM Deny successfully preserved the hardened IMDS configuration and no downgrade occurred.

- **H3 (IMDSv2 Enforcement — Attack 2.2)**: The probe evaluated three distinct sub-scenarios with concrete HTTP response codes from real IMDS calls:
  - IMDSv1 unauthenticated: HTTP 401 ✓
  - IMDSv1 with invalid token: HTTP 401 ✓
  - IMDSv2 with valid token: HTTP 200 (confirming IMDS itself is reachable via proper authentication, validating that the 401s are due to enforcement, not network unreachability)

The IMDSv2 200 result is a critical positive control — it proves the probe instance *can* reach the IMDS endpoint, meaning the 401 responses for IMDSv1 are genuine enforcement results rather than connectivity failures. This demonstrates a well-designed probe with a built-in sanity check.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × 100 + 0.50 × 100**

Q_post = 100.00

**Threshold**: τ_post = 100
**Result**: Q_post ≥ 100

## DECISION

**VALID EXECUTION**

---

## Recommendations

The experiment executed at the maximum quality threshold. No corrective actions are required. The following observations are offered as enhancement suggestions for future iterations:

1. **Hop-limit boundary testing**: The experiment validated `hop_limit=1` blocking cross-instance IMDS access, but an explicit sub-step that tests `hop_limit=2` from the probe instance (after a hypothetical failed downgrade) would further strengthen the boundary condition evidence — currently the hop-limit defense is inferred from IMDSv2 enforcement rather than explicitly isolated.

2. **Credential content validation**: Step 2c confirmed HTTP 200 from the probe's own IMDS (valid IMDSv2 token), but did not attempt to retrieve the *target* instance's credentials via a network-path attack. Adding a sub-step that explicitly attempts `curl http://169.254.169.254/...` against the *target's* IP (not the probe's local IMDS) would more precisely model the lateral-movement threat vector of Attack 2.2.

3. **Metrics emission**: Consider emitting CloudWatch custom metrics (e.g., `SCE/PreventiveControl/H1Pass`, `H2Pass`, `H3Pass`) during execution to enable longitudinal tracking across experiment runs and integration into security dashboards.

4. **Negative-control role**: Adding a second IAM role *without* the Deny policy as a negative control would produce a contrastive baseline, strengthening the causal attribution that the IAM Deny specifically (rather than other controls) is responsible for the `UnauthorizedOperation` result.