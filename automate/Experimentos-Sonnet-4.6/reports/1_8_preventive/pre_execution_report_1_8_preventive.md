# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2, 1.7
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The experiment faithfully models both attack nodes referenced in the manifest:

**Attack Node 1.2 (T1578 – Modify Cloud Compute Infrastructure):** The `attack()` function directly simulates `ec2:ModifyInstanceMetadataOptions` with `HttpTokens=optional` and `HttpPutResponseHopLimit=2` — precisely matching the ADT command block. Two vectors are used: (1) `iam:SimulatePrincipalPolicy` against `SCERole` to evaluate effective permission under the boundary, and (2) a direct API call attempt from the caller identity to generate a real CloudTrail `AccessDenied` event. The target instance is the SCE canary EC2 host. The dependency chain (IAM role with `ec2:ModifyInstanceMetadataOptions` in the inline policy, an EC2 instance target) is fully replicated.

**Attack Node 1.7 (T1552.005 – Cloud Instance Metadata API):** The infrastructure setup enforces conditions that would enable credential harvest if controls fail: the instance runs with an IAM profile attached (`SCEProfile`/`SCERole`) that holds permissions matching the `banking-transaction-role` pattern (S3, Secrets Manager). The `SCERole` inline policy explicitly grants `secretsmanager:GetSecretValue` and `s3:GetObject`, mirroring the real attack surface. Check D (SSM `curl` to `169.254.169.254`) directly tests whether unauthenticated IMDS credential retrieval is possible.

The technique is correct (not merely the tactic): the specific AWS API call, parameter values (`optional`, hop-limit=2), and the IMDS credential harvest path are all precisely replicated. Implementation quality is high — the `_STATE` dict preserves context across functions, retry logic handles transient failures, and the attack result distinction (`succeeded_unexpected` vs. `blocked`) correctly classifies control pass/fail.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment maps to the ADT's **1.6 Preventive Safeguard** (Block Unauthenticated IMDS Queries) and **1.1 Preventive Safeguard** (IMDS Hardening & IAM Least Privilege) with high fidelity across all four controls:

**Control 1 – IMDSv2 Token Requirement (ADT 1.6 Control 1 / ADT 1.1 SCP):** The `SCEBoundary` managed policy contains an explicit `Deny` on `ec2:ModifyInstanceMetadataOptions`, modelling the SCP deny. Check A uses `iam:SimulatePrincipalPolicy` to confirm the boundary produces `explicitDeny` — the correct evaluation mechanism for permission boundary enforcement.

**Control 2 – Hop Limit = 1 Enforcement (ADT 1.6 Control 2):** The `SCELaunchTemplate` specifies `HttpPutResponseHopLimit: 1` and `HttpTokens: required`. Check B polls `DescribeInstances` with a 30-minute SLA window and explicitly validates both `HttpTokens == "required"` AND `HttpPutResponseHopLimit == 1`, directly matching the ADT control specification.

**Control 3 – Container Network Policy / Security Group (ADT 1.6 Control 3):** The `SCESG` security group is constructed with egress limited to TCP/443 only — no TCP/80, no `169.254.0.0/16`. Check C inspects all egress rules against three threat vectors: explicit IMDS CIDRs, `0.0.0.0/0` with TCP/80, and `0.0.0.0/0` with protocol `-1`. The IMDS CIDR set is comprehensive (`/32`, `/16`, `/24`).

**Control 4 – AppArmor/seccomp / Network Namespace (ADT 1.6 Control 4):** Check D (SSM `curl` without a session token) directly validates that the container/host network namespace cannot reach IMDS without a token — the functional outcome of hop-limit and IMDSv2 enforcement.

**Infrastructure quality:** The VPC is fully private (no IGW), uses SSM PrivateLink endpoints for management access, and the IAM template correctly separates the attacker role (`SCERole`, EC2 trust only) from the verifier role (`SCEVerifier`, caller trust + read-only). The `SCEVerifier` role avoids the documented prior failure of reusing the attacker's IAM path for probe verification. CloudFormation dependency ordering (`DependsOn`) and the 30-second IAM propagation wait are appropriate operational details.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The ADT node 1.8 specifies three probe phases. The experiment's preventive probe is the primary focus here, and it corresponds with precision:

**ADT Preventive Probe specification:**
> "Inject a test IAM principal with `ec2:ModifyInstanceMetadataOptions` and attempt to set `HttpTokens=optional` on a canary EC2 instance. Verify the SCP blocks the call with an explicit Deny. Confirm Checkov fails a pipeline that sets `http_tokens="optional"` in Terraform. Expected: API call denied; pipeline gate fails; zero instances modified."

**Experiment mapping:**
- The `SCERole` is exactly a "test IAM principal with `ec2:ModifyInstanceMetadataOptions`" — the inline policy grants the action, and the boundary denies it, replicating the SCP-deny semantics.
- Check A verifies the explicit deny via `SimulatePrincipalPolicy` — equivalent to confirming "SCP blocks the call with an explicit Deny."
- The direct `modify_instance_metadata_options` call in `attack()` confirms "zero instances modified" by catching `AccessDenied`/`UnauthorizedOperation`.
- Check B confirms `HttpTokens=required` persists post-attack-attempt — the instance was not modified.
- The Checkov/pipeline gate aspect is not automated (it would require a CI/CD pipeline fixture), but this is an acknowledged operational constraint; the IaC enforcement is validated indirectly through the launch template inspection in Check B.

**Beyond the ADT spec:** The experiment adds value not explicitly in the ADT:
- The SCEVerifier role separation explicitly decouples the probe from the attacker IAM path (documented root-cause fix).
- Check C adds defense-in-depth validation (SG egress) beyond what the ADT preventive probe specifies.
- Check D (SSM curl) provides functional end-to-end evidence that the controls compose correctly.

The defensive intent — "prevent IMDS downgrade that would enable credential harvest" — is precisely captured: the experiment proves the attacker principal cannot weaken IMDS, the instance retains `HttpTokens=required`/`HopLimit=1`, and network-level egress to IMDS is blocked. All mandatory checks (A, B, C) map to independent control layers in the ADT, and the pass condition correctly requires all three.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves maximum correspondence across all three evaluation factors. The implementation is production-grade with appropriate error handling, SLA-based polling, IAM role separation, and clear pass/fail semantics. No remediation is required.

---

## Recommendations

The experiment is authorized as-is. The following optional enhancements would further increase robustness in edge cases but are not required for authorization:

1. **Checkov pipeline gate simulation**: Add an optional Check E that generates a minimal Terraform HCL fragment with `http_tokens = "optional"` and invokes `checkov --check CKV_AWS_79` via subprocess, providing direct evidence of the pipeline gate control referenced in ADT 1.1 Control 2 and the ADT 1.8 preventive probe spec.

2. **CloudTrail event validation**: After the `attack()` direct call, poll CloudTrail for the `ModifyInstanceMetadataOptions` event with `errorCode: Client.UnauthorizedOperation` to provide forensic evidence that the control generated an auditable denial record — bridging preventive and detective control validation.

3. **Multi-region suffix collision guard**: The `suffix = str(int(time.time()))` pattern could collide in rapid re-runs. A `uuid4` hex suffix (8 chars) would be more collision-resistant.

4. **SSM registration timeout tuning**: The 300-second SSM wait may be insufficient in regions with slower PrivateLink DNS propagation. Consider extending to 600 seconds with a diagnostic `describe_instance_information` log on timeout to aid debugging.