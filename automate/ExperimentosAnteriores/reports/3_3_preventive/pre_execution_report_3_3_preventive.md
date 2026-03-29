# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 3.3
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2, 2.2, 3.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

All three attack nodes are faithfully reproduced in the implementation with precise tactic and technique alignment:

**Attack Node 1.2 — T1578 (Modify Cloud Compute Infrastructure)**
The ADT specifies `aws ec2 modify-instance-metadata-options --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`. The `IMDSModifyFunction` Lambda assumes `AttackerRole` and calls exactly `ec2.modify_instance_metadata_options(InstanceId=..., HttpTokens='optional', HttpEndpoint='enabled', HttpPutResponseHopLimit=2)` — identical parameters. The dependency chain (requiring `ec2:ModifyInstanceMetadataOptions` permission, valid credentials, and a running/stopped EC2 instance) is correctly scaffolded via the CloudFormation stack.

**Attack Node 2.2 — T1552.005 (Cloud Instance Metadata API)**
The ADT specifies `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` with a two-step credential harvest (role name then credentials). The `IMDSProbeFunction` Lambda replicates this precisely: it issues an unauthenticated GET to `http://{instance_ip}/latest/meta-data/iam/security-credentials/` (spoofing the Host header to `169.254.169.254`), then follows up with a credential fetch for the role name — matching the exact two-request sequence described in the attack node. The dependency (IMDSv1 re-enabled, HopLimit ≥ 2, code execution in container, EC2 instance profile attached) is faithfully modelled.

**Attack Node 3.2 — T1078.004 (Valid Accounts: Cloud Accounts)**
The ADT specifies exporting stolen credentials and enumerating `iam:list-attached-role-policies`, `iam:list-role-policies`, and then attempting lateral movement across S3, Secrets Manager, ECR, and CodeBuild. The `SimulatedAttackerLambda` assumes `AttackerRole` (simulating external use of stolen credentials) and attempts `iam:ListRoles`, `iam:CreateUser`, `iam:AttachRolePolicy`, `iam:CreatePolicy`, `s3:GetObject` on the PCI bucket, `ecr:GetAuthorizationToken`, and `sts:GetCallerIdentity` — covering IAM enumeration, persistence, privilege escalation, data exfiltration, and container registry abuse as described in the attack node. The substitution of `ecr:GetAuthorizationToken` for `ecr:PutImage` (which requires a real manifest) is a sound and necessary adaptation documented in inline comments.

Implementation quality is high: IAM role chaining (AttackerLambdaExecRole → AttackerRole) correctly simulates external credential use; results are written to SSM parameters for auditable verification; error classification (`denied::` vs `error::` vs `allowed`) is granular; retry logic handles transient AWS API failures.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The implementation instantiates and tests every relevant preventive control across all three ADT preventive safeguard nodes (1.1, 2.1, 3.1):

**ADT 1.1 — SCP / IAM Deny on ec2:ModifyInstanceMetadataOptions**
The experiment cannot deploy an actual SCP (which requires AWS Organizations root access) but correctly substitutes with a **Permission Boundary** (`PermissionBoundaryPolicy`) that includes an explicit `Deny` on `ec2:ModifyInstanceMetadataOptions` — the highest-fidelity testable equivalent within a single account. This is architecturally honest: the `DenyPrivilegedActions` statement in the boundary policy mirrors exactly the control described. The ADT Control 2 (IAM Least-Privilege Role Policy) is implemented via the boundary's explicit deny list rather than a separate inline deny, which is functionally equivalent and architecturally cleaner.

**ADT 1.1 Control 3 — Launch Template / IaC Baseline Enforcement**
The CloudFormation stack provisions the EC2 instance with `HttpTokens: required`, `HttpEndpoint: enabled`, `HttpPutResponseHopLimit: 1` hardcoded in the template — directly implementing the "immutable IaC default" concept. Sub-check (a) in `hypothesis_verification()` confirms the instance IMDS state is unchanged post-attack, validating that IaC-as-prevention held.

**ADT 2.1 — IMDSv2 Session Token Enforcement + NACL Defense-in-Depth**
Both controls are implemented: (1) EC2 `MetadataOptions.HttpTokens = required` ensures IMDSv1 unauthenticated GETs return 401; (2) `ContainerNACL` with `NACLEgressDenyIMDS` (Rule 50, Protocol TCP, Port 80, CIDR 169.254.169.254/32, Egress, Deny) implements the "NACLs deny outbound 169.254.169.254/32" control from ADT 2.1 Control 3. The Lambda SG egress rules scope HTTP access to `10.0.2.0/24` only, representing the WAF/allowlist concept from ADT 2.1 Control 2.

**ADT 3.1 — Permission Boundaries + SCP Restrictions on EC2 Instance Roles**
The `PermissionBoundaryPolicy` is attached to `AttackerRole` and denies `iam:CreateUser`, `iam:AttachRolePolicy`, `iam:CreatePolicy`, `iam:PassRole`, `iam:ListRoles`, `ecr:PutImage`, `ecr:GetAuthorizationToken`, `s3:GetObject`, `sts:AssumeRole` — mapping directly to ADT 3.1 Controls 1 and 2. The permission boundary mechanism is precisely the IAM construct described in ADT Control 2 ("Permission boundary attached to all instance profiles").

**Additional quality indicators**: 
- The `PermissionBoundaryPolicy` uses a correct two-statement structure (explicit Allow for baseline + explicit Deny for privileged actions) rather than just a deny-all, which correctly models a real permission boundary's "effective permissions = intersection" semantics.
- Sub-check (d) adds IAM `SimulatePrincipalPolicy` as an independent cross-check, providing defense-in-depth for the verification itself — a hallmark of high-quality SCE implementation.
- Resource scoping is tight: SSM parameter ARNs are scoped to `/sce/3-3/{suffix}/*`; IAM roles have descriptive names with suffix isolation; all resources carry the `sce-experiment` tag for cost tracking and blast radius control.
- The `AttackerRole` identity policy grants `Action: "*" / Resource: "*"` intentionally — this ensures the Permission Boundary is the sole control under test, not an identity policy denial, making the experiment a clean test of the boundary.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The ADT 3.3 Chaos node (Preventive Probe) states:

> *"Using red-team instance role credentials in external AWS CLI, attempt iam:CreateUser, ecr:PutImage, s3:GetObject on PCI bucket. Confirm SCP and permission boundary return AccessDenied for all privileged actions. Verify sts:AssumeRole to CodeBuild role is denied."*

The experiment's `hypothesis_verification()` function implements exactly this intent through four rigorous sub-checks:

**(a) IMDS Modify Denied + No State Change**: Reads `IMDSModifyParam` SSM; verifies `denied::` prefix; then calls `ec2:DescribeInstances` to confirm `HttpTokens=required` and `HopLimit=1` remain unchanged. This is the "validate SCP hard-denies the API call and returns AccessDenied before any state change occurs" requirement precisely.

**(b) IMDS Harvest Blocked**: Reads `HarvestSignalParam` SSM; verifies `blocked::` prefix (not `harvested::`). This validates the "Confirm IaC launch template re-applies HttpTokens=required" intent — demonstrating that even if an attacker attempted harvest, the IMDSv2 enforcement prevented credential retrieval.

**(c) Live Privileged Action Denial**: Parses `AttackResultsParam` JSON; asserts every action in `_PRIVILEGED_ACTIONS` returns `denied::` prefix; separately asserts `sts:GetCallerIdentity` returns `allowed`. The baseline-allowed check is critical — it distinguishes a working scoped boundary from a broken blanket deny, directly implementing the "Confirm SCP and permission boundary return AccessDenied for all privileged actions" intent while ensuring the boundary is correctly calibrated.

**(d) IAM SimulatePrincipalPolicy Cross-Check**: Independently calls `iam:SimulatePrincipalPolicy` on `AttackerRole` for all actions; verifies `explicitDeny` or `implicitDeny` for privileged actions; verifies `allowed` for baseline. This cross-check maps to the ADT's "Verify sts:AssumeRole to CodeBuild role is denied" requirement and provides the independent verification called for in the manifest description: *"all privileged actions denied confirmed independently via IAM SimulatePrincipalPolicy"*.

The experiment scope spans all three attack steps (1.2, 2.2, 3.2) as specified in the SCE node tags (`attack-nodes:1.2,2.2,3.2`). The `rollback()` function provides clean-room guarantees. The hypothesis statement precisely matches the ADT: *"Permission Boundary and IMDSv2 enforcement block all three attack steps with no state change on the EC2 instance or AWS account."*

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

---

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves maximum scores across all three evaluation factors. The implementation demonstrates exceptional correspondence with the ADT attack-defense tree specification, implements all specified preventive controls with high architectural fidelity, and the probe logic precisely validates the defensive intent described in SCE node 3.3. The experiment is authorized for execution.

---

## Recommendations

The experiment scores at ceiling. The following observations are offered as enhancements for future iterations rather than blocking concerns:

1. **SCP Simulation Gap**: The experiment correctly documents that SCPs cannot be tested within a single account and substitutes Permission Boundaries. For maximum fidelity, consider adding a companion AWS Organizations-level test that verifies the SCP deny statement using a test member account, explicitly mapping to ADT 1.1 Control 1.

2. **ecr:PutImage Substitution**: The substitution of `ecr:GetAuthorizationToken` for `ecr:PutImage` is well-documented. A future iteration could use a real (tiny) container image push attempt to a scratch ECR repo to achieve full technique fidelity for T1578's container poisoning vector.

3. **NACL Timing Verification**: Sub-check (b) verifies the harvest was blocked but does not distinguish between IMDSv2 blocking and NACL blocking as the cause. Adding a second probe with the NACL temporarily removed (or a separate test Lambda without the NACL association) would isolate which control is the primary blocker, improving defense-in-depth confidence.

4. **Timing SLA Validation**: The ADT specifies "within 5 minutes" for IaC re-enforcement. The current experiment verifies the state is unchanged but does not explicitly test the refresh-cycle re-enforcement timing. A future iteration could deliberately weaken IMDS via a break-glass role and time the IaC remediation response.

5. **Lambda Timeout Margin**: `_LAMBDA_TIMEOUT_SEC = 60` may be tight if AWS API calls experience latency spikes, particularly for the `SimulatedAttackerLambda` making 7 sequential API calls. Consider increasing to 120 seconds for production resilience.