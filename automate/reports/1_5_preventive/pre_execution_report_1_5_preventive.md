# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.5
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The implementation demonstrates **full correspondence** with Attack Node 1.2 at both the tactic and technique levels, with high implementation quality.

**TTP Alignment — T1578 (Modify Cloud Compute Infrastructure):**
- The ADT Attack Node 1.2 specifies: `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`
- The Python implementation in `attack()` calls exactly: `ec2_attacker.modify_instance_metadata_options(InstanceId=_INSTANCE_ID, HttpTokens="optional", HttpEndpoint="enabled", HttpPutResponseHopLimit=2)` — a precise parameter-for-parameter match.

**Dependencies faithfully modelled:**
- The ADT lists "IAM permission ec2:ModifyInstanceMetadataOptions; valid AWS credentials; knowledge of target instance ID; AWS CLI configured in attacker-controlled environment." The experiment provisions an IAM attacker role via CloudFormation, assumes it via `sts:AssumeRole`, and creates a scoped EC2 client with the assumed credentials — all dependencies are accurately instantiated.

**Attack Result fidelity:**
- The ADT states the result is "IMDS reconfigured to accept unauthenticated IMDSv1 requests; hop-limit raised to 2." The implementation explicitly checks for this mutation in H2 of `hypothesis_verification()`, confirming the expected state change was (or was not) blocked.

**Implementation quality:**
- The `attack()` function handles three distinct response paths (AccessDenied at `assume_role` stage, AccessDenied at `modify_imds` stage, and unexpected success), each recorded in `_ATTACK_RESULT` with full diagnostic metadata.
- The use of a dedicated boto3 client scoped to attacker credentials (rather than the deploying principal) correctly isolates the attack surface.
- The `_ATTACK_RESULT` dict differentiates between `stage="assume_role"` and `stage="modify_imds"` AccessDenied events, enabling precise root-cause attribution.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment corresponds fully to Defense Node 1.1 (IAM Least-Privilege + IaC Drift Prevention) and exhibits high-quality code implementing that defense.

**ADT Defense Node 1.1 elements and their implementation:**

| ADT Defense Specification | Implementation |
|---|---|
| "SCP and IAM policy explicitly deny ec2:ModifyInstanceMetadataOptions on all EC2 instances tagged Environment=production" | CloudFormation provisions `SCEAttackerRole` with `Sid: DenyIMDSWeakeningOnProduction` — `Effect: Deny`, `Action: ec2:ModifyInstanceMetadataOptions`, `Condition: StringEquals: ec2:ResourceTag/Environment: production` |
| "Terraform enforces http_tokens=required and hop-limit=1 at deploy time" | `SCETargetInstance` is provisioned with `MetadataOptions: {HttpTokens: required, HttpEndpoint: enabled, HttpPutResponseHopLimit: 1}` |
| "AWS Config Rule ec2-imdsv2-check runs continuously to detect drift" | Verified via `_imdsv2_enforced()` with backoff polling checking `HttpTokens == "required"` and `HopLimit == 1` |
| "CodeBuild IaC pipeline gate blocks any change weakening IMDS config" | Represented by the `_validate_template_strings()` gate and pre-flight `_preflight_check()` blocking misconfigured submissions |

**Defence-in-depth layering correctly modelled:**
- The policy comment explicitly notes "Layer 1 - Implicit deny: no Allow for ec2:ModifyInstanceMetadataOptions" and "Layer 2 - Explicit Deny scoped to Environment=production." This matches the ADT's SCP + IAM dual-layer model.

**Tagging condition precision:**
- The `ec2:ResourceTag/Environment = production` condition key exactly matches the ADT's "tagged Environment=production" specification.

**Implementation quality highlights:**
- `_ascii_safe()` and `_validate_template_strings()` protect against CFN submission failures (documented from run 2).
- `_resolve_ami()` via SSM avoids CFN dynamic substitution (documented from run 1).
- IAM propagation backoff in `steady_state()` (up to 120s) prevents race conditions between role creation and assumption.
- The `_wait_with_backoff()` pattern with configurable `initial_delay`, `max_delay`, and `timeout` provides robust eventual-consistency handling.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The probe fully corresponds to the **Preventive** defensive intent specified in SCE Node 1.5.

**ADT SCE Node 1.5 Preventive Probe specification:**
> "Execute modify-instance-metadata-options with a test IAM role lacking the permission on a canary instance. Expected: AccessDenied returned; IaC drift check fails pipeline gate."

**Implementation correspondence:**

1. **"Test IAM role lacking the permission"** → `SCEAttackerRole` is provisioned with an explicit Deny on `ec2:ModifyInstanceMetadataOptions` scoped to `Environment=production`. The role has only `ec2:DescribeInstances`, `ec2:DescribeInstanceAttribute`, and `sts:GetCallerIdentity` as allowed actions — it lacks any Allow for the attack action.

2. **"AccessDenied returned"** → H1 in `hypothesis_verification()` directly asserts `_ATTACK_RESULT.get("access_denied", False) == True`, checking for error codes `AccessDenied`, `AccessDeniedException`, or `UnauthorizedOperation`.

3. **"IaC drift check fails pipeline gate"** → H2 asserts `http_tokens == "required"` and `hop_limit == 1` after the attack attempt, verifying the IaC-enforced baseline was not mutated.

4. **"Canary instance"** → The CloudFormation stack deploys a dedicated isolated EC2 instance (`SCETargetInstance`) with `Environment=production` tag, functioning as a purpose-built canary that does not touch production infrastructure.

**Steady-State Hypothesis alignment:**
The JSON manifest's SSH title states: "Production EC2 instance has IMDSv2 enforced and attacker role carries explicit Deny on ec2:ModifyInstanceMetadataOptions for Environment=production resources" — this maps precisely to the two verification hypotheses H1 (Deny fires) and H2 (state unchanged).

**Rollback completeness:**
The rollback function tears down the full stack including VPC, EC2 instance, IAM roles, and security groups, ensuring no residual state in the target environment — critical for a safe preventive probe.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves a perfect quality score of 100.00, exceeding the execution threshold of 80 across all three evaluation dimensions. The implementation demonstrates:
- Exact TTP T1578 technique fidelity with parameter-level attack accuracy
- Full defence node correspondence including condition-keyed IAM Deny, IaC baseline enforcement, and drift verification
- Complete preventive probe intent realisation with dual hypothesis verification (access denial + state immutability)

---

## Recommendations

The experiment is approved for execution without modification. The following observations are provided as enhancement opportunities for future iterations:

1. **IAM Condition Key Scope**: The current Deny uses `ec2:ResourceTag/Environment` (resource-based tag condition). Consider also adding `aws:RequestedRegion` as an additional condition to tighten the geographic scope of the Deny, reflecting SCP-level controls more precisely.

2. **Drift Verification Timing**: The H2 check in `hypothesis_verification()` performs a single `describe_instances` call. A brief polling loop (similar to `_wait_with_backoff`) would guard against eventual consistency in the EC2 metadata propagation layer, though this is unlikely to affect results given the synchronous nature of `modify_instance_metadata_options`.

3. **Negative Control Documentation**: Consider adding a third hypothesis H3 that verifies the attack *would succeed* if the `Environment=production` tag were absent, confirming the Deny is tag-scoped and not a blanket block. This would strengthen the precision of the preventive control validation.

4. **CloudTrail Cross-Validation**: Although this is a preventive probe, logging the CloudTrail event for the denied `ModifyInstanceMetadataOptions` call within `hypothesis_verification()` would provide forensic confirmation that the Deny fired at the API layer rather than being blocked by a network or client-side condition.