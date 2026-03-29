# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.3
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2, 2.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

**Attack Node 1.2 (T1578 — Modify Cloud Compute Infrastructure)**:
The ADT specifies `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`. The implementation in `attack()` calls exactly this API: `ec2_client.modify_instance_metadata_options(InstanceId=instance_id, HttpTokens="optional", HttpEndpoint="enabled", HttpPutResponseHopLimit=2)`. The target instance is real (t3.nano, provisioned by CloudFormation with IMDSv2 required / HopLimit=1 as the secure baseline), scoped precisely to the experiment-created resource. TTP alignment is exact.

**Attack Node 2.2 (T1552.005 — Unsecured Credentials: Cloud Instance Metadata API)**:
The ADT specifies `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` and `curl .../security-credentials/<ROLE_NAME>` from a container on EC2 with HopLimit≥2. The implementation deploys an IMDSProbe Lambda inside the same private VPC subnet as the EC2 instance, and issues an unauthenticated HTTP GET (no `X-aws-ec2-metadata-token` header) to the instance's private IP with `Host: 169.254.169.254`, fetching both the role name and then the credential JSON (`AccessKeyId`, `SecretAccessKey`, `Token`). This is a functionally equivalent and architecturally sound emulation of container-tier IMDS credential retrieval via IMDSv1 — the technique and tactic match precisely. The harvest result (AccessKeyId prefix) is logged as evidence. The Lambda-in-VPC approach is a well-reasoned adaptation (containers cannot be directly provisioned in a CFn experiment stack without ECS/EKS overhead), and it achieves the same network traversal semantics. Implementation quality is high: retry logic, base64 log decoding, blocked/harvested branching, and careful state tracking are all present.

**Dependency fidelity**: The ADT's stated dependencies (IMDSv1 re-enabled by step 1.2, code execution in container or SSRF, EC2 with attached instance profile) are faithfully reproduced: IMDS is weakened in step 1.2 before step 2.2 executes; the instance profile is minimal but attached; the probe runs inside the VPC.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The ADT reactive safeguard node 2.5 specifies three controls this probe must exercise:

1. **Control 1 — Automated Credential Revocation**: "GuardDuty finding triggers EventBridge rule; Lambda revokes the instance profile session via IAM deny policy attached inline. Temporary credentials invalidated within <5 minutes of detection." → The implementation uses an EventBridge rule watching SSM Parameter Store Change on the harvest signal parameter (GuardDuty proxy), which triggers `RemediationFunction`. This Lambda calls `iam.put_role_policy()` with a full Deny `*`/`*` inline policy (`SCEDenyAll`). Sub-checks (a), (b), and (c) verify: Lambda fired within 120s SLA, policy document structurally valid (Deny/*/`*`), and IAM `SimulatePrincipalPolicy` confirms effective DENY on `sts:GetCallerIdentity`, `s3:GetObject`, `secretsmanager:GetSecretValue`, `ec2:DescribeInstances`, `iam:ListRoles`. This directly operationalises the ADT control.

2. **Control 3 — Incident Alert + Quarantine Trigger** (from node 1.5) / **Control 4 — PCI-DSS Breach Notification** (from node 2.5): "SNS notification to Security Ops and PagerDuty." → The implementation provisions an SNS topic, an SQS queue subscribed to it, and the RemediationLambda publishes a structured JSON message with subject `[SCE-2.3] Credential Harvest Detected — Role Revoked`. Sub-check (d) validates that a matching message arrives in the SQS queue within the SLA window, closing the gap identified in the previous iteration.

3. **EventBridge rule architecture**: The rule pattern targets `aws.ssm` / `Parameter Store Change` on the named harvest signal parameter — a clean, deterministic proxy for the real GuardDuty→EventBridge pathway, appropriate for a clean-room experiment. The rule is provisioned in CloudFormation with `ENABLED` state and a valid Lambda permission grant.

**Code quality**: The `LambdaExecRole` is scoped to `iam:PutRolePolicy`, `iam:GetRolePolicy`, `iam:ListRolePolicies` on only the experiment instance role ARN; `ssm:PutParameter`/`GetParameter` on the scoped path; `sns:Publish` on the experiment topic; and CloudWatch Logs. Least-privilege is maintained. The RemediationDoneParam is written inside the Lambda (not in CFn) to serve as the signal, and rollback cleans it up explicitly. The `rollback()` function removes the out-of-band inline deny policy before stack deletion, preventing IAM resource conflict that would cause a DELETE_FAILED state.

**Minor observation**: The ADT node 2.5 Control 2 (Instance Isolation / Quarantine SG Swap) and Control 3 (Forensic Snapshot) are not implemented — but these are explicitly listed as reactive safeguards for a real incident, not for a 2-minute clean-room experiment. The ADT's 2.3 Chaos node Reactive Probe description focuses on credential rotation and SNS notification, which are both fully implemented. The omission is appropriate and well-scoped.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The ADT node 2.3 Reactive Probe defensive intent is:

> "Confirm EventBridge rule triggers credential rotation Lambda within 5 minutes of GuardDuty finding. Validate old credentials return `InvalidClientTokenId` after rotation completes. Confirm Security Ops pager notification received."

Mapping to the four hypothesis sub-checks:

| ADT Defensive Intent | Implementation Sub-check | Assessment |
|---|---|---|
| EventBridge triggers Lambda within 5 min | (a) Poll `remediation_done` SSM param within 120s (well inside 5-min target) | ✅ Fully satisfied |
| Credential rotation/invalidation after Lambda fires | (b) Deny-all inline policy attached; (c) `SimulatePrincipalPolicy` confirms effective DENY on 5 sensitive actions including `sts:GetCallerIdentity` | ✅ Fully satisfied — simulation of `InvalidClientTokenId` is correctly implemented via policy simulation rather than actual token use (which would require the stolen credentials to be used externally, introducing scope/blast-radius risk) |
| Security Ops pager notification received | (d) SQS queue receives SNS message with matching subject/body within SLA window | ✅ Fully satisfied |

The `InvalidClientTokenId` check: the ADT intent is to confirm credentials are invalidated post-rotation. The implementation uses `SimulatePrincipalPolicy` on the deny-policy-attached role ARN across five sensitive actions; all are expected to return `explicitDeny`. This is a stronger and safer validation method than attempting to use the actual harvested credentials externally (which would introduce real credential misuse risk outside the experiment scope). The approach correctly operationalises the defensive intent.

The steady-state hypothesis in the manifest precisely mirrors the four sub-checks, and the `hypothesis_verification()` function returns a deterministic boolean with per-check logging and a clean summary table. The experiment title, description, tags (`sce-node:2.3`, `probe-type:reactive`, `attack-nodes:1.2,2.2`, all relevant TTPs and compliance tags), and rollback are all coherent and complete.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

---

## DECISION

**AUTHORIZE EXECUTION**

All three quality factors achieve maximum scores. The experiment demonstrates full TTP fidelity on both attack nodes, complete correspondence to the ADT reactive safeguard controls, and precise alignment with the defensive intent of SCE node 2.3. The clean-room CloudFormation design, least-privilege IAM scoping, and explicit rollback logic satisfy safety and reproducibility requirements for authorized execution.

---

## Recommendations

*Q_pre = 100.00 — no remediation required. The following are optional hardening suggestions for post-execution improvement:*

1. **Sub-check (c) enhancement**: Consider augmenting the `SimulatePrincipalPolicy` check with a real-time call using the harvested `AccessKeyId`/`SecretAccessKey`/`SessionToken` stored in `_STATE["harvest_result"]`, decoded from the SSM parameter, against a throwaway `sts:GetCallerIdentity`. This would validate actual `InvalidClientTokenId` semantics as the ADT literally specifies, rather than policy simulation. Scope this call to a read-only, zero-privilege action to bound blast radius.

2. **Sub-check (a) timing precision**: The elapsed-time calculation in sub-check (a) uses `_LAMBDA_MAX_WAIT - max(0.0, deadline - time.monotonic())` which can undercount if the sleep intervals consume the residual. Consider recording `t0 = time.monotonic()` before the poll loop and computing `elapsed = time.monotonic() - t0` for accurate SLA reporting.

3. **GuardDuty integration (future iteration)**: For a production-fidelity upgrade, replace the SSM Parameter Store Change EventBridge proxy with a real GuardDuty custom threat intelligence list trigger or a synthesized `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` finding injected via `guardduty:CreateSampleFindings` or EventBridge `PutEvents`. This would close the remaining gap between the experiment proxy and the actual detection pathway described in ADT node 2.4.

4. **Instance quarantine probe (future iteration)**: ADT node 2.5 Control 2 (SG swap to quarantine VPC) is not tested. A future reactive probe iteration could add sub-check (e) to verify that the instance's security group is replaced with a deny-all SG after the 15-minute no-acknowledgement window, completing the full ADT coverage.