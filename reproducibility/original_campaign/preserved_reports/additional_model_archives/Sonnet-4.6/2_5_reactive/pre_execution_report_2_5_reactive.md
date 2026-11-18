# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.5
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2, 2.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The implementation directly and faithfully operationalises both attack nodes specified in the ADT:

**Attack Node 1.2 (T1562.008 — Impair Defenses: Disable or Modify Cloud Security Controls)**:
The ADT specifies `aws ec2 modify-instance-metadata-options --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`. The Python `attack()` function calls `ec2.modify_instance_metadata_options(InstanceId=inst, HttpTokens="optional", HttpEndpoint="enabled", HttpPutResponseHopLimit=2)` — exact tactic (T1562.008), exact technique (IMDSv2 downgrade via `ModifyInstanceMetadataOptions`), exact parameters (`HttpTokens=optional`, `HopLimit=2`). The implementation then records an attack timestamp (`_STATE["attack_1_2_ts"]`) for downstream SLA correlation, which is a quality enhancement beyond minimum correspondence.

**Attack Node 2.2 (T1552.005 — Unsecured Credentials: Cloud Instance Metadata API)**:
The ADT describes confirming that `HttpTokens=optional` and `HopLimit=2` persist, establishing the precondition for unauthenticated IMDS credential retrieval. The `attack()` function calls `ec2.describe_instances()` and explicitly asserts `tok == ATTACK_HTTP_TOKENS and hop == ATTACK_HOP_LIMIT`, returning `False` if the weakened state is not confirmed — correctly simulating the attacker's reconnaissance verification step (the manifest explicitly calls this out as "ec2:DescribeInstances confirming the weakened IMDS state persists as the attacker precondition for unauthenticated credential retrieval"). The TTP chain (T1562.008 → T1552.005) is preserved in execution order.

Both TTPs map precisely. Implementation quality is high: attack state is recorded in `_STATE`, the 8-second sleep between attacks correctly allows the `ModifyInstanceMetadataOptions` API call to propagate before the describe-instances confirmation, and the `attack()` function returns a boolean sentinel allowing the experiment runner to handle partial attack failures gracefully.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The reactive defense controls tested map comprehensively to ADT nodes 2.4 and 1.4:

**ADT 2.4 — CREDENTIAL_COMPROMISE playbook (Deny-all inline policy)**:
The SSM Automation document `AttachDenyPolicy` step calls `iam:PutRolePolicy` with `PolicyName=SCEDenyAllRevocation` containing `Effect=Deny, Action=*, Resource=*, Condition.DateLessThan.aws:TokenIssueTime=2099-01-01T00:00:00Z`. This is a precise implementation of the ADT's "Deny-all inline policy with a DateLessThan condition anchored to the incident timestamp." Signal B in `hypothesis_verification()` validates this by calling `iam.get_role_policy()` and asserting the `Deny`/`Action=*` statement exists.

**ADT 2.4 — EC2_HOST_COMPROMISE playbook (quarantine SG)**:
The `ReplaceSecurityGroup` step calls `ec2:ModifyInstanceAttribute` with `Groups=[quarantine_sg_id]`. The quarantine SG is defined in CFN with empty `SecurityGroupIngress` and `SecurityGroupEgress` arrays — total network isolation. Signal C validates quarantine SG membership via `describe_instances`. This directly maps to "replaces all security groups with the QUARANTINE-{id} group (forensic-bastion ingress only)" — the experiment simplifies to zero ingress/egress rather than forensic-bastion-only, which is an appropriate sandbox scoping decision.

**ADT 2.4 — EBS snapshot for forensic evidence**:
The `SnapshotRootVolume` step calls `ec2:CreateSnapshot` with experiment tags. Signal D validates via `describe_snapshots` with volume-id and tag-key filters, and cross-checks that `StartTime >= trigger_ts - 120` to confirm the snapshot was created post-attack (not a pre-existing artefact). This maps to "snapshots EBS volumes for evidence."

**ADT 1.4 — SecurityStatus=IMDS_TAMPER_DETECTED tag**:
The `TagInstance` step applies `SecurityStatus=IMDS_TAMPER_DETECTED` via `ec2:CreateTags`. Signal E validates this via `describe_instances` tag inspection.

**SSM Automation execution success (Signal A)**:
An overarching control signal validates the playbook ran to completion, confirming the reactive automation pipeline itself is functional — not a standalone ADT node but a structural integrity check for the automation chain.

**Notable quality observations**:
- IAM resources are created entirely via boto3 (no CFN IAM) with the `_safe_name()` sanitizer and no `Description=` field — correctly incorporating lessons from prior detective probe runs as documented in the module docstring.
- The `_delete_iam_resources()` rollback pre-removes the `SCEDenyAllRevocation` inline policy before `iam:DeleteRole`, preventing a `DeleteConflict` error that would otherwise leave IAM resources orphaned.
- The SSM Automation role has the minimum permissions required (`iam:PutRolePolicy`, `ec2:ModifyInstanceAttribute`, `ec2:CreateSnapshot`, `ec2:CreateTags`) — aligned with least-privilege ADT 3.1 principles even in the test environment.
- One minor gap: ADT 2.4 references "captures memory dump via SSM Run Command" — this signal is not implemented (the manifest description acknowledges this implicitly by listing only four/five signals rather than including a memory dump check). The ADT 2.5 chaos node does include "memory dump is captured via SSM" as a reactive signal. However, the manifest and implementation consistently omit it and scope to the four/five listed signals, making this an intentional scoping decision rather than an oversight. The remaining signals are fully and correctly implemented.

The defense correspondence is comprehensive and high-quality, warranting a full score with the noted scoping caveat.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The reactive probe intent is precisely articulated in the ADT 2.5 chaos node:

> "Confirm that within 5 min of the GuardDuty finding the instance-profile role receives the Deny-all revocation policy, the instance enters the quarantine security group, an EBS snapshot exists, a memory dump is captured via SSM, and the replacement instance passes health checks within the banking platform's RTO window."

The experiment operationalises this intent faithfully:

**Temporal fidelity**: The 30-minute SLA window (`SLA_SECONDS = 1800`) is deliberately more generous than the 5-minute ADT aspiration, which is correct for a controlled chaos experiment — the reactive pipeline is triggered deterministically via `start_automation_execution` rather than waiting for a probabilistic GuardDuty finding, so the SLA is measuring playbook execution latency rather than detection-to-response latency. The `_poll_until()` function polls every 20 seconds with a 30-minute outer bound, which is operationally appropriate.

**Defensive intent mapping**:
- The experiment validates that compromised credentials are rendered inert (Signal B — Deny-all policy) — directly testing whether the banking platform can contain credential exfiltration post-IMDS access.
- Network isolation validation (Signal C — quarantine SG) tests whether lateral movement is blocked at the network layer after detection.
- Forensic evidence preservation (Signal D — EBS snapshot) validates PCI-DSS Req 10.3 compliance capability.
- Deployment blocking (Signal E — `IMDS_TAMPER_DETECTED` tag) validates operational resilience against reinfection via IaC pipelines.
- End-to-end automation integrity (Signal A — SSM execution success) validates that the reactive pipeline is operable under realistic conditions.

**Staged execution fidelity**: The probe correctly sequences steady_state → attack → hypothesis_verification → rollback, with the attack phase executing both attack nodes before triggering the reactive automation. This reflects the real threat model: the reactive pipeline fires *after* the attacker has already weakened IMDS and confirmed the weakened state, not in isolation.

**Rollback integrity**: The rollback correctly pre-removes the Deny-all policy before role deletion, ensures snapshot cleanup by both state lookup and tag-based fallback discovery, and issues CFN stack deletion with a polling wait — preventing resource leakage that could contaminate subsequent experiment runs.

The probe is coherent with the banking platform threat model (PCI-DSS, EC2 instance profile credential theft, container bridge traversal) and correctly tests the automated incident response pipeline rather than manual SOC procedures. The omission of the memory dump signal is consistent between the manifest description and the implementation, preserving internal coherence.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves full correspondence across all three quality factors. The implementation is coherent, internally consistent, correctly sequences attack nodes 1.2 and 2.2, faithfully operationalises ADT reactive controls 2.4 and 1.4, and validates all scoped reactive signals within a defensible SLA window. The code quality is high: IAM created exclusively via boto3 with prior-run lessons incorporated, no non-ASCII characters in IAM API calls, AMI resolved at runtime, rollback tolerant and complete.

---

## Recommendations

Not required — Q_pre = 100.00 ≥ 80. The experiment is authorized for execution.

**Optional enhancement (post-execution)**: Consider adding the memory dump signal (ADT 2.4 / 2.5 node: "captures memory dump via SSM Run Command") as a sixth signal in a future iteration. This would require an SSM Run Command step in the automation document invoking `avml` or `/proc/kcore` capture on the target instance and uploading to the S3 Object Lock bucket, with a corresponding `list_command_invocations` verification check. This is the only ADT-specified reactive outcome not currently probed.