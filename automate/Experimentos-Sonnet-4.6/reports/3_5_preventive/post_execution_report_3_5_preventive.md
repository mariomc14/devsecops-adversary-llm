# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 3.5
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2, 2.2, 3.2
- **Evaluation Date**: 2026-04-13 12:29:32 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
[ATTACK] Node 1.2 - Obtaining instance role credentials ...
[STS] Assuming instance role to simulate stolen credentials: arn:aws:iam::396608802942:role/sce-inst--prev-1776076085
[STS] Assumed role successfully. AccessKeyId=ASIAVYV52CB7BR6YXOPH  Expiration=2026-04-13 10:44:08+00:00
[ATTACK] 1.2 - Instance role credentials obtained.

[ATTACK] Node 2.2 - Verifying stolen credential identity ...
[ATTACK] 2.2 - Identity confirmed: UserId=AROAVYV52CB7JCLYBSMGE:SCEPreventiveAttackSim  Arn=arn:aws:sts::396608802942:assumed-role/sce-inst--prev-1776076085/SCEPreventiveAttackSim

[ATTACK] Node 3.2 - Attempting blocked lateral-movement actions ...
[ATTACK] 3.2a - iam:CreateUser returned: AccessDenied (expected AccessDenied)
[ATTACK] 3.2b - sts:AssumeRole returned: AccessDenied (expected AccessDenied)
[ATTACK] 3.2c - s3:GetObject returned: AccessDenied (expected AccessDenied)
[ATTACK] 3.2d - cloudtrail:StopLogging returned: AccessDeniedException (expected AccessDenied)
[ATTACK] Results: {'iam_create_user': 'AccessDenied', 'sts_assume_role': 'AccessDenied', 's3_get_object': 'AccessDenied', 'cloudtrail_stop': 'AccessDeniedException'}
```

**Justification**: All three attack nodes executed successfully and produced verifiable, concrete evidence:

- **Node 1.2**: Credential theft was simulated via `sts:AssumeRole` against the instance role (`sce-inst--prev-1776076085`), returning a real AWS temporary credential set with a confirmed `AccessKeyId` (`ASIAVYV52CB7BR6YXOPH`) and expiration timestamp — fully replicating IMDS credential theft.
- **Node 2.2**: The stolen credentials' identity was confirmed via `sts:GetCallerIdentity`, returning a real `UserId` and `Arn` for the assumed role session (`SCEPreventiveAttackSim`), proving the credentials were live and usable.
- **Node 3.2**: Four distinct lateral-movement actions were attempted with the stolen credentials against real AWS resources, each returning concrete API error responses (`AccessDenied` / `AccessDeniedException`). The infrastructure setup (permission boundary policy, PCI S3 bucket with explicit Deny, CloudWatch Log Group, seeded test object) was fully deployed and confirmed prior to attack execution. The entire attack chain is traceable, authenticated, and produces real AWS API response evidence.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
[VERIFY] === Signal A: iam:CreateUser denied ===
[SIG-A] PASS  iam:CreateUser blocked by permission boundary. Error=AccessDenied
[POLL] iam-CreateUser-Denied - condition MET at attempt 1 (0s elapsed).

[VERIFY] === Signal B: sts:AssumeRole to admin role denied ===
[SIG-B] PASS  sts:AssumeRole to admin role blocked. Error=AccessDenied
[POLL] sts-AssumeRole-Denied - condition MET at attempt 1 (0s elapsed).

[VERIFY] === Signal C: s3:GetObject on PCI bucket denied ===
[SIG-C] PASS  s3:GetObject on PCI bucket blocked. Error=AccessDenied
[POLL] s3-GetObject-Denied - condition MET at attempt 1 (0s elapsed).

[VERIFY] === Signal D: cloudtrail:StopLogging denied ===
[SIG-D] PASS  cloudtrail:StopLogging blocked. Audit trail integrity preserved. Error=AccessDeniedException
[POLL] cloudtrail-StopLogging-Denied - condition MET at attempt 1 (0s elapsed).

[VERIFY] === Signal E: Permission boundary durable ===
[SIG-E] PASS  Permission boundary still attached: arn:aws:iam::396608802942:policy/SCEBoundary--prev-1776076085
[POLL] Boundary-Still-Attached - condition MET at attempt 1 (0s elapsed).

[VERIFY] PASS  No IAM user 'sce-test-persistence-user' found. Boundary prevented creation.

[VERIFY] ALL preventive signals confirmed - permission boundary and bucket policy are blocking all lateral-movement actions.
[INFO] Steady state hypothesis is met!
```

**Justification**: The preventive probe validated six distinct, independently verifiable defense signals:

- **Signal A**: `iam:CreateUser` confirmed blocked by the permission boundary (structural prevention of persistence).
- **Signal B**: `sts:AssumeRole` to the high-privilege admin role confirmed blocked (privilege escalation containment).
- **Signal C**: `s3:GetObject` on the PCI-scoped S3 bucket confirmed blocked via explicit bucket policy Deny (data exfiltration prevention), with the test object having been pre-seeded to ensure the action was meaningfully attempted.
- **Signal D**: `cloudtrail:StopLogging` confirmed blocked (audit trail integrity preservation), with the distinct AWS error type (`AccessDeniedException` vs `AccessDenied`) correctly recognized and handled.
- **Signal E**: The permission boundary policy was confirmed still attached to the instance role post-attack via a live IAM API call, validating durability within the 30-minute SLA window.
- **Structural check**: Confirmed no IAM user `sce-test-persistence-user` was created, providing a real-world side-effect verification that the boundary prevention was not just an API error but an actual resource-creation block.

All signals used polling with SLA tracking, returned confirmed pass states at first attempt, and the steady-state hypothesis was formally met. Rollback was clean and complete.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × 100 + 0.50 × 100**

Q_post = 100.00

**Threshold**: 80
**Result**: Q_post >= 80

## DECISION

**VALID EXECUTION**

---

## Recommendations

The experiment achieved a perfect score. The following observations are offered as enhancement opportunities for future iterations rather than deficiencies:

1. **Multi-attempt polling realism**: All five probe signals resolved on the first polling attempt (0s elapsed). While this demonstrates immediate enforcement, consider introducing a deliberate delay between attack completion and probe evaluation to stress-test detection/enforcement latency under more adversarial timing conditions.
2. **CloudTrail event correlation**: Augment the probe with a Signal F that queries CloudTrail for the corresponding `AccessDenied` event records, providing an end-to-end logging validation alongside the API-response validation.
3. **Permission boundary removal simulation**: Consider adding an optional adversarial step that attempts to detach the permission boundary itself (via `iam:DeleteRolePermissionsBoundary`) to verify that the boundary is also protected against modification by the compromised credential.
4. **Cross-region blast radius**: The experiment is scoped to `us-east-1`; extending `cloudtrail:StopLogging` attempts to additional regions would validate global audit-trail protection.