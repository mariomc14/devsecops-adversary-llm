# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2026-04-04 21:08:57 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100
**Log Excerpts**:
```
2026-04-04T21:08:38Z  INFO      === attack() ===
2026-04-04T21:08:38Z  INFO      Assuming AttackRole: arn:aws:iam::941377112071:role/sce-attack-role-1775354870
2026-04-04T21:08:39Z  INFO      Successfully assumed AttackRole (session expires: 2026-04-05 02:23:39+00:00)
2026-04-04T21:08:39Z  INFO      Attack BLOCKED by preventive control — AccessDeniedException (HTTP 400, RequestId: e8067f4f-25af-4687-b3f8-8e2b90890e59)
```
**Justification**: The action provides full verifiable evidence of execution. The attack sequence was carried out end-to-end: the IAM attack role (`sce-attack-role-1775354870`) was successfully assumed, and the attempt to create a malicious CodeBuild project (`sce-malicious-cb-1775354870`) was made with concrete, traceable evidence — an `AccessDeniedException` with an HTTP 400 status code and a specific AWS `RequestId` (`e8067f4f-25af-4687-b3f8-8e2b90890e59`). This confirms the attack action was genuinely executed against the AWS control plane and not simulated or skipped.

---

## Factor 2: PROBE Capability
**Score**: 100
**Log Excerpts**:
```
2026-04-04T21:08:39Z  INFO      === hypothesis_verification() ===
2026-04-04T21:08:40Z  INFO      batch_get_projects result — found: [], notFound: ['sce-malicious-cb-1775354870']
2026-04-04T21:08:40Z  INFO      Deny policy 'sce-deny-cb-create-1775354870' attached to attack role: True
2026-04-04T21:08:40Z  INFO      HYPOTHESIS VERIFIED: malicious CodeBuild project 'sce-malicious-cb-1775354870' was NOT created (preventive deny policy is active and effective).
[2026-04-04 21:08:40 INFO] Steady state hypothesis is met!
```
**Justification**: The preventive probe returned fully verifiable evidence of defense behavior across two independent verification dimensions:
1. **Resource non-existence check**: A `batch_get_projects` API call confirmed the malicious CodeBuild project was not found (`notFound: ['sce-malicious-cb-1775354870']`), proving no project was created despite the attack attempt.
2. **Policy attachment verification**: The deny policy (`sce-deny-cb-create-1775354870`) was confirmed as actively attached to the attack role (`True`), directly corroborating the mechanism responsible for blocking the attack.

Both checks together constitute robust, multi-layered evidence that the preventive defense control is active and effective, satisfying the steady-state hypothesis.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × 100 + 0.50 × 100**

Q_post = 100.00

**Threshold**: 100
**Result**: Q_post >= 100

## DECISION

**VALID EXECUTION**

---

## Recommendations

The experiment achieved a perfect score and no corrective actions are required. However, the following enhancements could further strengthen future runs:

1. **CloudTrail correlation**: Capture and log the CloudTrail event corresponding to the `AccessDeniedException` `RequestId` (`e8067f4f-25af-4687-b3f8-8e2b90890e59`) to provide an immutable, independently auditable record of the blocked action.
2. **Negative control baseline**: Consider adding a pre-experiment probe confirming the deny policy does *not* exist before deployment, to make the before/after contrast explicit and rule out pre-existing controls.
3. **Timing metrics**: Record and report the elapsed time between attack attempt and block confirmation to benchmark detection/prevention latency.
4. **Rollback verification note**: The rollback log mentions deleting a CodeBuild project (`Deleted CodeBuild project 'sce-malicious-cb-1775354870' during rollback`), which is slightly inconsistent with the probe confirming it was never created — clarifying this behavior (e.g., idempotent delete call on a non-existent resource) in the experiment documentation would improve auditability.