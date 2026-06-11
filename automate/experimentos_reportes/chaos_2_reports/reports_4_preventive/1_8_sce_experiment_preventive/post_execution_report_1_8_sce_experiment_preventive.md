# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2026-04-11 21:47:11 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-11 21:46:52,481 [INFO] sce.1_8.preventive — Calling codebuild:StartBuild on project: sce-18-malicious-1775961979
2026-04-11 21:46:52,991 [INFO] sce.1_8.preventive — StartBuild returned AccessDeniedException (HTTP 400) — RequestId: 796ee94e-c5b0-4a09-98e4-88ebc913c720
```

**Justification**:
The attack action was fully and verifiably executed. The experiment:
1. Successfully deployed the malicious CodeBuild infrastructure stack (`sce-experiment-1775961979`) with `CREATE_COMPLETE` status.
2. Successfully assumed the restricted attack role (`arn:aws:sts::941377112071:assumed-role/sce-18-attack-1775961979/sce18-attack-session`).
3. Explicitly called `codebuild:StartBuild` on the target project `sce-18-malicious-1775961979` using the assumed attack role.
4. Received a concrete, traceable AWS API response — `AccessDeniedException (HTTP 400)` with a unique `RequestId: 796ee94e-c5b0-4a09-98e4-88ebc913c720` — confirming the call was made and rejected at the IAM layer.

The action produced verifiable, real evidence of an attack execution attempt against a live AWS environment. The `RequestId` from AWS constitutes an immutable audit trail record.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-11 21:46:53,715 [INFO] sce.1_8.preventive — Inline policies found: ['deny-startbuild']
2026-04-11 21:46:53,828 [INFO] sce.1_8.preventive — ✓ Explicit Deny on codebuild:StartBuild found in policy 'deny-startbuild'
2026-04-11 21:46:54,128 [INFO] sce.1_8.preventive — IAM simulator decision for codebuild:StartBuild: explicitDeny
2026-04-11 21:46:54,128 [INFO] sce.1_8.preventive — ✓ Simulator confirms Deny for codebuild:StartBuild.
2026-04-11 21:46:54,570 [INFO] sce.1_8.preventive — Build IDs on project: []
2026-04-11 21:46:54,570 [INFO] sce.1_8.preventive — ✓ No builds found — StartBuild was never executed.
2026-04-11 21:46:54,570 [INFO] sce.1_8.preventive — === hypothesis_verification() → ALL checks PASSED → True ===
```

**Justification**:
The preventive probe returned verifiable, multi-layered evidence of defense behavior through three independent checks:

1. **Check 1 — IAM Policy Inspection**: Confirmed the existence of inline policy `deny-startbuild` on the attack role, with a verified `Explicit Deny` statement targeting `codebuild:StartBuild`. This is structural defense evidence.

2. **Check 2 — IAM Policy Simulator**: The AWS IAM Policy Simulator independently returned `explicitDeny` for `codebuild:StartBuild`, corroborating the structural inspection with a behavioral simulation result. This is functional defense evidence.

3. **Check 3 — Build Execution Audit**: Querying the CodeBuild project `sce-18-malicious-1775961979` confirmed zero build IDs, meaning no build was ever initiated. This is outcome-level defense evidence confirming the control's real-world effectiveness.

All three checks collectively and independently confirm that the preventive control (IAM Explicit Deny) successfully blocked the attack node 1.7 (Start Malicious Build). The steady-state hypothesis was fully validated.

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

The experiment executed flawlessly and achieved the maximum score. The following observations are provided as enhancement suggestions for future iterations:

1. **CloudTrail Integration**: Consider adding a fourth hypothesis check that queries AWS CloudTrail for the `StartBuild` API call event matching the `RequestId: 796ee94e-c5b0-4a09-98e4-88ebc913c720`. This would create a complete, forensic-grade audit trail linkage between the attack attempt and the IAM deny record.

2. **SCPs as Additional Layer**: If this experiment is intended to test defense-in-depth, consider extending it to verify that an AWS Organizations Service Control Policy (SCP) also independently blocks `codebuild:StartBuild`, validating multi-layer preventive controls.

3. **Negative Test Coverage**: A complementary experiment could verify that a *legitimately authorized* role *can* start builds on approved projects, ensuring the deny policy is correctly scoped and does not cause over-blocking (false positives in the security control).

4. **Timing Metrics**: Capture and report the latency between the `StartBuild` call and the `AccessDeniedException` response to characterize the control's enforcement speed, which is relevant for real-time attack scenarios.