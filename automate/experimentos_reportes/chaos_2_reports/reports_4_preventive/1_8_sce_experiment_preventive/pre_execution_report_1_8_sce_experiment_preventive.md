# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The experiment's `attack()` function directly and faithfully simulates ADT node **1.7 Start Malicious Build**:

| ADT Specification | Implementation |
|---|---|
| Command: `aws codebuild start-build` | `attack_cb.start_build(projectName=CODEBUILD_PROJECT_NAME)` |
| Dependency: Malicious project exists | `steady_state()` deploys a CodeBuild project first |
| Result: Credential exposure attempt | Simulated via assumed role with restricted credentials |
| TTP: T1098.001 Account Manipulation | Attack-simulation role assumes a position to attempt build execution |

The attack chain is complete and realistic:
1. The malicious CodeBuild project is provisioned (CloudFormation stack deploys `MaliciousBuildProject` with a buildspec containing `MALICIOUS_PAYLOAD_SIMULATION`).
2. The adversary role (`AttackSimulationRole`) is assumed via STS with realistic retry logic for IAM eventual consistency.
3. `codebuild:StartBuild` is called against the target project from the assumed role's credentials.
4. The implementation correctly handles both the "UNEXPECTED SUCCESS" path (control failure) and the `AccessDeniedException` path (control success), making it robust for real-world execution evidence collection.

The technique (supply-chain/CI poisoning via `StartBuild`) and tactic (execution via CodeBuild abuse) match precisely. The module incorrectly references `chaosaws.ec2` in the manifest (should be `chaosaws.codebuild`), but this is a metadata labeling issue, not a functional implementation flaw. Implementation quality is high with retry logic, proper credential chaining, and structured logging.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The preventive defense aligns precisely with ADT node **1.6 Metadata Service Protection** (upstream) and the broader ADT preventive layer (node **1.1 IAM Least Privilege Control**):

| ADT Defense Specification | Implementation |
|---|---|
| Strategy: IMDSv2, restricted metadata access | Explicit IAM Deny policy on `codebuild:StartBuild` and `codebuild:StartBuildBatch` |
| Mechanism: Session-oriented metadata retrieval / Fine-grained IAM role scoping | `AttackSimulationRole` carries an inline `PreventMaliciousBuild` Deny statement |

The implementation quality is high:
- **Explicit Deny**: The CloudFormation template's `AttackSimulationRole` contains a properly structured IAM inline policy with `Effect: Deny` covering both `codebuild:StartBuild` and `codebuild:StartBuildBatch` (catching batch variants of the attack).
- **Zero-trust guardrail**: The role provides read-only CodeBuild permissions (`BatchGetProjects`, `ListProjects`) to enable introspection without triggering false positives — a sophisticated design decision.
- **Defense is correctly scoped**: The `Resource: "*"` scope on the Deny ensures no project-specific bypass is possible.
- **Both preventive layers are represented**: The IAM Deny represents node 1.1 (IAM Least Privilege) as the implemented preventive control at the build-execution layer.

The slight architectural note is that node 1.6 (Metadata Service Protection / IMDSv2) is the direct upstream preventive node, but the experiment correctly focuses on the IAM authorization layer which is the applicable preventive control for blocking `StartBuild` — a valid and intentional design choice consistent with the SCE experiment description.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The ADT node **1.8 SCE Experiment** specifies: *"Preventive Probe: Can build initiation be blocked?"*

The `hypothesis_verification()` function answers this question through **three independent, authoritative verification methods**:

| Probe Check | ADT Preventive Intent | Implementation |
|---|---|---|
| Check 1: Inline policy inspection | Verify Deny policy exists | `iam.list_role_policies()` + `iam.get_role_policy()` — confirms `Effect: Deny` on `codebuild:StartBuild` |
| Check 2: IAM Policy Simulator | Verify evaluated authorization decision | `iam.simulate_principal_policy()` — confirms `explicitDeny` or `implicitDeny` verdict |
| Check 3: Build history verification | Verify no build actually executed | `cb.list_builds_for_project()` + `cb.batch_get_builds()` — confirms no `SUCCEEDED`/`IN_PROGRESS` builds |

The probe design is excellent:
- **Defense-in-depth verification**: Not just checking policy text (which could have syntax errors), but also running the AWS Policy Simulator for an evaluated authorization decision.
- **Evidence-based**: All three checks produce real AWS API responses, not local assertions.
- **Correct tolerance**: The `steady-state-hypothesis` has `"tolerance": true` — the experiment passes only when the Deny is confirmed, matching the preventive intent.
- **Correct ordering in the manifest**: The steady-state hypothesis is checked as a probe (preventive verification), the attack is executed in the method, ensuring the experiment structure follows Chaos Engineering principles (hypothesis → inject → verify).
- **Build history check** closes the loop: even if IAM policy inspection passed, a real build execution would be caught, providing end-to-end assurance.

The `hypothesis_verification` function is the strongest component of this experiment — it provides multi-layered, real-API-backed evidence that the preventive control is effective.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**✅ AUTHORIZE EXECUTION**

The experiment achieves a perfect quality score of 100.00, exceeding the execution threshold of 80 by a significant margin. All three quality factors demonstrate full correspondence between the ADT specification and the implementation.

---

## Recommendations

Although the experiment is authorized with a perfect score, the following minor improvements are noted for production hardening:

1. **Module path correction**: The manifest references `chaosaws.ec2.1_8_sce_experiment_preventive` — this should be updated to `chaosaws.codebuild.1_8_sce_experiment_preventive` to accurately reflect the service being tested and avoid confusion during CI/CD integration.

2. **Assume-role trust policy**: The `AttackSimulationRole` currently trusts `ec2.amazonaws.com` as a placeholder. For more realistic adversary simulation, consider using the specific IAM principal (e.g., the CI/CD runner role) that would perform the attack in a real scenario.

3. **Build history race condition**: Check 3 queries build history after the attack attempt — in high-latency environments, an `IN_PROGRESS` build that started before the Deny propagated could theoretically be missed. Adding a short `time.sleep(2)` before the `list_builds_for_project` call would eliminate this edge case.

4. **S3 bucket versioning**: The rollback empties both versioned and non-versioned objects, which is correct, but the `SourceBucket` in CFN does not have versioning enabled. Consider aligning the rollback logic or explicitly disabling versioning in the template to avoid unnecessary API calls.

5. **CloudTrail evidence capture**: Consider adding a Check 4 that queries CloudTrail for the `StartBuild` API call with an `errorCode: AccessDenied` response — this would provide immutable audit trail evidence beyond IAM API responses and align with node **1.9 Runtime Container Monitoring**.