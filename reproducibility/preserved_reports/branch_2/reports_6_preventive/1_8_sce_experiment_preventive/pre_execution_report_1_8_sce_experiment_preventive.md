# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Preventive
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2024-01-20

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: 

The ADT attack node 1.7 specifies:
- **Command**: `aws codebuild start-build`
- **Dependencies**: Malicious project exists
- **Result**: Credential exposure attempt
- **TTP**: T1098.001 Account Manipulation

The experiment's `attack()` function directly implements this by:
1. Assuming an attacker role (simulating a compromised/malicious actor)
2. Calling `cb.start_build()` with `sourceTypeOverride="GITHUB"`, `sourceLocationOverride="https://github.com/malicious-actor/evil-repo.git"`, and a malicious `buildspecOverride` — this is precisely the `aws codebuild start-build` command with a malicious source override
3. The dependency (malicious project exists) is satisfied through the CloudFormation deployment of the CodeBuild project in `steady_state()`
4. The attack targets credential exposure through a malicious buildspec that could be used for credential extraction

The tactic (execution of a malicious build) and technique (StartBuild with source override to inject malicious code) are fully aligned. The implementation quality is high: it properly assumes a separate attacker role, captures detailed results (blocked/allowed, error codes, HTTP status), and even attempts to stop the build if it succeeds to prevent charges. Full correspondence.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 50
**Justification**: 

The ADT defense node 1.6 (Metadata Service Protection) specifies:
- **Classification**: Preventive
- **Strategy**: IMDSv2, restricted metadata access
- **Mechanism**: Session-oriented metadata retrieval

The SCE node 1.8 Preventive Probe asks: "Can build initiation be blocked?"

The experiment implements a **different** preventive control than what's specified in node 1.6. Instead of IMDSv2/metadata service protection, the experiment implements an IAM policy-based preventive control that denies `codebuild:StartBuild` when a source override is detected (via `codebuild:SourceProvider` condition key). This is an IAM-level preventive control, not a metadata service protection mechanism.

However, there is a legitimate argument that the experiment addresses the broader preventive intent of the SCE node 1.8 ("Can build initiation be blocked?"). The experiment does deploy a preventive control that aims to block the malicious build from starting. Furthermore, looking at the overall ADT, node 1.1 is the IAM Least Privilege Control which is conceptually what this experiment tests at the build-start level.

There's also a technical concern with the IAM condition used: `codebuild:SourceProvider` is a condition key, but the way it's used (`StringLike` with `*`) would deny ALL StartBuild calls, not specifically those with source overrides. This means the preventive control might work but for the wrong reason — it would block all builds, not just malicious ones. This reduces the quality of the defense implementation, though it still corresponds to a preventive control against the attack.

The defense corresponds to the ADT in that it is a preventive control against the specific attack node, but it does not match node 1.6's specific IMDSv2 mechanism. Score: 50.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: 

The SCE node 1.8's Preventive Probe asks: **"Can build initiation be blocked?"**

The experiment's `hypothesis_verification()` function directly answers this question by:
1. Checking whether the `StartBuild` API call was denied (via `AccessDeniedException` or similar error codes)
2. Cross-validating by querying CodeBuild to confirm no malicious builds were actually started on the project
3. Returning `True` only if the preventive control successfully blocked the malicious build

The probe logic is well-structured with dual verification:
- **Primary check**: Was the API call blocked? (checks `blocked` flag, error code, HTTP status 403)
- **Secondary check**: Are there any builds with malicious sources in the project? (queries `list_builds_for_project` and `batch_get_builds`)

The steady-state hypothesis in the manifest ("Malicious build start is blocked by preventive IAM policy") directly maps to the defensive intent. The probe fully corresponds to the preventive defensive intent of determining whether build initiation can be blocked.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 50 + 0.30 × 100**

Q_pre = 85.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

---

## Recommendations

While the experiment passes the threshold, the following improvements would strengthen it:

1. **Defense Alignment with ADT Node 1.6**: The preventive control should ideally test IMDSv2 enforcement or metadata service restrictions rather than (or in addition to) IAM-based StartBuild denial. Consider adding an IMDSv2 check within the CodeBuild project configuration (e.g., verifying that the build environment enforces IMDSv2).

2. **IAM Condition Key Accuracy**: The `codebuild:SourceProvider` condition with `StringLike: "*"` will deny ALL StartBuild calls regardless of whether a source override is present. A more precise implementation would use conditions that specifically target source overrides (e.g., checking for `sourceTypeOverride` or `sourceLocationOverride` parameters). This would better demonstrate that the control blocks **malicious** builds while allowing **legitimate** ones.

3. **Positive Control Test**: Add a verification step that confirms a **legitimate** build (without source override) can still be started, proving the control is targeted rather than blanket-denying all builds.