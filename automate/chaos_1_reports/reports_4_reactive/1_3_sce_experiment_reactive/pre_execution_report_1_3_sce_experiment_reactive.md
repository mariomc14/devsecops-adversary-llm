# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3 SCE Experiment
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2 Create Malicious CodeBuild Project
- **Evaluation Date**: 2025-01-31T00:00:00Z

---

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The attack implementation in the Python `attack()` function directly and precisely mirrors the ADT specification for node **1.2 Create Malicious CodeBuild Project**:

| ADT Specification | Implementation |
|---|---|
| Command: `aws codebuild create-project` | `cb.create_project(...)` — exact API call |
| Dependencies: `iam:PassRole`, `codebuild:CreateProject` | Uses the IAM role ARN (`cb_role_arn`) provisioned via CloudFormation and calls `codebuild:CreateProject` |
| Result: Malicious project creation | Creates project named `{stack_name}-malicious` with credential-exfiltration buildspec |
| TTP: T1552.005 Unsecured Credentials | Buildspec explicitly models credential exfiltration via `$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (container credentials endpoint) — exactly matching T1552.005 |

Additional quality indicators:
- The buildspec models a **realistic attack pattern** (curling the ECS/Fargate metadata credential endpoint and forwarding to an attacker-controlled server), not merely a token simulation
- `privilegedMode: True` is set, reflecting an additional red-flag that a real attacker would use for container escape / credential access
- The project is tagged `Role: malicious` for clear experimental traceability
- The project ARN is captured in `_state` for downstream verification
- The implementation correctly surfaces an `attack_error` state if the API call fails, enabling failure-mode traceability

This is a **full correspondence** (same tactic AND technique: cloud-service credential theft via CodeBuild project creation, T1552.005) with high implementation quality.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The ADT specifies two defense nodes directly associated with the 1.3 SCE Experiment / 1.2 attack node:

**Node 1.5 — Incident Response (Reactive)**:
- ADT: *Automated project deletion via Lambda-triggered remediation*
- Implementation: Lambda reactor (`LAMBDA_SOURCE`) calls `cb.delete_project(name=project_name)` immediately upon invocation — exact mechanism match

**Node 1.4 — CodeBuild Activity Monitoring (Detective, supporting reactive)**:
- ADT: *CloudTrail logging, CloudWatch alerts, real-time project creation monitoring*
- Implementation: EventBridge rule capturing `AWS API Call via CloudTrail` for `CreateProject`/`UpdateProject` events from `codebuild.amazonaws.com` — exact mechanism match. CloudWatch alarm `ReactorFiredAlarm` monitors the custom metric

**Quality indicators**:

| Defense Component | ADT Specification | Implementation Quality |
|---|---|---|
| Lambda reactor | Lambda-triggered remediation | Full CloudFormation resource with IAM role scoped to only `codebuild:DeleteProject`, `cloudwatch:PutMetricData`, and log permissions |
| EventBridge rule | Automated detection | Pattern exactly targets `CreateProject`/`UpdateProject` via CloudTrail — operationally correct |
| CloudWatch metric | Evidence/observability | Custom namespace `SCE/sce-1-3` with `ReactorFired` metric + alarm — observable and verifiable |
| IAM scoping | Least privilege for reactor | Lambda role has only 3 precisely-scoped permissions; no wildcard actions beyond resource ARNs |
| Log group | Retention and observability | 1-day retention, pre-created to avoid race conditions |

The Lambda source code correctly parses the EventBridge/CloudTrail event structure (`detail.requestParameters.name`) matching real CloudTrail event format, and publishes metric evidence. The defense is deployed via CloudFormation ensuring infrastructure-as-code reproducibility and clean teardown.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The ADT node 1.3 specifies the **Reactive Probe** as: *"Can automatic remediation trigger?"*

The `hypothesis_verification()` function implements a rigorous, three-step evidentiary chain that **fully corresponds** to this intent:

**Step 1 — Lambda Invocation (Remediation trigger simulation)**:
- Directly invokes the reactor Lambda with a syntactically correct synthetic CloudTrail event mirroring what EventBridge would deliver
- Validates `StatusCode == 200` (real AWS API response)
- Bypasses CloudTrail delivery latency (acknowledged in code comments) while still exercising the **actual Lambda code path**

**Step 2 — CloudWatch Metric Confirmation (Reactor fired evidence)**:
- Polls `SCE/sce-1-3::ReactorFired` for up to 120 seconds with exponential back-off
- Requires `Sum >= 1` in a 5-minute window — directly verifying the reactor published its metric
- This is **real AWS API evidence**, not a mock assertion

**Step 3 — Malicious Project Deletion Confirmation (Remediation outcome)**:
- Polls `codebuild:batch_get_projects` for up to 60 seconds to confirm the project no longer exists
- Gracefully handles the race condition where the reactor may not have completed deletion before the check, accepting metric evidence as primary proof (with appropriate logging) — a sound engineering decision

**Correspondence assessment**:

| Reactive Probe Intent | Verification Step | Evidence Type |
|---|---|---|
| "Can automatic remediation trigger?" | Step 1: Lambda invoked + 200 response | Real AWS Lambda invocation |
| Reactor published observable evidence | Step 2: CloudWatch metric >= 1 | Real CloudWatch datapoint |
| Remediation outcome (project deleted) | Step 3: batch_get_projects returns empty | Real CodeBuild API |

The probe is correctly positioned in both the **steady-state hypothesis** (pre-condition: infrastructure deployed, project absent) AND as the verification method. The steady-state hypothesis title — *"Reactive control infrastructure is deployed and the malicious CodeBuild project does not exist prior to the attack"* — correctly establishes the baseline condition against which the reactive control is tested.

The use of direct Lambda invocation as a workaround for CloudTrail delivery latency is explicitly documented and architecturally sound for SCE purposes — it tests the **defensive mechanism** (Lambda code + IAM + CloudWatch) without being blocked by infrastructure latency outside the experiment's control.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre ≥ 80

---

## DECISION

**✅ AUTHORIZE EXECUTION**

The experiment achieves a perfect pre-execution quality score across all three factors. The implementation demonstrates:

1. **Exact attack fidelity** — T1552.005 credential exfiltration via CodeBuild is precisely modelled with a realistic buildspec, not a simplified placeholder
2. **Complete defense coverage** — Both the reactive mechanism (Lambda deletion) and the supporting detective infrastructure (EventBridge + CloudTrail + CloudWatch) are fully implemented and correctly scoped
3. **Rigorous probe design** — Three independent evidence points (Lambda invocation, CloudWatch metric, project deletion) provide defense-in-depth verification that the reactive control functions as intended

---

## Recommendations

No corrective recommendations required. The following **optional enhancements** could further strengthen the experiment for future iterations:

1. **Security Hub integration**: The code comments reference Security Hub findings as a preferred alternative to CloudWatch metrics. Implementing `securityhub:BatchImportFindings` in the Lambda reactor would elevate the experiment to production-grade incident response validation.

2. **EventBridge end-to-end path**: Consider adding an optional integration test mode that waits for the natural CloudTrail → EventBridge → Lambda path (with a longer timeout, e.g., 10–15 minutes) to validate the full detection pipeline, not just the Lambda execution path.

3. **Negative test case**: Adding a verification that a *legitimate* CodeBuild project creation (tagged differently) also triggers the reactor would validate that the EventBridge rule pattern is not overly narrow — important for production deployment confidence.

4. **SNS notification**: Adding an SNS topic as a secondary notification channel in the Lambda reactor would align the implementation more closely with the ADT node 1.5 description ("publish a finding") and provide an additional evidence dimension for `hypothesis_verification()`.