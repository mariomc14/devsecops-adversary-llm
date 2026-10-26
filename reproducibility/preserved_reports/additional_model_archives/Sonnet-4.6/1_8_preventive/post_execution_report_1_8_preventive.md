# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2, 1.7
- **Evaluation Date**: 2026-04-13 10:11:48 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-04-13 09:37:27,%f [INFO] Attack Vector 1: iam:SimulatePrincipalPolicy on SCERole …
2026-04-13 09:37:28,%f [INFO] SimulatePrincipalPolicy: Action=ec2:ModifyInstanceMetadataOptions Decision=explicitDeny MatchedStatements=['SCEBoundary-1776065185', 'role_SCERole-1776065185_SCERoleInline']
2026-04-13 09:37:28,%f [INFO] Attack Vector 2: direct ModifyInstanceMetadataOptions call from caller identity …
2026-04-13 09:37:29,%f [ERROR] CONTROL FAILURE: ModifyInstanceMetadataOptions SUCCEEDED – HttpTokens was set to optional on i-0b609f8222e4a5459!
```

**Justification**: The action produced rich, verifiable evidence of attack execution across two distinct attack vectors:

1. **Attack Vector 1 (IAM simulation)**: `iam:SimulatePrincipalPolicy` was successfully executed against `SCERole`, returning a concrete decision (`explicitDeny`) and the matched statements (`SCEBoundary-1776065185`, `role_SCERole-1776065185_SCERoleInline`). This confirms the simulation path of the attack (Node 1.2 – IAM-based credential-scope manipulation).

2. **Attack Vector 2 (direct API call)**: `ec2:ModifyInstanceMetadataOptions` was directly invoked using the `ChaosXploit-Labs` caller identity and **succeeded**, setting `HttpTokens=optional` on instance `i-0b609f8222e4a5459`. This is a critical finding — the caller identity (not constrained by the SCERole boundary) was able to weaken IMDS protections on the live instance (Node 1.7 – IMDS credential harvest enablement). This constitutes confirmed exploitation evidence: the attack modified instance metadata options, downgrading IMDSv2 enforcement. The ERROR-level log entry with a specific instance ID and the resulting state change (`HttpTokens=optional`) constitutes strong, non-ambiguous execution evidence.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-04-13 09:37:30,%f [INFO] Check A PASSED: ec2:ModifyInstanceMetadataOptions is denied (decision=explicitDeny, matched=['SCEBoundary-1776065185', 'role_SCERole-1776065185_SCERoleInline']).
2026-04-13 10:07:36,%f [ERROR] Check B FAILED: metadata options not as expected within 1800s SLA.
2026-04-13 10:07:37,%f [INFO] Check C PASSED: no egress rule permits TCP/80 or any path to 169.254.x.x. Egress rules: [{'proto': 'tcp', 'from': 443, 'to': 443, 'cidrs': ['0.0.0.0/0']}]
2026-04-13 10:07:37,%f [WARNING] Check D SKIPPED: SSM agent not online on i-0b609f8222e4a5459 within 300s.
2026-04-13 10:07:37,%f [ERROR] hypothesis_verification: FAILED (A=True, B=False, C=True, D=None) – one or more mandatory preventive controls not confirmed.
[CRITICAL] Steady state probe 'verify-imds-preventive-controls' is not in the given tolerance so failing this experiment
```

**Justification**: The probe executed a structured, multi-dimensional verification of defensive controls, delivering a verifiable and differentiated result for each check:

- **Check A (IAM Boundary – PASSED)**: The probe successfully assumed the `SCEVerifier` role and ran `SimulatePrincipalPolicy`, confirming that `ec2:ModifyInstanceMetadataOptions` is denied via `explicitDeny` on `SCERole`. This represents a confirmed, functioning IAM control.

- **Check B (EC2 Metadata Options – FAILED)**: The probe polled `DescribeInstanceAttribute` repeatedly over the full 1800-second SLA window (09:37:31 to 10:07:36) and consistently observed `HttpTokens=optional` and `HopLimit=2` — both deviating from the expected `required`/`1` values. This is a confirmed defense failure with persistent, timestamped evidence caused by the successful Attack Vector 2 execution. The probe correctly identified and reported this weakness.

- **Check C (Security Group Egress – PASSED)**: The probe verified the security group egress rules and confirmed no rule permits traffic to `169.254.0.0/16`. The exact egress rules are enumerated (`tcp/443 to 0.0.0.0/0` only), providing auditable, specific evidence.

- **Check D (SSM IMDS curl test – SKIPPED)**: The probe attempted SSM-based in-instance validation but correctly flagged it as skipped due to the SSM agent not reaching `Online` status within the 300-second window. This is a transparent, honest reporting of a partial observability gap rather than a silent failure.

The overall probe outcome is **FAILED** with a clear, structured summary (`A=True, B=False, C=True, D=None`), correctly triggering experiment deviation. The probe demonstrated full capability to distinguish passing controls from failing ones, and its verdict is well-supported by the collected evidence. The SKIPPED status of Check D is noted but does not diminish the probe's capability, as it was correctly handled and the three executed checks produced actionable, differentiated results.

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

Although the execution is VALID and the quality score is perfect, the following improvements are recommended to strengthen future iterations of this experiment:

1. **Check D – SSM Agent Availability**: The SSM agent failed to come online within the 300-second window on instance `i-0b609f8222e4a5459`. To improve Check D reliability:
   - Increase the SSM wait timeout (e.g., to 600s) or add a pre-launch SSM readiness gate before proceeding to the hypothesis phase.
   - Ensure the instance profile grants `ssm:RegisterManagedInstance` and that the VPC has an SSM endpoint or NAT gateway (the SG only allows TCP/443 outbound, which may or may not cover the SSM endpoint depending on VPC configuration).
   - Consider using an SSM-optimized AMI or verifying SSM agent pre-installation for the selected `ami-0e10497160c48e829`.

2. **Attack Vector 2 – Caller Identity Scope**: The confirmed control failure (Check B) stemmed from the `ChaosXploit-Labs` IAM user (not `SCERole`) being able to call `ModifyInstanceMetadataOptions` directly. Future experiments should consider:
   - Adding an SCP (Service Control Policy) at the organization or account level to deny `ec2:ModifyInstanceMetadataOptions` for all principals not explicitly authorized, not just IAM roles with the permission boundary.
   - Adding a verification step (Check E) that confirms the **account-level default IMDSv2 enforcement** setting via `DescribeInstanceMetadataDefaults` or AWS Config rule `ec2-imdsv2-check`.

3. **Launch Template Enforcement Gap**: The root cause of Check B's failure is that the EC2 instance was launched but the `HttpTokens=required` + `HopLimit=1` settings from the launch template were subsequently overwritten by the direct API call. Consider adding an AWS Config remediation rule or EventBridge rule that automatically re-enforces `HttpTokens=required` if a `ModifyInstanceMetadataOptions` API call is detected, closing the reactive remediation loop.

4. **Check B SLA Reduction**: The 1800-second SLA for Check B led to an extended polling loop (~30 minutes) after the failure was effectively certain from the first poll. Consider shortening the SLA to a more operationally meaningful window (e.g., 300s with a clear distinction between "not yet applied" and "actively degraded by attack") to reduce experiment runtime.