# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.5
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2026-03-17 12:02:21 UTC

## Factor 1: Effectiveness of the ACTION
**Score**: 100

**Log Excerpts**:
```
2026-03-17T12:00:56Z [INFO] sce.1_5.preventive - Successfully assumed AttackerRole. Session: AROAVYV52CB7O2ARIAV5S:sce-attack-1773745062
2026-03-17T12:00:56Z [INFO] sce.1_5.preventive - Attempting ec2:ModifyInstanceMetadataOptions on instance i-0495611dc1d061467 (http_tokens=optional, hop_limit=2) ...
2026-03-17T12:00:56Z [INFO] sce.1_5.preventive - AccessDenied for ec2:ModifyInstanceMetadataOptions -- preventive IAM Deny control WORKING AS EXPECTED. Code: UnauthorizedOperation | Message: You are not authorized to perform this operation. User: arn:aws:sts::396608802942:assumed-role/sce-attacker-role-1773745062/sce-attack-1773745062 is not authorized to perform: ec2:ModifyInstanceMetadataOptions on resource: arn:aws:ec2:us-east-1:396608802942:instance/i-0495611dc1d061467 with an explicit deny in an identity-based policy.
```

**Justification**: The attack action was fully and verifiably executed. The log provides concrete evidence of:
1. **Role assumption success**: The attacker role `sce-attacker-role-1773745062` was successfully assumed (session token `AROAVYV52CB7O2ARIAV5S:sce-attack-1773745062` is confirmed).
2. **Attack attempt execution**: The `ec2:ModifyInstanceMetadataOptions` call was actually dispatched against a real EC2 instance (`i-0495611dc1d061467`) with the intended downgrade parameters (`http_tokens=optional`, `hop_limit=2`).
3. **AWS-generated response**: An `UnauthorizedOperation` error was returned by AWS with an encoded authorization failure message, confirming the API call reached AWS infrastructure and was evaluated by IAM — this is not a simulated or mocked response.
4. **Infrastructure was real**: The preceding CloudFormation stack deployment (stack `sce-experiment-1773745062`) confirms a live AWS environment with a production-tagged EC2 instance and the restricted attacker IAM role was provisioned and active.

---

## Factor 2: PROBE Capability
**Score**: 100

**Log Excerpts**:
```
2026-03-17T12:00:56Z [INFO] sce.1_5.preventive - [H1] PASS -- ec2:ModifyInstanceMetadataOptions was denied at stage='modify_imds'. Error code: UnauthorizedOperation
2026-03-17T12:00:57Z [INFO] sce.1_5.preventive - [H2] PASS -- Instance i-0495611dc1d061467 IMDS is unchanged after attack: HttpTokens=required, HopLimit=1, State=applied
2026-03-17T12:00:57Z [INFO] sce.1_5.preventive - hypothesis_verification() -> PASS. Preventive control is effective: IAM Deny blocked ec2:ModifyInstanceMetadataOptions and the instance IMDS state remains http_tokens=required, hop_limit=1.
[2026-03-17 12:00:57 INFO] Steady state hypothesis is met!
```

**Justification**: The probe returned fully verifiable and dual-dimensional evidence of defense behavior:
1. **H1 — IAM Deny verification**: The probe confirmed that the `ec2:ModifyInstanceMetadataOptions` call was explicitly denied at the IAM layer (`UnauthorizedOperation` with `explicit deny in an identity-based policy`), directly validating the preventive IAM Deny control targeting `Environment=production` tagged resources.
2. **H2 — IMDS state integrity verification**: A direct AWS API query against instance `i-0495611dc1d061467` confirmed that the IMDS configuration remained unchanged post-attack (`HttpTokens=required`, `HopLimit=1`, `State=applied`). This is a live, real-time verification — not an inference — proving the defense prevented any actual configuration mutation.
3. **Steady-state hypothesis met**: The Chaos Toolkit framework confirmed the steady-state hypothesis was satisfied after the attack phase, providing a structured, auditable conclusion.
4. **Baseline coherence**: The pre-attack baseline (established in `steady_state()`) confirmed `http_tokens=required, hop_limit=1`, and the post-attack probe confirmed identical values, providing a before/after comparison with verifiable integrity.

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

The experiment executed flawlessly with full verifiability on both factors. The following observations are offered as enhancements for future iterations:

1. **Extend attack surface coverage**: Consider testing the same IAM Deny control against additional IMDS-weakening vectors, such as modifying `http_put_response_hop_limit` alone or disabling `http_endpoint` entirely, to ensure the Deny policy covers all downgrade permutations.
2. **Add negative control test**: Include a secondary attack step using a role that *lacks* the Deny policy to confirm that the Deny is specifically the blocking mechanism (not an unrelated permission absence), strengthening causal attribution of the control's effectiveness.
3. **Cross-account and SCP validation**: If Service Control Policies (SCPs) are part of the defense-in-depth strategy, a complementary probe verifying SCP enforcement would provide a more complete picture of the preventive control landscape for attack node 1.2.
4. **CloudTrail evidence capture**: Capturing the CloudTrail event ARN or event ID for the denied `ModifyInstanceMetadataOptions` call would provide immutable audit trail evidence linkable to the experiment run ID, strengthening compliance and forensic documentation.
5. **Tag boundary testing**: Verify that the `Environment=production` condition key in the Deny policy is resistant to tag manipulation (e.g., an attacker attempting to remove the tag before calling `ModifyInstanceMetadataOptions`), which would represent a tag-based privilege escalation path that warrants a separate SCE node.