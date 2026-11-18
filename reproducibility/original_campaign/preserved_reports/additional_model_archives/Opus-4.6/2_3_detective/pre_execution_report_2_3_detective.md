# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.3
- **Probe Type**: Detective
- **Attack Nodes**: 1.2, 1.7, 2.2
- **Evaluation Date**: 2025-01-XX

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: 

The experiment implements all three attack nodes specified in the ADT with precise tactic and technique alignment:

1. **Attack Node 1.2 (T1580 – Cloud Infrastructure Discovery)**: The `attack()` function assumes the attacker role and calls `ec2.describe_instances()` with the target instance ID, querying `MetadataOptions` fields (HttpTokens, HopLimit, HttpEndpoint). This exactly matches the ADT specification of `aws ec2 describe-instances` to enumerate IMDS configuration.

2. **Attack Node 1.7 (T1562.001 – Impair Defenses: Disable or Modify Tools)**: The `attack()` function calls `atk.modify_instance_metadata_options()` with `HttpTokens="optional"`, `HttpEndpoint="enabled"`, and `HttpPutResponseHopLimit=2`. This is a verbatim implementation of the ADT-specified command to downgrade IMDSv2 to IMDSv1 and increase hop limit.

3. **Attack Node 2.2 (T1552.005 – Unsecured Credentials: Cloud Instance Metadata API)**: The experiment uses SSM Run Command to execute `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` from within the target instance, directly matching the ADT specification. It also tests the IMDSv2 token PUT request to validate both v1 and v2 paths.

The implementation quality is high: attacks are executed from a dedicated attacker IAM role (proper attribution), the sequence follows the attack chain order, results are captured with detailed logging, and error handling distinguishes between blocked and successful attempts.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 50
**Justification**: 

The experiment corresponds to detective defense nodes in the ADT but with notable gaps in coverage:

**What is implemented:**
- **CloudTrail monitoring (Node 1.4 / 1.9)**: The experiment provisions a CloudTrail trail with S3 and CloudWatch Logs integration, then verifies that `DescribeInstances` and `ModifyInstanceMetadataOptions` events are logged with attacker attribution. This aligns with the ADT's detective controls for CloudTrail-based detection.
- **VPC Flow Logs (Node 2.4 partial)**: The experiment provisions VPC Flow Logs to CloudWatch Logs and verifies that traffic entries are present. This partially maps to the ADT's specification of "VPC Flow Logs capture connection attempt to 169.254.169.254."
- **IAM Deny policy on attacker role**: The attacker role includes an explicit Deny for `ModifyInstanceMetadataOptions` when `HttpTokens=optional`, simulating the SCP defense from Node 1.6.

**What is NOT implemented:**
- **Falco/eBPF runtime monitoring (Node 2.4)**: The ADT detective probe 2.3 explicitly requires "Falco/eBPF runtime monitor detects curl to metadata IP from container and generates alert." This is entirely absent.
- **GuardDuty detection (Nodes 1.4, 2.4)**: The ADT specifies GuardDuty `Recon:EC2/*` findings and `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS`. No GuardDuty verification is implemented.
- **AWS Config ec2-imdsv2-check (Node 1.9)**: Not provisioned or verified.
- **SIEM correlation rules**: Not implemented.
- **CloudWatch Events/Alarms**: No CloudWatch alarms or EventBridge rules are provisioned to detect the API calls.

The VPC Flow Log check only verifies that *any* traffic entries exist rather than specifically confirming connection attempts to 169.254.169.254, which weakens the detective signal validation.

The defense correspondence is present at the infrastructure level (CloudTrail trail, Flow Logs) but missing several key detective mechanisms specified in the ADT.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: 

The probe's defensive intent fundamentally aligns with the ADT Node 2.3 detective probe specification. The core intent is to verify that **attack activity against IMDS is observable** by the security monitoring stack:

1. **Intent alignment**: The ADT detective probe for Node 2.3 states: "Execute curl attempt and verify: (1) VPC Flow Logs capture connection attempt to 169.254.169.254, (2) Falco/eBPF runtime monitor detects curl..., (3) GuardDuty detects credential use from outside instance." The experiment's hypothesis verification checks whether attack activity is captured in detective telemetry (CloudTrail events for Steps 1.2 and 1.7, VPC Flow Logs for Step 2.2), which directly corresponds to the defensive intent of ensuring observability.

2. **Detection verification pattern**: The probe polls for detective evidence with a time budget (SLA of 1800s), validates attribution (attacker role name matching), and confirms specific event details (instance ID in CloudTrail events). This is a proper detective probe pattern.

3. **Multi-step coverage**: The probe verifies detection across all three attack steps rather than just the final step, which exceeds the minimum intent of Node 2.3 and covers the broader attack chain observability requirement.

4. **The probe answers the right question**: "Can our detective controls see IMDS-related attack activity?" This is precisely the defensive intent of the detective probe in the ADT.

While the implementation omits Falco and GuardDuty checks (scored in Factor 2), the *intent* of the probe—validating that attack activity is detectable by AWS-native monitoring tools—fully corresponds to the defensive intent specified in the ADT. The experiment description explicitly acknowledges focusing on "AWS-native detective controls that can be validated programmatically in a clean account."

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

While the experiment clears the threshold, the following improvements would strengthen Factor 2 toward a higher score:

1. **VPC Flow Log specificity**: Filter Flow Log entries for destination IP `169.254.169.254` rather than accepting any traffic entry as proof of detection. This would directly validate the ADT's requirement.

2. **GuardDuty integration**: Enable GuardDuty in the experiment account and verify that reconnaissance findings are generated for the enumeration activity, or that `InstanceCredentialExfiltration` findings fire when credentials are used externally.

3. **AWS Config rule**: Provision `ec2-imdsv2-check` as a Config rule and verify compliance evaluation status, since the ADT Node 1.9 explicitly calls this out as a detective control.

4. **CloudWatch Alarm/EventBridge rule**: Add an EventBridge rule triggering on `ModifyInstanceMetadataOptions` to validate the "zero false-positive tolerance" high-fidelity signal described in Node 1.9.

5. **Partial pass logic**: The current 2-of-3 partial pass threshold is lenient; consider requiring all 3 checks for a full pass to maintain detective rigor for a PCI-DSS-scoped banking platform.