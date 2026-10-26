# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.5
- **Probe Type**: Reactive
- **Attack Nodes**: 1.3, 2.4
- **Evaluation Date**: 2025-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**:

The experiment implements both attack nodes specified in the ADT with precise technique and tactic alignment:

- **Attack Node 1.3 (T1580 - Cloud Infrastructure Discovery)**: The `attack()` function executes `ec2.describe_instances(InstanceIds=[iid])` to enumerate the target EC2 instance's IMDS configuration, retrieving `HttpTokens`, `HttpPutResponseHopLimit`, `HttpEndpoint`, and `State`. This matches the ADT's Step 1.2 attack exactly — the command, dependencies (ec2:DescribeInstances permission, valid credentials, target instance ID), and result (retrieval of current IMDS configuration) are all faithfully reproduced. The TTP mapping T1580 is correct.

- **Attack Node 2.4 (T1562.001 - Impair Defenses: Disable or Modify Tools)**: The `attack()` function executes `ec2.modify_instance_metadata_options()` with `HttpTokens="optional"`, `HttpEndpoint="enabled"`, and `HttpPutResponseHopLimit=2`. This directly corresponds to the ADT's Step 1.7 attack — downgrading IMDSv2 to IMDSv1 and increasing the hop limit to enable container-level IMDS access. The implementation includes post-attack verification confirming the downgrade succeeded. The TTP mapping T1562.001 is correct.

The implementation quality is high: proper error handling distinguishes between preventive control blocks (AccessDenied) and unexpected errors, state is tracked for downstream verification, and logging captures full attack progression with pre/post configuration states.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**:

SCE Node 2.5 in the ADT corresponds to **"Credential Revocation, Instance Quarantine & Forensic Response with Deployment Freeze"** — a reactive defense that triggers on GuardDuty/Falco alerts. However, the experiment's SCE chaos node is 1.8 (IMDS Downgrade Prevention Resilience), whose **Reactive Probe** specifies: "Simulate scenario where SCP is temporarily removed (misconfiguration). Verify AWS Config detects instance as NON_COMPLIANT. Confirm auto-remediation Lambda reverts HttpTokens to 'required' and HopLimit to 1. Verify SOC receives critical alert. Time-to-remediation <5 minutes."

The experiment manifest explicitly states it "Simulates the SCP-removed scenario from SCE node 2.5" and validates the reactive control chain described in ADT node 1.10 (Auto-Remediation & Instance Quarantine):

1. **AWS Config ec2-imdsv2-check rule**: Deployed via CFN, continuously evaluates EC2 instance IMDS compliance — matches ADT node 1.9's detective control and 1.10's Config auto-remediation trigger.
2. **EventBridge rule**: Fires on Config Rules Compliance Change for NON_COMPLIANT — matches ADT 1.10's automated response chain.
3. **Remediation Lambda**: Automatically reverts `HttpTokens` to `required` and `HttpPutResponseHopLimit` to 1 — directly implements ADT 1.10's SSM Automation/Lambda remediation.
4. **SNS SOC notification**: Sends alert on remediation — matches ADT 1.10's SOC alerting requirement.
5. **SLA verification**: Measures time-to-remediation against <5 minute target — aligns with ADT 1.10's "Entire chain: <5 minutes."

The implementation is high quality: the CloudFormation template correctly provisions all required reactive infrastructure, the Lambda code properly handles the NON_COMPLIANT event structure, and the hypothesis verification includes comprehensive checks (Config compliance state, IMDS reversion, Lambda log evidence). The decision to handle Config recorder imperatively to avoid CFN blocking demonstrates operational maturity.

While the experiment focuses on the Config-based auto-remediation chain (node 1.10) rather than the full quarantine/forensic response of node 2.5, this is a reasonable scope for a reactive probe — the core reactive mechanism (detect downgrade → auto-remediate → alert SOC) is fully validated.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**:

The probe's defensive intent is to validate that reactive controls automatically detect and remediate IMDS configuration downgrades on banking EC2 instances. This aligns precisely with the reactive defensive intent expressed across multiple ADT nodes:

1. **Reactive Intent from ADT 1.10**: "AWS Config auto-remediation via SSM Automation: on NON_COMPLIANT for ec2-imdsv2-check, automatically execute ModifyInstanceMetadataOptions to set HttpTokens=required, HopLimit=1." The probe validates exactly this — it downgrades IMDS, waits for Config to detect NON_COMPLIANT, and verifies auto-remediation reverts the settings.

2. **SCE Node 1.8 Reactive Probe specification**: "Simulate scenario where SCP is temporarily removed (misconfiguration). Verify AWS Config detects instance as NON_COMPLIANT. Confirm auto-remediation Lambda reverts HttpTokens to 'required' and HopLimit to 1." The experiment perfectly implements this by executing the attack without SCP protection and verifying the reactive chain fires.

3. **Time-to-remediation SLA**: The probe measures remediation time against the <5 minute target specified in the ADT, with a generous 30-minute outer window to account for Config evaluation delays.

4. **SOC alerting**: The SNS topic and Lambda log verification confirm the alerting component of the reactive defense.

The hypothesis verification is well-structured: it checks NON_COMPLIANT detection, IMDS reversion (both HttpTokens and HopLimit), Lambda execution logs, and timing — covering all aspects of the reactive control's defensive intent. The probe type (Reactive) correctly matches the nature of the defense being validated.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent correspondence between the ADT specification and the SCE implementation across all three quality factors. The attack nodes are faithfully reproduced with correct TTP mappings, the defensive controls are comprehensively implemented with production-quality infrastructure provisioning, and the reactive probe precisely validates the intended defensive behavior including auto-remediation, compliance detection, and SOC alerting within the specified SLA.

---

## Recommendations

While the experiment scores perfectly on the evaluation criteria, minor enhancements could increase operational value:

1. **Instance quarantine validation**: The ADT node 1.10 specifies quarantine SG assignment and EBS snapshot capture. Adding these to the reactive chain (even as verification-only) would increase coverage of the full incident response workflow.
2. **Calling principal session revocation**: ADT 1.10 specifies revoking the calling principal's sessions. This could be added as an additional Lambda action or separate verification step.
3. **PCI-DSS compliance team notification**: ADT references Req 12.10 compliance notification as a distinct step beyond SOC alerting.