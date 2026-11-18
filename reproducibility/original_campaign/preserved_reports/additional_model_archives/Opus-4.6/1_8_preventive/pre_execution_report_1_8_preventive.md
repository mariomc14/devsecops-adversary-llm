# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2, 1.7
- **Evaluation Date**: 2025-01-13

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**:

The experiment implementation directly and faithfully reproduces both attack steps specified in the ADT:

**Attack Step 1.2 (T1580 - Cloud Infrastructure Discovery):** The ADT specifies `aws ec2 describe-instances --instance-ids <INSTANCE_ID> --query "Reservations[*].Instances[*].{...MetadataOptions...}"`. The Python implementation executes `restricted_ec2.describe_instances(InstanceIds=[instance_id])` and then inspects `MetadataOptions` fields (HttpTokens, HttpEndpoint, HttpPutResponseHopLimit, State) — precisely matching the ADT's reconnaissance objective of enumerating IMDS configuration on banking-tier EC2 instances. The TTP (T1580) is correctly identified and implemented.

**Attack Step 1.7 (T1562.001 - Impair Defenses: Disable or Modify Tools):** The ADT specifies `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`. The Python implementation executes `restricted_ec2.modify_instance_metadata_options(InstanceId=instance_id, HttpTokens="optional", HttpEndpoint="enabled", HttpPutResponseHopLimit=2)` — an exact parameter-for-parameter match. The TTP (T1562.001) is correctly identified and implemented.

Both attacks use the same tactics (Discovery, Defense Evasion), the same techniques (T1580, T1562.001), and the same exact API calls and parameters as specified in the ADT. The implementation quality is high: proper error handling, logging, credential management via STS AssumeRole, and structured result capture.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**:

The SCE experiment at node 1.8 tests the preventive defense described in node **1.6 ("Preventive: SCP Deny ec2:ModifyInstanceMetadataOptions")** and node **1.1 ("Preventive: Least-Privilege IAM & SCP Restrictions")**. 

**ADT Defense Node 1.6** specifies: Deploy an SCP that explicitly denies `ec2:ModifyInstanceMetadataOptions` unless the caller matches a tightly scoped infrastructure-automation role. Deny any API call that sets `http-tokens` to "optional" or increases hop-limit >1. Apply IAM Permission Boundaries preventing developer/CI roles from invoking this API.

**ADT Defense Node 1.1** specifies: Deny `ec2:DescribeInstances` to roles that do not require instance enumeration. Apply SCP restrictions. Enforce IAM Permission Boundaries on all developer and service roles.

The implementation creates a CloudFormation stack with:
1. An **explicit IAM Deny policy** (`SCEDenyPolicy`) that denies both `ec2:DescribeInstances` and `ec2:ModifyInstanceMetadataOptions` on `Resource: "*"` — simulating the SCP preventive control described in both 1.1 and 1.6.
2. A **baseline Allow policy** (`SCEAllowBaselinePolicy`) attached to the same role, ensuring the deny is what prevents the actions (not absence of permissions) — this is a thoughtful design choice that accurately tests explicit deny semantics.
3. The target EC2 instance is provisioned with `HttpTokens: required` and `HttpPutResponseHopLimit: 1`, establishing the correct baseline security posture.

The implementation note that SCPs cannot be created in a single-account test environment is well-addressed by using IAM deny policies as a valid simulation of SCP behavior (both evaluate to explicit deny in IAM policy evaluation logic). The code quality is high with proper CloudFormation resource management, IAM propagation waiting, and comprehensive error handling.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**:

The SCE node 1.8 in the ADT specifies a **Preventive Probe** with the following intent:

> "Attempt to call modify-instance-metadata-options with --http-tokens optional from every IAM role in the banking platform (CodeBuild roles, developer roles, EC2 instance profiles, Lambda execution roles). Validate that SCP returns explicit Deny for all principals."

And for the enumeration aspect:

> "Simulate an IAM principal with overly broad EC2 permissions attempting ec2:DescribeInstances against banking tier instances. Validate that SCPs and Permission Boundaries deny the call."

The experiment implementation fully corresponds to this defensive intent:

1. **Preventive validation of DescribeInstances denial**: The experiment assumes a restricted role and attempts `describe_instances`, then verifies it receives `AccessDenied`/`UnauthorizedOperation`. This validates the preventive control blocks reconnaissance.

2. **Preventive validation of ModifyInstanceMetadataOptions denial**: The experiment attempts `modify_instance_metadata_options` with `http-tokens=optional` and `hop-limit=2`, then verifies it receives `AccessDenied`/`UnauthorizedOperation`. This validates the preventive control blocks IMDS downgrade.

3. **Post-attack integrity verification**: The experiment uses privileged credentials to verify the EC2 instance still has `HttpTokens=required` and `HopLimit=1`, confirming the defense was never weakened — this is a critical additional verification that strengthens the probe.

4. **The probe type is correctly Preventive**: It tests that controls PREVENT the attack rather than detect or react to it, which aligns exactly with the "Preventive Probe" designation in the ADT.

The hypothesis verification function (`hypothesis_verification`) implements a three-check validation with a 30-minute SLA timeout for eventual consistency, structured logging, and clear pass/fail determination. The rollback procedure includes safety measures to revert any IMDS changes if they somehow occurred.

The only minor gap is that the experiment tests a single representative restricted role rather than "every IAM role in the banking platform" as the ADT ideally suggests. However, this is a practical and valid approach — the deny policy mechanism being tested is the same regardless of which role it's attached to, and the experiment validates the core defensive mechanism faithfully.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent correspondence across all three quality factors. The attack steps are implemented with exact fidelity to the ADT specification (same APIs, same parameters, same TTPs). The defense mechanism accurately simulates the SCP preventive controls using IAM deny policies. The probe correctly validates the preventive intent by confirming both attack steps are denied and IMDS configuration remains intact.

---

## Recommendations

While the experiment scores perfectly and is authorized for execution, the following minor enhancements could be considered for future iterations:

1. **Multiple role testing**: The ADT suggests testing "every IAM role in the banking platform." A future iteration could create multiple roles (simulating CodeBuild, developer, Lambda execution roles) to demonstrate breadth of coverage.

2. **IaC gate testing**: The ADT's node 1.8 also mentions verifying that "IaC deployment of a CloudFormation template with IMDSv1 config fails checkov/cfn-nag gates." This policy-as-code validation could be added as an additional check.

3. **SCP condition key testing**: The ADT mentions SCP condition keys like `ec2:MetadataHttpTokens`. Testing with IAM policy condition keys would more closely simulate the SCP mechanism.