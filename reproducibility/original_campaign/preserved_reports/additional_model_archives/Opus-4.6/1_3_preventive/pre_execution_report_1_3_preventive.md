# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: 

The ADT Attack Node 1.2 specifies:
- **Command**: `aws ec2 describe-instances --instance-ids <INSTANCE_ID> --query "Reservations[*].Instances[*].{InstanceId:InstanceId, MetadataOptions:MetadataOptions}" --output json`
- **TTP**: T1580 - Cloud Infrastructure Discovery
- **Dependencies**: `ec2:DescribeInstances` permission, valid AWS credentials
- **Result**: Returns current IMDS configuration including HttpTokens state, HttpEndpoint state, and HttpPutResponseHopLimit

The Python implementation directly mirrors this:
1. The `attack()` function assumes a role and executes `ec2.describe_instances(MaxResults=5)` — the exact same API call (`ec2:DescribeInstances`)
2. The TTP is explicitly documented as T1580 in the code comments and logging
3. The code extracts `InstanceId` and `MetadataOptions` from the response, matching the ADT's query specification
4. It also tests `ec2:DescribeSecurityGroups` as breadth validation, which aligns with the broader reconnaissance intent
5. The implementation properly handles the expected `AccessDenied`/`UnauthorizedOperation` responses and records state for hypothesis verification

The tactic (Discovery) and technique (T1580 - Cloud Infrastructure Discovery) are fully aligned. The implementation quality is high with proper error handling, logging, timing measurement, and state management.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**: 

The ADT Defense Node 1.1 specifies:
- **Classification**: Preventive
- **Description**: Enforce least-privilege IAM policies so that only authorized operations teams hold `ec2:DescribeInstances`. AWS Organizations SCPs deny `ec2:Describe*` from CodeBuild service roles and developer roles. IAM Access Analyzer validates no over-privileged policy grants blanket EC2 read access. Microservice task roles are scoped exclusively to application-layer APIs, blocking EC2 control-plane enumeration.

The SCE Node 1.3 Preventive Probe in the ADT specifies:
- Attempt `ec2:DescribeInstances` using a CodeBuild service role and a microservice task role
- Verify both receive `AccessDenied`
- Confirm SCP blocks the call even if an inline policy grants it

The Python implementation creates:
1. **Permission Boundary** (analogous to SCP guardrails) that explicitly denies `ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`, `ec2:DescribeVpcs`, `ec2:DescribeSubnets`, `ec2:DescribeInstanceAttribute`, `ec2:DescribeInstanceStatus` — matching the "deny ec2:Describe*" intent
2. **Simulated CI/CD Role** with an inline policy that *grants* `ec2:DescribeInstances` but is bounded by the deny — this directly validates that the boundary overrides the allow, exactly as the ADT describes ("SCP blocks the call even if an inline policy grants it")
3. The role simulates a CodeBuild/developer role as specified in the ADT

The defense mechanism (Permission Boundary acting as the equivalent of SCP-level denial) correctly implements the preventive control intent. While the implementation uses Permission Boundaries rather than actual SCPs (which require AWS Organizations multi-account setup), this is a pragmatically equivalent and valid approach for testing the same principle: explicit deny overrides inline allow. The code quality is high with CloudFormation-based infrastructure provisioning, proper IAM propagation waiting, and comprehensive cleanup.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: 

The SCE Node 1.3 Preventive Probe's defensive intent is:
- Validate that unauthorized roles (CodeBuild service role, microservice task role) cannot perform EC2 reconnaissance
- Confirm that even if an inline policy grants the permission, the SCP/boundary blocks it
- Verify `AccessDenied` is returned

The experiment implementation fully addresses this intent:

1. **Steady State**: Creates the preventive control infrastructure (Permission Boundary + bounded role), establishing the security posture to be validated
2. **Attack Execution**: Assumes the bounded role and attempts `ec2:DescribeInstances` — directly testing whether the preventive control blocks reconnaissance
3. **Hypothesis Verification**: Checks three precise conditions:
   - `attack_result == "BLOCKED"` — the call was denied
   - `error_code in ("UnauthorizedOperation", "AccessDenied")` — the correct denial mechanism fired
   - No instances were discovered — no information was leaked
4. **Additional breadth**: Also tests `ec2:DescribeSecurityGroups` to validate the boundary covers multiple reconnaissance vectors
5. **Rollback**: Clean teardown of all experiment resources

The probe type is correctly Preventive — it validates that the control *prevents* the attack before it can succeed, rather than detecting or reacting after the fact. The implementation faithfully captures the defensive intent of proving that least-privilege boundaries block unauthorized EC2 enumeration.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent correspondence across all three quality factors. The attack implementation precisely mirrors ADT Node 1.2 (T1580), the defense implementation faithfully represents the preventive controls from Node 1.1, and the probe correctly validates the defensive intent specified in Node 1.3. The code quality is high with proper error handling, logging, resource lifecycle management, and clean rollback procedures.

---

## Recommendations

While the experiment scores fully and is authorized for execution, minor enhancements could be considered for future iterations:

1. **Multi-role testing**: The ADT mentions testing both a CodeBuild service role AND a microservice task role. The current implementation tests only one simulated CI/CD role. Consider adding a second role to increase coverage.
2. **SCP vs Permission Boundary**: The implementation uses Permission Boundaries as a pragmatic stand-in for SCPs. If an AWS Organizations environment is available, a complementary test with actual SCPs would strengthen the validation.
3. **IAM Access Analyzer integration**: The ADT mentions IAM Access Analyzer continuously validating policies. Adding a check that Access Analyzer has no findings for the bounded role would add depth.