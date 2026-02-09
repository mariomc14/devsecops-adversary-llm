# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8
- **Probe Type**: Preventive
- **Attack Nodes**: 1.3
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Analysis**:
- **Attack node in ADT**: Node 1.3 "Identify Target EC2 Instance" specifies:
  - Command: `aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions]' --output table`
  - Dependencies: ec2:DescribeInstances permission, valid AWS credentials, network access to AWS API endpoints
  - Result: List of EC2 instances with metadata config identifying targets with IMDSv2 enforced or low hop limits
  - TTP: T1580 - Cloud Infrastructure Discovery

- **ACTION implementation**: The `attack()` function implements:
  ```python
  response = ec2_client.describe_instances(
      InstanceIds=[_experiment_state['test_instance_id']]
  )
  ```
  - Uses unprivileged credentials created during steady state
  - Attempts to retrieve instance information including MetadataOptions
  - Captures both success and failure scenarios with detailed logging

- **Tactic alignment**: Yes - Cloud Infrastructure Discovery (Reconnaissance)
- **Technique alignment**: Yes - T1580 explicitly referenced in code comments and matches ADT specification
- **Implementation quality**: 
  - Well-documented with docstrings explaining the attack purpose
  - Proper error handling with ClientError exception catching
  - Captures attack timing metrics
  - Stores detailed results including error codes, messages, and any leaked data
  - Distinguishes between AccessDenied (expected) and other errors

**Justification**: The implementation achieves full correspondence with the ADT attack node. The `attack()` function directly implements the `ec2:DescribeInstances` API call specified in node 1.3, targeting the test instance to retrieve its MetadataOptions. The TTP T1580 is explicitly documented in the code comments. The implementation includes comprehensive error handling, timing metrics, and detailed result capture for both success and failure scenarios. The code structure is clean with proper logging at each step.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Analysis**:
- **Defense node in ADT**: Node 1.1 "Least Privilege IAM Policy" specifies:
  - Classification: Preventive
  - Description: Restrict ec2:DescribeInstances permission to specific resource ARNs and require MFA for API calls. Implement permission boundaries on all CI/CD roles.
  - PCI-DSS: Req 7.1 - Least Privilege

- **Defense implementation**: The CloudFormation template in `_get_cloudformation_template()` creates:
  ```python
  "UnprivilegedUserPolicy": {
      "Type": "AWS::IAM::Policy",
      "Properties": {
          "PolicyDocument": {
              "Version": "2012-10-17",
              "Statement": [
                  {
                      "Sid": "AllowOnlySTSGetCallerIdentity",
                      "Effect": "Allow",
                      "Action": ["sts:GetCallerIdentity"],
                      "Resource": "*"
                  },
                  {
                      "Sid": "ExplicitDenyEC2Describe",
                      "Effect": "Deny",
                      "Action": [
                          "ec2:DescribeInstances",
                          "ec2:DescribeInstanceAttribute",
                          "ec2:DescribeInstanceStatus"
                      ],
                      "Resource": "*"
                  }
              ]
          }
      }
  }
  ```

- **Correspondence**: Yes - The implementation creates an IAM policy with explicit deny on ec2:DescribeInstances, directly implementing the least privilege principle from node 1.1
- **Code quality**: Excellent
  - CloudFormation template is well-structured with proper resource dependencies
  - Uses `DependsOn` to ensure policy is attached before access keys are created
  - Includes comprehensive tagging for resource tracking
- **Documentation**: Comprehensive
  - Function docstrings explain purpose and what resources are created
  - Inline comments describe the policy structure
  - PCI-DSS alignment is logged during hypothesis verification
- **Error handling**: Robust
  - `steady_state()` includes retry logic with exponential backoff
  - Handles existing stack scenarios gracefully
  - Verifies credential propagation before proceeding
  - Uses `_wait_with_backoff()` for reliable timing

**Justification**: The defense implementation fully corresponds to ADT node 1.1. The CloudFormation template creates an IAM user with an explicit deny policy on `ec2:DescribeInstances` and related actions, implementing the least privilege principle. The code quality is high with proper error handling, retry mechanisms, and comprehensive documentation. The implementation goes beyond basic requirements by including credential verification and IAM propagation delays to ensure reliable testing.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Analysis**:
- **Defensive intent in ADT**: Node 1.1 states the defense should "Restrict ec2:DescribeInstances permission to specific resource ARNs" to prevent unauthorized reconnaissance. The SCE node 1.8 specifies the Preventive Probe should: "Attempt ec2:DescribeInstances with test credentials lacking permission - verify AccessDenied response and no data leak."

- **PROBE implementation**: The `hypothesis_verification()` function validates:
  ```python
  criteria = {
      "access_denied_received": attack_result.get("access_denied", False),
      "no_data_leaked": len(attack_result.get("instances_leaked", [])) == 0,
      "attack_blocked": not attack_result.get("success", True)
  }
  ```

- **Intent correspondence**: Yes - The PROBE directly validates:
  1. AccessDenied error was received (policy enforcement)
  2. No instance data was leaked (data protection)
  3. Attack was blocked (preventive control effectiveness)

**Justification**: The PROBE implementation perfectly aligns with the defensive intent specified in the ADT. The `hypothesis_verification()` function checks exactly what the preventive control (node 1.1) is designed to achieve: blocking unauthorized ec2:DescribeInstances calls and preventing data leakage. The three verification criteria directly map to the expected outcomes of a properly implemented least privilege IAM policy. The function also logs PCI-DSS compliance alignment (Req 7.1, 7.1.2) as specified in the ADT defense node.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × f1 + 0.30 × f2 + 0.30 × f3**
**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
**Q_pre = 40 + 30 + 30**
**Q_pre = 100**

**Threshold**: 80
**Result**: Q_pre (100) >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent quality across all evaluation factors and is approved for execution.

---

## Detailed Observations

### Strengths

1. **Complete Attack-Defense Alignment**: The experiment precisely implements the attack (node 1.3) and defense (node 1.1) specified in the ADT, with explicit TTP references and PCI-DSS compliance mapping.

2. **Robust Infrastructure-as-Code**: The CloudFormation template creates a complete, isolated test environment including:
   - VPC with subnet and security group
   - Test EC2 instance with IMDSv2 enforced
   - Unprivileged IAM user with explicit deny policy
   - Proper resource tagging for tracking

3. **Comprehensive Error Handling**: The implementation includes:
   - Exponential backoff retry logic
   - Graceful handling of existing resources
   - Detailed error capture and logging
   - Guaranteed rollback in finally block

4. **Clear Experiment Structure**: The code follows the Chaos Toolkit pattern with well-defined phases:
   - `steady_state()`: Resource provisioning
   - `attack()`: Attack execution
   - `hypothesis_verification()`: Control validation
   - `rollback()`: Cleanup

5. **Detailed Logging**: Every phase includes comprehensive logging with clear status indicators, timing information, and result summaries.

### Minor Observations

1. The ADT mentions "require MFA for API calls" in node 1.1, but the implementation uses explicit deny rather than MFA requirement. This is acceptable as explicit deny is a stronger preventive control for this test scenario.

2. The implementation tests a single instance rather than the broader reconnaissance pattern in the ADT command, but this is appropriate for a controlled experiment.

## Recommendations

No critical recommendations - the experiment is ready for execution. For future enhancements:

1. Consider adding a test case that verifies the policy also blocks `ec2:DescribeInstanceAttribute` and `ec2:DescribeInstanceStatus` as specified in the deny policy.

2. The experiment could be extended to test permission boundaries as mentioned in node 1.1 ("Implement permission boundaries on all CI/CD roles").

3. Consider adding CloudTrail event verification to confirm the denied API call was logged, which would validate the detective control (node 1.4) integration.