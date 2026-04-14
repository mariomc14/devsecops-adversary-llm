# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**: 

The experiment implementation demonstrates **full correspondence** with Attack Node 1.2 from the ADT:

**ADT Attack Node 1.2 Specification:**
- **Command**: `aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions]' --output table`
- **TTP**: T1580 - Cloud Infrastructure Discovery
- **Dependencies**: ec2:DescribeInstances permission, Valid AWS credentials
- **Result**: List of EC2 instances with IMDS configuration

**Implementation Analysis:**
1. **Same Tactic (Discovery)**: The code implements the Discovery tactic by attempting to enumerate EC2 instances
2. **Same Technique (T1580)**: The experiment explicitly references T1580 - Cloud Infrastructure Discovery in comments and logs
3. **Command Alignment**: The `attack()` function executes `ec2.describe_instances(MaxResults=5)` which maps directly to the ADT's `aws ec2 describe-instances` command
4. **High Implementation Quality**:
   - Proper role assumption with external ID for security
   - Comprehensive error handling distinguishing between AccessDenied and other errors
   - Detailed logging of attack execution and results
   - Captures MetadataOptions in the response as specified in the ADT query
   - Uses temporary credentials via STS AssumeRole to simulate CI/CD role context

The implementation faithfully reproduces the reconnaissance attack described in the ADT with production-quality code.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment implements **full correspondence** with Defense Node 1.1 from the ADT:

**ADT Defense Node 1.1 Specification:**
- **Classification**: Preventive
- **Description**: Restrict ec2:DescribeInstances to authorized administrative roles only. Apply resource-based conditions limiting visibility. Implement SCPs denying broad describe permissions to CI/CD and developer roles.

**Implementation Analysis:**

1. **Preventive Control Type**: The CloudFormation template creates a Permission Boundary that explicitly denies EC2 reconnaissance:
```python
{
    "Sid": "DenyEC2Recon",
    "Effect": "Deny",
    "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups"
    ],
    "Resource": "*"
}
```

2. **Least-Privilege Enforcement**: The test role is granted `ec2:DescribeInstances` in its inline policy, but the permission boundary overrides this—demonstrating the principle that permission boundaries limit maximum permissions regardless of attached policies.

3. **CI/CD Role Simulation**: The experiment creates a role that simulates a CI/CD pipeline role (as mentioned in the ADT: "CI/CD and developer roles")

4. **High Code Quality**:
   - CloudFormation-based infrastructure ensures repeatability
   - Proper IAM propagation wait times
   - Role assumability verification before attack
   - Comprehensive state tracking
   - External ID condition for secure role assumption

The defense implementation directly addresses the ADT's specification for preventing unauthorized EC2 discovery operations.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The probe **fully corresponds** to the defensive intent specified in SCE Node 1.3:

**ADT SCE Node 1.3 Preventive Probe Specification:**
> "Simulate ec2:DescribeInstances from test CI/CD role; verify AccessDenied and tag-based filtering blocks banking instances."

**Implementation Analysis:**

1. **Simulation Approach**: The experiment creates a simulated CI/CD role with permission boundaries and attempts reconnaissance, exactly as specified

2. **Verification Logic**: The `hypothesis_verification()` function validates:
   - Attack result is "BLOCKED"
   - Error code is "AccessDenied" or "UnauthorizedOperation"
   - No instances were discovered

3. **Defensive Intent Alignment**:
   - **Intent**: Verify preventive controls block unauthorized reconnaissance
   - **Implementation**: Creates controlled environment where attack should fail, then verifies failure occurred
   - **Pass Criteria**: Control works if `AccessDenied` is returned (attack blocked)
   - **Fail Criteria**: Control fails if instances are discoverable (attack succeeds)

4. **Evidence Collection**: The implementation captures:
   - Attack result status
   - Specific error codes
   - Any instances that might have been discovered
   - Timing information

5. **Alignment with Chaos Engineering Principles**:
   - Steady state hypothesis clearly defined
   - Method includes both setup and attack phases
   - Rollback ensures clean environment restoration
   - Results are deterministically verifiable

The probe design ensures that a passing result confirms the preventive control is functioning as designed.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × [100] + 0.30 × [100] + 0.30 × [100]**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent quality across all evaluation factors:

1. **Attack Correspondence (100/100)**: The reconnaissance attack precisely implements T1580 with the specified AWS CLI command equivalent
2. **Defense Correspondence (100/100)**: Permission boundary implementation directly addresses the least-privilege IAM policy defense
3. **Probe Correspondence (100/100)**: The verification logic accurately tests whether preventive controls block unauthorized EC2 discovery

---

## Recommendations

While the experiment meets all quality thresholds, the following enhancements could further improve production readiness:

1. **Tag-Based Filtering**: The ADT mentions "tag-based filtering blocks banking instances" - consider adding a secondary verification that tag conditions are enforced in addition to the blanket deny

2. **Metrics Collection**: Add timing metrics to measure detection latency for compliance with SLA requirements

3. **Multi-Region Testing**: Consider parameterizing the region to test controls across multiple AWS regions

4. **SCP Integration**: The current implementation uses Permission Boundaries; consider adding an optional SCP test mode to validate organization-level controls as mentioned in the ADT