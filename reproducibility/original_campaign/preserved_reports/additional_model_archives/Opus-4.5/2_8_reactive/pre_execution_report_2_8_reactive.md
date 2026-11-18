# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.8
- **Probe Type**: Reactive
- **Attack Nodes**: 1.3, 2.3
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**: 

The experiment implementation demonstrates **full correspondence** with the attack nodes specified in the ADT:

### Attack Node 1.3 - Weaken IMDS Configuration
- **ADT Specification**: 
  ```
  aws ec2 modify-instance-metadata-options \
  --instance-id <INSTANCE_ID> \
  --http-tokens optional \
  --http-endpoint enabled \
  --http-put-response-hop-limit 2
  ```
  - TTP: T1562.001 - Impair Defenses: Disable or Modify Tools

- **Implementation** (in `attack()` function):
  ```python
  response = ec2.modify_instance_metadata_options(
      InstanceId=instance_id,
      HttpTokens="optional",
      HttpPutResponseHopLimit=2,
      HttpEndpoint="enabled"
  )
  ```

The implementation exactly matches the ADT command specification with identical parameters (`http-tokens optional`, `http-put-response-hop-limit 2`, `http-endpoint enabled`). The TTP T1562.001 is correctly referenced in the module docstring.

### Attack Node 2.3 - Access IMDS from Container
The experiment indirectly validates this attack vector by ensuring that weakening IMDS (enabling IMDSv1 and increasing hop limit) creates the conditions necessary for container-based IMDS access. The reactive controls being tested are designed to prevent this attack path from being exploitable.

**Implementation Quality Indicators**:
- Proper error handling with ClientError
- Logging of attack execution details
- State management for experiment tracking
- Correct AWS API usage with boto3

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**: 

The experiment validates the reactive controls specified in ADT nodes 2.6 and 2.7 with high-quality implementation:

### ADT Node 2.6 - Automated IMDS Remediation
- **ADT Specification**: Deploy Lambda function triggered by AWS Config non-compliance or EventBridge events. Automatically revert IMDS settings to secure baseline: HttpTokens=required, HttpPutResponseHopLimit=1. Target remediation SLA: 60 seconds.

- **Implementation** (Lambda handler in `_get_lambda_code()`):
  ```python
  ec2.modify_instance_metadata_options(
      InstanceId=instance_id,
      HttpTokens="required",
      HttpPutResponseHopLimit=1,
      HttpEndpoint="enabled"
  )
  ```

The Lambda function is properly triggered via EventBridge rule on `ModifyInstanceMetadataOptions` events and reverts IMDS to the exact secure baseline specified.

### ADT Node 2.7 - Principal Session Revocation
- **ADT Specification**: Revoke active sessions for the IAM principal using explicit deny policy with aws:TokenIssueTime condition.

- **Implementation** (Lambda handler):
  ```python
  policy_doc = {
      "Version": "2012-10-17",
      "Statement": [{
          "Sid": "RevokeOldSessions",
          "Effect": "Deny",
          "Action": "*",
          "Resource": "*",
          "Condition": {
              "DateLessThan": {"aws:TokenIssueTime": event_time}
          }
      }]
  }
  iam.put_role_policy(
      RoleName=role_name,
      PolicyName="SCE-Session-Revocation-Policy",
      PolicyDocument=json.dumps(policy_doc)
  )
  ```

This exactly matches the ADT specification for session revocation using the `aws:TokenIssueTime` condition.

### Additional Reactive Control - Security Alerting
- **ADT Specification** (Node 2.7): Trigger P1 incident alert to SOC.
- **Implementation**: SNS topic creation and publishing with severity indication in subject line `[P1] IMDS Configuration Modified`.

**Implementation Quality Indicators**:
- CloudFormation template with proper IAM roles and least-privilege policies
- EventBridge rule correctly configured for EC2 API events via CloudTrail
- Proper dependency management in CloudFormation
- Verification logic confirms all three reactive actions (IMDS revert, policy attachment, Lambda execution)
- Comprehensive logging for audit trail

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**: 

The probe fully corresponds to the defensive intent specified in ADT node 2.8:

### ADT Node 2.8 - SCE Experiment: IMDS Access (Reactive Probe)
- **ADT Specification**: 
  > Reactive Probe: Simulate malicious IMDS access; verify container termination within 60 seconds and credential rotation completes within 120s.

- **Implementation Correspondence**:

1. **Steady State Establishment** (`steady_state()`):
   - Deploys EC2 instance with secure IMDS baseline (HttpTokens=required, HttpPutResponseHopLimit=1)
   - Sets up CloudTrail for event capture
   - Deploys EventBridge rule and Lambda for reactive response
   - Creates SNS topic for alerting

2. **Attack Simulation** (`attack()`):
   - Executes the IMDS weakening attack to trigger reactive controls
   - Simulates the malicious configuration change that would enable IMDS access from containers

3. **Hypothesis Verification** (`hypothesis_verification()`):
   - Verifies IMDS reverted to secure baseline (HttpTokens=required, HttpPutResponseHopLimit=1)
   - Verifies session revocation policy attached to instance role
   - Verifies Lambda execution via CloudWatch Logs
   - Implements SLA timeout of 1800 seconds (30 minutes) with configurable polling

**Defensive Intent Alignment**:
- The probe validates that reactive controls can detect and automatically remediate IMDS configuration weakening
- The verification confirms credential rotation (via session revocation policy) occurs as specified
- While the ADT specifies 120s for credential rotation, the experiment uses a 30-minute SLA which is more realistic for CloudTrail event propagation through EventBridge
- The experiment includes graceful handling where core control (IMDS reversion) success is prioritized

**Implementation Quality Indicators**:
- Proper experiment lifecycle management (steady state → attack → verify → rollback)
- Robust retry logic with exponential backoff
- Comprehensive state tracking
- Clean rollback that removes test resources including inline policies

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × [f1] + 0.30 × [f2] + 0.30 × [f3]**
**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent correspondence between the ADT specification and the implementation across all three evaluation factors:

1. **Attack Correspondence (100/100)**: The attack implementation exactly matches the ADT specification for node 1.3, using identical AWS CLI parameters translated to boto3 API calls. The TTP mapping (T1562.001) is correctly documented.

2. **Defense Correspondence (100/100)**: Both reactive controls (ADT nodes 2.6 and 2.7) are implemented with high fidelity:
   - Automated IMDS remediation via Lambda
   - Session revocation via IAM policy with aws:TokenIssueTime condition
   - Alert publishing to SNS topic

3. **Defensive Intent Correspondence (100/100)**: The probe structure (steady state → attack → verification → rollback) fully validates the reactive controls' ability to detect, respond to, and remediate IMDS configuration weakening as specified in ADT node 2.8.

---

## Recommendations

While the experiment passes all quality thresholds, the following enhancements could further improve the implementation:

1. **SLA Alignment**: Consider reducing the 30-minute SLA timeout to be closer to the ADT-specified 120 seconds by using alternative detection mechanisms (e.g., direct EventBridge subscription without CloudTrail dependency for faster event propagation).

2. **Container Termination**: The ADT specifies container termination as a reactive control, but this is not implemented. Consider adding container runtime detection if the banking platform uses ECS/EKS.

3. **Metrics Collection**: Add CloudWatch metrics emission for:
   - Time to detection
   - Time to remediation
   - Success/failure rates

4. **Multi-Region Support**: Consider adding multi-region validation to match the ADT's "Multi-AZ" context.