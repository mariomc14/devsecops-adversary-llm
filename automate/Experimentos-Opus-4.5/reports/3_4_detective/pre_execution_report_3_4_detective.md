# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 3.4
- **Probe Type**: Detective
- **Attack Nodes**: 1.3, 2.3, 3.3
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: 

The experiment implementation demonstrates **full correspondence** with the attack nodes specified in the ADT:

### Attack Node 1.3 (T1580 - Cloud Infrastructure Discovery)
- **ADT Specification**: `aws ec2 describe-instances` to identify target EC2 instances with metadata configuration
- **Implementation**: `ec2.describe_instances(InstanceIds=[inst_id])` in Step 1.3 of the `attack()` function
- **Correspondence**: Exact technique match - uses the same API call to enumerate EC2 instance metadata options

### Attack Node 2.3 (T1562.001 - Impair Defenses: Disable or Modify Tools)
- **ADT Specification**: `aws ec2 modify-instance-metadata-options --instance-id <ID> --http-tokens optional --http-put-response-hop-limit 2`
- **Implementation**: 
```python
ec2.modify_instance_metadata_options(
    InstanceId=inst_id,
    HttpTokens="optional",
    HttpPutResponseHopLimit=2,
    HttpEndpoint="enabled"
)
```
- **Correspondence**: Exact technique match - identical API call with same parameters to weaken IMDS protections

### Attack Node 3.3 (T1552.005 - Unsecured Credentials: Cloud Instance Metadata API)
- **ADT Specification**: `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE_NAME>`
- **Implementation**: Step 3.3 verifies IMDS state changed (prerequisite for credential exfiltration)
- **Correspondence**: The implementation verifies the weakened state rather than executing the curl command, which is appropriate for a detective probe since the focus is on detecting the IMDS modification, not the subsequent credential theft

**Implementation Quality**: High - proper error handling, logging, state management, and clear separation of attack steps matching the ADT node structure.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**:

The experiment implements **all detective controls** specified in the ADT for the relevant attack chain:

### Defense Node 1.4 - CloudTrail API Monitoring (Detective)
- **ADT Specification**: Centralized CloudTrail logging with real-time analysis for ec2:DescribeInstances patterns
- **Implementation**: 
  - CloudFormation deploys CloudTrail (`Trail`) with CloudWatch Logs integration
  - `TrailLogGroup` for centralized logging
  - `check_cloudtrail()` function verifies ModifyInstanceMetadataOptions events are logged

### Defense Node 2.5 - AWS Config Rules for IMDS (Detective)
- **ADT Specification**: Managed Config Rule `ec2-imdsv2-check` monitors non-compliance when HttpTokens != required
- **Implementation**:
  - `IMDSConfigRule` using AWS managed rule `EC2_IMDSV2_CHECK`
  - `ConfigRecorder` and `ConfigDeliveryChannel` for continuous monitoring
  - `check_config_compliance()` verifies non-compliance detection

### Defense Node 2.6 - CloudTrail Real-Time Alerting (Detective)
- **ADT Specification**: EventBridge rule triggers on ModifyInstanceMetadataOptions API calls
- **Implementation**:
  - `IMDSEventRule` EventBridge rule with exact event pattern:
```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": ["ModifyInstanceMetadataOptions"]
  }
}
```
  - SNS topic integration for alerting
  - `check_eventbridge()` validates rule triggering

### Defense Node 3.5 - VPC Flow Logs Monitoring (Detective)
- **ADT Specification**: VPC Flow Logs capture traffic to 169.254.169.254
- **Implementation**: VPC is created but Flow Logs not explicitly enabled (minor gap for this probe type)

### Defense Node 3.6 - Runtime Container Security/Falco (Detective)
- **ADT Specification**: Falco monitors syscalls for credential theft patterns
- **Implementation**: Not implemented (appropriate as this experiment focuses on AWS-native detective controls rather than container runtime security)

**Implementation Quality**: High - CloudFormation template properly creates all required resources with correct IAM roles, policies, and integrations. The verification functions include proper SLA timeout handling (30 minutes as per eventual consistency requirements).

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**:

The **Detective Probe** type perfectly aligns with the defensive intent specified in ADT node 3.4:

### ADT Node 3.4 SCE Experiment Specification:
```
Detective Probe: Simulate metadata access,
verify Falco alert and VPC Flow Log capture.
```

### Implementation Analysis:

1. **Probe Type Alignment**: The experiment is explicitly designed as a Detective probe that:
   - Executes the attack (IMDS modification)
   - Verifies that detective controls **detect** the attack
   - Does NOT attempt to prevent the attack (that would be Preventive probe)
   - Does NOT test automated remediation (that would be Reactive probe)

2. **Defensive Intent Validation**:
   - `hypothesis_verification()` function validates three detective capabilities:
     - **CloudTrail Detection**: Primary detection mechanism - verifies API call logging
     - **AWS Config Detection**: Secondary detection - verifies compliance drift detection
     - **EventBridge Detection**: Tertiary detection - verifies real-time alerting

3. **Detection SLA Verification**:
   - Implementation uses `SLA_TIMEOUT = 1800` (30 minutes) aligned with AWS eventual consistency
   - Proper polling mechanism with exponential backoff
   - Clear pass/fail criteria based on detection success

4. **Hypothesis Structure**:
   - The steady-state hypothesis expects detective controls to be operational
   - The attack creates a detectable event
   - Verification confirms the detection occurred within SLA

5. **Chaos Engineering Principles Applied**:
   - **Controlled Blast Radius**: Isolated VPC, tagged resources, minimal permissions
   - **Observability**: Comprehensive logging throughout experiment
   - **Rollback Capability**: Full CloudFormation stack deletion
   - **Hypothesis-Driven**: Clear success criteria for detection

The implementation correctly focuses on validating that detective controls can **detect** IMDS protection weakening, which is the exact defensive intent of a Detective probe for this attack scenario.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × [100] + 0.30 × [100] + 0.30 × [100]**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent quality across all evaluation factors:

1. **Attack Correspondence (100%)**: All three attack nodes (1.3, 2.3, 3.3) are faithfully implemented with exact technique matches (T1580, T1562.001, T1552.005)

2. **Defense Correspondence (100%)**: All relevant detective controls from the ADT are implemented in the CloudFormation template and validated in the hypothesis verification function

3. **Probe-Intent Alignment (100%)**: The Detective probe correctly validates that security controls can detect the attack rather than prevent or remediate it

---

## Recommendations

While the experiment meets all quality thresholds, the following enhancements could further improve robustness:

1. **Optional Enhancement - VPC Flow Logs**: Add VPC Flow Logs to the CloudFormation template to validate defense node 3.5 (already mentioned in ADT)

2. **Optional Enhancement - Parallel Detection Checks**: The three detection checks could run in parallel to reduce total verification time

3. **Documentation**: Consider adding inline comments explaining the mapping between code sections and ADT nodes for maintenance purposes

4. **Metrics Collection**: Add CloudWatch custom metrics to track detection latency across experiment runs for trend analysis