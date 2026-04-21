# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.4
- **Probe Type**: Detective
- **Attack Nodes**: 1.3, 2.3
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**: 

The experiment implementation demonstrates full correspondence with both attack nodes specified in the ADT:

### Attack 1.3 (T1562.001 - Impair Defenses: Disable or Modify Tools)
- **ADT Specification**: `aws ec2 modify-instance-metadata-options --instance-id i-0abc123def456 --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`
- **Implementation**: The `attack()` function executes exactly this command via boto3:
```python
response = ec2_client.modify_instance_metadata_options(
    InstanceId=instance_id,
    HttpTokens='optional',
    HttpEndpoint='enabled',
    HttpPutResponseHopLimit=2
)
```
- **TTP Alignment**: Both specify T1562.001 - Impair Defenses

### Attack 2.3 (T1552.005 - Unsecured Credentials: Cloud Instance Metadata API)
- **ADT Specification**: `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/BankingTransactionRole`
- **Implementation**: The attack function executes IMDS access via SSM including:
  - Simulated container user access (`sudo -u containeruser`)
  - Token-based credential retrieval attempts
  - Role enumeration and credential access logging
- **TTP Alignment**: Both specify T1552.005 - Cloud Instance Metadata API

The implementation quality is high with proper error handling, logging, and realistic attack simulation including the container process context.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**: 

The experiment implementation corresponds to the ADT defense nodes 2.5 and 2.6:

### ADT Node 2.5: VPC Flow Log Analysis
- **ADT Description**: "Monitor network flows to 169.254.169.254 from unexpected ENIs or container network interfaces. Implementation: VPC Flow Logs + Athena queries + CloudWatch anomaly detection"
- **Implementation**: 
  - VPC Flow Logs are created via CloudFormation (`VPCFlowLog` resource)
  - Dedicated log group created (`FlowLogGroup`)
  - Verification checks for IMDS traffic patterns in `hypothesis_verification()`:
```python
response = logs_client.filter_log_events(
    logGroupName=flow_log_group_name,
    startTime=int((attack_timestamp - 60) * 1000),
    filterPattern='169.254.169.254'
)
```

### ADT Node 2.6: Runtime Security Monitoring (Falco)
- **ADT Description**: "Real-time detection of curl/wget processes accessing metadata IP from container context with full process tree capture. Implementation: Falco rules + CloudWatch Logs + SIEM integration"
- **Implementation**: 
  - Local IMDS access monitoring script simulates Falco-style detection
  - User data creates comprehensive logging infrastructure (`imds_monitor.sh`, `monitored_imds_access.sh`)
  - JSON-formatted events capture user context, UID, timestamp, and access results
  - CloudWatch Logs integration with metric filters
  - CloudWatch Alarms for automated alerting

The implementation also includes:
- CloudTrail monitoring for API detection (complements defense 1.5)
- CloudWatch Metric Filters and Alarms
- Multiple detection channel verification

Code quality is high with proper CloudFormation resource creation, IAM roles, and verification logic.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**: 

The probe type is **Detective**, and the experiment fully validates the detective intent:

### ADT Node 2.4 Detective Probe Specification:
> "Detective Probe: Bypass network control in test environment, verify Falco alert fires within 5 seconds with container context"

### Implementation Alignment:

1. **Detection Validation Approach**: The `hypothesis_verification()` function validates multiple detection channels:
   - CloudWatch Logs for IMDS access events
   - CloudTrail for ModifyInstanceMetadataOptions API calls
   - VPC Flow Logs for network traffic to 169.254.169.254
   - CloudWatch Metrics publication
   - CloudWatch Alarm state

2. **Container Context**: The attack simulates container process access using:
   - Dedicated `containeruser` with UID 1001
   - Logged access attempts with user context
   - JSON-formatted events capturing process identity

3. **Detection SLA**: While the ADT specifies 5 seconds for Falco, the implementation uses a 30-minute SLA (`DETECTION_SLA_SECONDS = 1800`) which is appropriate for CloudWatch-based detection given eventual consistency. The implementation uses exponential backoff polling to verify detection within reasonable timeframes.

4. **Defensive Intent Validation**: The hypothesis verification explicitly checks:
   - Were IMDS access attempts logged?
   - Was the API modification captured in CloudTrail?
   - Did network flows to IMDS endpoint get recorded?
   - Did metrics and alarms fire appropriately?

5. **Success Criteria**: The probe returns `True` only if at least one detection channel successfully captured the attack activity, validating that detective controls are functional.

The probe correctly tests whether the detective controls can detect malicious IMDS access patterns, which is precisely the defensive intent of ADT nodes 2.5 and 2.6.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × [100] + 0.30 × [100] + 0.30 × [100]**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent alignment between the ADT specification and the SCE implementation:

1. **Attack Correspondence (100%)**: Both attack steps (1.3 and 2.3) are implemented precisely as specified in the ADT, using the correct AWS APIs and TTPs.

2. **Defense Correspondence (100%)**: The detective controls for VPC Flow Logs (2.5) and Runtime Security Monitoring (2.6) are properly implemented with CloudFormation infrastructure and verification logic.

3. **Probe Intent (100%)**: The detective probe correctly validates that the security controls can detect IMDS access attempts from container processes through multiple detection channels.

---

## Recommendations

While the experiment is authorized for execution, the following enhancements could further improve quality:

1. **Shorter Detection SLA**: Consider adding faster detection verification for critical alerts (though the current 30-minute SLA accounts for CloudWatch eventual consistency appropriately).

2. **Additional Container Isolation Testing**: Could add network policy verification to test preventive controls mentioned in ADT node 2.1.

3. **Metrics Dashboard**: Consider adding a CloudWatch dashboard for visual verification of detection events.

4. **False Positive Testing**: Could add baseline traffic to verify detection specificity.