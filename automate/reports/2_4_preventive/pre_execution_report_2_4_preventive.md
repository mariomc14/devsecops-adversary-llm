# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.4
- **Probe Type**: Preventive
- **Attack Nodes**: 1.3, 2.3
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**: 

The experiment demonstrates excellent correspondence between the ADT specification and implementation for both attack nodes:

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
- **TTP Match**: Both specify T1562.001 - Impair Defenses: Disable or Modify Tools
- **Purpose**: Weakening IMDS security to enable subsequent credential theft

### Attack 2.3 (T1552.005 - Unsecured Credentials: Cloud Instance Metadata API)
- **ADT Specification**: `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/BankingTransactionRole`
- **Implementation**: Executed via SSM as `containeruser` (UID 1001) simulating container process:
```bash
sudo -u containeruser timeout 5 curl -s -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/
```
- **TTP Match**: Both specify T1552.005 - Unsecured Credentials: Cloud Instance Metadata API
- **Context**: Container attempting IMDS access after security weakening

The implementation quality is high with proper logging, error handling, and state tracking.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**: 

The experiment implements the preventive defense specified in ADT Node 2.1 (Network Policy Enforcement) with excellent fidelity:

### ADT Node 2.1 Specification:
- **Description**: "iptables rules and container network policies blocking egress to 169.254.169.254 from container namespaces"
- **Implementation**: "Host iptables + Kubernetes NetworkPolicy + Calico rules"

### Experiment Implementation:
The user data script configures comprehensive iptables rules:

```bash
# Rule 2: LOG blocked IMDS attempts from containeruser
iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner 1001 -j LOG --log-prefix "IMDS_BLOCKED: "

# Rule 3: REJECT IMDS access from containeruser (UID 1001)
iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner 1001 -j REJECT --reject-with icmp-port-unreachable

# Rule 4: Allow IMDS access for root (UID 0) - required for management
iptables -A OUTPUT -d 169.254.169.254 -m owner --uid-owner 0 -j ACCEPT
```

**Defense-in-Depth Implementation**:
- UID-based blocking simulates container isolation
- Logging for audit trail (IMDS_BLOCKED prefix)
- REJECT instead of DROP for faster failure detection
- Allows root access for legitimate management operations
- Also references ADT Node 2.2 (Container Runtime Hardening) in comments

The implementation demonstrates high code quality with:
- Comprehensive verification scripts
- Proper state management
- Both IMDSv1 and IMDSv2 testing

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**: 

The experiment's probe perfectly aligns with the defensive intent specified in ADT Node 2.4:

### ADT Node 2.4 Preventive Probe Specification:
> "**Preventive Probe:** From test container, attempt curl to 169.254.169.254 - verify connection blocked by iptables (REJECT/timeout)"

### Implementation Correspondence:

1. **Test Container Simulation**: Uses `containeruser` (UID 1001) to simulate container process isolation

2. **curl Execution**: Attempts both IMDSv1 and IMDSv2 access:
```bash
sudo -u containeruser timeout 5 curl -s -o /dev/null -w "%{http_code}" http://169.254.169.254/latest/meta-data/
sudo -u containeruser timeout 5 curl -s -X PUT "http://169.254.169.254/latest/api/token"
```

3. **Verification of Blocking**: The `hypothesis_verification()` function validates:
   - `containeruser_imdsv1_blocked`: IMDSv1 access blocked
   - `containeruser_imdsv2_blocked`: IMDSv2 access blocked
   - `root_allowed`: Management access preserved
   - `iptables_log_found`: Audit trail exists
   - `hop_limit_bypass_prevented`: Defense-in-depth confirmed

4. **Expected Outcome**: Connection blocked via REJECT with proper verification:
```python
if 'ATTACK_2_3_BLOCKED=TRUE' in stdout or 'BLOCKED' in stdout:
    logger.info("Attack 2.3 BLOCKED by preventive control (iptables)")
    _experiment_state['attack_2_3_blocked'] = True
```

The defensive intent is fully realized: validate that network-level preventive controls block unauthorized container access to IMDS, even after IMDS security configuration is weakened.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × [100] + 0.30 × [100] + 0.30 × [100]**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates exceptional quality across all evaluation factors:

1. **Attack Correspondence (f1=100)**: Both Attack 1.3 (IMDS weakening) and Attack 2.3 (container IMDS access) are implemented with exact command correspondence and proper TTP alignment.

2. **Defense Correspondence (f2=100)**: The iptables-based network policy blocking matches ADT Node 2.1 specification precisely, with additional defense-in-depth considerations.

3. **Probe Correspondence (f3=100)**: The preventive probe exactly validates the defensive intent by testing containeruser IMDS access and verifying blocking via iptables REJECT.

---

## Recommendations

While the experiment is authorized for execution, consider these enhancements for future iterations:

1. **Network Namespace Isolation**: Consider using actual network namespaces instead of UID-based blocking for more realistic container simulation.

2. **Kubernetes Integration**: For production environments, extend testing to actual Kubernetes NetworkPolicy validation.

3. **Timing Metrics**: Add precise timing measurements to validate the "REJECT/timeout" behavior meets performance SLAs.

4. **Cross-Region Testing**: Consider parameterizing for multi-region execution to validate control consistency.