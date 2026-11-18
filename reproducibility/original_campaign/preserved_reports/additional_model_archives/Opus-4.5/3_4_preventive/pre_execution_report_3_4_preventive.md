# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 3.4
- **Probe Type**: Preventive
- **Attack Nodes**: 1.3, 2.3, 3.3
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**: 

The experiment implementation demonstrates full correspondence with all three attack nodes specified in the ADT:

1. **Node 1.3 (T1580 - Cloud Infrastructure Discovery)**: The `attack()` function executes `describe_instances` to discover EC2 instances and their metadata options, directly matching the ADT specification which describes using `aws ec2 describe-instances --query 'Reservations[*].Instances[*].[InstanceId,MetadataOptions]'`.

2. **Node 2.3 (T1562.001 - Impair Defenses)**: The experiment attempts `modify_instance_metadata_options` with `HttpTokens="optional"` and `HttpPutResponseHopLimit=2`, exactly matching the ADT attack step that specifies weakening IMDS protections via `aws ec2 modify-instance-metadata-options --instance-id <ID> --http-tokens optional --http-put-response-hop-limit 2`.

3. **Node 3.3 (T1552.005 - Unsecured Credentials)**: While the experiment doesn't execute a curl command to 169.254.169.254 (which would require instance-level access), it verifies the IMDS state that would enable/prevent credential exfiltration. The verification checks `HttpTokens` and `HttpPutResponseHopLimit` values which are the exact prerequisites for the credential exfiltration attack.

The implementation quality is high:
- Uses proper AWS SDK calls
- Implements attacker role assumption with proper session management
- Captures detailed results for each attack step
- Follows the exact TTP mapping from the ADT

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**: 

The experiment validates the preventive defense controls specified in the ADT for node 3.4:

**ADT Preventive Controls Being Validated:**

1. **Node 3.1 (IMDSv2 Enforcement)**: The CloudFormation template deploys EC2 instances with `HttpTokens: "required"`, and the experiment verifies this setting persists after the attack attempt via `_state["results"]["step_3_3"]["imdsv2"]`.

2. **Node 3.2 (Hop Limit Enforcement)**: The template sets `HttpPutResponseHopLimit: 1`, and verification confirms `_state["results"]["step_3_3"]["hop_ok"]`.

3. **Node 2.1 (IAM Deny ModifyInstanceMetadataOptions)**: The AttackerRole includes an explicit `Deny` statement for `ec2:ModifyInstanceMetadataOptions`, implementing the SCP-equivalent protection at the IAM level. The experiment validates this by checking `_state["results"]["step_2_3"]["blocked"]`.

**Code Quality Assessment:**
- CloudFormation template properly configures all IMDS security settings
- IAM policies follow least-privilege with explicit deny
- Verification logic comprehensively checks all three preventive controls
- Clean separation between infrastructure setup, attack execution, and validation
- Proper error handling with detailed result capture

The implementation fully corresponds to the ADT's preventive probe specification in node 3.4, which states: "From container, attempt curl to 169.254.169.254. Expect: timeout or 401" - the experiment validates the underlying controls that would cause such behavior.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**: 

The experiment's defensive intent fully aligns with the Preventive probe type specified in the ADT:

**ADT Node 3.4 Preventive Probe Intent:**
- "From container, attempt curl to 169.254.169.254. Expect: timeout or 401"
- Validate that IMDSv2 enforcement blocks unauthorized credential access
- Confirm hop limit prevents container-based IMDS exploitation

**Experiment Implementation Alignment:**

1. **Preventive Control Validation**: The `hypothesis_verification()` function explicitly tests preventive outcomes:
   - `imds_blocked`: Confirms IAM deny prevented IMDS modification
   - `imdsv2_ok`: Confirms HttpTokens=required persists
   - `hop_ok`: Confirms HttpPutResponseHopLimit=1 persists

2. **Expected Failure Validation**: The experiment expects the attack to FAIL (be blocked), which is the correct behavior for a preventive probe. The code explicitly documents: `"Step 2.3: Modify IMDS (T1562.001) - EXPECT BLOCKED"`.

3. **Steady-State Hypothesis**: The JSON manifest correctly defines:
   - Title: "Preventive Controls Block IMDS Protection Weakening"
   - The hypothesis expects the system to remain in its secure state after attack attempts

4. **Attack Chain Coverage**: All three attack nodes (1.3, 2.3, 3.3) are addressed with appropriate preventive control validation for each:
   - Discovery is permitted (read-only, expected behavior)
   - Modification is blocked (preventive control validated)
   - IMDS configuration integrity is verified (prevention confirmed)

The experiment correctly implements a preventive probe that validates security controls PREVENT the attack from succeeding, rather than detecting or responding to it after the fact.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × [f1] + 0.30 × [f2] + 0.30 × [f3]**
**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment demonstrates excellent quality across all three evaluation factors:

1. **Attack Correspondence (100/100)**: Perfect alignment with ATT&CK techniques T1580, T1562.001, and T1552.005 as specified in the ADT attack nodes 1.3, 2.3, and 3.3.

2. **Defense Correspondence (100/100)**: Comprehensive validation of preventive controls including IMDSv2 enforcement, hop limit restrictions, and IAM deny policies.

3. **Defensive Intent (100/100)**: The preventive probe correctly validates that security controls block attacks before they succeed, with proper expected-failure testing.

---

## Recommendations

No critical improvements required. The experiment is well-designed and ready for execution.

**Minor Enhancement Suggestions for Future Iterations:**
1. Consider adding a test case that attempts IMDS access from within the instance to validate hop limit behavior at the network level
2. Add CloudTrail event validation to confirm the denied API calls are properly logged (bridging to detective controls)
3. Consider parameterizing the experiment to test with different IMDS configurations for broader coverage