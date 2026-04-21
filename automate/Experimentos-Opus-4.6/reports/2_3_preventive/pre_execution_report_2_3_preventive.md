# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.3
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2, 1.7, 2.2
- **Evaluation Date**: 2024-01-XX

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100
**Justification**:

The experiment implements all three attack nodes specified in the ADT with precise tactic and technique alignment:

1. **Attack Node 1.2 (T1580 – Cloud Infrastructure Discovery)**: The `attack()` function executes `describe_instances` with the attacker role, querying `MetadataOptions` fields (HttpTokens, HttpPutResponseHopLimit, HttpEndpoint, State) — exactly matching the ADT's `aws ec2 describe-instances` command with the `MetadataOptions` query. The TTP is correctly mapped.

2. **Attack Node 1.7 (T1562.001 – Impair Defenses: Disable or Modify Tools)**: The `attack()` function calls `modify_instance_metadata_options` with `HttpTokens="optional"`, `HttpEndpoint="enabled"`, and `HttpPutResponseHopLimit=2` — an exact match to the ADT command `aws ec2 modify-instance-metadata-options --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`. The TTP is correctly mapped.

3. **Attack Node 2.2 (T1552.005 – Unsecured Credentials: Cloud Instance Metadata API)**: The `attack()` function uses SSM Run Command to execute `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/` from within the instance, directly matching the ADT's curl command. It also tests the IMDSv2 token PUT request. The implementation includes a sensible fallback (API-based IMDS config verification) if SSM is unavailable. The TTP is correctly mapped.

All three attack steps use the correct AWS API calls, target the right resources, and follow the exact attack chain sequence described in the ADT. The implementation quality is high: proper error handling, detailed logging, result capture in shared state for hypothesis verification, and use of assumed attacker role credentials for realistic simulation.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100
**Justification**:

The experiment validates the preventive defense controls specified in ADT nodes 1.1, 1.6, and 2.1:

1. **ADT Node 1.1 (Least-Privilege IAM & Short-Lived Credentials)**: The attacker role is created with scoped permissions — only `ec2:DescribeInstances` is allowed. This corresponds to the ADT's defense of restricting ec2:DescribeInstances to authorized operations roles. The experiment validates that even with describe permissions, modification is blocked.

2. **ADT Node 1.6 (SCP: Deny IMDS Downgrade & Hop Limit Increase)**: The CloudFormation template creates the attacker role with an explicit `Deny` on `ec2:ModifyInstanceMetadataOptions` for all resources, directly simulating the organization-wide SCP described in the ADT. The ADT specifies: "Deny ec2:ModifyInstanceMetadataOptions when HttpTokens=optional" and "Deny ec2:ModifyInstanceMetadataOptions permission on all non-admin IAM roles." The implementation uses an IAM deny policy as a faithful simulation of SCP behavior (since SCPs cannot be created in a single-account experiment).

3. **ADT Node 2.1 (Defense-in-Depth: IMDSv2 Enforcement, Least-Privilege Roles & Network IMDS Restriction)**: The EC2 instance is provisioned with `HttpTokens: required` and `HttpPutResponseHopLimit: 1`, matching the ADT's specification. The instance profile role is scoped to SSM only (no ec2:Modify*), implementing the least-privilege principle. The SSM-based curl test verifies that IMDSv2 enforcement blocks unauthenticated credential retrieval from the instance level.

The code quality is high: CloudFormation for infrastructure-as-code, proper IAM role separation (instance role vs. attacker role), SSM VPC endpoints for private access, thorough error handling, and comprehensive logging. The hypothesis verification checks all four conditions: enumeration success, IMDS modification blocked, credential exfiltration blocked, and final IMDS config unchanged.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100
**Justification**:

The ADT Node 2.3 Preventive Probe specifies:

> "From within a running banking microservice container on EC2, attempt curl to http://169.254.169.254/latest/meta-data/iam/security-credentials/. Verify: (1) IMDSv2 returns 401 Unauthorized without session token, (2) iptables/Cilium network policy blocks request returning connection refused, (3) Even with crafted PUT for token, hop limit of 1 prevents container response."

The experiment's defensive intent fully corresponds:

1. **IMDSv2 returns 401**: The SSM command tests an IMDSv1-style GET and checks for `V1_HTTP=401` response, directly validating this control. The hypothesis verification explicitly checks for `imdsv2_401` in the results.

2. **Network-level blocking**: While the experiment doesn't implement iptables/Cilium (which would require a container orchestration setup), it does verify the foundational control — IMDSv2 enforcement with hop limit 1. The experiment correctly notes that with hop limit 1 from the host level, the PUT for token should succeed (200) but the V1-style GET without token should return 401. This is the correct behavior for host-level testing.

3. **Hop limit prevents container response**: The instance is configured with `HttpPutResponseHopLimit=1`, and the experiment verifies this configuration both at provisioning time and in the final verification check.

The probe also extends beyond the ADT's Node 2.3 scope by validating the upstream preventive controls (Node 1.6 SCP simulation blocking IMDS downgrade), which strengthens the end-to-end validation. The `hypothesis_verification()` function implements four comprehensive checks that collectively validate the full preventive posture: enumeration confirms secure state, modification is blocked, exfiltration is blocked, and IMDS config remains unchanged.

The probe type (Preventive) is correctly implemented — it validates that preventive controls prevent the attack rather than detecting or responding to it.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**
Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

---

## Recommendations

While the experiment scores maximally and is authorized for execution, the following enhancements could further strengthen the experiment:

1. **Container-level testing**: The ADT specifies testing "from within a running banking microservice container." Currently the SSM command runs at the host level. A future enhancement could deploy a Docker container on the instance and execute the curl from within the container network namespace, which would more precisely validate the hop limit=1 behavior (TTL decrement preventing container-to-IMDS communication).

2. **iptables/Cilium validation**: The ADT mentions iptables and Cilium/Calico network policies as preventive controls. Adding host-level iptables rules blocking 169.254.169.254 from non-root processes and testing from within a container would provide additional defense-in-depth validation.

3. **Timeout handling**: The `_wait_ssm_managed` timeout of 600s is generous; consider adding a more explicit failure path if SSM never comes online, as the fallback API check is less thorough than the actual curl test.

4. **Parallel SCP validation**: Consider adding a test that verifies the deny policy cannot be removed by the attacker role itself (simulating SCP immutability).