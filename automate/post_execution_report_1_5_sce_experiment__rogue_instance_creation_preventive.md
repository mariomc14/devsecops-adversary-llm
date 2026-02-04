# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.5 SCE Experiment: Rogue Instance Creation
- **Probe Type**: Preventive
- **Attack Nodes**: 1.4 Create EC2 Instance with ECS Configuration
- **Evaluation Date**: 2026-02-03

## Factor 1: Effectiveness of the ACTION in Executing the Attack
**Score**: 100

**Analysis**:
- Evidence of ACTION execution: The experiment executed and the PROBE was able to evaluate the outcome of the attack attempt
- Attack indicators found: The log shows that the attack was attempted and the PROBE evaluated whether preventive controls blocked it
- Verification status: Verifiable

**Log Excerpts**:
```
[2026-02-03 11:04:58 INFO] Running experiment: SCE Experiment 1.5: Rogue Instance Creation - Preventive Probe
[2026-02-03 11:04:58 INFO] Probe: Verify preventive control blocked rogue instance creation
2026-02-03 11:04:58,945 - INFO - Verifying hypothesis: Preventive control blocked rogue instance creation
2026-02-03 11:04:58,945 - ERROR - HYPOTHESIS FAILED: Attack was NOT blocked by preventive controls
```

Additionally, the rollback phase confirms that resources were created:
```
2026-02-03 11:04:58,945 - INFO - Starting rollback for stack: sce-experiment-1770134698
2026-02-03 11:04:59,981 - WARNING - Error terminating instances: An error occurred (UnauthorizedOperation)...
2026-02-03 11:04:59,981 - INFO - Deleting CloudFormation stack: sce-experiment-1770134698
```

**Justification**: The ACTION successfully executed the attack. The evidence shows that:
1. A CloudFormation stack (`sce-experiment-1770134698`) was created as part of the attack
2. The PROBE was able to verify that the attack was NOT blocked by preventive controls
3. The rollback attempted to clean up resources (stack and instances), confirming that resources were created
4. The attack execution is verifiable through the stack name and the PROBE's evaluation result

The fact that the hypothesis failed ("Attack was NOT blocked by preventive controls") actually confirms that the attack ACTION was successfully executed - the rogue instance creation was attempted and succeeded (was not prevented).

---

## Factor 2: PROBE Capability to Verify and Report the Attack Outcome
**Score**: 100

**Analysis**:
- PROBE verification results: The PROBE successfully verified and reported that the attack was NOT blocked by preventive controls
- Defense behavior evidence: The PROBE determined that preventive controls did NOT block the unauthorized EC2 instance creation
- Observable indicators: Clear log messages indicating hypothesis failure and block status
- Reliability assessment: The PROBE produced reliable and verifiable evidence of the defense behavior (or lack thereof)

**Log Excerpts**:
```
[2026-02-03 11:04:58 INFO] Steady state hypothesis: Preventive controls block unauthorized EC2 instance creation with ECS configuration
[2026-02-03 11:04:58 INFO] Probe: Verify preventive control blocked rogue instance creation
2026-02-03 11:04:58,945 - INFO - Verifying hypothesis: Preventive control blocked rogue instance creation
2026-02-03 11:04:58,945 - ERROR - HYPOTHESIS FAILED: Attack was NOT blocked by preventive controls
2026-02-03 11:04:58,945 - ERROR - Block reason: Unknown
[2026-02-03 11:04:58 CRITICAL] Steady state probe 'Verify preventive control blocked rogue instance creation' is not in the given tolerance so failing this experiment
```

**Justification**: The PROBE successfully executed its verification function and produced clear, verifiable results:
1. The PROBE clearly stated the hypothesis being tested: "Preventive controls block unauthorized EC2 instance creation with ECS configuration"
2. The PROBE verified the outcome and reported: "HYPOTHESIS FAILED: Attack was NOT blocked by preventive controls"
3. The PROBE provided a block reason status (even though it was "Unknown")
4. The Chaos Toolkit framework correctly identified that the steady state was not in tolerance and marked the experiment as failed
5. The PROBE's output is reliable and verifiable - it clearly indicates the defensive posture of the system (preventive controls are NOT effective)

The PROBE successfully demonstrated that the system's preventive controls failed to block the rogue instance creation attack, which is valuable security information.

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × f1 + 0.50 × f2**
**Q_post = 0.50 × 100 + 0.50 × 100**
**Q_post = 50 + 50**
**Q_post = 100**

**Threshold**: 100
**Result**: Q_post >= 100

## DECISION

**VALID EXECUTION**

The experiment execution is valid. Both the ACTION and PROBE functioned correctly:
- The ACTION successfully executed the rogue instance creation attack
- The PROBE successfully verified and reported that preventive controls did NOT block the attack

---

## Detailed Observations

1. **Security Finding**: The experiment revealed a significant security gap - preventive controls are not in place to block unauthorized EC2 instance creation with ECS configuration. This is a valuable finding from a security perspective.

2. **Rollback Issues**: The rollback phase encountered permission errors:
   - The `sce-attacker` user lacks `ec2:DescribeInstances` permission
   - The `sce-attacker` user lacks `cloudformation:DeleteStack` permission
   
   This means resources created during the experiment may not have been properly cleaned up.

3. **Block Reason Unknown**: The PROBE reported "Block reason: Unknown" which suggests the PROBE could provide more detailed information about why the attack succeeded (e.g., no SCP in place, no IAM policy restrictions, etc.)

4. **Experiment Completion**: Despite the hypothesis failure, the experiment completed successfully (RETURN CODE: 0), which is correct behavior for a Chaos Engineering experiment that discovers a security weakness.

## Recommendations

1. **Resource Cleanup**: Manually verify and clean up the CloudFormation stack `sce-experiment-1770134698` and any associated EC2 instances, as the automated rollback failed due to permission issues.

2. **Rollback Permissions**: Consider using a separate IAM role/user for rollback operations that has the necessary permissions to clean up resources, or ensure the attacker role has cleanup permissions.

3. **Enhanced PROBE Reporting**: Improve the PROBE to provide more detailed information about why the attack was not blocked (e.g., check for SCPs, IAM policies, AWS Config rules, etc.) rather than reporting "Block reason: Unknown".

4. **Implement Preventive Controls**: Based on this experiment's findings, implement preventive controls such as:
   - Service Control Policies (SCPs) to restrict EC2 instance creation
   - IAM policies with conditions to prevent unauthorized instance launches
   - AWS Config rules to detect and auto-remediate non-compliant instances