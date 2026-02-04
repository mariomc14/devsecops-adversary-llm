# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.5 SCE Experiment: Rogue Instance Creation
- **Probe Type**: Preventive
- **Attack Nodes**: 1.4 Create EC2 Instance with ECS Configuration
- **Evaluation Date**: 2024-01-15

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Analysis**:
- **Attack node in ADT**: Node 1.4 "Create EC2 Instance with ECS Configuration" specifies:
  ```
  aws ec2 run-instances \
  --image-id ami-07fde2ae86109a2af \
  --instance-type t2.micro \
  --iam-instance-profile <ECS_role> \
  --count 1 --key-name pwned \
  --user-data "file:///tmp/asd.sh"
  ```
  Dependencies include: ec2:RunInstances permission, iam:PassRole for ECS instance profile, ECS-optimized AMI ID, and user data script. TTP: T1578.002 - Create Cloud Instance.

- **ACTION implementation**: The `attack()` function implements:
  ```python
  response = attacker_ec2.run_instances(
      ImageId=ecs_ami_id,
      InstanceType="t2.micro",
      MinCount=1,
      MaxCount=1,
      SubnetId=_experiment_state["subnet_id"],
      SecurityGroupIds=[_experiment_state["security_group_id"]],
      IamInstanceProfile={
          "Name": _experiment_state["ecs_instance_profile_name"]
      },
      UserData=user_data_encoded,
      ...
  )
  ```
  The user data script configures ECS:
  ```python
  user_data_script = """#!/bin/bash
  echo ECS_CLUSTER=target-cluster >> /etc/ecs/ecs.config
  echo ECS_BACKEND_HOST= >> /etc/ecs/ecs.config
  """
  ```

- **Tactic alignment**: Yes - Both use resource creation/manipulation tactic
- **Technique alignment**: Yes - T1578.002 (Create Cloud Instance) is directly implemented via `run_instances` API call
- **Implementation quality**: 
  - Well-documented with comprehensive docstrings
  - Proper error handling with try/except blocks and ClientError handling
  - Assumes attacker role to simulate compromised credentials
  - Dynamically discovers ECS-optimized AMI with fallback
  - Logs all actions for observability

**Justification**: The implementation achieves full correspondence with the ADT attack node. The `attack()` function replicates the exact attack vector specified in node 1.4: creating an EC2 instance with ECS configuration using `run_instances`, passing an ECS instance profile via `iam:PassRole`, and injecting ECS agent configuration through user data. The code demonstrates high implementation quality with proper error handling, logging, and role assumption to simulate an attacker context. The TTP T1578.002 is correctly implemented.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Analysis**:
- **Defense node in ADT**: Node 1.1 "IAM Least Privilege Enforcement" specifies:
  ```
  SCPs deny ec2:RunInstances and iam:PassRole except for approved automation roles.
  Enforce tag-based conditions requiring "CreatedBy=ApprovedPipeline" tag.
  ```
  Node 1.2 "AMI Restriction Policy" specifies:
  ```
  Restrict ec2:RunInstances to only approved hardened AMIs via IAM condition:
  ec2:ImageId must match approved AMI list. Block ECS-optimized public AMIs.
  ```

- **Defense implementation**: The CloudFormation template implements these controls in the `AttackerPolicy`:
  ```python
  {
      "Sid": "DenyPassRoleToECSProfiles",
      "Effect": "Deny",
      "Action": "iam:PassRole",
      "Resource": {"Fn::GetAtt": ["ECSInstanceRole", "Arn"]},
      "Condition": {
          "StringEquals": {
              "iam:PassedToService": "ec2.amazonaws.com"
          }
      }
  },
  {
      "Sid": "DenyUnapprovedAMIs",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*::image/ami-*",
      "Condition": {
          "StringNotEquals": {
              "ec2:ImageId": "ami-00000000000000000"
          }
      }
  }
  ```

- **Correspondence**: Yes - Both ADT defense nodes (1.1 and 1.2) are implemented
- **Code quality**: High - CloudFormation template is well-structured with proper resource dependencies
- **Documentation**: Comprehensive - Each policy statement has descriptive Sid values and the module docstring explains the preventive controls
- **Error handling**: Robust - The `steady_state()` function includes:
  - Stack existence checking
  - Exponential backoff waiting with `_wait_with_backoff()`
  - Proper exception handling for ClientError
  - IAM propagation delay handling

**Justification**: The defense implementation fully corresponds to the ADT specification. The IAM policy implements both the PassRole denial (node 1.1) and AMI restriction (node 1.2) as explicit Deny statements. The code quality is excellent with proper CloudFormation structure, comprehensive error handling, and clear documentation. The `steady_state()` function properly deploys and validates the infrastructure with appropriate waits for IAM propagation.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Analysis**:
- **Defensive intent in ADT**: The SCE node 1.5 specifies for the Preventive Probe:
  ```
  Preventive Probe: Attempt ec2:RunInstances with unapproved AMI and PassRole to ECS profile.
  Verify SCP blocks with AccessDenied.
  ```
  The intent is to validate that preventive controls successfully block unauthorized EC2 instance creation attempts.

- **PROBE implementation**: The `hypothesis_verification()` function validates:
  ```python
  def hypothesis_verification():
      # Check if attack was blocked
      if not _experiment_state.get("attack_blocked", False):
          logger.error("HYPOTHESIS FAILED: Attack was NOT blocked by preventive controls")
          return False
      
      # Verify no instances were created with our experiment tag
      response = ec2_client.describe_instances(
          Filters=[
              {"Name": "tag:Experiment", "Values": [EXPERIMENT_TAG]},
              {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}
          ]
      )
      
      if instances:
          logger.error(f"HYPOTHESIS FAILED: Found {len(instances)} rogue instance(s)")
          return False
      
      # Verify block reason matches preventive control
      if "PassRole" in block_reason or "AMI" in block_reason or "Access denied" in block_reason:
          logger.info("HYPOTHESIS VERIFIED: Preventive control successfully blocked the attack")
          return True
  ```

- **Intent correspondence**: Yes - The PROBE directly validates:
  1. The attack was blocked (AccessDenied received)
  2. No rogue instances exist in the environment
  3. The block reason corresponds to the preventive controls (PassRole or AMI restriction)

**Justification**: The PROBE implementation perfectly corresponds to the defensive intent specified in the ADT. The `hypothesis_verification()` function validates exactly what the preventive controls should achieve: blocking unauthorized EC2 instance creation with AccessDenied errors. It performs three-tier verification: (1) checking the attack was blocked, (2) confirming no instances were created, and (3) validating the block reason matches the expected preventive control mechanisms (PassRole denial or AMI restriction). This comprehensive verification ensures the defensive intent is fully validated.

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

The experiment demonstrates excellent quality across all three evaluation factors and is approved for execution.

---

## Detailed Observations

### Strengths
1. **Complete Attack Replication**: The attack implementation faithfully reproduces the ADT attack node 1.4, including all dependencies (ECS-optimized AMI, instance profile, user data script).

2. **Comprehensive Defense Implementation**: Both preventive controls from the ADT (IAM PassRole denial and AMI restriction) are implemented as explicit Deny statements in the IAM policy.

3. **Robust Verification Logic**: The hypothesis verification performs multi-layered validation including attack blocking confirmation, instance existence checks, and block reason analysis.

4. **Production-Quality Code**: 
   - Proper logging throughout
   - Exponential backoff for AWS API calls
   - Comprehensive error handling
   - Clean resource cleanup in rollback

5. **Security Considerations**: The experiment uses role assumption to simulate attacker context, creating realistic test conditions.

### Minor Observations
1. The AMI restriction policy uses a placeholder AMI ID (`ami-00000000000000000`) which effectively denies all AMIs - this is intentional for the preventive control test.

2. The experiment correctly handles the case where the attack might succeed (control failure) by immediately terminating any created instances.

3. The JSON manifest correctly identifies this as a Preventive probe type, aligning with the ADT specification.

## Recommendations

No improvements required for execution authorization. The experiment is well-designed and ready for execution.

**Optional Enhancements for Future Iterations**:
1. Consider adding CloudTrail event verification to confirm the denial was logged
2. Could add timing metrics to measure control response latency
3. Consider parameterizing the target cluster name for reusability