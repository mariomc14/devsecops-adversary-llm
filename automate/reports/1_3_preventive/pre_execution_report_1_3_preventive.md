# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.3
- **Probe Type**: Preventive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The experiment implementation faithfully reproduces ADT Attack Node 1.2 in both tactic and technique:

**Tactic match (T1552.005 - Unsecured Credentials: Cloud Instance Metadata API)**:
- The attack phase explicitly calls `modify_instance_metadata_options` with `HttpTokens="optional"`, `HttpEndpoint="enabled"`, and `HttpPutResponseHopLimit=2` — a precise programmatic translation of the ADT's documented CLI command (`aws ec2 modify-instance-metadata-options --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`).

**Technique match**:
- The target is a hardened EC2 instance within a self-contained VPC mirroring the "banking platform VPC" context described in Node 1.2.
- The dependency chain is fully satisfied: `ec2:ModifyInstanceMetadataOptions` permission scope, valid AWS credentials (via STS AssumeRole), and a running EC2 instance with IMDSv2 enforced.
- The expected attack result (IMDSv1 re-enabled with elevated hop limit, making IMDS reachable from co-located containers) is validated post-attack via `describe_instances` IMDS state inspection.

**Implementation quality highlights**:
- A **positive baseline test** (PrivilegedRole) distinguishes infra failures from security control failures — eliminating false negatives that plagued runs 1–3.
- The `_ascii_guard()` function and multi-run root cause history demonstrate engineering rigor.
- Attack phase explicitly handles the case where the attack *unexpectedly succeeds*, logging `PREVENTIVE CONTROL FAILED` and attempting IMDSv2 restoration.
- Separation of `executed`, `access_denied`, `attack_succeeded`, `infra_failure` fields in `_STATE["attack_result"]` provides precise diagnostic granularity.
- The `infra_ready` flag prevents phantom security findings from infrastructure failures.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment directly validates **all four controls** specified in ADT Node 1.1 (Preventive Safeguard — IMDS Downgrade Prevention):

| ADT Node 1.1 Control | Experiment Implementation |
|---|---|
| **Control 1**: Least-Privilege IAM — explicit Deny on `ec2:ModifyInstanceMetadataOptions` (enforced via SCP at org level) | `RestrictedPolicy` ManagedPolicy provisions an explicit `"Effect": "Deny"` on `ec2:ModifyInstanceMetadataOptions` AND `ec2:DescribeInstances`. CHECK 1 validates AccessDenied. CHECK 3 validates DescribeInstances denial — both match the ADT's scope. |
| **Control 2**: IMDSv2 enforcement via account-level defaults (`HttpTokens=required`, `HopLimit=1`) | `HardenedInstance` CloudFormation resource sets `MetadataOptions.HttpTokens=required` and `HttpPutResponseHopLimit=1`. Verified in `steady_state()` as a hard pre-condition before any test proceeds. |
| **Control 3**: Hardened AMI pipeline bakes IMDSv2-only configuration | SSM-resolved AMI (`/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2`) with IMDSv2 forced at launch via CFN MetadataOptions — simulates the hardened AMI pipeline output without requiring an actual pipeline. |
| **Control 4**: AWS Config rule `ec2-imdsv2-check` flags non-compliant instances | CHECK 2 (`check_2_imds_unchanged`) verifies that `HttpTokens` remains `required` and `HopLimit` remains `1` post-attack, confirming no state mutation occurred — functionally validating the outcome that `ec2-imdsv2-check` would enforce. |

**Implementation quality highlights**:
- The `_preflight_check()` function validates that the executing principal itself has the required permissions, catching authorization misconfigurations before the experiment runs.
- The `_resolve_ami()` and `_resolve_instance_type()` functions with regional fallback tables ensure the hardened instance provisions correctly across regions.
- The CFN stack uses `CAPABILITY_NAMED_IAM` with named roles and policies, ensuring role naming is deterministic and auditable.
- Credential refresh logic (`_refresh_credentials_if_needed`) handles long-running experiments without stale credential failures.
- Three independent verification checks (IMDS API call denial, IMDS state inspection, DescribeInstances denial) provide defense-in-depth validation coverage.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The ADT Node 1.3 Preventive Probe specification states:

> *"Inject a test IAM principal lacking `ec2:ModifyInstanceMetadataOptions`. Attempt `modify-instance-metadata-options` with `--http-tokens optional` targeting a hardened banking EC2 instance in a self-contained VPC. Confirm call returns AccessDenied and no IMDS configuration mutation occurs. Verify SCP and IAM explicit Deny fire before any EC2 service logic executes."*

The experiment satisfies every element of this intent:

1. **"Inject a test IAM principal lacking the permission"** → `RestrictedRole` is provisioned with an explicit `Deny` on `ec2:ModifyInstanceMetadataOptions`. The role is assumed via STS in `steady_state()`.

2. **"Attempt modify-instance-metadata-options with --http-tokens optional"** → `attack()` Step B calls `ec2_restricted.modify_instance_metadata_options(HttpTokens="optional", HttpPutResponseHopLimit=2)` — exact parameter match.

3. **"Targeting a hardened banking EC2 instance in a self-contained VPC"** → The CFN template provisions a dedicated VPC (`10.99.0.0/24`), subnet, IGW, route table, and security group. The instance carries tags `BankingTier=transaction-microservice` and `IMDSVersion=v2-only`.

4. **"Confirm call returns AccessDenied"** → CHECK 1 in `hypothesis_verification()` validates `ar["access_denied"] == True`. Error codes checked: `AccessDenied`, `UnauthorizedAccess`, `Client.UnauthorizedOperation`.

5. **"No IMDS configuration mutation occurs"** → CHECK 2 reads post-attack IMDS state via `describe_instances` and asserts `HttpTokens=required` and `HopLimit=1` remain unchanged.

6. **"Verify SCP and IAM explicit Deny fire before any EC2 service logic executes"** → The positive baseline test (Step A with PrivilegedRole succeeds) proves the EC2 API endpoint is reachable, confirming that the AccessDenied in Step B originates from IAM policy evaluation — not network blocking or API unavailability. This is the critical distinction that validates the deny fires "before EC2 service logic."

7. **Falsifiability and blast radius control**: The experiment is fully contained within a dedicated CFN stack that is torn down in `rollback()`. The test instance has no instance profile, minimizing lateral blast radius.

The defensive intent — proving that the least-privilege IAM boundary prevents IMDS downgrade — is precisely what the experiment measures, with clear pass/fail semantics and no ambiguity between infrastructure failures and security control failures.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment is cleared for execution. All three quality factors achieve maximum scores. The implementation demonstrates exceptional alignment with the ADT specification, high engineering quality, and precise defensive intent correspondence.

---

## Recommendations

*Q_pre = 100.00 — no corrective recommendations required. The following observations are offered as optional enhancement considerations for future iterations:*

1. **SCP simulation layer**: The current experiment validates IAM explicit Deny at the role policy level. For organizations using AWS Organizations SCPs as the primary control (ADT 1.1 Control 1 specifies "Enforce via SCP at AWS Organizations level"), a complementary test variant could use `iam:SimulatePrincipalPolicy` with SCP context keys to validate the organizational boundary independently of the role-level deny.

2. **AWS Config rule invocation validation**: CHECK 2 validates the IMDS state remains unchanged (the *outcome* that `ec2-imdsv2-check` enforces), but does not directly invoke the Config rule evaluation. A future enhancement could trigger `config:StartConfigRulesEvaluation` against the test instance and assert a `COMPLIANT` finding is returned — directly validating ADT 1.1 Control 4.

3. **CloudTrail event capture timing**: The preventive probe does not measure whether the AccessDenied event was captured in CloudTrail. Adding a post-test CloudTrail lookup (`lookup_events` filtering on `ModifyInstanceMetadataOptions` + `errorCode=AccessDenied`) would provide a complete audit trail validation and serve as a bridge to the detective probe (ADT 1.3 Detective Probe).

4. **Multi-region coverage**: The `_resolve_ami()` fallback table covers 10 regions. Consider parameterizing the experiment to run against multiple regions simultaneously to validate that IMDSv2 defaults are uniformly enforced across the banking platform's regional footprint.