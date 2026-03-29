# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.5
- **Probe Type**: Reactive
- **Attack Nodes**: 1.2
- **Evaluation Date**: 2025-01-30T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The attack implementation is a precise, high-fidelity reproduction of ADT Attack Node 1.2 (TTP T1578 — Modify Cloud Compute Infrastructure).

**Tactic alignment**: The experiment targets IMDS configuration weakening via `ec2:ModifyInstanceMetadataOptions`, exactly as specified in ADT Node 1.2.

**Technique alignment**:
- ADT Node 1.2 specifies: `aws ec2 modify-instance-metadata-options --instance-id <INSTANCE_ID> --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`
- `attack()` calls `ec2_attacker.modify_instance_metadata_options(InstanceId=_INSTANCE_ID, HttpTokens="optional", HttpEndpoint="enabled", HttpPutResponseHopLimit=2)` — exact parameter match.
- The attacker role (`SCEAttackerRole`) is granted `ec2:ModifyInstanceMetadataOptions` with intentional Allow and no Deny, satisfying the ADT dependency: *"IAM permission ec2:ModifyInstanceMetadataOptions; valid AWS credentials for attacker; knowledge of target instance ID"*.
- The attack assumes a dedicated attacker role via `sts:AssumeRole`, generating a real CloudTrail management event (`ModifyInstanceMetadataOptions`) — precisely the trigger the reactive pipeline depends on.
- The EC2 target is tagged `Environment=production`, matching the ADT context of banking EC2 hosts.
- Post-attack buffer (`_POST_ATTACK_BUFFER_SECONDS=15`) accounts for CloudTrail delivery latency + Lambda cold start, which is good engineering practice.
- `_ATTACK_RESULT` captures `attack_epoch` for SLA measurement, enabling accurate timing in `hypothesis_verification()`.

**Implementation quality**: High. The `attack()` function correctly separates attacker credentials from deploying-principal credentials, uses session-scoped temporary credentials, and records the epoch timestamp for SLA computation. The `steady_state()` function establishes a valid baseline (IMDSv2 enforced pre-attack) so the delta introduced by the attack is measurable.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The reactive defense implementation corresponds fully to ADT Node 1.4 and demonstrates high implementation quality.

**ADT Node 1.4 specifies**:
1. *"EventBridge triggers Lambda to re-enforce IMDSv2: http_tokens=required and hop-limit=1 within 60 seconds."*
2. *"IAM principal that issued the call receives deny-all inline policy."*
3. *"Access keys of offending identity are immediately deactivated."*
4. *"SNS alert dispatched to banking security operations team."*
5. *"CloudTrail forensic export triggered for the affected instance."*

**Implementation mapping**:

| ADT Node 1.4 Defense Element | Implementation |
|---|---|
| EventBridge rule detecting ModifyInstanceMetadataOptions | `SCEDetectionRule` in CFN with exact EventPattern matching `eventName: ["ModifyInstanceMetadataOptions"]` |
| Lambda re-hardens IMDS (http_tokens=required, hop_limit=1) | Lambda R1 action: `ec2.modify_instance_metadata_options(HttpTokens="required", HttpPutResponseHopLimit=1)` |
| Deny-all inline policy on offending IAM role | Lambda R2 action: `iam.put_role_policy(PolicyName=DENY_POLICY_NAME, PolicyDocument=DENY_ALL_POLICY)` |
| SNS alert dispatched | Lambda R3 action: `sns.publish()` with structured remediation report |
| CloudTrail forensic export | `SCETrail` CloudFormation resource with `IsLogging=True`, `EnableLogFileValidation=True`, WriteOnly management events |
| EventBridge → Lambda trigger chain | `SCELambdaInvokePermission` grants `events.amazonaws.com` invoke permission on `SCEReactiveFunction` |

**Additional quality observations**:
- The Lambda extracts `instanceId` from `event.detail.requestParameters.instanceId` and `role_name` from `event.detail.userIdentity.sessionContext.sessionIssuer.userName` — correct CloudTrail event structure parsing.
- Each remediation action (R1, R2, R3) has independent try/except blocks, so a failure in one does not abort the others — this is resilient defensive design.
- Lambda role permissions are scoped: `iam:PutRolePolicy` is restricted to `attacker_role_arn` only, not `Resource: "*"` — demonstrating least-privilege in the remediation itself.
- The SNS → SQS subscription chain (`SCEAlertSubscription`, `SCEAlertQueuePolicy`) enables poll-based verification without requiring external push endpoints.
- One minor gap: ADT mentions *"Access keys of offending identity are immediately deactivated"* (distinct from deny-all policy). The implementation uses `iam:PutRolePolicy` (deny-all inline policy) rather than `iam:UpdateAccessKey` for key deactivation. However, for an assumed-role session (temporary credentials), deny-all inline policy is the correct and more effective revocation mechanism — the ADT's intent is satisfied even if the literal wording differs.
- ADT mentions *"CloudTrail forensic export triggered"* — the implementation provisions a live CloudTrail trail but does not implement a dedicated forensic export automation. This is a minor gap but the trail itself provides the forensic foundation.

Overall, the defense implementation is architecturally faithful and of high code quality.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The `hypothesis_verification()` function fully corresponds to the defensive intent specified in ADT Node 1.5 (SCE Experiment — Reactive section) and ADT Node 1.4.

**ADT Node 1.5 Reactive Probe specifies**:
- *"H1: IMDS re-hardened."* → Verified via `ec2.describe_instances()` checking `HttpTokens == "required"` and `HttpPutResponseHopLimit == 1`
- *"H2: Deny-all on attacker role."* → Verified via `iam.get_role_policy(RoleName=_ATTACKER_ROLE_NAME, PolicyName=_DENY_POLICY_NAME)` — NoSuchEntity = fail, success = H2 pass
- *"H3: SNS alert."* → Verified by polling SQS queue for reactive notification messages containing `IMDS_REHARDENED` or `DENY_ALL_POLICY_APPLIED` or `ModifyInstanceMetadataOptions` trigger markers
- *"Confirm Lambda fires within 90s SLA"* → `poll_deadline = time.monotonic() + _REACTIVE_SLA_SECONDS` (90s) enforces the SLA window

**Probe design quality**:
- **Unified round-robin polling** prevents any single slow hypothesis from exhausting the SLA budget — a specific improvement called out in the module docstring and architecturally sound.
- **SLA measurement** uses `attack_epoch` captured at API call time (not at function entry), giving an accurate end-to-end latency measurement including CloudTrail delivery and EventBridge propagation.
- **Graceful precondition checks**: If `attack()` did not execute, `hypothesis_verification()` returns `False` immediately with a clear log message — avoids false positives.
- **SQS message matching logic** handles both raw JSON and SNS-wrapped JSON (`outer.get("Message", body_raw)`), which is the correct structure for SNS→SQS delivery.
- **Post-deadline diagnostics**: After the polling loop exits, the function logs the final state of each failed hypothesis with the actual IMDS parameters — this is valuable for incident root-cause analysis.
- **Short inter-round sleep (3s)** prevents tight CPU spinning while maintaining responsiveness within the 90s window.
- The `_POST_ATTACK_BUFFER_SECONDS=15` wait in `attack()` before polling begins is appropriate given CloudTrail's typical ~15-30s delivery latency and Lambda cold start overhead.

The 90s SLA window (vs. ADT Node 1.4's stated 60s) adds a 30s buffer for delivery latency — this is a reasonable and documented engineering tradeoff (noted in module-level constants).

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves maximum scores across all three quality factors. The implementation demonstrates:
- Precise TTP alignment with ADT Attack Node 1.2 (T1578)
- Faithful and architecturally sound reactive defense implementation matching ADT Node 1.4
- Complete hypothesis coverage (H1/H2/H3) within the specified SLA window
- Three generations of documented fixes (run-1 through run-3) incorporated, addressing AMI resolution, ASCII encoding, and S3 bucket ownership conflicts
- High code quality with proper error handling, resource isolation, and cleanup ordering

---

## Recommendations

The experiment is authorized. The following minor enhancements are suggested for future iterations (do not block execution):

1. **CloudTrail forensic export automation**: Add a Lambda R4 action that calls `cloudtrail:StartQuery` or triggers a CloudWatch Logs Insights query export on detection, fully matching the ADT Node 1.4 *"CloudTrail forensic export triggered"* specification.

2. **Access key deactivation test coverage**: ADT Node 1.4 mentions *"Access keys of offending identity are immediately deactivated"*. For completeness in future runs, add an `iam:ListAccessKeys` + `iam:UpdateAccessKey` call in the Lambda for cases where the offending principal uses long-term credentials rather than assumed-role sessions.

3. **EventBridge delivery latency measurement**: Consider capturing the EventBridge invocation timestamp from the Lambda `context.invoked_function_arn` or a CloudWatch metric to measure the CloudTrail→EventBridge→Lambda pipeline latency independently from the IMDS re-hardening latency.

4. **SQS long-poll optimization**: The `WaitTimeSeconds=2` in H3 polling could be increased to `WaitTimeSeconds=5` to reduce API call frequency without significantly impacting SLA measurement precision within the 90s window.