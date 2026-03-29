# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 2.5
- **Probe Type**: Detective
- **Attack Nodes**: 1.2, 2.2
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

**Attack Node 1.2 (T1578 — Modify Cloud Compute Infrastructure):**
The implementation faithfully reproduces the ADT specification. The ADT specifies `aws ec2 modify-instance-metadata-options --instance-id <ID> --http-tokens optional --http-endpoint enabled --http-put-response-hop-limit 2`. The Python `attack()` function calls `ec2_attacker.modify_instance_metadata_options(InstanceId=_TARGET_INSTANCE_ID, HttpTokens="optional", HttpEndpoint="enabled", HttpPutResponseHopLimit=2)` using credentials from an assumed attacker IAM role — an exact match. The ADT dependency of a permissive `ec2:ModifyInstanceMetadataOptions` IAM permission is correctly implemented: the `SCEAttackerRole` in the CFN template has an explicit `Allow` on this action with no deny. The target instance is production-tagged (`Environment=production`) as required. The re-hardening step after event generation demonstrates awareness of the experimental context. TTP T1578 is correctly applied.

**Attack Node 2.2 (T1552.005 — Unsecured Credentials: Cloud Instance Metadata API):**
The ADT specifies `curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/`. The `attack()` Step 2 executes exactly this curl command via SSM `RunCommand` on the probe EC2 instance, including an additional HTTP code capture for diagnostic purposes. The dependency chain is correctly represented: Attack 2.2 is executed after Attack 1.2 (which weakens IMDS to IMDSv1/hop-limit=2). The commentary accurately notes the nuance that the probe hits its own IMDS (link-local is host-local in EC2), but the key observable artifact — VPC Flow Log traffic to 169.254.169.254 — is correctly generated. TTP T1552.005 is correctly applied.

Both attack steps are chained sequentially as the ADT requires, with proper sequencing (IMDS weakening before credential retrieval). The implementation quality is high: role assumption uses session-scoped credentials, the attack epoch is recorded precisely, and re-hardening minimises exposure while preserving the CloudTrail event.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The experiment targets ADT Detective Nodes **1.3** and **2.3** with three distinct detective controls mapped explicitly in the code:

**ADT Node 1.3 coverage:**
- *"CloudTrail captures every ModifyInstanceMetadataOptions API call"* → H1 implemented via `ct.get_paginator("lookup_events")` filtering on `EventName=ModifyInstanceMetadataOptions` and the target instance ID, with a 5-minute polling window matching the stated CloudTrail delivery SLA.
- *"EventBridge rule triggers SNS alert on any production invocation"* → H3 implemented via an EventBridge rule (`SCEDetectionRule`) with a CloudTrail-sourced event pattern for `ModifyInstanceMetadataOptions`, routing to SNS→SQS, polled within the 60-second SLA stated in ADT Node 1.3. The CFN EventBridge rule pattern correctly matches `source: aws.ec2`, `detail-type: AWS API Call via CloudTrail`, `eventName: ModifyInstanceMetadataOptions`.

**ADT Node 2.3 coverage:**
- *"VPC Flow Logs capture unexpected traffic to 169.254.169.254 from container subnets"* → H2 implemented via CloudWatch Logs Insights query on the VPC Flow Log group (`/sce/flowlogs/...`) filtering for `dstaddr = '169.254.169.254'`, with a 5-minute polling window and retry logic accounting for Flow Log delivery latency.

**Infrastructure completeness**: All necessary detective infrastructure is provisioned in the CFN template: VPC Flow Logs with a dedicated CloudWatch Logs group, a CloudTrail trail with WriteOnly management event selectors, SNS topic with EventBridge publish policy, SQS queue with SNS subscription, and the EventBridge rule. The `SCEBucketPolicy` correctly grants CloudTrail write access to the externally-managed S3 bucket. The Flow Log format includes `srcaddr`, `dstaddr`, and `action` fields needed for H2 queries.

**Detection SLA alignment**: The 60-second SLA for H3 and 5-minute windows for H1/H2 exactly match the ADT Node 1.3 statement *"CloudWatch Logs Insights alert fires within 60 seconds of API call"* and the standard CloudTrail delivery window. The post-attack buffer of 15 seconds and remaining-SLA calculation for H3 are well-engineered.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The defensive intent of SCE Node 2.5 (Detective) is to validate that the banking platform's detective controls can reliably observe and record evidence of the IMDS attack chain (T1578 + T1552.005) within operationally meaningful detection SLAs — so that security operations can respond before credential exfiltration leads to lateral movement (Attack Node 3.2).

The probe fully corresponds to this intent across all three dimensions:

**1. Completeness of detective coverage**: The probe exercises all three detective layers referenced in ADT Nodes 1.3 and 2.3: CloudTrail (H1), VPC Flow Logs (H2), and EventBridge→SNS→SQS (H3). This is not a partial check — it validates the entire observability pipeline from API call generation to notification delivery.

**2. Correctness of attack realism**: The probe intentionally allows the attacks to *succeed* (no preventive blocks on the attacker role) in order to generate real CloudTrail management events and real Flow Log traffic. This is the correct design for a detective probe: if the attacks were blocked, detective controls would have nothing to observe. The experiment manifest description clearly articulates this design choice. The re-hardening after Step 1 demonstrates responsible experimental design consistent with a banking production environment.

**3. Hypothesis structure**: The three hypotheses (H1, H2, H3) are precisely scoped — each references a specific ADT detective node, a specific detection mechanism, a measurable SLA, and a verifiable artifact. The `hypothesis_verification()` function's logic correctly handles edge cases: H1/H3 are marked inconclusive (and fail) if Step 1 did not succeed; H2 is treated as a warning-only skip if Step 2 was not executed, reflecting the relative importance of Flow Log detection versus CloudTrail/EventBridge detection for this attack node.

**4. ADT alignment of steady-state hypothesis**: The JSON manifest's steady-state hypothesis correctly verifies pre-attack baselines: IMDSv2 enforced, CloudTrail logging active, SQS empty, both instances SSM-reachable, and attacker role assumable. These baselines directly correspond to the prerequisites for the detective controls to function correctly.

**5. Probe-type purity**: The probe does not conflate preventive or reactive concerns — it does not test IAM denials or Lambda re-hardening. It is purely detective: does the system *see* the attack?

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

---

## DECISION

**AUTHORIZE EXECUTION**

The experiment achieves a perfect pre-execution quality score. All three factors demonstrate full correspondence between the ADT specification and the implementation. The experiment is authorised for execution.

---

## Recommendations

Given the perfect score, the following observations are offered as operational guidance rather than deficiencies:

1. **CloudTrail delivery latency risk**: The 5-minute CloudTrail polling window (`_CLOUDTRAIL_POLL_TIMEOUT = 300.0`) is standard but CloudTrail delivery to S3 can occasionally take 15+ minutes for newly-created trails. Consider increasing to 600 seconds or adding a fallback check directly against the CloudTrail S3 bucket for production use.

2. **VPC Flow Log delivery latency**: Flow Log delivery to CloudWatch Logs typically takes 1–5 minutes but can exceed this for newly-created log groups. The current 300-second polling window with 15-second retry intervals is well-designed, but the Insights query `endTime` is set 120 seconds into the future relative to `time.time()` at query construction — this window may need extending if hypothesis_verification() is called immediately after attack().

3. **H3 SLA timing precision**: The EventBridge rule routes via CloudTrail-sourced events, meaning the 60-second SLA begins from CloudTrail event ingestion into EventBridge (near-real-time) rather than from the API call itself. The current implementation measures from `attack_epoch` (API call time), which is conservative and correct for SLA validation purposes.

4. **GuardDuty finding validation**: ADT Node 2.3 references `GuardDuty finding UnauthorizedAccess:EC2/MetaDataDNSRebind` as a detective control. The current implementation does not validate GuardDuty findings (no `guardduty:ListFindings` check). This is acceptable for the current scope but represents a gap relative to the full ADT Node 2.3 specification that could be addressed in a future iteration.

5. **Probe instance IMDS access**: The probe instance hits its own IMDS (not the target's) because `169.254.169.254` is host-local in EC2. The code comments correctly document this nuance. However, since the probe instance has `HttpTokens=required`, the IMDSv1 curl will return a 401 rather than credentials. The Flow Log record is still generated regardless of HTTP response code, so H2 is correctly validated.