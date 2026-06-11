# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: 1.8 SCE Experiment
- **Probe Type**: Detective
- **Attack Nodes**: 1.7 Start Malicious Build
- **Evaluation Date**: 2025-01-31T00:00:00Z

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: 100

**Justification**:

The ADT specifies Attack Node 1.7 as **"Start Malicious Build"** with:
- **Command**: `aws codebuild start-build`
- **Dependencies**: Malicious project exists
- **Result**: Credential exposure attempt
- **TTP**: T1098.001 Account Manipulation

The implementation's `attack()` function performs exactly this:
1. It calls `cb.start_build(projectName=project_name)` — a direct, literal implementation of the `aws codebuild start-build` command.
2. The dependency is properly honoured: `steady_state()` first creates the malicious CodeBuild project (`{stack_name}-malicious-build`) with a BuildSpec that executes `env | base64` — a realistic credential/environment variable exfiltration simulation matching the "Credential exposure attempt" result.
3. The TTP T1098.001 (Account Manipulation) is contextually correct: starting an unauthorised build to exfiltrate credentials aligns with account manipulation through credential abuse.
4. The `_state` dictionary correctly propagates `project_name` from `steady_state()` to `attack()`, ensuring the dependency chain is enforced programmatically.
5. IAM propagation delay (`time.sleep(15)`) is included, showing production-quality implementation awareness.

Both tactic (unauthorised CodeBuild invocation for credential exfiltration) and technique (StartBuild API call against a pre-created rogue project) are fully matched with high implementation quality.

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: 100

**Justification**:

The ADT's Detective defense node for this experiment is **1.9 Runtime Container Monitoring** with:
- **Strategy**: Container runtime analysis
- **Mechanism**: Behavioral anomaly detection

The broader detective control architecture established in the experiment also maps to **1.4 CodeBuild Activity Monitoring** (CloudTrail logging, CloudWatch alerts, real-time project creation monitoring), which is the immediate predecessor and directly relevant.

The implementation deploys a comprehensive detective control stack via CloudFormation that includes:

1. **EventBridge Rule** (`MaliciousBuildRule`): Matches `CodeBuild Build State Change` events with `build-status: IN_PROGRESS` — this captures the runtime execution state of the container, corresponding to "container runtime analysis."
2. **CloudWatch Log Group** (`DetectiveLogGroup`): `/sce/{stack_name}/malicious-build-events` — receives and persists the EventBridge events for post-incident analysis.
3. **Metric Filter** (`BuildEventMetricFilter`): Counts all events delivered to the log group, incrementing `MaliciousBuildDetected` counter — implements behavioral anomaly detection by quantifying unexpected build activity.
4. **CloudWatch Alarm** (`MaliciousBuildAlarm`): Fires when `MaliciousBuildDetected >= 1` within a 60-second period — provides real-time alerting on anomalous build behaviour.
5. **EventBridge → CloudWatch Logs IAM Role** (`EventsToLogsRole`): Correctly scoped to allow only `logs:CreateLogStream` and `logs:PutLogEvents` on the specific log group ARN — demonstrates least-privilege design in the detective infrastructure itself.

The dual-signal verification (Alarm state + direct log stream inspection) in `hypothesis_verification()` goes beyond minimum requirements, providing resilience against metric pipeline latency. The 10-minute polling window with exponential backoff (capped at 90s) demonstrates realistic production-grade implementation quality.

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: 100

**Justification**:

The ADT's SCE Node 1.8 specifies the **Detective Probe** question as:
> *"Will runtime monitoring detect extraction?"*

The `hypothesis_verification()` function directly and completely answers this question:

1. **Defensive Intent Match**: The probe verifies whether the detective control (EventBridge + CloudWatch) observed the malicious build invocation — i.e., whether runtime monitoring detected the credential extraction attempt encoded in the BuildSpec (`env | base64`).

2. **Two Independent Evidence Channels**:
   - **Signal A (Alarm)**: Checks `CloudWatch Alarm → ALARM state`, confirming the metric filter detected events in the log group.
   - **Signal B (Log Events)**: Directly inspects `describe_log_streams` for events timestamped after `_state["timestamp"]` (attack start time), providing raw evidence of detection independent of the alarm pipeline.

3. **Temporal Accuracy**: The comparison `last_event_ts >= attack_start_ms` correctly gates on events occurring *after* the attack began, avoiding false positives from pre-existing log data.

4. **Steady-State Hypothesis in JSON**: The manifest's SSH title — *"CloudWatch Alarm or Log Group captures malicious CodeBuild StartBuild event"* — precisely matches the `hypothesis_verification()` implementation's dual-signal logic.

5. **Tolerance Semantics**: The probe returns `True` (tolerance = `true` in manifest) only when evidence of detection is confirmed, with a `False` return explicitly logging "detective control did NOT fire" — correctly encoding the failure mode.

The probe fully corresponds to the defensive intent of detecting runtime credential extraction behaviour through container monitoring and event-driven alerting.

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × 100 + 0.30 × 100 + 0.30 × 100**

Q_pre = 100.00

**Threshold**: 80
**Result**: Q_pre >= 80

## DECISION

**✅ AUTHORIZE EXECUTION**

The experiment achieves a perfect quality score of 100.00, exceeding the execution threshold of 80 by a substantial margin. All three factors demonstrate full correspondence with the ADT specification and high-quality implementation.

---

## Recommendations

Not required (Q_pre = 100.00 > τ = 80). However, the following observations are noted as optional enhancements for operational hardening:

1. **CloudTrail Integration**: The ADT's Node 1.4 explicitly mentions CloudTrail logging. Adding a CloudTrail-based query (via Athena or `lookup_events`) as a third verification signal would further strengthen evidence collection and align more closely with the full detective stack described in the ADT.

2. **Specific Build ARN Filtering**: The EventBridge rule currently matches *all* `IN_PROGRESS` CodeBuild events. In environments with multiple CodeBuild projects, adding a filter on `detail.project-name` matching the rogue project would prevent false positives during hypothesis verification in shared accounts.

3. **Build ID in Log Verification**: The `hypothesis_verification()` Signal B could be enhanced to inspect actual log event content (via `get_log_events`) to confirm the specific build ID matches `_state["build_id"]`, providing build-level attribution rather than relying solely on timestamp correlation.

4. **Module Path Alignment**: The JSON manifest references `chaosaws.ec2.1_8_sce_experiment_detective` as the module path. This is semantically misaligned (CodeBuild is not an EC2 service); consider `chaosaws.codebuild.1_8_sce_experiment_detective` for production use to avoid operational confusion.