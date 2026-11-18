# Controlled validation campaign — runner v5 (no-resampling, audit trail) — Reviewer 2 follow-up

This directory contains the **prospective controlled validation campaign** added after the second IJIS major-revision decision. It is isolated from the historical `automate/` workflow so that the original archive remains unchanged.

## Frozen scientific design

- Branch: Branch 1 only.
- Tasks: `CN1-P` (final-manuscript Chaos Node `1.3`, preventive) and `CN2-D` (final-manuscript Chaos Node `1.8`, detective).
- Models: Claude Haiku 4.5 and Claude Sonnet 4.6 via AWS Bedrock.
- Conditions:
  1. `chaos_adt_feedback`: Chaos ADT + semantic `Q_pre` gate + iterative feedback.
  2. `chaos_adt_no_feedback`: same Chaos-ADT representation/gate, but fresh no-feedback regeneration.
  3. `conventional_adt_feedback`: conventional ADT baseline, no Chaos Node / semantic gate, with feedback.
  4. `direct_sce_feedback`: direct LLM-to-SCE baseline, no ADT / semantic gate, with feedback.
- 5 independent repetitions per `(task, model, condition)`.
- Maximum 3 scientific attempts per trajectory; online early stopping at `Q_post >= 100`.
- Primary paper outcome should use independent/adjudicated human `VALID / INCONCLUSIVE / INVALID`, not automated `Q_post` alone.
- Region: `us-east-1`.
- Bedrock requests: `maxTokens=8192`, `temperature=1.0`; `topP/topK` are not overridden.
- Predetermined sequential schedule: 80 trajectories.

Sonnet 4.5 from v1 was replaced **before any scientific trajectory was executed** because Bedrock rejected access after the model entered Legacy state and the account had been inactive on that model. Sonnet 4.6 was already part of the original paper's model set and is used prospectively under the same frozen request configuration as Haiku 4.5.

## Important changes from v1

- CloudFormation-safe attempt names (`cn1-p`, `cn2-d`; no underscores).
- A fixed campaign network (`cvr2-network`) is provisioned once and reused across all conditions.
- Attempt stacks must reference that subnet/security group and may not create/delete VPC/network resources.
- CN2-D uses **CloudTrail Event History (`LookupEvents`)**; it does not create a CloudTrail trail, S3 trail bucket, AWS Config, EventBridge, or CloudWatch telemetry resources.
- Existing historical `sce-*` resources are reported as warnings and are never deleted by this runner.
- `chaos run` has a 30-minute hard timeout.
- Once Bedrock has produced a candidate for an attempt, that candidate is frozen. Resumption reuses the archived candidate/evaluations/execution evidence and never silently re-samples the model under the same attempt ID.
- Technical validation no longer rejects harmless words such as `simulated`, `todo`, or `placeholder` merely because they appear in comments/docstrings; only unambiguous unresolved markers are hard failures.
- Preflight checks every configured model and reports all results instead of crashing on the first unavailable model.

## Changes in v4

v4 changes only the runner's technical validation and its resume/audit bookkeeping. Prompts, models, tasks, thresholds, schedule, conditions and the fixed `cvr2-network` are identical to v3.

1. **Typed network parameters are accepted.** `AWS::EC2::VPC::Id`, `AWS::EC2::Subnet::Id` and `AWS::EC2::SecurityGroup::Id` are CloudFormation parameter types that reference the existing fixed network, which is what the prompt asks for. v3 rejected them because the forbidden-resource check matched them as text. Real forbidden resources (`AWS::EC2::VPC`, `AWS::EC2::Subnet`, `AWS::EC2::SecurityGroup`, `AWS::EC2::SecurityGroupIngress`, `AWS::S3::Bucket`, `AWS::CloudTrail::Trail`, `AWS::Config::*`, `AWS::IAM::User`…) are still rejected.
2. **Interrupted retries are no longer re-sampled.** In v3, after a failed Bedrock call (for example throttling), the failure record stayed on disk. If the retry was then interrupted, the next resume called the model again instead of stopping as ambiguous. v4 clears the failure record only when a new call starts, so an interrupted retry is reported as `ambiguous_*_state`.
3. **Append-only audit trail per attempt.** See "Audit trail per attempt" below.

## Changes in v5 (applied on 2026-11-15, after the campaign halted at trajectory 30/80)

v5 changes only the runner's technical validation and per-attempt stack cleanup. Prompts, models, tasks, thresholds, schedule, conditions and the fixed `cvr2-network` are identical to v4. The working directory keeps its `-v4` name so that the running campaign's paths do not change; the code revision is recorded as `runner_revision = v5-paginator-never-created-cleanup`.

1. **CN2-D validator false positive fixed.** v4 required a direct `cloudtrail.lookup_events()` call and rejected the equivalent `cloudtrail.get_paginator("lookup_events")`, which issues the same CloudTrail LookupEvents API. This rejected 20 of the 21 Sonnet 4.6 CN2-D candidates generated before the halt, and it was their only validation error. None of them was executed. Offline re-validation of all 71 archived candidates with v5 changes exactly those 20 verdicts (all now pass with no error) and leaves the other 51 unchanged. Calls that never use LookupEvents are still rejected.
2. **Campaign restarted from scratch.** The 7 Sonnet 4.6 CN2-D trajectories completed under the false positive (orders 5, 11, 12, 15, 17, 26, 28) are listed in `INVALIDATED.json`. To keep every trajectory under the same runner revision and in the predetermined schedule order, the whole first run (runner v4, trajectories 1–30) was archived unmodified, with SHA-256 hashes, in `previous_runs/run1_v4_halted_at_order30_20261115/` (see `ARCHIVE.json` there), and the campaign restarts all 80 trajectories under v5. Nothing was deleted. The runner only reads `results/`, so the archive is never resumed or overwritten.
3. **Per-attempt stacks stuck in `DELETE_FAILED` by a resource that was never created.** At trajectory 30, a generated template named its IAM role `<attempt>-role-<stack name>` (73 characters; IAM allows 64). IAM rejected the creation, but CloudFormation sends the same invalid name on every delete, so the stack stayed in `DELETE_FAILED` and the campaign halted. v5 retries the delete with `RetainResources` only for resources that never reached any `*_COMPLETE` state and whose creation **and** deletion were both rejected by AWS input validation (`validation error detected ... failed to satisfy constraint`); such a resource cannot exist. Anything else still halts the campaign, as before. Retained resources are listed in the cleanup report and in `attempt_events.jsonl` (`cleanup_retained_never_created_resources`). The candidate's own failure (stack creation failed) is unchanged and is scored by `Q_post` as usual.
4. **Cleanup reports are no longer overwritten on resume.** A previous `cleanup_report.json` of the attempt is kept as `cleanup_report_superseded_<UTC>.json` (event `previous_cleanup_report_preserved`).

## Audit trail per attempt

Each attempt directory contains `attempt_events.jsonl`, which is only ever appended to. One timestamped line is written for each:

- Bedrock call start, completion, failure and retry (`generation_*`, `qpre_*`, `qpost_*`), including the previous failure record when a call is retried;
- `infrastructure_error` (AWS/Bedrock client errors) and `attempt_halted` (ambiguous state, unresolved cleanup, unexpected exception or interruption);
- `attempt_resumed` (with the status found on disk), `archived_candidate_reused`, `archived_execution_reused`;
- `chaos_execution_started` / `chaos_execution_finished`, and `resume_pre_execution_cleanup` before a frozen candidate is executed again.

Further changes:

- If a Chaos run was interrupted, its partial `chaostoolkit.log` / `journal*.json` are moved to `interrupted_execution_<UTC>/` inside the attempt before the frozen candidate runs again.
- Each pre-execution cleanup report on resume has its own timestamped file.
- `infrastructure_error.json` now carries a timestamp.
- `attempt_status.json` and `campaign_results.csv` have three new columns: `resume_count`, `model_call_retries` and `infrastructure_errors`. Together with `attempt_events.jsonl`, they answer which attempts were retried after an infrastructure error, and why.

## Attempt outcome semantics (for the Methods section)

Since v3, an evaluator response that cannot be parsed does not halt the campaign and is never re-queried:

- Unparseable `Q_pre` → `gate_evaluation_error`. The attempt is consumed and the candidate is not executed, as with a gate rejection. In feedback conditions the next attempt receives the candidate and the unparseable `Q_pre` report.
- Unparseable `Q_post` → `qpost_evaluation_error`. The attempt is consumed and counts as non-terminal, as with `qpost_insufficient`.

In v1/v2 both cases halted the campaign. This affects how attempts and trajectories are counted, so it should be stated explicitly in the paper's methods.

**Confirmed by the researchers on 2026-11-15.** If an evaluator response does not contain a score that can be interpreted reliably, the attempt is consumed and the original response is preserved as an evaluation/parsing failure. The evaluator model is not queried again for that attempt, because doing so would introduce a new stochastic sample. These cases are reviewed later through the independent human evaluation.

## Execution sequence for Mario

Activate the Python environment used for the experiments first.

### 1. Static check

```bash
python controlled_validation/campaign_runner.py \
  --config controlled_validation/campaign.yaml \
  --static-check
```

### 2. First non-destructive preflight

```bash
python controlled_validation/campaign_runner.py \
  --config controlled_validation/campaign.yaml \
  --aws-profile default \
  --preflight
```

At this stage both models should report `[OK]`. It is expected that the fixed campaign network may still be reported as absent.

### 3. Prepare the fixed network once

This is the only explicit preparation step that creates AWS resources before the scientific campaign:

```bash
python controlled_validation/campaign_runner.py \
  --config controlled_validation/campaign.yaml \
  --aws-profile default \
  --prepare-infrastructure
```

It creates/reuses only the `cvr2-network` CloudFormation stack (VPC + subnet + security group) and records its outputs.

### 4. Final preflight

```bash
python controlled_validation/campaign_runner.py \
  --config controlled_validation/campaign.yaml \
  --aws-profile default \
  --preflight
```

Do **not** continue unless both models are `[OK]`, the fixed network is `[OK]`, and `ready_for_run` is `true`.

### 5. Scientific campaign

```bash
python controlled_validation/campaign_runner.py \
  --config controlled_validation/campaign.yaml \
  --aws-profile default \
  --run
```

Do not edit generated artifacts or manually repeat model/experiment failures. External infrastructure failures are preserved. Restarting the same command reconstructs the attempt from archived files. If a candidate already exists, it is reused; it is never regenerated under the same attempt ID. If execution had not completed, AWS leftovers are cleaned before re-running that same frozen candidate.

### 6. Optional network cleanup after results are safely archived

```bash
python controlled_validation/campaign_runner.py \
  --config controlled_validation/campaign.yaml \
  --aws-profile default \
  --cleanup-infrastructure
```

Do this only after the campaign has finished and the complete `controlled_validation/results/` directory has been archived.

## CN2-D evidence rule

CN2-D must use CloudTrail Event History (`cloudtrail.lookup_events`) and match the current attempt by:

- event name `ModifyInstanceMetadataOptions`;
- current attempt-owned EC2 instance ID;
- CloudTrail event timestamp inside the current attempt window;
- parsed `CloudTrailEvent` request parameters confirming the IMDS weakening action.

Historical events/trails therefore cannot satisfy a current probe merely because they exist in the account.

## Cleanup/isolation

Each scientific attempt still owns exactly one per-attempt CloudFormation stack. Generated rollback runs first; the campaign runner then performs an external attempt-prefix cleanup. If an attempt-owned stack cannot be removed, the campaign halts instead of contaminating the next repetition.

The fixed `cvr2-network` stack is explicitly excluded from per-attempt cleanup and remains constant throughout all 80 trajectories.

## Outputs

Every attempt preserves its prompt, Bedrock model/configuration/usage, raw response, generated Python/JSON, technical validation, `Q_pre` where applicable, exact Chaos Toolkit command, logs/journals, `Q_post`, supplied feedback, cleanup result, timestamps and status. Existing evidence is never intentionally overwritten. Stored Q_pre/Q_post responses are parsed again locally if needed, but the evaluator is not queried again merely because parsing failed.

At the end, archive the complete `controlled_validation/results/` directory without deleting failed/interrupted attempts.
