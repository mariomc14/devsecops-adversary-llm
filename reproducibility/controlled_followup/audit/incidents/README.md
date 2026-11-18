# Technical incidents of the controlled follow-up

The technical incidents of the campaign are documented here for transparency. They are **not** scientific results. None of them changed the scientific protocol (prompts, models, tasks, inference configuration, thresholds, schedule, condition assignment or evaluation criteria).

Runner revisions: v4 `v4-typed-params-audit-trail` → v5 `v5-paginator-never-created-cleanup` → v6 `v6-artifact-order-json-guard`. Code diffs: [`../v4_to_v5.diff`](../v4_to_v5.diff), [`../v5_to_v6.diff`](../v5_to_v6.diff). Exact code: [`../runner_versions/`](../runner_versions/). The English description of each change is in the runner README (sections "Changes in v5" and "Changes in v6"); `V5_CORRECTIONS.md`, `V6_CORRECTIONS.md` and `Informe_errores_v5.docx` are the original internal reports (Spanish).

## 1. CloudTrail validator false positive → campaign restarted (runner v4 → v5)

- **What happened.** In a preliminary run (run 1, runner v4), the technical validator accepted direct `cloudtrail.lookup_events()` calls but wrongly rejected the equivalent `cloudtrail.get_paginator("lookup_events")` form, which issues the same CloudTrail LookupEvents API.
- **Effect.** It systematically affected Sonnet 4.6 / CN2-D: 20 of its 21 candidates were rejected, and it was their only validation error. None of them was executed. Seven trajectories were affected (orders 5, 11, 12, 15, 17, 26, 28; see [`run1_excluded/INVALIDATED.json`](run1_excluded/INVALIDATED.json)).
- **Second problem in the same run.** Run 1 halted at trajectory 30: a generated template named an IAM role with 73 characters (IAM allows 64); IAM rejected the creation, CloudFormation sent the same invalid name on every delete, and the attempt stack stayed in `DELETE_FAILED`. Evidence: [`run1_halt_order30/`](run1_halt_order30/).
- **Fix (v5).** The validator accepts both forms; candidates that never use LookupEvents are still rejected. Offline re-validation of the 71 archived candidates changed exactly those 20 verdicts. The cleanup now retains, on delete, only resources that never reached a `*_COMPLETE` state and whose creation and deletion were both rejected by AWS input validation; anything else still halts the campaign.
- **Decision.** The scientific campaign was **restarted from trajectory 1** under v5, so that every trajectory follows the predetermined schedule under the same protocol. Run 1 was archived unmodified, with SHA-256 hashes ([`run1_excluded/ARCHIVE.json`](run1_excluded/ARCHIVE.json)), and is excluded from all results.
- **Verification before the restart:** [`verification_v5/`](verification_v5/) — static check and tests, offline re-validation of the archive, resume harness, cleanup of the blocked stack, quarantine of the invalidated trajectories, prompts/configuration unchanged, archive of run 1, preflight with empty results.

## 2. Artifact extraction at trajectory 20 (runner v5 → v6)

- **What happened.** During the restarted campaign, v5 halted at trajectory 20 (`cn1_p / sonnet-4.6 / conventional_adt_feedback / rep 2`), attempt 2. The prompt asks for exactly two fenced artifacts, Python first and then JSON. The response contained an explanatory JSON fragment (a quoted piece of the previous template) **before** the expected artifacts; v5 selected that fragment as the manifest, it was not valid JSON, and the error was not handled.
- **Fix (v6).** The manifest is the first JSON block after the Python block (falling back to the v5 rule if there is none), and an unparseable manifest becomes a `technical_rejected` attempt instead of a campaign halt.
- **Resumption.** Attempt 2 of trajectory 20 was resumed under v6 **from the archived model response**:
  - the archived model response was reused;
  - **no new model call was made**;
  - prompts, task definitions, inference configuration, validation criteria and condition assignment were not modified.
- **Verification:** [`verification_v6/`](verification_v6/). Over the 115 responses archived at that point, v6 extracts exactly the same artifacts as v5 except for that attempt; the 38 candidates of trajectories 1–19 get the same validator verdict under v5 and v6; all prompt combinations are byte-identical; the resume harness passes its 13 scenarios. The final audit repeats the extraction comparison over all 164 responses of the campaign: 163 identical, 1 different (the halted attempt) — [`../audit_final.log`](../audit_final.log).
- **Provenance in the final dataset.** 19 trajectories are associated with runner v5 (1–19) and 61 with runner v6 (20–80; trajectory 20 has attempt 1 under v5 and attempt 2 resumed under v6). The v5→v6 transition affects artifact extraction only, not the scientific protocol. It is **not** correct to state that all 80 trajectories were executed entirely with v6.

## 3. Excluded preliminary run

The complete run 1 archive is available. It is published as the separate release asset `ijis_controlled_followup_run1_EXCLUDED.zip`, clearly marked **EXCLUDED FROM SCIENTIFIC RESULTS**, sanitized with the same rules as the main archive. It contains 22 completed trajectories plus the halted trajectory 30 (55 attempts) and the 7 invalidated trajectories (21 attempts). No file was reconstructed.

## Operational events recorded in the final dataset (not incidents)

From [`../audit_final.log`](../audit_final.log) and `results_summary/campaign_results.csv`:

- 0 infrastructure errors and 0 model-call retries in the 164 attempts; 1 resumed attempt (trajectory 20, attempt 2, described above).
- 7 `cleanup_retained_never_created_resources` events (trajectories 5, 58, 67, 70 ×3, 72): the v5 cleanup rule acting as designed on resources that AWS had refused to create. The candidates' own failures are kept and scored as usual.
