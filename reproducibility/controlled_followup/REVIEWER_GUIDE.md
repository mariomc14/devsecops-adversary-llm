# Reviewer guide — controlled follow-up (Reviewer #2, points R2.1–R2.4)

Every value below is recomputed from the published files by one command, which ends with `RESULT: OK` if all values match [`analysis/EXPECTED_RESULTS.md`](analysis/EXPECTED_RESULTS.md):

```bash
python reproducibility/controlled_followup/analysis/reproduce_paper_results.py
```

| Comment | What to open | Main result |
|---|---|---|
| **R2.1 · Baselines** | [`protocol/schedule.csv`](protocol/schedule.csv), [`protocol/tasks/`](protocol/tasks/), [`results_summary/human_adjudication_final.csv`](results_summary/human_adjudication_final.csv), [`analysis/reproduce_paper_results.py`](analysis/reproduce_paper_results.py) | VALID trajectories: Chaos ADT + feedback 4/20, Chaos ADT no-feedback 4/20, conventional ADT 4/20, direct LLM-to-SCE 6/20 |
| **R2.2 · Reliability** | Human package ([`human_evaluation/`](human_evaluation/), [`RUBRIC.md`](human_evaluation/RUBRIC.md), [`results_summary/human_adjudication_trace.csv`](results_summary/human_adjudication_trace.csv)), validation script, `Q_pre`/`Q_post` audit ([`EXPECTED_RESULTS.md` §4–5](analysis/EXPECTED_RESULTS.md)) | A/B agreement 98.2% on both outcomes; κ 0.905 (experiment) / 0.899 (security); automated vs human, trajectory level: 17 / 29 / 1 / 33 |
| **R2.3 · Feedback** | `chaos_adt_feedback` vs `chaos_adt_no_feedback` rows in [`results_summary/campaign_results.csv`](results_summary/campaign_results.csv), [`results_summary/human_adjudication_final.csv`](results_summary/human_adjudication_final.csv) and [`results_summary/paper_results_summary.csv`](results_summary/paper_results_summary.csv) | VALID 4/20 vs 4/20; first attempt 3/20 vs 3/20; automated terminal 11/20 vs 10/20; cloud executions 24 vs 37 |
| **R2.4 · Reproducibility** | [`audit/`](audit/), [`audit/runner_versions/`](audit/runner_versions/), [`audit/incidents/`](audit/incidents/), [`audit/SHA256SUMS.txt`](audit/SHA256SUMS.txt), [`full_archive/`](full_archive/) | 80 trajectories, 164 attempts; runner provenance 19 v5 / 61 v6; integrity checks pass |

## R2.1 — Baselines

Four conditions on the same 2 tasks × 2 models, 5 independent repetitions each, executed in one predetermined sequential schedule (definitions in [`README.md`](README.md#conditions)). The two baselines remove, respectively, the explicit Chaos Node and semantic `Q_pre` (conventional ADT) and the ADT itself (direct LLM-to-SCE). Human validity is the primary outcome. By model: Haiku 4.5 2/40, Sonnet 4.6 16/40 VALID; by task: CN1-P 16/40, CN2-D 2/40.

## R2.2 — Reliability of the evaluation

- Two blinded evaluators labelled all 164 attempts independently; three discrepant attempts (HR033, HR051, HR112) were adjudicated by a third blinded evaluator. Final labels: 161 A/B agreement, 3 C adjudication. The evaluators did not see model, condition, `Q_pre`, `Q_post`, the automated decision or aggregate results.
- Automated criterion (`Q_post ≥ 100`) vs human VALID — trajectory level: TP 17, FP 29, FN 1, TN 33 (agreement 62.5%, κ ≈ 0.307, PPV ≈ 37.0%, sensitivity ≈ 94.4%, specificity ≈ 53.2%); attempt level: TP 17, FP 29, FN 1, TN 117 (agreement ≈ 81.7%, κ ≈ 0.443, specificity ≈ 80.1%).
- Scale audit: 35/61 parseable `Q_pre` (57.4%) are not values of the formally defined discrete scale, and 70/128 parseable `Q_post` (54.7%) fall outside {0, 50, 100}. All 61 parseable `Q_pre` are ≥ 80.

## R2.3 — Feedback ablation

`chaos_adt_feedback` and `chaos_adt_no_feedback` share the Chaos ADT representation and the `Q_pre` gate; in the no-feedback condition every new attempt is regenerated from the frozen original input with no previous candidate, scores, logs, errors or evidence. Result: no human-validity advantage for feedback (4/20 vs 4/20 VALID; 3/20 vs 3/20 at the first attempt). Feedback used fewer cloud executions (24 vs 37).

**Interpretation.** In the controlled study the semantic `Q_pre` gate rejected no candidate (all parseable `Q_pre` ≥ 80). Candidates that were not executed (36 `technical_rejected` attempts in total) were stopped by the technical/safety validator common to all conditions. Differences in cloud executions must not be attributed to the semantic `Q_pre`.

## R2.4 — Configuration, incidents, runner versions, integrity, traceability

- Frozen configuration and schedule: [`protocol/`](protocol/); canonical runner v6: [`controlled_validation/`](../../controlled_validation/) (static check and 24 tests pass).
- Runner provenance: 19 trajectories with runner v5, 61 with runner v6; the change affects artifact extraction only. Trajectory 20 reused its archived model response; no new model call. See [`audit/incidents/README.md`](audit/incidents/README.md), which also documents the CloudTrail-validator false positive that led to restarting the campaign, and the excluded preliminary run.
- Every attempt is preserved with prompts, raw responses, generated code, logs, journals, scores, feedback and an append-only event log in [`ijis_controlled_followup_public.zip`](full_archive/README.md) (release asset, SHA-256 in `full_archive/README.md`).
- Integrity: `cd reproducibility/controlled_followup && sha256sum -c audit/SHA256SUMS.txt`; inside the archive, `sha256sum -c SHA256SUMS.txt`. Sanitization: [`audit/SANITIZATION.md`](audit/SANITIZATION.md).

Limitations relevant to these points: [`../LIMITATIONS.md`](../LIMITATIONS.md).
