# Human evaluation — controlled follow-up

Human validity is the **primary outcome** of the controlled comparisons. This folder documents how it was obtained; the data are in [`../results_summary/`](../results_summary/).

| File | Content |
|---|---|
| [`RUBRIC.md`](RUBRIC.md) | Labels, rules, blinding and adjudication procedure. |
| [`../results_summary/human_adjudication_final.csv`](../results_summary/human_adjudication_final.csv) | **Canonical** final dataset, one row per attempt (164): blinded ID, trajectory/attempt metadata, final `experiment_outcome` and `security_outcome`, whether adjudication was required and `final_label_source`. |
| [`../results_summary/human_adjudication_trace.csv`](../results_summary/human_adjudication_trace.csv) | Independent A and B judgments, their agreement, and C's adjudication (with confidence) for the three discrepant attempts. |
| [`../results_summary/blind_id_mapping.csv`](../results_summary/blind_id_mapping.csv) | Blinded ID → order, repetition, task, model, condition, attempt and attempt directory in the public archive. |
| [`../results_summary/VALIDATION_SUMMARY.json`](../results_summary/VALIDATION_SUMMARY.json) | Machine-readable checks and aggregates delivered with the package. |
| [`delivered_package/`](delivered_package/) | `README.md` and `SHA256SUMS.txt` of the package exactly as delivered (`human_adjudication_final_package.zip`, also attached unchanged to the GitHub Release). |

## Status of the data

The human results are **closed**. The four data files in `results_summary/` are byte-identical to the delivered package; `reproduce_paper_results.py` verifies them against `delivered_package/SHA256SUMS.txt` before computing anything. No label was reconstructed, recomputed or edited during integration.

In the final dataset, `q_pre`, `q_post`, `executed` and `technical_status` are included only to compare the human outcome with the automated pipeline afterwards. They were **not** shown to the evaluators.

`results/human_adjudication.csv` inside the public campaign archive is the blank rating template written by the runner; it is not used.

## Results

| Level | Result |
|---|---|
| Attempts · experiment | 18 VALID · 1 INCONCLUSIVE · 145 INVALID (164) |
| Attempts · security | 18 EFFECTIVE · 0 INEFFECTIVE · 146 NOT_ASSESSABLE (164) |
| Final label source | 161 A_B_AGREEMENT · 3 C_ADJUDICATION (HR033, HR051, HR112) |
| A/B agreement before adjudication | experiment 161/164 = 98.2%, κ = 0.905 · security 161/164 = 98.2%, κ = 0.899 |
| Trajectories | 18 VALID · 1 INCONCLUSIVE · 61 INVALID (80) |
| VALID trajectories per condition | `chaos_adt_feedback` 4/20 · `chaos_adt_no_feedback` 4/20 · `conventional_adt_feedback` 4/20 · `direct_sce_feedback` 6/20 |

All values are reproduced by [`../analysis/reproduce_paper_results.py`](../analysis/reproduce_paper_results.py); see [`../analysis/EXPECTED_RESULTS.md`](../analysis/EXPECTED_RESULTS.md).

## Inspecting an attempt

Look up the blinded ID in `blind_id_mapping.csv`; `source_attempt_path` is the attempt directory inside `ijis_controlled_followup_public.zip` (prompts, raw response, generated code, execution logs and journals, `Q_pre`/`Q_post` reports). The blinded evidence folders given to the evaluators (`evidence_folder`) are not part of this release.
