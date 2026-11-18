# Prospective controlled follow-up (IJIS third revision)

This folder contains the **prospective controlled follow-up** added in the third revision of “LLM-Driven Chaos Attack–Defense Trees for Empirical Security Validation in DevSecOps Scenarios”. It was designed, frozen and executed after the original campaign, and it is kept strictly separate from it: nothing in [`../original_campaign/`](../original_campaign/) was modified, and no data of the original campaign are used here.

**Reviewers: start with [`REVIEWER_GUIDE.md`](REVIEWER_GUIDE.md).**

```bash
python reproducibility/controlled_followup/analysis/reproduce_paper_results.py   # all paper values, standard library only
```

## Protocol

### Common configuration

| Parameter | Value |
|---|---|
| Models | Claude Haiku 4.5 and Claude Sonnet 4.6 (AWS Bedrock) |
| Haiku 4.5 model ID | `us.anthropic.claude-haiku-4-5-20251001-v1:0` |
| Sonnet 4.6 model ID | `us.anthropic.claude-sonnet-4-6` |
| `maxTokens` | 8192 |
| `temperature` | 1.0 |
| `topP` / `topK` | Not overridden; provider defaults |
| AWS region | `us-east-1` |
| Chaos Toolkit hypothesis strategy | `after-method-only` |
| Campaign network | `cvr2-network` (one fixed VPC/subnet/security group reused by every attempt) |
| Maximum scientific attempts | 3 per trajectory (early stop at `Q_post ≥ 100`) |
| Python | 3.12.13 |
| Design | 2 tasks × 2 models × 4 conditions × 5 repetitions = **80 trajectories** (164 attempts executed) |
| Tasks | `cn1_p` — CN1-P, Chaos Node 1.3, preventive; `cn2_d` — CN2-D, Chaos Node 1.8, detective ([`protocol/tasks/`](protocol/tasks/)) |
| Schedule | Predetermined sequential order, seed 20261111 ([`protocol/schedule.csv`](protocol/schedule.csv)) |

### Conditions

| Condition | Definition |
|---|---|
| `chaos_adt_feedback` | Chaos ADT + semantic `Q_pre` + feedback-guided refinement. |
| `chaos_adt_no_feedback` | Chaos ADT + semantic `Q_pre`; each new attempt is regenerated from the frozen original input, without the previous candidate, scores, logs, errors or evidence. |
| `conventional_adt_feedback` | Conventional ADT, without an explicit Chaos Node and without semantic `Q_pre`; with feedback. |
| `direct_sce_feedback` | Direct LLM-to-SCE generation, without ADT and without semantic `Q_pre`; with feedback. |

All four conditions go through the **same deterministic technical/safety validator** before any cloud execution. This matters when reading the non-executed candidates: they were stopped by this common validator, not by the semantic `Q_pre` gate.

**Primary outcome.** Blinded human validity (`VALID / INCONCLUSIVE / INVALID`) per trajectory, see [`human_evaluation/`](human_evaluation/). `Q_pre` and `Q_post` are operational heuristics of the automated pipeline.

## Runner provenance

The canonical code is runner **v6**, in [`../../controlled_validation/`](../../controlled_validation/) (identical to [`audit/runner_versions/v6/`](audit/runner_versions/v6/)); runner **v5** is kept in [`audit/runner_versions/v5/`](audit/runner_versions/v5/) with the diffs.

19 trajectories of the final dataset are associated with runner v5 and 61 with runner v6. The v5→v6 transition affects artifact extraction, not the scientific protocol. For trajectory 20, the already archived model response was reused after the extraction was corrected; no new model call was made. Details: [`audit/incidents/README.md`](audit/incidents/README.md).

## Contents

| Path | Content |
|---|---|
| [`REVIEWER_GUIDE.md`](REVIEWER_GUIDE.md) | Where to verify each Reviewer #2 point (R2.1–R2.4). |
| [`protocol/`](protocol/) | Frozen configuration (`campaign.yaml`), schedule, task definitions, experiment template and pinned dependencies (`requirements.txt` = `automate/requirements.txt`, referenced by `controlled_validation/requirements.txt`). |
| [`results_summary/`](results_summary/) | Attempt-level runner results (`campaign_results.csv/json`), trajectory index, the final human dataset with its trace, blind-ID mapping and validation summary, and the computed paper values (`paper_results_summary.csv/json`). |
| [`human_evaluation/`](human_evaluation/) | Human evaluation README and rubric; delivered package README and hashes. |
| [`analysis/`](analysis/) | `reproduce_paper_results.py` (single script for every paper value), [`EXPECTED_RESULTS.md`](analysis/EXPECTED_RESULTS.md), and the runner's analysis helpers. |
| [`audit/`](audit/) | Final audit, runner versions and diffs, incidents with verification logs, sanitization records, integrity hashes. |
| [`full_archive/`](full_archive/) | Release assets with the complete attempt-level evidence and their SHA-256. |

`analysis/analyze_campaign.py` is the runner's summary script, adapted only in its default input paths and in reading the final human label column (documented in its header). `analysis/analyze_gate_validation.py` is the runner's generic helper for comparing automated admission decisions with expert decisions; it was written for the 36-artifact assessment of the original campaign and is not used for the controlled follow-up values.

## Main results (reproduced by `analysis/reproduce_paper_results.py`)

| Condition | VALID trajectories | First-attempt VALID | Cloud executions | Automated terminal |
|---|---|---|---|---|
| `chaos_adt_feedback` | 4/20 (20%) | 3/20 | 24 | 11/20 |
| `chaos_adt_no_feedback` | 4/20 (20%) | 3/20 | 37 | 10/20 |
| `conventional_adt_feedback` | 4/20 (20%) | 2/20 | 33 | 13/20 |
| `direct_sce_feedback` | 6/20 (30%) | 4/20 | 34 | 12/20 |

Total 18/80 VALID (22.5%), 1 INCONCLUSIVE, 61 INVALID. With 5 repetitions per model–task–condition cell these results are descriptive; they show neither equivalence nor general superiority between strategies. See [`../LIMITATIONS.md`](../LIMITATIONS.md).

## Re-executing the campaign

Re-execution needs an AWS account with Bedrock access to both models and creates real AWS resources. The step-by-step procedure (static check, preflight, fixed network, run, cleanup) is in [`controlled_validation/README.md`](../../controlled_validation/README.md). Because `temperature = 1.0`, a re-execution produces new samples; the archived evidence in the release asset is the record of the reported campaign.
