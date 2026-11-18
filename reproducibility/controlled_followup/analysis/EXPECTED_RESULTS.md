# Expected results — IJIS controlled follow-up

These are the controlled follow-up values reported in the paper and the response letter (third revision). Run, from the repository root:

```bash
python reproducibility/controlled_followup/analysis/reproduce_paper_results.py
```

The script reads only files published in this release, recomputes every value below, and compares them with the machine-readable block at the end of this file, with `results_summary/VALIDATION_SUMMARY.json` (delivered with the human package) and with the committed `results_summary/paper_results_summary.json`. It ends with `RESULT: OK` and exit status 0 only if everything matches. It needs Python ≥ 3.9 and no third-party package.

Definitions used by the script:

- **Human labels** come only from `results_summary/human_adjudication_final.csv` (`experiment_outcome`, `security_outcome`).
- **Trajectory label**: VALID if at least one attempt is human-VALID; otherwise INCONCLUSIVE if at least one attempt is INCONCLUSIVE; otherwise INVALID.
- **First-attempt VALID**: attempt 1 of the trajectory is human-VALID.
- **Cloud executions**: attempts with `executed = True` in `campaign_results.csv` (the candidate passed the technical/safety validator and, in the Chaos ADT conditions, the `Q_pre` gate).
- **Automated terminal**: the automated pipeline stopped with `Q_post ≥ 100` (`status = terminal_qpost`). At trajectory level: any attempt of the trajectory is terminal.
- Percentages are rounded to one decimal; Cohen's κ to three decimals.

## 1. Human evaluation (attempt level, 164 attempts)

| Level | Result |
|---|---|
| Experiment outcome | 18 VALID · 1 INCONCLUSIVE · 145 INVALID · total 164 |
| Security outcome | 18 EFFECTIVE · 0 INEFFECTIVE · 146 NOT_ASSESSABLE · total 164 |
| Final label source | 161 A_B_AGREEMENT · 3 C_ADJUDICATION (HR033, HR051, HR112) |
| A/B agreement, experiment (before adjudication) | 161/164 = 98.2% · Cohen κ = 0.905 |
| A/B agreement, security (before adjudication) | 161/164 = 98.2% · Cohen κ = 0.899 |

## 2. Human validity per condition (trajectory level, 80 trajectories)

| Condition | VALID | First-attempt VALID | Cloud executions | Automated terminal |
|---|---|---|---|---|
| `chaos_adt_feedback` | 4/20 (20.0%) | 3/20 | 24 | 11/20 |
| `chaos_adt_no_feedback` | 4/20 (20.0%) | 3/20 | 37 | 10/20 |
| `conventional_adt_feedback` | 4/20 (20.0%) | 2/20 | 33 | 13/20 |
| `direct_sce_feedback` | 6/20 (30.0%) | 4/20 | 34 | 12/20 |
| **Total** | **18/80 (22.5%)** · 1 INCONCLUSIVE · 61 INVALID | 12/80 | 128 | 46/80 |

## 3. By model and task (trajectory level)

| Group | VALID |
|---|---|
| Claude Haiku 4.5 | 2/40 = 5.0% |
| Claude Sonnet 4.6 | 16/40 = 40.0% |
| CN1-P | 16/40 = 40.0% |
| CN2-D | 2/40 = 5.0% |

## 4. Automated criterion (`Q_post ≥ 100`) vs human VALID

Trajectory level:

| | Human VALID | Human not VALID |
|---|---|---|
| Automated terminal | 17 | 29 |
| Automated non-terminal | 1 | 33 |

Agreement 62.5% · κ = 0.307 · PPV 37.0% · sensitivity 94.4% · specificity 53.2%.

Attempt level: TP = 17, FP = 29, FN = 1, TN = 117 · agreement 81.7% · κ = 0.443 · PPV 37.0% · sensitivity 94.4% · specificity 80.1%.

## 5. `Q_pre` / `Q_post` scale audit

The runner prompts define `Q_pre = 0.40·f1 + 0.30·f2 + 0.30·f3` with f1, f2 ∈ {0, 50, 100} and f3 ∈ {0, 100}, and `Q_post = 0.50·f1 + 0.50·f2` with f1, f2 ∈ {0, 100}, i.e. `Q_post` ∈ {0, 50, 100}.

| Item | Value |
|---|---|
| Parseable `Q_pre` (Chaos ADT conditions only) | 61 |
| `Q_pre` incompatible with the formal discrete scale | 35/61 (57.4%) |
| Parseable `Q_pre` with `Q_pre ≥ 80` | 61/61 |
| Parseable `Q_post` | 128 |
| `Q_post` outside {0, 50, 100} | 70/128 (54.7%) |
| Attempts `technical_rejected` | 36 |
| Attempt status | 46 `terminal_qpost` · 82 `qpost_insufficient` · 36 `technical_rejected` · 0 other |

**Mandatory interpretation.** Every parseable `Q_pre` passed the gate (≥ 80), so the semantic `Q_pre` gate rejected no candidate in the controlled study. The candidates that were not executed were stopped by the technical/safety validator, which is common to all four conditions. The reduction in cloud executions must **not** be attributed to the semantic `Q_pre`.

## 6. Runner provenance

19 trajectories of the final dataset are associated with runner v5 and 61 with runner v6 (`trajectory_runner_revision` in `results_summary/trajectory_index.csv`). The v5→v6 transition changes artifact extraction only, not the scientific protocol.

## Machine-readable expected values

```json expected-results
{
  "attempts.total": 164,
  "attempts.experiment.VALID": 18,
  "attempts.experiment.INCONCLUSIVE": 1,
  "attempts.experiment.INVALID": 145,
  "attempts.security.EFFECTIVE": 18,
  "attempts.security.INEFFECTIVE": 0,
  "attempts.security.NOT_ASSESSABLE": 146,
  "attempts.label_source.A_B_AGREEMENT": 161,
  "attempts.label_source.C_ADJUDICATION": 3,
  "attempts.c_adjudicated_blind_ids": ["HR033", "HR051", "HR112"],
  "human_ab.experiment.agreement_count": 161,
  "human_ab.experiment.agreement_pct": 98.2,
  "human_ab.experiment.cohen_kappa": 0.905,
  "human_ab.security.agreement_count": 161,
  "human_ab.security.agreement_pct": 98.2,
  "human_ab.security.cohen_kappa": 0.899,
  "trajectories.total": 80,
  "trajectories.VALID": 18,
  "trajectories.INCONCLUSIVE": 1,
  "trajectories.INVALID": 61,
  "trajectories.VALID_pct": 22.5,
  "conditions.chaos_adt_feedback.n": 20,
  "conditions.chaos_adt_feedback.valid": 4,
  "conditions.chaos_adt_feedback.valid_pct": 20.0,
  "conditions.chaos_adt_feedback.first_attempt_valid": 3,
  "conditions.chaos_adt_feedback.cloud_executions": 24,
  "conditions.chaos_adt_feedback.automated_terminal": 11,
  "conditions.chaos_adt_no_feedback.n": 20,
  "conditions.chaos_adt_no_feedback.valid": 4,
  "conditions.chaos_adt_no_feedback.valid_pct": 20.0,
  "conditions.chaos_adt_no_feedback.first_attempt_valid": 3,
  "conditions.chaos_adt_no_feedback.cloud_executions": 37,
  "conditions.chaos_adt_no_feedback.automated_terminal": 10,
  "conditions.conventional_adt_feedback.n": 20,
  "conditions.conventional_adt_feedback.valid": 4,
  "conditions.conventional_adt_feedback.valid_pct": 20.0,
  "conditions.conventional_adt_feedback.first_attempt_valid": 2,
  "conditions.conventional_adt_feedback.cloud_executions": 33,
  "conditions.conventional_adt_feedback.automated_terminal": 13,
  "conditions.direct_sce_feedback.n": 20,
  "conditions.direct_sce_feedback.valid": 6,
  "conditions.direct_sce_feedback.valid_pct": 30.0,
  "conditions.direct_sce_feedback.first_attempt_valid": 4,
  "conditions.direct_sce_feedback.cloud_executions": 34,
  "conditions.direct_sce_feedback.automated_terminal": 12,
  "models.haiku-4.5.n": 40,
  "models.haiku-4.5.valid": 2,
  "models.haiku-4.5.valid_pct": 5.0,
  "models.sonnet-4.6.n": 40,
  "models.sonnet-4.6.valid": 16,
  "models.sonnet-4.6.valid_pct": 40.0,
  "tasks.CN1-P.n": 40,
  "tasks.CN1-P.valid": 16,
  "tasks.CN1-P.valid_pct": 40.0,
  "tasks.CN2-D.n": 40,
  "tasks.CN2-D.valid": 2,
  "tasks.CN2-D.valid_pct": 5.0,
  "auto_vs_human.trajectory.TP": 17,
  "auto_vs_human.trajectory.FP": 29,
  "auto_vs_human.trajectory.FN": 1,
  "auto_vs_human.trajectory.TN": 33,
  "auto_vs_human.trajectory.agreement_pct": 62.5,
  "auto_vs_human.trajectory.cohen_kappa": 0.307,
  "auto_vs_human.trajectory.ppv_pct": 37.0,
  "auto_vs_human.trajectory.sensitivity_pct": 94.4,
  "auto_vs_human.trajectory.specificity_pct": 53.2,
  "auto_vs_human.attempt.TP": 17,
  "auto_vs_human.attempt.FP": 29,
  "auto_vs_human.attempt.FN": 1,
  "auto_vs_human.attempt.TN": 117,
  "auto_vs_human.attempt.agreement_pct": 81.7,
  "auto_vs_human.attempt.cohen_kappa": 0.443,
  "auto_vs_human.attempt.ppv_pct": 37.0,
  "auto_vs_human.attempt.sensitivity_pct": 94.4,
  "auto_vs_human.attempt.specificity_pct": 80.1,
  "qscores.qpre_parseable": 61,
  "qscores.qpre_off_scale": 35,
  "qscores.qpre_off_scale_pct": 57.4,
  "qscores.qpre_ge_80": 61,
  "qscores.qpost_parseable": 128,
  "qscores.qpost_off_scale": 70,
  "qscores.qpost_off_scale_pct": 54.7,
  "attempts.status.terminal_qpost": 46,
  "attempts.status.qpost_insufficient": 82,
  "attempts.status.technical_rejected": 36,
  "attempts.status.other": 0,
  "attempts.cloud_executions": 128,
  "provenance.trajectories_runner_v5": 19,
  "provenance.trajectories_runner_v6": 61,
  "provenance.trajectories_other_revision": 0
}
```
