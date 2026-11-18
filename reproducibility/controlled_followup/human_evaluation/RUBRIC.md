# Human evaluation rubric — controlled follow-up

Each of the 164 generated attempts was assessed on two outcomes. The experiment outcome is assessed first; the security outcome depends on it.

## 1. Experiment outcome

| Label | Definition |
|---|---|
| **VALID** | The experiment is technically meaningful, and its evidence is sufficient and reliable. |
| **INCONCLUSIVE** | There is no unequivocal defect that invalidates the test, but the evidence is insufficient or ambiguous to establish the outcome. |
| **INVALID** | A defect in the implementation, the probe, a dependency, the configuration or the execution prevents a meaningful test, or makes the evidence unreliable. |

## 2. Security outcome

| Label | Definition |
|---|---|
| **EFFECTIVE** | The experiment is VALID and its evidence shows that the defense worked as intended. |
| **INEFFECTIVE** | The experiment is VALID and its evidence shows that the defense did not work as intended. |
| **NOT_ASSESSABLE** | The experiment is INVALID or INCONCLUSIVE. |

Rules:

- EFFECTIVE / INEFFECTIVE are assigned **only** when the experiment outcome is VALID.
- INVALID or INCONCLUSIVE always implies NOT_ASSESSABLE.
- An ineffective defense does **not** make the experiment invalid: a VALID experiment can legitimately show an INEFFECTIVE defense.

`reproduce_paper_results.py` checks that every final label follows these rules.

## 3. Blinding

The evaluators were blinded with respect to:

- the model that generated the attempt;
- the experimental condition;
- `Q_pre` and `Q_post`;
- the automated terminal / non-terminal decision of the pipeline;
- the aggregate results of the campaign.

Attempts were identified to the evaluators only by a blinded ID (`HR001`–`HR164`). `blind_id_mapping.csv` maps each blinded ID back to its trajectory and attempt.

## 4. Procedure and final label

1. Two evaluators (A and B) independently labelled all 164 attempts on both outcomes.
2. When A and B agreed on both outcomes (161 attempts), the agreed labels are final (`final_label_source = A_B_AGREEMENT`).
3. The three remaining attempts (`HR033`, `HR051`, `HR112`) were adjudicated by a third blinded evaluator (C), whose labels are final (`final_label_source = C_ADJUDICATION`).

Agreement statistics (98.2% exact agreement on each outcome; Cohen's κ 0.905 for experiment and 0.899 for security) are computed from the independent A/B judgments **before** adjudication.

The trajectory label is derived from the attempt labels: VALID if at least one attempt is VALID; otherwise INCONCLUSIVE if at least one attempt is INCONCLUSIVE; otherwise INVALID.
