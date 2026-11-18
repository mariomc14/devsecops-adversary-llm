# Final human adjudication dataset — IJIS controlled follow-up

This package contains the final human labels for the 164 generated attempts in the prospective controlled follow-up study.

## Files

- `human_adjudication_final.csv` — canonical final attempt-level labels used for the manuscript analyses.
- `human_adjudication_trace.csv` — transparent A/B agreement and C adjudication trace.
- `blind_id_mapping.csv` — mapping from blinded IDs to controlled-campaign trajectory/attempt metadata.
- `VALIDATION_SUMMARY.json` — machine-readable validation checks and expected aggregate results.
- `SHA256SUMS.txt` — integrity hashes for the package files.

## Construction rule

Two blinded evaluators (A and B) independently assessed all 164 attempts.

For the 161 attempts where A and B agreed on both experiment and security outcome, the agreed labels are used directly.

The three remaining cases (`HR033`, `HR051`, `HR112`) were reviewed by a third blinded adjudicator (C). The adjudicated labels are used for those cases.

No other rating set is included in or used by this package.

## Final attempt-level results

Experiment outcome:

- VALID: 18
- INCONCLUSIVE: 1
- INVALID: 145
- Total: 164

Security outcome:

- EFFECTIVE: 18
- INEFFECTIVE: 0
- NOT_ASSESSABLE: 146
- Total: 164

## Agreement before adjudication

Experiment outcome:

- exact agreement: 161/164 = 98.2%
- Cohen's kappa: 0.905

Security outcome:

- exact agreement: 161/164 = 98.2%
- Cohen's kappa: 0.899

These agreement statistics are calculated from the independent A/B judgments before third-party adjudication.

## Final trajectory-level results

A trajectory is classified as VALID if at least one attempt in that trajectory is human-VALID; if none is VALID but at least one is INCONCLUSIVE, it is classified INCONCLUSIVE; otherwise it is INVALID.

- VALID: 18/80
- INCONCLUSIVE: 1/80
- INVALID: 61/80

VALID trajectories by condition:

- `chaos_adt_feedback`: 4/20
- `chaos_adt_no_feedback`: 4/20
- `conventional_adt_feedback`: 4/20
- `direct_sce_feedback`: 6/20

## Notes on columns

`human_adjudication_final.csv` includes the blinded ID, controlled-campaign trajectory metadata, technical/automated status retained for traceability, the final human experiment/security outcomes, whether adjudication was required, and the source used to determine the final label.

`final_label_source` is one of:

- `A_B_AGREEMENT`
- `C_ADJUDICATION`

The automated `q_pre`, `q_post`, and `technical_status` fields are included only to support later reproducibility analyses. They were not used as reference values by the blinded human evaluators.
