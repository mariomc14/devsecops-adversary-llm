# Limitations of the reproducibility material

These limitations are stated in the manuscript and apply when interpreting the material in this folder.

## Original experimental campaign ([`original_campaign/`](original_campaign/))

1. **`maxTokens` per trajectory cannot be reconstructed.** The original campaign used `maxTokens` configurations of 64000 and 8192, and the exact configuration of each trajectory cannot be fully reconstructed.
2. **Some intermediate artifacts were overwritten.** The original iterative automation reused output paths, so some intermediate artifacts and journals of earlier refinement attempts were overwritten. The archive is not a complete immutable record of every attempt (see `original_campaign/docs/archival_limitations.md`).

## Prospective controlled follow-up ([`controlled_followup/`](controlled_followup/))

3. **Limited scope.** It covers only two tasks (CN1-P and CN2-D) and two models (Claude Haiku 4.5 and Claude Sonnet 4.6).
4. **Small cells.** There are five repetitions per model–task–condition cell; results are interpreted descriptively.
5. **`Q_pre` / `Q_post` are operational heuristics**, not expert-equivalent validity judgments. Human validity is the primary outcome.
6. **Free-form LLM scoring did not always respect the formally defined discrete scales**: 35/61 parseable `Q_pre` and 70/128 parseable `Q_post` are not values of their formal scales.
7. **The feedback vs no-feedback ablation showed no human-validity advantage** for feedback (4/20 vs 4/20 VALID trajectories).
8. **No claim of equivalence or general superiority.** The controlled study does not demonstrate equivalence or general superiority between strategies.

Further notes on the controlled follow-up:

- In the controlled study the semantic `Q_pre` gate rejected no candidate; candidates that were not executed were stopped by the technical/safety validator common to all conditions. Reductions in cloud executions must not be attributed to the semantic `Q_pre`.
- The final dataset combines two runner revisions (19 trajectories v5, 61 v6). They differ only in artifact extraction; see `controlled_followup/audit/incidents/README.md`.
- Re-executing the campaign uses `temperature = 1.0` against live AWS services, so it produces new samples; the archived evidence is the record of the reported campaign.
