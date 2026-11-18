# Audit and integrity material — controlled follow-up

| Path | Content |
|---|---|
| [`audit_final.py`](audit_final.py), [`audit_final.log`](audit_final.log) | Read-only audit of the finished campaign, run on the internal (unsanitized) archive on 2026-11-16: 80/80 trajectories complete and in schedule, 164 attempts, runner revision per trajectory (19 v5 / 61 v6), incident events, consistency of `campaign_results.csv/json` with the attempt directories, runner manifest (3,424 entries, 0 mismatches) and v5-vs-v6 extraction over all 164 responses (163 identical, 1 different). |
| [`runner_versions/v5/`](runner_versions/v5/), [`runner_versions/v6/`](runner_versions/v6/) | Exact code of the two runner revisions used in the final dataset (v6 is identical to `controlled_validation/` at the repository root). |
| [`v4_to_v5.diff`](v4_to_v5.diff), [`v5_to_v6.diff`](v5_to_v6.diff) | Code changes between revisions. |
| [`incidents/`](incidents/) | Technical incidents (validator false positive and restart, trajectory-20 extraction fix, excluded run 1), with the verification logs run before each restart. Start with [`incidents/README.md`](incidents/README.md). |
| [`SANITIZATION.md`](SANITIZATION.md), [`SANITIZATION.json`](SANITIZATION.json) | Sanitization policy and per-file record (original SHA-256, public SHA-256, replacements) for the repository and for `ijis_controlled_followup_public.zip`. |
| [`REDACTION.json`](REDACTION.json) | Redaction record of the earlier shareable bundle (superseded by `SANITIZATION.json`). |
| [`build_public_release.py`](build_public_release.py) | Script that copied and sanitized the internal archive into this repository and the release assets. |
| [`SHA256SUMS.txt`](SHA256SUMS.txt) | SHA-256 of every file under `reproducibility/controlled_followup/` (except itself). |

## Verifying integrity

```bash
cd reproducibility/controlled_followup
sha256sum -c audit/SHA256SUMS.txt
```

The public campaign archive carries its own `SHA256SUMS.txt`; its SHA-256 is given in [`../full_archive/README.md`](../full_archive/README.md).

## Runner provenance

19 trajectories of the final dataset are associated with runner v5 and 61 with runner v6. The v5→v6 transition affects the extraction of artifacts from the model response, not the scientific protocol. For trajectory 20, the already archived model response was reused after the extraction was fixed; no new model call was made.

## Re-running the checks

```bash
# from the repository root
# canonical runner (needs the pinned dependencies in reproducibility/controlled_followup/protocol/requirements.txt, no AWS access)
python controlled_validation/campaign_runner.py --config controlled_validation/campaign.yaml --static-check
python -m pytest controlled_validation/tests        # or any runner that calls the test_* functions

# paper values
python reproducibility/controlled_followup/analysis/reproduce_paper_results.py
```
