# Full campaign archive — controlled follow-up

The complete attempt-level evidence of the controlled follow-up (about 3,500 files) is not expanded in Git. It is published as an asset of the GitHub Release [`v3.0-ijis-reproducibility`](https://github.com/mariomc14/devsecops-adversary-llm/releases/tag/v3.0-ijis-reproducibility).

## Release assets

| Asset | SHA-256 | Content |
|---|---|---|
| [`ijis_controlled_followup_public.zip`](https://github.com/mariomc14/devsecops-adversary-llm/releases/download/v3.0-ijis-reproducibility/ijis_controlled_followup_public.zip) (6.6 MB, 3,480 files) | `3118f0f54acbc22e0141976c4431589f726b8493d7aa0a4ad73d1a0bcaf4178b` | Sanitized runner output of the 80 trajectories / 164 attempts, trajectory index, session logs and environments, runner v5 and v6, incidents and verification logs, final audit, the human adjudication package and the sanitization records. |
| [`human_adjudication_final_package.zip`](https://github.com/mariomc14/devsecops-adversary-llm/releases/download/v3.0-ijis-reproducibility/human_adjudication_final_package.zip) (9 KB) | `ccd12ae7e87c410800311a71eed1193ef3949d156a2622ee61343e9ca36ea36d` | The final human adjudication package exactly as delivered (also expanded in `../results_summary/` and `../human_evaluation/delivered_package/`). |
| [`ijis_controlled_followup_run1_EXCLUDED.zip`](https://github.com/mariomc14/devsecops-adversary-llm/releases/download/v3.0-ijis-reproducibility/ijis_controlled_followup_run1_EXCLUDED.zip) (3.0 MB) | `bf891ac2615be0b850276564ad69b7f262da4ddc836201c7ae916401ea078008` | **EXCLUDED FROM SCIENTIFIC RESULTS.** Preliminary run 1 (runner v4, halted at trajectory 30), published only for transparency; see [`../audit/incidents/README.md`](../audit/incidents/README.md). |

## Checking a download

```bash
sha256sum ijis_controlled_followup_public.zip      # must print the SHA-256 above
unzip ijis_controlled_followup_public.zip
cd ijis_controlled_followup_public
sha256sum -c SHA256SUMS.txt                        # must finish without mismatches
```

## Layout of `ijis_controlled_followup_public.zip`

```text
ijis_controlled_followup_public/
├── README.md                 what the archive contains and how to check it
├── SHA256SUMS.txt            SHA-256 of every file in the archive
├── SANITIZATION.md / .json   what was replaced; original and public SHA-256 of each modified file
├── REDACTION.json            record of the earlier shareable bundle (superseded)
├── trajectory_index.csv      one row per trajectory (attempts, statuses, runner revision, session)
├── results/                  80 trajectories as written by the runner (task/model/condition/rep_NN/attempt_NN/)
│   ├── campaign_results.csv / .json, campaign_environment.json
│   └── SHA256SUMS.txt        runner's original manifest (historical; sanitized files match via SANITIZATION.json)
├── human_evaluation/         the delivered human adjudication package, unchanged
├── sessions/                 console log and environment of session 1 (v5) and session 2 (v6)
├── code/                     runner_v5/, runner_v6/, automate/inputs/template.json
├── incidents/                v4_to_v5.diff, v5_to_v6.diff, internal report, verification_v5/, verification_v6/
└── final_verification/       audit_final.py, audit_final.log, build_final_bundle.py
```

Each attempt directory contains the generation prompt and raw response with metadata (model ID, inference configuration, token usage), the generated Python module and Chaos Toolkit JSON, the technical validation, `Q_pre` prompt/report (Chaos ADT conditions), the exact `chaos run` command, `execution.log`, `chaostoolkit.log`, `journal.json`, `Q_post` prompt/report, the feedback supplied to the next attempt, the cleanup report, `attempt_status.json` and the append-only `attempt_events.jsonl`.

The internal (unsanitized) archive is kept privately by the authors. It differs from the public archive only in the values listed in [`../audit/SANITIZATION.md`](../audit/SANITIZATION.md).
