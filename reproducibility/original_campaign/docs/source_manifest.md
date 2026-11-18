# Source manifest

This reproducibility folder was assembled from two archived experimental repository snapshots already available to the research team.

- Principal archived snapshot: `devsecops-adversary-llm-experimentos-miguel`, archive commit identifier `32526a3fe89b74906b6a252fa58778c6e20754c3`.
- Additional model-organized snapshot: `devsecops-adversary-llm-experiments-Mario`, archive commit identifier `eee7ef89b9f3e391fffa79ee404a7ff87c0c60b8`.

The principal snapshot is used for the reference automation, common configuration, static inputs, Branch 1/Branch 2 tracking summaries, and the principal preserved artifact/report trees. The second snapshot contributes additional preserved generated experiments, reports, and one additional tracking summary. Its older/development automation is not presented as the reference final configuration.

| Reproducibility path | Archived source |
|---|---|
| `automation/sce_automation_api.py` | principal: `automate/sce_automation_api.py` |
| `automation/run.sh` | principal: `automate/run.sh` |
| `automation/requirements.txt` | principal: `automate/requirements.txt` |
| `inputs/` | principal: `automate/inputs/` |
| `tracking/branch_1/` | principal: `automate/1_tracking_summary_*.md` |
| `tracking/branch_2/` | principal: `automate/2_tracking_summary_*.md` |
| `preserved_artifacts/branch_1/` | principal: `automate/chaos_1_experiments/` |
| `preserved_artifacts/branch_2/` | principal: `automate/chaos_2_experiments/` |
| `preserved_reports/branch_1/` | principal: `automate/chaos_1_reports/` |
| `preserved_reports/branch_2/` | principal: `automate/chaos_2_reports/` |
| `preserved_artifacts/additional_model_archives/` | additional: `automate/Experimentos-*/experiments/` |
| `preserved_reports/additional_model_archives/` | additional: `automate/Experimentos-*/reports/` |
| `tracking/additional_archives/mario_tracking_summary.md` | additional: `automate/tracking_summary.md` |

The original directory organization is retained inside each provenance group wherever practical. No attempt is made to infer a one-to-one mapping between every surviving file in the second snapshot and the canonical Branch 1/Branch 2 result tables when that mapping is not explicitly stored in the archive.

The additional model-organized snapshot can contain auxiliary/development executions as well as preserved study-related material. Its directories are therefore exposed as archival evidence rather than asserted to be a one-to-one representation of the manuscript's consolidated experiment population. See `docs/additional_archive_scope.md`.
