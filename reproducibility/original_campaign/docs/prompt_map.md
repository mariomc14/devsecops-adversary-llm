# Prompt provenance and reconstruction

The exact prompt-generation logic is preserved in `automation/sce_automation_api.py`. The principal prompt-builder functions are:

- `_build_mission_prompt`
- `_build_attack_prompt`
- `_build_attack_defense_tree_prompt`
- `_build_sce_experiment_prompt`
- `_build_metrics_prompt`
- `_build_metrics_post_prompt`

The static inputs used by these builders are preserved under `inputs/`. Later refinement prompts may also incorporate the preceding execution log and pre-/post-execution metric reports. Because some intermediate files were overwritten during the original iterative runs, the repository preserves the exact prompt-building implementation and static inputs but does **not** claim byte-identical reconstruction of every later-attempt prompt.
