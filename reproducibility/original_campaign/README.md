# Reproducibility material for the Chaos ADT / SCE evaluation

This folder contains the preserved implementation, configuration, inputs, tracking information, generated experiment artifacts, metric reports, and runtime evidence available from the experimental campaign reported in **“LLM-Driven Chaos Attack–Defense Trees for Empirical Security Validation in DevSecOps Scenarios.”**

The material reflects the experimental archive that remains available. Because successive refinement attempts reused output paths, the archive is not complete at the artifact level for every model–experiment trajectory and refinement attempt. The preserved attempt-level and runtime material included here is therefore provided as reproducibility evidence rather than as a complete immutable record of all 384 generated candidates.

The folder is intended to be added to the paper's canonical source-code repository on a dedicated reproducibility branch and fixed release/tag.

## Contents

- `automation/` — final preserved automation, runner, and pinned dependencies used as the reference implementation for the reported workflow.
- `inputs/` — historical static inputs consumed by the generation workflow, plus an identifier-normalized copy of the structural input for alignment with the manuscript terminology.
- `tracking/` — preserved attempt-level tracking summaries. The six Branch 1/Branch 2 summaries come from the principal archived experimental snapshot; `tracking/additional_archives/` contains additional preserved tracking evidence from a second archived snapshot.
- `preserved_artifacts/branch_1/` and `preserved_artifacts/branch_2/` — preserved generated experiments and sanitized Chaos Toolkit runtime evidence from the principal archived snapshot.
- `preserved_artifacts/additional_model_archives/` — additional preserved generated experiments and sanitized runtime evidence organized by model from a second archived snapshot; see `docs/additional_archive_scope.md` before interpreting these directories as manuscript runs.
- `preserved_reports/` — preserved and sanitized pre-/post-execution metric reports from both archived snapshots.
- `docs/experimental_configuration.md` — Bedrock and Chaos Toolkit runtime configuration.
- `docs/model_identifiers.md` — exact evaluated AWS Bedrock model identifiers.
- `docs/prompt_map.md` — location and composition of the prompt templates.
- `docs/archival_limitations.md` — explicit description of unavailable immutable per-attempt archives and package coverage.
- `docs/additional_archive_scope.md` — scope and interpretation of the second model-organized archived snapshot.
- `docs/manuscript_alignment.md` — relationship between historical experimental artifacts and terminology/interpretation clarified in the manuscript.
- `docs/sanitization.md` — public-release sanitization policy.
- `docs/source_manifest.md` — provenance of the packaged material.

## Key execution configuration

The preserved final automation uses AWS Bedrock Converse with:

```python
inferenceConfig={
    "maxTokens": 8192,
    "temperature": 1,
}
```

No explicit `topP` or `topK` override is supplied.

Runtime execution uses:

```bash
chaos run <experiment>.json --hypothesis-strategy=after-method-only
```

See `docs/experimental_configuration.md` for details.

## Prompts

The exact prompt-building logic is preserved in `automation/sce_automation_api.py`; the static inputs it consumes are under `inputs/`. See `docs/prompt_map.md`.

## Attempt-level evidence and archival limitation

The principal files under `tracking/branch_1/` and `tracking/branch_2/` preserve recorded attempt sequences for the trajectories present in that archived snapshot, including loop number, `Q_pre`, `Q_post`, and the selected Bedrock model identifier. Additional preserved tracking evidence is included under `tracking/additional_archives/`. These materials should not be interpreted as a complete immutable per-attempt archive for all 90 model–experiment trajectories.

The original iterative automation reused output paths, so later attempts could overwrite files produced by preceding attempts. Therefore, this package does **not** contain an immutable artifact-and-journal bundle for every intermediate refinement attempt. The package preserves the material that remains available and documents the limitation rather than reconstructing missing historical files retrospectively. See `docs/archival_limitations.md`.

## Relationship to the manuscript

The automation, prompt-building code, and archived experiment artifacts are preserved as historical experimental evidence. The manuscript subsequently clarifies the interpretation of the post-execution criteria; that clarification does not rewrite the historical automation or archived scores.

The historical structural input `inputs/structure.dot` also retains the identifier `Final_Node` present during the experimental campaign. The manuscript normalizes this terminal identifier to `Goal_Node` when reconciling the formal representation. For convenience, `inputs/structure_identifier_normalized.dot` provides an identifier-only normalized copy while the original historical input is retained unchanged.

See `docs/manuscript_alignment.md` for details.

## Public-release note

Runtime evidence has been sanitized to remove cloud-account identifiers, access-key identifiers, signed-request material, e-mail addresses, and local home-directory prefixes where detected. Verbose `output_*.log` files are intentionally omitted because some contain low-level AWS SDK signed-request metadata. Sanitization is documented in `docs/sanitization.md` and does not intentionally alter scientific scores, generated experiment logic, model identifiers, or metric-report conclusions.
