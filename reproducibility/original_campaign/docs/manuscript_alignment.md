# Relationship between archived artifacts and manuscript terminology

The files in this reproducibility package preserve historical experimental material. They are not silently rewritten to mirror every terminology clarification introduced during manuscript refinement.

## Post-execution interpretation

`automation/sce_automation_api.py` preserves the prompt and scoring implementation used during the experimental campaign. The manuscript clarifies the interpretation of the post-execution evidence by separating operational evaluability from security effectiveness. This clarification is an analytical interpretation of the archived evidence; it does not retroactively modify the historical automation, generated reports, or recorded scores included here.

## `Final_Node` and `Goal_Node`

The historical input `inputs/structure.dot` contains the terminal identifier `Final_Node`. The manuscript formalization normalizes this identifier to `Goal_Node` to make the template consistent with the defined goal-node semantics. The original `structure.dot` is retained unchanged for provenance. `inputs/structure_identifier_normalized.dot` is provided only as an identifier-normalized reference copy and was **not** the historical input consumed during the reported experimental campaign.

## Source snapshots

The reference automation/configuration is taken from the archived snapshot identified in `docs/source_manifest.md`. Additional model-organized experiment evidence is included from a second archived snapshot, but older/development automation from that second snapshot is not presented as the reference final configuration.
