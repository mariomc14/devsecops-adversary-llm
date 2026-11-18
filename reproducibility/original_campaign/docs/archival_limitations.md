# Archival limitations and coverage

The original automation reused the same output paths during successive refinement attempts for several generated artifacts and reports. Generated experiment files, metric reports, captured execution output, and Chaos Toolkit journals could therefore be written again during a later refinement attempt.

Consequently, this package is **not a complete immutable archive of every one of the 384 generated candidates or every runtime execution**. It preserves the experimental material that remains available in the archived repositories.

## Principal archived snapshot

The six Branch 1/Branch 2 tracking summaries currently preserve **128 recorded attempt rows across 36 distinct tracked model–experiment trajectories** in the principal archived snapshot. These summaries retain recorded `Q_pre`, `Q_post`, loop numbers, and model identifiers for those trajectories. The principal artifact/report trees preserve generated experiment definitions and runtime evidence where those files survived the overwrite behavior.

## Additional model-organized snapshot

A second archived repository contains additional generated experiment and report directories organized by model. These materials are included under `preserved_artifacts/additional_model_archives/` and `preserved_reports/additional_model_archives/` to increase the amount of preserved evidence without forcing an inferred mapping into the principal Branch 1/Branch 2 directory structure.

The additional snapshot contributes the following preserved experiment directories:

- `Haiku-3.5`: 6 experiment directories and 6 report directories.
- `Haiku-4.5`: 8 experiment directories and 8 report directories.
- `Opus-4.5`: 8 experiment directories and 8 report directories.
- `Opus-4.6`: 10 experiment directories and 10 report directories.
- `Sonnet-4.5`: 9 experiment directories and 9 report directories.
- `Sonnet-4.6`: 11 experiment directories and 11 report directories.

Some of these directories overlap conceptually with material in the principal snapshot; they are retained under their original model-oriented provenance rather than deduplicated in a way that could obscure source history.

## Missing immutable per-attempt bundles

An immutable artifact-and-journal bundle is **not available for every individual intermediate refinement attempt**. Later attempts may have overwritten earlier generated `.py`/`.json` files, metric reports, captured output, or `journal.json` files. The package intentionally documents this limitation rather than retrospectively fabricating missing historical states.

Verbose `output_*.log` files are intentionally excluded from the public package because some contain low-level AWS SDK request-signature metadata. Available generated experiment definitions, selected Chaos Toolkit logs/journals, metric reports, and tracking summaries are retained where possible after sanitization.
