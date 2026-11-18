# Public-release sanitization

The runtime evidence in this package is a sanitized copy of archived experimental material. Sanitization is limited to infrastructure/account metadata that is not required to interpret the scientific results, including detected:

- AWS access-key identifiers;
- 12-digit AWS account identifiers;
- request-signature and authorization material;
- e-mail addresses;
- local home-directory prefixes.

Verbose `output_*.log` files are intentionally not copied into the public package because some contain low-level AWS SDK request metadata, including signed-request headers. Generated experiments, selected Chaos Toolkit `journal.json`/`chaostoolkit.log` files, metric reports, and tracking summaries are retained where available.

The sanitization process is pattern-based and was followed by a repository-wide verification scan for the principal credential/account/path patterns documented above. It should not be interpreted as a formal guarantee that every conceivable sensitive string has been detected.

No scientific score, model identifier, generated experiment code path, runtime outcome, or metric-report conclusion is intentionally changed by this sanitization.
