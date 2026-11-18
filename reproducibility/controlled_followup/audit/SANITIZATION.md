# Sanitization of the public controlled follow-up material

The controlled follow-up was executed against a real AWS account. Its raw evidence therefore contains account metadata that has no scientific value and must not be published. This document describes what was replaced, what was deliberately kept, and how to check it. The machine-readable record is [`SANITIZATION.json`](SANITIZATION.json).

## Scope

Sanitization was applied, with the same rules, to:

1. every file of the public release asset `ijis_controlled_followup_public.zip`;
2. every file copied from the internal campaign archive into this repository (`controlled_validation/`, `automate/inputs/template.json` and `reproducibility/controlled_followup/`);
3. the separate asset with the excluded preliminary run 1 (`ijis_controlled_followup_run1_EXCLUDED.zip`), which carries its own `SANITIZATION.json`.

The internal campaign archive itself was only read and is not modified. The script that performed the copy is [`build_public_release.py`](build_public_release.py). It does not contain any of the replaced values: it reads them from the campaign's own `campaign_environment.json` at build time or matches them by pattern.

## Replaced values

| Placeholder | Replaced value |
|---|---|
| `<REDACTED_AWS_ACCOUNT_ID>` | 12-digit ID of the campaign AWS account (inside ARNs, environment records and logs) |
| `<REDACTED_IAM_USER>` | Name of the IAM user that ran the campaign (caller ARN) |
| `<REDACTED_AWS_ACCESS_KEY_ID>` | AWS access-key IDs (long-term and temporary). Only the campaign profile's own key ID appeared, inside one CloudTrail event printed by a CN2-D probe (trajectory 75, attempt 3). The masked form used in the earlier shareable bundle is replaced too. |
| `<REDACTED_AWS_PRINCIPAL_ID>` | IAM unique principal IDs (`AIDA…`/`AROA…`) printed inside CloudTrail events |
| `<LOCAL_HOME>` | Local home-directory prefix of the workstation that ran the campaign |
| `<CAMPAIGN_VPC_ID>`, `<CAMPAIGN_SUBNET_ID>`, `<CAMPAIGN_SECURITY_GROUP_ID>` | IDs of the fixed `cvr2-network` VPC, subnet and security group. Every attempt used the same network, so stable placeholders keep the evidence interpretable. |

Checked and **absent** (the build stops if any of them is found): AWS secret access keys, session tokens, SigV4 signed-request material (credential and signature query parameters, authorization headers), private-key material and e-mail addresses.

## Values deliberately kept

Model IDs and names, AWS region, timestamps, task IDs, condition names, `Q_pre`/`Q_post`, token usage, generated code logic, experiment outcomes and human labels, runner revision, attempt IDs and the execution structure, attempt-owned resource names (`cvr2-*`) and EC2 instance IDs (needed to read the CN2-D evidence rule), public AMI IDs, and the AWS documentation example IDs (`123456789012`, `*-0123456789abcdef0`) that some generated templates contain.

## Other editorial changes

- Folder names of the internal bundle were translated in the public archive (`codigo/` → `code/`, `sesiones/` → `sessions/`, `incidencias/` → `incidents/`, `verificacion_final/` → `final_verification/`, `indice_trayectorias.csv` → `trajectory_index.csv`). The mapping is in `SANITIZATION.json`.
- In `trajectory_index.csv` the Spanish token `+reanudado_v6` was translated to `+resumed_v6` (one cell, trajectory 20). Nothing else was changed.
- The Spanish `LEEME.md` of the internal bundle is not copied; the public archive has its own English `README.md`.
- The internal incident reports (`Informe_errores_v5.docx`, `V5_CORRECTIONS.md`, `V6_CORRECTIONS.md`) are kept in their original language (Spanish). The same content is given in English in the runner `README.md` ("Changes in v5", "Changes in v6") and in the repository file `reproducibility/controlled_followup/audit/incidents/README.md`.

## Integrity records

- `SANITIZATION.json` lists, for every modified file, its original SHA-256, its public SHA-256 and the number of replacements per rule.
- `results/SHA256SUMS.txt` inside the public archive is the **runner's original manifest**, kept unchanged as historical evidence. Files modified by sanitization no longer match it directly; they match it through the `original_sha256` recorded in `SANITIZATION.json`.
- The public archive has a new root `SHA256SUMS.txt` (`sha256sum -c SHA256SUMS.txt` must finish without mismatches), and the repository folder `reproducibility/controlled_followup/` is covered by `reproducibility/controlled_followup/audit/SHA256SUMS.txt`.

## Verification scan

After the build, every published file (repository and both archives, including the XML inside `.docx` files) was scanned for: access-key ID prefixes, IAM unique principal IDs, the campaign account ID, IAM/STS ARNs containing a real account, the IAM user name, local home-directory paths, private-key headers, SigV4 credential/signature parameters, e-mail addresses and secret-key/session-token values. The search strings listed in the release guide were also searched literally. The remaining occurrences of the strings `aws_account_id` and `caller_arn` are JSON keys and runner code whose values are redacted. The scan is a safety aid, not a formal proof that no sensitive information exists.
