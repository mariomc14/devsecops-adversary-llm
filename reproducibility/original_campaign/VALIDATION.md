# Validation checks

The package was checked before ZIP creation using the following classes of validation:

1. `automation/sce_automation_api.py` compiles with Python's bytecode compiler.
2. `automation/run.sh` passes `bash -n` syntax validation.
3. All JSON files included in the public package parse successfully.
4. The package is scanned for common AWS access-key identifiers, 12-digit account identifiers, private-key headers, e-mail addresses, local home-directory prefixes, and common signed-request fields.
5. `SHA256SUMS.txt` contains checksums for every file in `reproducibility/` except the checksum file itself.

The scan is a safety aid, not a formal proof that no sensitive information exists. A human review before publication is still recommended.
