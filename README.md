# IJIS Reproducibility Package: LLM-Driven Chaos Attack–Defense Trees

[![Status](https://img.shields.io/badge/Branch-Reproducibility%20IJIS-success.svg)](#)
[![Release](https://img.shields.io/badge/Release-v2.0--ijis--reproducibility-blue.svg)](#)
[![Status](https://img.shields.io/badge/Status-Under_Review_at_IJIS-informational.svg)](#)
[![Integrity](https://img.shields.io/badge/Checksums-SHA256%20Verified-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> [!IMPORTANT]
> **Artifact for Peer Review:** This branch (`reproducibility/ijis-paper`) contains the formal, frozen reproducibility package supporting the research manuscript:
> 
> **“LLM-Driven Chaos Attack–Defense Trees for Empirical Security Validation in DevSecOps Scenarios”**  
> *(Currently under review at the International Journal of Information Security - IJIS)*
> 
> To cite an immutable snapshot of this package in the manuscript, reference the release tag:
> `v2.0-ijis-reproducibility`

---

## 📦 Package Overview

This reproducibility package provides the complete preserved implementation, configuration, input specifications, attempt-level tracking summaries, generated experiment artifacts, metric reports, and sanitized runtime evidence from the evaluation campaign reported in the manuscript:

```text
reproducibility/
├── README.md                           # Detailed reproducibility documentation & runtime config
├── SHA256SUMS.txt                      # Cryptographic checksums of all preserved package files
├── VALIDATION.md                       # Validation criteria & integrity verification steps
│
├── automation/                         # Preserved reference automation & dependencies
│   ├── sce_automation_api.py           # Final reference generation & refinement orchestrator
│   ├── run.sh                          # Automated test execution script
│   └── requirements.txt                # Pinned Python package dependencies
│
├── inputs/                             # Historical static inputs & normalized structure
│   ├── structure.dot                   # Input Attack-Defense Tree graph
│   ├── structure_identifier_normalized.dot # Identifier-normalized graph aligned with manuscript
│   ├── attack.yaml                     # Attack scenario and safeguard definitions
│   ├── mission.yaml                    # System context definition
│   ├── template.json                   # Experiment JSON schema template
│   ├── EC2Attack.txt                   # Threat intelligence input for Branch 1
│   └── CodeBuildAttack.txt             # Threat intelligence input for Branch 2
│
├── preserved_artifacts/                # Preserved generated experiments and runtime evidence
│   ├── branch_1/                       # Branch 1 (EC2 IMDS privilege escalation) experiments
│   ├── branch_2/                       # Branch 2 (CodeBuild project compromise) experiments
│   └── additional_model_archives/      # Additional model-organized experimental snapshots
│
├── preserved_reports/                  # Preserved metric evaluation reports
│   ├── branch_1/                       # Pre- and post-execution reports for Branch 1
│   ├── branch_2/                       # Pre- and post-execution reports for Branch 2
│   └── additional_model_archives/      # Pre- and post-execution reports organized by model
│
├── tracking/                           # Preserved attempt-level tracking summaries
│   ├── branch_1/                       # Attempt logs for preventive, detective, and reactive
│   ├── branch_2/                       # Attempt logs for preventive, detective, and reactive
│   └── additional_archives/            # Additional model-level tracking summaries
│
└── docs/                               # Methodological & archival documentation
    ├── experimental_configuration.md   # Bedrock & Chaos Toolkit parameters
    ├── model_identifiers.md            # Exact evaluated AWS Bedrock model IDs
    ├── prompt_map.md                   # Prompt templates & composition
    ├── manuscript_alignment.md         # Terminology mapping to manuscript
    ├── source_manifest.md              # Provenance & snapshot manifest
    ├── sanitization.md                 # Public-release sanitization policy
    ├── archival_limitations.md         # Limitations & package coverage details
    └── additional_archive_scope.md     # Scope and interpretation of secondary archives
```

---

## 🔍 Cryptographic Validation

All files in the reproducibility directory are verified against `SHA256SUMS.txt`. To verify package integrity:

```bash
cd reproducibility
sha256sum -c SHA256SUMS.txt
```

Expected result: All files return `OK`.

---

## ⚙️ Key Runtime Configuration

The experiments evaluated foundation models via AWS Bedrock Converse using:
```python
inferenceConfig = {
    "maxTokens": 8192,
    "temperature": 1.0,
}
```

The runtime validation executed compliant experiments in an AWS cloud sandbox using Chaos Toolkit:
* Pinned Chaos Toolkit version: `chaostoolkit==1.18.0`
* Python runtime: Python 3.12+

For detailed instructions on recreating the execution environment and running the validation suite, refer to [`reproducibility/README.md`](reproducibility/README.md) and [`reproducibility/VALIDATION.md`](reproducibility/VALIDATION.md).

---

## 📚 Repository Navigation

* [`main`](https://github.com/mariomc14/devsecops-adversary-llm/tree/main): Master index and navigation portal.
* [`ijis-experiments`](https://github.com/mariomc14/devsecops-adversary-llm/tree/ijis-experiments): Full combined Git history and development experiments.
* [`jnic`](https://github.com/mariomc14/devsecops-adversary-llm/tree/jnic) (`tag: v1.0-jnic`): Conference artifacts for JNIC 2026.
