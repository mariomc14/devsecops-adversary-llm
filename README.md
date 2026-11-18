# IJIS Reproducibility Package: LLM-Driven Chaos Attack–Defense Trees

[![Status](https://img.shields.io/badge/Branch-Reproducibility%20IJIS-success.svg)](#)
[![Release](https://img.shields.io/badge/Release-v3.0--ijis--reproducibility-blue.svg)](https://github.com/mariomc14/devsecops-adversary-llm/releases/tag/v3.0-ijis-reproducibility)
[![Status](https://img.shields.io/badge/Status-Under_Review_at_IJIS-informational.svg)](#)
[![Integrity](https://img.shields.io/badge/Checksums-SHA256%20Verified-brightgreen.svg)](#)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

## IJIS reproducibility material

Canonical release: **`v3.0-ijis-reproducibility`**

Evidence is separated into:

1. **Original experimental campaign** — [`reproducibility/original_campaign/`](reproducibility/original_campaign/)
2. **Prospective controlled follow-up** — [`reproducibility/controlled_followup/`](reproducibility/controlled_followup/) (canonical runner: [`controlled_validation/`](controlled_validation/))
3. **Human validation** — [`reproducibility/controlled_followup/human_evaluation/`](reproducibility/controlled_followup/human_evaluation/)
4. **Audit and integrity material** — [`reproducibility/controlled_followup/audit/`](reproducibility/controlled_followup/audit/)

➡️ **Start here:** [`reproducibility/README.md`](reproducibility/README.md) · **Reviewers:** [`reproducibility/controlled_followup/REVIEWER_GUIDE.md`](reproducibility/controlled_followup/REVIEWER_GUIDE.md) · [`EXPECTED_RESULTS.md`](reproducibility/controlled_followup/analysis/EXPECTED_RESULTS.md) · [`LIMITATIONS.md`](reproducibility/LIMITATIONS.md)

All controlled follow-up values reported in the paper are reproduced with one command (standard library only, no AWS access):

```bash
python reproducibility/controlled_followup/analysis/reproduce_paper_results.py
```

---

> [!IMPORTANT]
> **Artifact for Peer Review:** This branch (`reproducibility/ijis-paper`) contains the formal, frozen reproducibility package supporting the research manuscript:
> 
> **“LLM-Driven Chaos Attack–Defense Trees for Empirical Security Validation in DevSecOps Scenarios”**  
> *(Currently under review at the International Journal of Information Security - IJIS)*
> 
> To cite an immutable snapshot of this package in the manuscript, reference the release tag:
> `v3.0-ijis-reproducibility`
>
> The earlier tag `v2.0-ijis-reproducibility` (original campaign only) is kept unchanged.

---

## 📦 Package Overview

```text
README.md                                    # This file
controlled_validation/                       # Canonical controlled-validation runner (v6)
automate/inputs/template.json                # Experiment template read by the runner
reproducibility/
├── README.md                                # Index of the reproducibility material
├── LIMITATIONS.md                           # Limitations aligned with the manuscript
│
├── original_campaign/                       # ORIGINAL CAMPAIGN (unchanged content of v2.0-ijis-reproducibility)
│   ├── README.md                            # Detailed documentation & runtime config of the original campaign
│   ├── SHA256SUMS.txt                       # Checksums of the original-campaign files
│   ├── VALIDATION.md                        # Validation checks of the original package
│   ├── automation/                          # Preserved reference automation & pinned dependencies
│   ├── inputs/                              # Historical static inputs & identifier-normalized structure
│   ├── preserved_artifacts/                 # Generated experiments and sanitized runtime evidence
│   ├── preserved_reports/                   # Pre-/post-execution metric reports
│   ├── tracking/                            # Attempt-level tracking summaries
│   └── docs/                                # Configuration, model IDs, prompts, limitations, sanitization
│
└── controlled_followup/                     # PROSPECTIVE CONTROLLED FOLLOW-UP (third revision)
    ├── README.md                            # Protocol, conditions, runner provenance
    ├── REVIEWER_GUIDE.md                    # Reviewer #2 points R2.1–R2.4
    ├── protocol/                            # campaign.yaml, schedule.csv, tasks/, template.json, requirements.txt
    ├── results_summary/                     # Runner results, human dataset, paper values
    ├── human_evaluation/                    # README, RUBRIC, delivered package hashes
    ├── analysis/                            # reproduce_paper_results.py, EXPECTED_RESULTS.md
    ├── audit/                               # Final audit, runner v5/v6, diffs, incidents, sanitization, SHA256SUMS
    └── full_archive/                        # Release assets (complete attempt-level evidence) and their SHA-256
```

---

## 🔍 Cryptographic Validation

```bash
# controlled follow-up
cd reproducibility/controlled_followup && sha256sum -c audit/SHA256SUMS.txt && cd -

# original campaign
cd reproducibility/original_campaign && sha256sum -c SHA256SUMS.txt && cd -
```

Expected result: All files return `OK`. The release asset `ijis_controlled_followup_public.zip` contains its own `SHA256SUMS.txt`; the SHA-256 of the asset itself is listed in [`reproducibility/controlled_followup/full_archive/README.md`](reproducibility/controlled_followup/full_archive/README.md).

---

## ⚙️ Key Runtime Configuration

Both campaigns evaluated foundation models via AWS Bedrock Converse and executed compliant experiments in an AWS cloud sandbox using Chaos Toolkit (`--hypothesis-strategy=after-method-only`).

| | Original campaign | Controlled follow-up |
|---|---|---|
| Models | 6 Claude variants | Claude Haiku 4.5, Claude Sonnet 4.6 |
| `maxTokens` | 64000 / 8192 (per-trajectory mapping not fully reconstructable) | 8192 (uniform) |
| `temperature` | 1.0 | 1.0 |
| `topP` / `topK` | not overridden | not overridden |
| Pinned Chaos Toolkit | `chaostoolkit==1.19.0` | `chaostoolkit==1.19.0` |
| Python | 3.12+ | 3.12.13 |

Details: [`reproducibility/original_campaign/README.md`](reproducibility/original_campaign/README.md) and [`reproducibility/controlled_followup/README.md`](reproducibility/controlled_followup/README.md).

---

## 📚 Repository Navigation

* [`main`](https://github.com/mariomc14/devsecops-adversary-llm/tree/main): Master index and navigation portal.
* [`ijis-experiments`](https://github.com/mariomc14/devsecops-adversary-llm/tree/ijis-experiments): Full combined Git history and development experiments.
* [`jnic`](https://github.com/mariomc14/devsecops-adversary-llm/tree/jnic) (`tag: v1.0-jnic`): Conference artifacts for JNIC 2026.
