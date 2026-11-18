# Reproducibility material — IJIS paper

Reproducibility material for **“LLM-Driven Chaos Attack–Defense Trees for Empirical Security Validation in DevSecOps Scenarios”** (International Journal of Information Security, under review — third revision).

Canonical release: **`v3.0-ijis-reproducibility`** ([GitHub Release](https://github.com/mariomc14/devsecops-adversary-llm/releases/tag/v3.0-ijis-reproducibility)).

## Evidence is separated into

| # | Evidence | Where | Start here |
|---|---|---|---|
| 1 | **Original experimental campaign** (historical evidence, unchanged) | [`original_campaign/`](original_campaign/) | [`original_campaign/README.md`](original_campaign/README.md) |
| 2 | **Prospective controlled follow-up** (third revision) | [`controlled_followup/`](controlled_followup/), canonical runner in [`../controlled_validation/`](../controlled_validation/) | [`controlled_followup/REVIEWER_GUIDE.md`](controlled_followup/REVIEWER_GUIDE.md) |
| 3 | **Human validation** of the controlled follow-up | [`controlled_followup/human_evaluation/`](controlled_followup/human_evaluation/), data in [`controlled_followup/results_summary/`](controlled_followup/results_summary/) | [`controlled_followup/human_evaluation/RUBRIC.md`](controlled_followup/human_evaluation/RUBRIC.md) |
| 4 | **Audit and integrity material** | [`controlled_followup/audit/`](controlled_followup/audit/), [`original_campaign/SHA256SUMS.txt`](original_campaign/SHA256SUMS.txt) | [`controlled_followup/audit/README.md`](controlled_followup/audit/README.md) |

Limitations of both bodies of evidence: [`LIMITATIONS.md`](LIMITATIONS.md).

## The two campaigns are different and are not mixed

| Original campaign | Controlled follow-up |
|---|---|
| 90 trajectories; 15 experiments; 6 Claude variants | 80 trajectories; 164 attempts; 2 tasks; 2 models; 4 conditions; 5 repetitions per cell |
| `maxTokens` configurations 64000/8192 whose mapping per trajectory cannot be fully reconstructed | Uniform `maxTokens = 8192` |
| Some intermediate artifacts/journals were overwritten | Attempt-specific evidence and an improved audit trail (append-only event log per attempt) |
| Mainly descriptive results of the original workflow | Human validity as the primary outcome for the controlled comparisons |

The original campaign does not acquire the reproducibility properties of the controlled follow-up. [`original_campaign/`](original_campaign/) is byte-identical to the `reproducibility/` folder of the earlier release `v2.0-ijis-reproducibility`; it was only moved into its own subfolder, so the paths in its README and in its `SHA256SUMS.txt` are relative to `original_campaign/`.

## Quick verification

From the repository root:

```bash
# 1. paper values of the controlled follow-up (standard library only, no AWS access)
python reproducibility/controlled_followup/analysis/reproduce_paper_results.py

# 2. integrity
(cd reproducibility/controlled_followup && sha256sum -c audit/SHA256SUMS.txt)
(cd reproducibility/original_campaign && sha256sum -c SHA256SUMS.txt)

# 3. canonical controlled-validation runner (needs PyYAML and boto3, see controlled_validation/requirements.txt; no AWS access)
python controlled_validation/campaign_runner.py --config controlled_validation/campaign.yaml --static-check
```

The complete attempt-level evidence of the controlled follow-up is a release asset (`ijis_controlled_followup_public.zip`); its SHA-256 and layout are in [`controlled_followup/full_archive/README.md`](controlled_followup/full_archive/README.md).
