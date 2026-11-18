#!/usr/bin/env python3
"""Reproduce every controlled follow-up value reported in the IJIS paper and response letter.

Usage (from the repository root):
    python reproducibility/controlled_followup/analysis/reproduce_paper_results.py
    python reproducibility/controlled_followup/analysis/reproduce_paper_results.py --write-summary   # regenerate results_summary/paper_results_summary.*

Reads only files published in this release (no AWS access, no model calls, standard library only):
    results_summary/campaign_results.csv          runner output: one row per attempt (automated pipeline)
    results_summary/trajectory_index.csv          runner revision per trajectory
    results_summary/human_adjudication_final.csv  canonical human labels (experiment_outcome, security_outcome)
    results_summary/human_adjudication_trace.csv  independent A/B judgments and C adjudication
    results_summary/VALIDATION_SUMMARY.json       aggregates delivered with the human package
    human_evaluation/delivered_package/SHA256SUMS.txt
    protocol/schedule.csv
    analysis/EXPECTED_RESULTS.md                  the fenced `json expected-results` block

Human labels come exclusively from human_adjudication_final.csv. q_pre, q_post and technical_status are used only to
compare the automated pipeline with the human outcome.

Exit status: 0 if every computed value equals EXPECTED_RESULTS.md, VALIDATION_SUMMARY.json and the committed
paper_results_summary.json; 1 otherwise.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

CF = Path(__file__).resolve().parents[1]
RS = CF / "results_summary"
CONDITIONS = ["chaos_adt_feedback", "chaos_adt_no_feedback", "conventional_adt_feedback", "direct_sce_feedback"]
MODELS = ["haiku-4.5", "sonnet-4.6"]
TASKS = ["CN1-P", "CN2-D"]
EXPERIMENT = ["VALID", "INCONCLUSIVE", "INVALID"]
SECURITY = ["EFFECTIVE", "INEFFECTIVE", "NOT_ASSESSABLE"]

problems: list[str] = []


def check(cond: bool, msg: str):
    if not cond:
        problems.append(msg)


def read_csv(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def pct(num: int, den: int) -> float:
    return round(100.0 * num / den, 1)


def kappa_from_pairs(pairs: list[tuple[str, str]]) -> float:
    n = len(pairs)
    po = sum(a == b for a, b in pairs) / n
    ca, cb = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return (po - pe) / (1 - pe)


def binary_metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    n = tp + fp + fn + tn
    pairs = [("A", "A")] * tp + [("A", "N")] * fp + [("N", "A")] * fn + [("N", "N")] * tn
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "agreement_pct": pct(tp + tn, n), "cohen_kappa": round(kappa_from_pairs(pairs), 3),
            "ppv_pct": pct(tp, tp + fp), "sensitivity_pct": pct(tp, tp + fn), "specificity_pct": pct(tn, tn + fp)}


def parse_score(s: str):
    s = (s or "").strip()
    return float(s) if s else None


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--write-summary", action="store_true", help="(re)write results_summary/paper_results_summary.json/.csv")
    args = ap.parse_args()

    # ---------------------------------------------------------------- integrity of the delivered human package
    delivered = {}
    for line in (CF / "human_evaluation" / "delivered_package" / "SHA256SUMS.txt").read_text(encoding="utf-8").splitlines():
        h, name = line.split(None, 1)
        delivered[name.strip()] = h
    for name in ("human_adjudication_final.csv", "human_adjudication_trace.csv", "blind_id_mapping.csv", "VALIDATION_SUMMARY.json"):
        got = hashlib.sha256((RS / name).read_bytes()).hexdigest()
        check(got == delivered.get(name), f"{name}: SHA-256 differs from the delivered human package")

    camp = read_csv(RS / "campaign_results.csv")
    human = read_csv(RS / "human_adjudication_final.csv")
    trace = read_csv(RS / "human_adjudication_trace.csv")
    tindex = read_csv(RS / "trajectory_index.csv")
    schedule = read_csv(CF / "protocol" / "schedule.csv")
    vsum = json.loads((RS / "VALIDATION_SUMMARY.json").read_text(encoding="utf-8"))

    # ---------------------------------------------------------------- structural consistency
    C = {(int(r["order"]), int(r["attempt"])): r for r in camp}
    H = {(int(r["order"]), int(r["attempt"])): r for r in human}
    T = {r["blind_id"]: r for r in trace}
    check(len(C) == len(camp) == 164 and len(H) == len(human) == 164, "expected 164 unique attempts in both files")
    check(set(C) == set(H), "campaign_results.csv and human_adjudication_final.csv do not cover the same attempts")
    check(set(T) == {r["blind_id"] for r in human}, "trace and final dataset do not cover the same blind IDs")
    sched = {int(r["order"]): r for r in schedule}
    check(len(sched) == 80, "schedule.csv must have 80 trajectories")
    for k, c in C.items():
        h = H.get(k)
        if h is None:
            continue
        s = sched[k[0]]
        same = (c["task"] == s["task"] and c["model"] == s["model"] == h["model"] and c["condition"] == s["condition"] == h["condition"]
                and c["repetition"] == s["repetition"] and int(h["repetition"]) == int(c["repetition"])
                and h["task"] == c["task"].upper().replace("_", "-") and c["status"] == h["technical_status"]
                and c["executed"].lower() == h["executed"].lower()
                and parse_score(c["q_pre"]) == parse_score(h["q_pre"]) and parse_score(c["q_post"]) == parse_score(h["q_post"]))
        check(same, f"attempt {k}: metadata differ between campaign_results.csv, schedule.csv and human_adjudication_final.csv")
        # rubric consistency: a security outcome is assessable only for VALID experiments
        if h["experiment_outcome"] == "VALID":
            check(h["security_outcome"] in ("EFFECTIVE", "INEFFECTIVE"), f"{h['blind_id']}: VALID without EFFECTIVE/INEFFECTIVE")
        else:
            check(h["security_outcome"] == "NOT_ASSESSABLE", f"{h['blind_id']}: non-VALID must be NOT_ASSESSABLE")
        t = T[h["blind_id"]]
        check((t["final_experiment_outcome"], t["final_security_outcome"], t["final_label_source"]) ==
              (h["experiment_outcome"], h["security_outcome"], h["final_label_source"]), f"{h['blind_id']}: trace and final label differ")

    R: dict[str, object] = {}

    # ---------------------------------------------------------------- attempt-level human outcomes
    R["attempts.total"] = len(human)
    for lab in EXPERIMENT:
        R[f"attempts.experiment.{lab}"] = sum(r["experiment_outcome"] == lab for r in human)
    for lab in SECURITY:
        R[f"attempts.security.{lab}"] = sum(r["security_outcome"] == lab for r in human)
    src = Counter(r["final_label_source"] for r in human)
    R["attempts.label_source.A_B_AGREEMENT"] = src["A_B_AGREEMENT"]
    R["attempts.label_source.C_ADJUDICATION"] = src["C_ADJUDICATION"]
    R["attempts.c_adjudicated_blind_ids"] = sorted(r["blind_id"] for r in human if r["final_label_source"] == "C_ADJUDICATION")

    # ---------------------------------------------------------------- A/B agreement before adjudication
    for dim, a, b in (("experiment", "rater_a_experiment", "rater_b_experiment"), ("security", "rater_a_security", "rater_b_security")):
        pairs = [(r[a], r[b]) for r in trace]
        agree = sum(x == y for x, y in pairs)
        R[f"human_ab.{dim}.agreement_count"] = agree
        R[f"human_ab.{dim}.agreement_pct"] = pct(agree, len(pairs))
        R[f"human_ab.{dim}.cohen_kappa"] = round(kappa_from_pairs(pairs), 3)

    # ---------------------------------------------------------------- trajectory-level human outcomes
    traj = defaultdict(list)
    for r in human:
        traj[int(r["order"])].append(r)

    def tlabel(rows):
        labs = {r["experiment_outcome"] for r in rows}
        return "VALID" if "VALID" in labs else ("INCONCLUSIVE" if "INCONCLUSIVE" in labs else "INVALID")

    TL = {o: tlabel(rows) for o, rows in traj.items()}
    meta = {o: rows[0] for o, rows in traj.items()}
    auto_terminal = {o: any(C[(o, int(r["attempt"]))]["status"] == "terminal_qpost" for r in rows) for o, rows in traj.items()}
    R["trajectories.total"] = len(TL)
    for lab in EXPERIMENT:
        R[f"trajectories.{lab}"] = sum(v == lab for v in TL.values())
    R["trajectories.VALID_pct"] = pct(R["trajectories.VALID"], len(TL))

    for cond in CONDITIONS:
        os_ = [o for o in TL if meta[o]["condition"] == cond]
        R[f"conditions.{cond}.n"] = len(os_)
        R[f"conditions.{cond}.valid"] = sum(TL[o] == "VALID" for o in os_)
        R[f"conditions.{cond}.valid_pct"] = pct(R[f"conditions.{cond}.valid"], len(os_))
        R[f"conditions.{cond}.first_attempt_valid"] = sum(
            any(r["attempt"] == "1" and r["experiment_outcome"] == "VALID" for r in traj[o]) for o in os_)
        R[f"conditions.{cond}.cloud_executions"] = sum(C[(o, int(r["attempt"]))]["executed"].lower() == "true" for o in os_ for r in traj[o])
        R[f"conditions.{cond}.automated_terminal"] = sum(auto_terminal[o] for o in os_)
    for model in MODELS:
        os_ = [o for o in TL if meta[o]["model"] == model]
        R[f"models.{model}.n"] = len(os_)
        R[f"models.{model}.valid"] = sum(TL[o] == "VALID" for o in os_)
        R[f"models.{model}.valid_pct"] = pct(R[f"models.{model}.valid"], len(os_))
    for task in TASKS:
        os_ = [o for o in TL if meta[o]["task"] == task]
        R[f"tasks.{task}.n"] = len(os_)
        R[f"tasks.{task}.valid"] = sum(TL[o] == "VALID" for o in os_)
        R[f"tasks.{task}.valid_pct"] = pct(R[f"tasks.{task}.valid"], len(os_))

    # ---------------------------------------------------------------- automated (Q_post >= 100) vs human VALID
    cm = Counter((auto_terminal[o], TL[o] == "VALID") for o in TL)
    for k, v in binary_metrics(cm[(True, True)], cm[(True, False)], cm[(False, True)], cm[(False, False)]).items():
        R[f"auto_vs_human.trajectory.{k}"] = v
    cma = Counter((C[k]["status"] == "terminal_qpost", H[k]["experiment_outcome"] == "VALID") for k in C)
    for k, v in binary_metrics(cma[(True, True)], cma[(True, False)], cma[(False, True)], cma[(False, False)]).items():
        R[f"auto_vs_human.attempt.{k}"] = v

    # ---------------------------------------------------------------- Q_pre / Q_post scale audit
    # Formal scales (runner prompts): Q_pre = 0.40*f1 + 0.30*f2 + 0.30*f3 with f1,f2 in {0,50,100}, f3 in {0,100};
    # Q_post = 0.50*f1 + 0.50*f2 with f1,f2 in {0,100}  ->  {0, 50, 100}.
    qpre_allowed = {round(0.4 * a + 0.3 * b + 0.3 * c, 6) for a in (0, 50, 100) for b in (0, 50, 100) for c in (0, 100)}
    qpost_allowed = {round(0.5 * a + 0.5 * b, 6) for a in (0, 100) for b in (0, 100)}
    qpre = [parse_score(r["q_pre"]) for r in camp if parse_score(r["q_pre"]) is not None]
    qpost = [parse_score(r["q_post"]) for r in camp if parse_score(r["q_post"]) is not None]
    R["qscores.qpre_parseable"] = len(qpre)
    R["qscores.qpre_off_scale"] = sum(round(q, 6) not in qpre_allowed for q in qpre)
    R["qscores.qpre_off_scale_pct"] = pct(R["qscores.qpre_off_scale"], len(qpre))
    R["qscores.qpre_ge_80"] = sum(q >= 80 for q in qpre)
    R["qscores.qpost_parseable"] = len(qpost)
    R["qscores.qpost_off_scale"] = sum(round(q, 6) not in qpost_allowed for q in qpost)
    R["qscores.qpost_off_scale_pct"] = pct(R["qscores.qpost_off_scale"], len(qpost))
    status = Counter(r["status"] for r in camp)
    for s in ("terminal_qpost", "qpost_insufficient", "technical_rejected"):
        R[f"attempts.status.{s}"] = status[s]
    R["attempts.status.other"] = sum(v for k, v in status.items() if k not in ("terminal_qpost", "qpost_insufficient", "technical_rejected"))
    R["attempts.cloud_executions"] = sum(r["executed"].lower() == "true" for r in camp)

    # ---------------------------------------------------------------- runner provenance
    revs = Counter(r["trajectory_runner_revision"] for r in tindex)
    R["provenance.trajectories_runner_v5"] = sum(v for k, v in revs.items() if k.startswith("v5-"))
    R["provenance.trajectories_runner_v6"] = sum(v for k, v in revs.items() if k.startswith("v6-"))
    R["provenance.trajectories_other_revision"] = sum(v for k, v in revs.items() if not k.startswith(("v5-", "v6-")))

    # ---------------------------------------------------------------- cross-check with the delivered VALIDATION_SUMMARY.json
    pa = vsum["pre_adjudication"]
    check(pa["experiment_exact_agreement_count"] == R["human_ab.experiment.agreement_count"], "VALIDATION_SUMMARY: experiment agreement")
    check(pa["security_exact_agreement_count"] == R["human_ab.security.agreement_count"], "VALIDATION_SUMMARY: security agreement")
    check(round(pa["experiment_cohens_kappa"], 3) == R["human_ab.experiment.cohen_kappa"], "VALIDATION_SUMMARY: experiment kappa")
    check(round(pa["security_cohens_kappa"], 3) == R["human_ab.security.cohen_kappa"], "VALIDATION_SUMMARY: security kappa")
    check(sorted(pa["disputed_blind_ids"]) == R["attempts.c_adjudicated_blind_ids"], "VALIDATION_SUMMARY: disputed blind IDs")
    for lab in EXPERIMENT:
        check(vsum["final_attempt_outcomes"]["experiment"].get(lab, 0) == R[f"attempts.experiment.{lab}"], f"VALIDATION_SUMMARY: attempts {lab}")
        check(vsum["final_trajectory_outcomes"].get(lab, 0) == R[f"trajectories.{lab}"], f"VALIDATION_SUMMARY: trajectories {lab}")
    for lab in SECURITY:
        check(vsum["final_attempt_outcomes"]["security"].get(lab, 0) == R[f"attempts.security.{lab}"], f"VALIDATION_SUMMARY: security {lab}")
    for cond in CONDITIONS:
        v = vsum["valid_trajectories_by_condition"][cond]
        check((v["valid"], v["total"]) == (R[f"conditions.{cond}.valid"], R[f"conditions.{cond}.n"]), f"VALIDATION_SUMMARY: {cond}")

    # ---------------------------------------------------------------- comparison with EXPECTED_RESULTS.md
    md = (CF / "analysis" / "EXPECTED_RESULTS.md").read_text(encoding="utf-8")
    m = re.search(r"```json expected-results\n(.*?)\n```", md, re.S)
    expected = json.loads(m.group(1)) if m else {}
    check(bool(expected), "EXPECTED_RESULTS.md: machine-readable block not found")
    mismatches = [(k, v, R.get(k, "<missing>")) for k, v in expected.items() if R.get(k, "<missing>") != v]
    not_expected = [k for k in R if k not in expected]
    for k, v, got in mismatches:
        problems.append(f"EXPECTED_RESULTS.md mismatch: {k}: expected {v!r}, computed {got!r}")
    for k in not_expected:
        problems.append(f"computed value not listed in EXPECTED_RESULTS.md: {k}")

    # ---------------------------------------------------------------- outputs
    print_report(R)
    summary_json = json.dumps(R, indent=2, ensure_ascii=False) + "\n"
    summary_csv = "metric,value\n" + "".join(
        f"{k},{';'.join(v) if isinstance(v, list) else v}\n" for k, v in R.items())
    if args.write_summary:
        (RS / "paper_results_summary.json").write_text(summary_json, encoding="utf-8")
        (RS / "paper_results_summary.csv").write_text(summary_csv, encoding="utf-8")
        print("\nwrote results_summary/paper_results_summary.json and .csv")
    else:
        for name, text in (("paper_results_summary.json", summary_json), ("paper_results_summary.csv", summary_csv)):
            p = RS / name
            check(p.exists() and p.read_text(encoding="utf-8") == text, f"results_summary/{name} differs from the computed values (run with --write-summary)")

    print()
    print(f"compared with EXPECTED_RESULTS.md: {len(expected)} values, {len(mismatches)} mismatches")
    if problems:
        print("RESULT: FAIL")
        for p in problems:
            print("  -", p)
        return 1
    print("RESULT: OK — all values match EXPECTED_RESULTS.md, VALIDATION_SUMMARY.json and paper_results_summary.json")
    return 0


def print_report(R: dict):
    g = R.get
    print("IJIS controlled follow-up — paper values\n")
    print(f"Attempts: {g('attempts.total')}  |  experiment: " + ", ".join(f"{k} {g('attempts.experiment.' + k)}" for k in EXPERIMENT)
          + "  |  security: " + ", ".join(f"{k} {g('attempts.security.' + k)}" for k in SECURITY))
    print(f"Final label source: A_B_AGREEMENT {g('attempts.label_source.A_B_AGREEMENT')}, C_ADJUDICATION {g('attempts.label_source.C_ADJUDICATION')} "
          f"({', '.join(g('attempts.c_adjudicated_blind_ids'))})")
    for d in ("experiment", "security"):
        print(f"A/B agreement ({d}): {g(f'human_ab.{d}.agreement_count')}/{g('attempts.total')} = {g(f'human_ab.{d}.agreement_pct')}%, "
              f"Cohen kappa = {g(f'human_ab.{d}.cohen_kappa')}")
    print(f"\nTrajectories: {g('trajectories.total')}  |  " + ", ".join(f"{k} {g('trajectories.' + k)}" for k in EXPERIMENT)
          + f"  |  VALID {g('trajectories.VALID_pct')}%")
    print(f"\n{'condition':28s} {'VALID':>12s} {'first VALID':>12s} {'cloud exec':>11s} {'auto terminal':>14s}")
    for c in CONDITIONS:
        n = g(f"conditions.{c}.n")
        print(f"{c:28s} {g(f'conditions.{c}.valid'):>3}/{n} ({g(f'conditions.{c}.valid_pct'):>4}%) {g(f'conditions.{c}.first_attempt_valid'):>9}/{n} "
              f"{g(f'conditions.{c}.cloud_executions'):>11} {g(f'conditions.{c}.automated_terminal'):>11}/{n}")
    print()
    for grp, keys in (("models", MODELS), ("tasks", TASKS)):
        for k in keys:
            print(f"{k:12s} {g(f'{grp}.{k}.valid')}/{g(f'{grp}.{k}.n')} VALID = {g(f'{grp}.{k}.valid_pct')}%")
    for level in ("trajectory", "attempt"):
        p = f"auto_vs_human.{level}."
        print(f"\nAutomated terminal (Q_post >= 100) vs human VALID, {level} level: TP={g(p + 'TP')} FP={g(p + 'FP')} FN={g(p + 'FN')} TN={g(p + 'TN')}")
        print(f"  agreement {g(p + 'agreement_pct')}%, kappa {g(p + 'cohen_kappa')}, PPV {g(p + 'ppv_pct')}%, "
              f"sensitivity {g(p + 'sensitivity_pct')}%, specificity {g(p + 'specificity_pct')}%")
    print(f"\nQ_pre parseable {g('qscores.qpre_parseable')}; off the formal scale {g('qscores.qpre_off_scale')} ({g('qscores.qpre_off_scale_pct')}%); "
          f">= 80: {g('qscores.qpre_ge_80')}")
    print(f"Q_post parseable {g('qscores.qpost_parseable')}; outside {{0, 50, 100}} {g('qscores.qpost_off_scale')} ({g('qscores.qpost_off_scale_pct')}%)")
    print(f"Attempt status: terminal_qpost {g('attempts.status.terminal_qpost')}, qpost_insufficient {g('attempts.status.qpost_insufficient')}, "
          f"technical_rejected {g('attempts.status.technical_rejected')}, other {g('attempts.status.other')}; cloud executions {g('attempts.cloud_executions')}")
    print(f"Runner provenance: {g('provenance.trajectories_runner_v5')} trajectories v5, {g('provenance.trajectories_runner_v6')} v6")


if __name__ == "__main__":
    sys.exit(main())
