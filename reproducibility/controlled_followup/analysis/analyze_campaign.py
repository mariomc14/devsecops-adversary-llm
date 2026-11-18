#!/usr/bin/env python3
"""Summarize controlled-validation results after execution/adjudication.

Reviewer-facing copy of controlled_validation/analyze_campaign.py (runner v6). Two changes only, so that it runs on
the files published in results_summary/:
  1. the default inputs are ../results_summary/campaign_results.csv and ../results_summary/human_adjudication_final.csv;
  2. the human label is read from `experiment_outcome` (final adjudicated dataset) when the runner-template column
     `adjudicated_experiment_outcome` is absent.
The summary logic is unchanged. The values reported in the paper are reproduced by reproduce_paper_results.py.
"""
from __future__ import annotations
import argparse, csv, json, math
from collections import defaultdict
from pathlib import Path

ROOT=Path(__file__).resolve().parent
RESULTS=ROOT.parent/'results_summary'

def wilson(successes:int,total:int,z:float=1.96):
    if total==0: return (None,None)
    p=successes/total
    d=1+z*z/total
    c=(p+z*z/(2*total))/d
    h=z*math.sqrt((p*(1-p)+z*z/(4*total))/total)/d
    return max(0,c-h),min(1,c+h)

def read_csv(path):
    if not path.exists(): return []
    with path.open(newline='',encoding='utf-8') as f: return list(csv.DictReader(f))

def human_label(r):
    return (r.get('adjudicated_experiment_outcome') or r.get('experiment_outcome') or '').strip()

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--results',type=Path,default=RESULTS/'campaign_results.csv')
    ap.add_argument('--adjudication',type=Path,default=RESULTS/'human_adjudication_final.csv')
    args=ap.parse_args()
    attempts=read_csv(args.results)
    adj=read_csv(args.adjudication)
    if not attempts:
        raise SystemExit('No campaign results found yet.')

    # Attempt-level operational summaries.
    groups=defaultdict(list)
    for r in attempts:
        groups[(r['condition'],r['model'],r['task'])].append(r)

    print('\n=== ATTEMPT-LEVEL OPERATIONAL SUMMARY ===')
    for key,rows in sorted(groups.items()):
        traj={(r['order'],r['repetition']) for r in rows}
        terminal={(r['order'],r['repetition']) for r in rows if r['status']=='terminal_qpost'}
        cloud=sum(str(r.get('executed','')).lower()=='true' for r in rows)
        print(f'{key}: trajectories={len(traj)}, online_terminal={len(terminal)}, attempts={len(rows)}, cloud_exec={cloud}')

    # Expert-adjudicated primary endpoint if filled.
    filled=[r for r in adj if human_label(r)]
    if filled:
        print('\n=== EXPERT-ADJUDICATED PRIMARY ENDPOINT ===')
        traj_groups=defaultdict(list)
        for r in filled:
            traj_groups[(r['condition'],r['model'],r['task'],r['order'],r['repetition'])].append(r)
        agg=defaultdict(lambda:[0,0])
        for (cond,model,task,order,rep), rows in traj_groups.items():
            success=any(human_label(r).upper()=='VALID' for r in rows)
            k=(cond,model,task)
            agg[k][1]+=1
            agg[k][0]+=int(success)
        for key,(succ,total) in sorted(agg.items()):
            lo,hi=wilson(succ,total)
            print(f'{key}: VALID-within-budget={succ}/{total} ({succ/total:.1%}), 95% Wilson CI [{lo:.1%}, {hi:.1%}]')
    else:
        print('\nHuman adjudication has not been filled yet; primary endpoint cannot be computed.')

if __name__=='__main__': main()
