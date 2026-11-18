#!/usr/bin/env python3
"""Compare automated admission decisions with adjudicated expert decisions.

Expected CSV columns: automated_decision, adjudicated_decision.
Values: ADMIT/REJECT (case-insensitive). Optional columns are ignored.
Use this with the existing 36-artifact independent-assessment dataset once exported.
"""
from __future__ import annotations
import argparse,csv,math
from pathlib import Path

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('csv_file',type=Path); args=ap.parse_args()
    with args.csv_file.open(newline='',encoding='utf-8') as f: rows=list(csv.DictReader(f))
    tp=fp=fn=tn=0
    for r in rows:
        a=r['automated_decision'].strip().upper(); e=r['adjudicated_decision'].strip().upper()
        if a=='ADMIT' and e=='ADMIT': tp+=1
        elif a=='ADMIT' and e=='REJECT': fp+=1
        elif a=='REJECT' and e=='ADMIT': fn+=1
        elif a=='REJECT' and e=='REJECT': tn+=1
        else: raise SystemExit(f'Unexpected decision row: {r}')
    n=tp+fp+fn+tn
    po=(tp+tn)/n if n else float('nan')
    pa=(tp+fp)/n; pe=(tp+fn)/n
    pchance=pa*pe+(1-pa)*(1-pe)
    kappa=(po-pchance)/(1-pchance) if (1-pchance) else float('nan')
    precision=tp/(tp+fp) if tp+fp else float('nan')
    recall=tp/(tp+fn) if tp+fn else float('nan')
    specificity=tn/(tn+fp) if tn+fp else float('nan')
    fpr=fp/(fp+tn) if fp+tn else float('nan')
    fnr=fn/(fn+tp) if fn+tp else float('nan')
    print(f'n={n}; TP={tp}, FP={fp}, FN={fn}, TN={tn}')
    print(f'agreement={po:.3f}; Cohen kappa={kappa:.3f}')
    print(f'admission precision={precision:.3f}; admission recall={recall:.3f}; specificity={specificity:.3f}')
    print(f'false-admission rate={fpr:.3f}; false-rejection rate={fnr:.3f}')
    print('Note: for the deliberately difficult 36-artifact sample these are diagnostic sample statistics, not prevalence estimates for the full 384-candidate corpus.')
if __name__=='__main__': main()
