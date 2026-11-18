"""Usage: python audit_final.py <controlled_validation_dir>  -- read-only audit of the finished campaign."""
import csv, json, sys, hashlib, collections
from pathlib import Path
cv = Path(sys.argv[1]); res = cv / "results"
sys.path.insert(0, str(cv))
rows = list(csv.DictReader(open(cv / "schedule.csv", encoding="utf-8")))
print("schedule rows:", len(rows))
COMPLETED = None
missing, incomplete = [], []
rev = collections.Counter(); att_status = collections.Counter(); traj_terminal = 0; inc = collections.Counter(); inc_where = collections.defaultdict(list)
attempt_dirs = set(); n_attempts = 0
for r in rows:
    d = res / r["task"] / r["model"] / r["condition"] / f"rep_{int(r['repetition']):02d}"
    if not d.is_dir(): missing.append(r["order"]); continue
    st = d / "trajectory_status.json"
    s = json.loads(st.read_text()) if st.exists() else {}
    if not s.get("completed"): incomplete.append(r["order"])
    rev[s.get("runner_revision", "-")] += 1
    traj_terminal += bool(s.get("terminal_qpost_reached"))
    for a in sorted(d.glob("attempt_*")):
        n_attempts += 1; attempt_dirs.add(str(a.relative_to(cv)))
        att_status[json.loads((a / "attempt_status.json").read_text())["status"]] += 1
        for line in (a / "attempt_events.jsonl").read_text().splitlines():
            e = json.loads(line)["event"]
            if e in ("attempt_halted", "infrastructure_error", "attempt_resumed", "manifest_unparseable_kept_verbatim") or e.endswith("_retry") or e.endswith("_failed") or e.startswith("cleanup_retained"):
                inc[e] += 1; inc_where[e].append(f"{r['order']}/{a.name}")
print("trajectory dirs missing:", missing, " incomplete:", incomplete)
print("trajectory runner_revision:", dict(rev))
print("trajectories reaching Q_post>=100:", traj_terminal, "/", len(rows))
print("attempts:", n_attempts, " status:", dict(att_status))
print("incident events:", {k: (v, inc_where[k]) for k, v in inc.items()})
# extra dirs not in schedule
sched_dirs = {f"{r['task']}/{r['model']}/{r['condition']}/rep_{int(r['repetition']):02d}" for r in rows}
found = {str(p.relative_to(res)) for p in res.glob("*/*/*/rep_*")}
print("trajectory dirs outside schedule:", sorted(found - sched_dirs))
# aggregate files
with open(res / "campaign_results.csv", encoding="utf-8") as f: cr = list(csv.DictReader(f))
keys = {(x["task"], x["model"], x["condition"], x["repetition"]) for x in cr}
print("campaign_results.csv rows:", len(cr), " distinct trajectories:", len(keys), " orders:", len({x["order"] for x in cr}))
print("csv attempt_dir set == attempt dirs on disk:", {x["attempt_dir"] for x in cr} == attempt_dirs)
cj = json.loads((res / "campaign_results.json").read_text())
print("campaign_results.json records:", len(cj) if isinstance(cj, list) else type(cj).__name__)
with open(res / "human_adjudication.csv", encoding="utf-8") as f: ha = list(csv.DictReader(f))
print("human_adjudication.csv rows:", len(ha), " columns:", list(ha[0].keys()) if ha else [])
# manifest
man = {}
for line in (res / "SHA256SUMS.txt").read_text().splitlines():
    h, p = line.split(None, 1); man[p.strip().lstrip("*")] = h
bad = []; 
for p, h in man.items():
    fp = res / p if not (cv / p).exists() or p.startswith("cn") else cv / p
    cand = [res / p, cv / p, cv.parent / p]
    fp = next((c for c in cand if c.is_file()), None)
    if fp is None or hashlib.sha256(fp.read_bytes()).hexdigest() != h: bad.append(p)
files = {str(p.relative_to(res)) for p in res.rglob("*") if p.is_file()}
mk = {p.split("results/", 1)[-1] for p in man}
print("SHA256SUMS entries:", len(man), " mismatching/missing:", len(bad), bad[:5])
print("files in results/ not in SHA256SUMS:", sorted(files - mk)[:10], len(files - mk))
