"""Serious-problem rate per model and condition for guard v2 (output/experiment_v2/), with the
exact McNemar test of each condition against baseline and the number of crates the guard had to remove."""
import glob, json, os
from scipy.stats import binomtest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = {"HALLUCINATED", "NO_SUCH_VERSION", "VULNERABLE"}
bad = lambda r: (not r["parsed"]) or (not r["results"]) or any(x["verdict"] in S for x in r["results"])
out = []
for f in sorted(glob.glob(os.path.join(ROOT, "output", "experiment_v2", "*.jsonl"))):
    rows = [json.loads(l) for l in open(f)]
    by = {}
    for r in rows: by.setdefault(r["condition"], {})[r["task_id"]] = r
    base = by["baseline"]
    line = [rows[0]["model"], f"baseline {sum(bad(r) for r in base.values())}"]
    for c in ("autofix_only", "v2_repair", "v2_final"):
        if c not in by or (c != "autofix_only" and all(by[c][t].get("reply", "") == "" for t in by[c])): continue
        k = sum(bad(r) for r in by[c].values())
        b = sum(bad(base[t]) and not bad(by[c][t]) for t in base); cc = sum(not bad(base[t]) and bad(by[c][t]) for t in base)
        p = binomtest(b, b + cc, 0.5).pvalue if b + cc else 1.0
        rm = sum(len(r.get("removed", [])) for r in by[c].values())
        line.append(f"{c} {k} (p={p:.2g}, removed {rm})")
    print(" | ".join(line))
