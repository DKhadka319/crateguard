"""Table I for the final report: serious-problem tasks per model under every condition.
Conditions: baseline, v1 (guard v1 feedback), v2r (guard v2 feedback, AI repairs), v2f (v2r + guard auto-fix).
Writes results/table_v1_v2.csv (counts, Wilson 95% CIs, exact McNemar p-values, crates removed)."""
import csv, glob, json, os
from scipy.stats import binomtest
from statsmodels.stats.proportion import proportion_confint
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = {"HALLUCINATED", "NO_SUCH_VERSION", "VULNERABLE"}
bad = lambda r: (not r["parsed"]) or (not r["results"]) or any(x["verdict"] in S for x in r["results"])
def load(f):
    by = {}
    for r in map(json.loads, open(f)): by.setdefault(r["condition"], {})[r["task_id"]] = r
    return by
def mcnemar(a, b):
    x = sum(bad(a[t]) and not bad(b[t]) for t in a); y = sum(not bad(a[t]) and bad(b[t]) for t in a)
    return binomtest(x, x + y, 0.5).pvalue if x + y else 1.0
rows = []
for f in sorted(glob.glob(os.path.join(ROOT, "runs", "experiment", "*.jsonl"))):
    v1 = load(f); model = next(iter(v1["baseline"].values()))["model"]
    v2 = load(os.path.join(ROOT, "runs", "experiment_v2", model.replace(":", "-").replace("/", "_") + ".jsonl"))
    c = {"base": v1["baseline"], "v1": v1["guarded"], "v2r": v2["v2_repair"], "v2f": v2["v2_final"]}
    row = {"model": model, "n": len(c["base"])}
    for k, d in c.items():
        n_bad = sum(bad(r) for r in d.values()); lo, hi = proportion_confint(n_bad, len(d), method="wilson")
        row[k] = n_bad; row[k + "_ci"] = f"{100*lo:.0f}-{100*hi:.0f}"
    row["p_v1_vs_base"] = mcnemar(c["base"], c["v1"]); row["p_v2r_vs_base"] = mcnemar(c["base"], c["v2r"])
    row["p_v2r_vs_v1"] = mcnemar(c["v1"], c["v2r"]); row["p_v2f_vs_base"] = mcnemar(c["base"], c["v2f"])
    row["v2f_removed_crates"] = sum(len(r.get("removed", [])) for r in c["v2f"].values())
    row["v2f_tasks_with_removal"] = sum(bool(r.get("removed")) for r in c["v2f"].values())
    rows.append(row)
out = os.path.join(ROOT, "results", "table_v1_v2.csv")
with open(out, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
for r in rows: print({k: (f"{v:.2g}" if isinstance(v, float) else v) for k, v in r.items()})
