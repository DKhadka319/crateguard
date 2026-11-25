"""Task-level statistics for Table I, read straight from output/experiment/*.jsonl.
Serious problem = any dependency HALLUCINATED, NO_SUCH_VERSION or VULNERABLE (or no usable answer).
Any warning      = any verdict other than OK (adds OLD_FLOOR and UNMAINTAINED).
McNemar exact test on discordant pairs: b = problem->clean, c = clean->problem."""
import csv, glob, json, os, sys
from scipy.stats import binomtest
from statsmodels.stats.proportion import proportion_confint

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERIOUS = {"HALLUCINATED", "NO_SUCH_VERSION", "VULNERABLE"}

def flags(r):
    v = {x["verdict"] for x in r["results"]}
    unusable = not r["parsed"] or not r["results"]
    return (unusable or bool(v & SERIOUS)), (unusable or bool(v - {"OK"})), unusable

def pct_ci(k, n):
    lo, hi = proportion_confint(k, n, method="wilson")
    return f"{100*k/n:.0f}% [{100*lo:.0f}-{100*hi:.0f}]"

rows = []
for f in sorted(glob.glob(os.path.join(ROOT, "output", "experiment", "*.jsonl"))):
    recs = [json.loads(l) for l in open(f)]
    model = recs[0]["model"]
    base = {r["task_id"]: flags(r) for r in recs if r["condition"] == "baseline"}
    guard = {r["task_id"]: flags(r) for r in recs if r["condition"] == "guarded"}
    n = len(base)
    for i, label in ((0, "serious"), (1, "any")):
        kb = sum(base[t][i] for t in base); kg = sum(guard[t][i] for t in base)
        b = sum(base[t][i] and not guard[t][i] for t in base)
        c = sum(not base[t][i] and guard[t][i] for t in base)
        p = binomtest(b, b + c, 0.5).pvalue if b + c else 1.0
        rows.append({"model": model, "measure": label, "n": n,
                     "baseline": pct_ci(kb, n), "guarded": pct_ci(kg, n),
                     "fixed_b": b, "new_c": c, "fix_rate": f"{100*b/kb:.0f}%" if kb else "-",
                     "mcnemar_p": f"{p:.2g}", "no_answer_base": sum(base[t][2] for t in base),
                     "no_answer_guard": sum(guard[t][2] for t in base)})

out = os.path.join(ROOT, "output", "results", "table1.csv")
with open(out, "w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=rows[0].keys()); w.writeheader(); w.writerows(rows)
for r in rows:
    print(" | ".join(str(v) for v in r.values()))
print("wrote", out)
