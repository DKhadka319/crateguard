"""Fig. 1: share of tasks with a serious dependency problem per model under each condition (Wilson 95% CI).
Reads results/table_v1_v2.csv (from stats_all.py)."""
import csv, os
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
rows = list(csv.DictReader(open(os.path.join(ROOT, "results", "table_v1_v2.csv"))))
rows.sort(key=lambda r: -int(r["base"]))
names = {"llama3.1:8b": "Llama 3.1 8B", "deepseek-coder:6.7b": "DeepSeek Coder 6.7B", "qwen2.5-coder:7b": "Qwen2.5 Coder 7B",
         "gpt-oss:20b": "gpt-oss 20B", "gemini-3.5-flash-lite": "Gemini 3.5 Flash-Lite", "gpt-4o-mini": "GPT-4o-mini"}
conds = (("base", "#2a78d6", "No guard"), ("v1", "#eb6834", "Guard v1 (warn only)"),
         ("v2r", "#1baf7a", "Guard v2 (warn + fix hint)"), ("v2f", "#eda100", "Guard v2 + auto-fix"))
plt.rcParams.update({"font.size": 7, "font.family": "serif"})
fig, ax = plt.subplots(figsize=(3.5, 2.4), dpi=300)
w = 0.2
for j, (k, color, label) in enumerate(conds):
    xs = [i + (j - 1.5) * (w + 0.01) for i in range(len(rows))]
    v = [int(r[k]) for r in rows]
    lo = [int(r[k + "_ci"].split("-")[0]) for r in rows]; hi = [int(r[k + "_ci"].split("-")[1]) for r in rows]
    ax.bar(xs, v, w, color=color, label=label, edgecolor="white", linewidth=0.4)
    ax.errorbar(xs, v, yerr=[[a - b for a, b in zip(v, lo)], [b - a for a, b in zip(v, hi)]],
                fmt="none", ecolor="#555", elinewidth=0.5, capsize=1)
ax.set_xticks(range(len(rows))); ax.set_xticklabels([names.get(r["model"], r["model"]) for r in rows], rotation=20, ha="right", fontsize=6)
ax.set_ylabel("Tasks with serious problem (%)", fontsize=7); ax.set_ylim(0, 75)
ax.spines[["top", "right"]].set_visible(False); ax.yaxis.grid(True, color="#e5e5e5", linewidth=0.5); ax.set_axisbelow(True)
ax.legend(frameon=False, fontsize=5.5, loc="upper right")
fig.tight_layout()
out = os.path.join(ROOT, "results", "fig1_serious_rate.png"); fig.savefig(out); print("wrote", out)
