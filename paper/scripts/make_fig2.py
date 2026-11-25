"""Fig. 2: the guard v2 loop (diagram, no data)."""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLUE, ORANGE, AQUA, YELLOW, INK, MUTED = "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#1f2328", "#59636e"
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 5.3})
fig, ax = plt.subplots(figsize=(3.5, 2.6), dpi=300)
ax.set_xlim(0, 100); ax.set_ylim(0, 72); ax.axis("off")


def box(x, y, w, h, text, edge, fill="#ffffff", bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.4,rounding_size=1.6",
                                linewidth=0.8, edgecolor=edge, facecolor=fill))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", color=INK,
            fontweight="bold" if bold else "normal", linespacing=1.25)


def arrow(p, q, color=MUTED, text=None, toff=(0, 0), rad=0.0):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle="-|>", mutation_scale=6, linewidth=0.7,
                                 color=color, connectionstyle=f"arc3,rad={rad}"))
    if text:
        ax.text((p[0] + q[0]) / 2 + toff[0], (p[1] + q[1]) / 2 + toff[1], text, color=color,
                ha="center", va="center", fontsize=5.4)


## row 1: answer -> check -> accept
box(1, 56, 22, 12, "AI answer\n[dependencies]", MUTED)
box(35, 56, 28, 12, "Check every crate:\ncrates.io index +\nNeo4j advisories", BLUE, "#eef4fc", bold=True)
box(76, 56, 23, 12, "Accept the\nanswer", AQUA, "#edf8f3")
arrow((23.8, 62), (34.2, 62))
arrow((63.8, 62), (75.2, 62), AQUA, "clean", (0, -2.6))
# row 2: feedback -> AI repairs -> re-check ; auto-fix
box(35, 31, 28, 14, "(a) Actionable feedback\nnames the fix: newest\nsafe version / real name", ORANGE, "#fdf0ea")
box(1, 31, 22, 14, "AI repairs\nits answer", MUTED)
box(76, 31, 23, 14, "(c) Auto-fix what is\nstill serious; remove\ninvented crates and\nreport them", ORANGE, "#fdf0ea")
arrow((49, 55.2), (49, 45.8), ORANGE, "serious", (-5, 0))
arrow((34.2, 38), (23.8, 38))
arrow((12, 45.8), (12, 55.2), BLUE, "(b) re-check", (-0.2, 0))
arrow((57, 55.2), (80, 45.8), ORANGE, "still serious", (2, -4.2))
arrow((87.5, 45.8), (87.5, 55.2), AQUA)
# row 3: memory
box(31, 4, 36, 14, "(d) Mistake memory in Neo4j\n(:Mistake)-[:CORRECTED_TO]\n->(:Crate), shared as JSON", YELLOW, "#fdf6e3")
arrow((49, 18.8), (49, 30.2), YELLOW, "did-you-mean", (-9, 0))
arrow((12, 30.2), (30.2, 11), YELLOW, "learn fixes\nthat passed", (-11, -5), rad=0.25)
fig.tight_layout(pad=0.1)
out = os.path.join(ROOT, "results", "fig2_guard_v2.png")
fig.savefig(out); print("wrote", out)
