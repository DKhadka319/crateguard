"""Step 5: pull the exposure subgraph out of Neo4j and draw it.

Writes
  output/exposure_graph.html  interactive (drag, zoom, hover). Works offline,
                              vis-network is inlined from scripts/vendor/.
  output/exposure_graph.png   static picture for slides (top vulnerable crates only)
"""
import argparse, json, os
import networkx as nx
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from neo4j import GraphDatabase

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "output")

SEV_COLOR = {"Critical": "#b3001b", "High": "#e8590c", "Medium": "#f2b705", "Low": "#8ab17d", "Unknown": "#9e9e9e"}
COLORS = {"vuln_crate": "#7b2cbf", "direct": "#f4a261", "transitive": "#90a4ae"}

SUBGRAPH = """
MATCH (a:Advisory {in_rustxec: true})-[:AFFECTS]->(vc:Crate)
OPTIONAL MATCH (d1:Crate)-[e1:DEPENDS_ON]->(vc) WHERE e1.admits_vulnerable AND e1.kind <> 'dev'
OPTIONAL MATCH (d2:Crate)-[e2:DEPENDS_ON]->(d1) WHERE e2.kind = 'normal'
RETURN a.id AS adv, a.title AS title, a.severity AS sev, vc.name AS vc,
       d1.name AS d1, e1.req AS req1, e1.resolves_vulnerable AS stuck, d1.downloads AS dl1,
       d2.name AS d2, e2.req AS req2, d2.downloads AS dl2
"""


def fetch(uri, auth):
    with GraphDatabase.driver(uri, auth=auth) as drv, drv.session() as s:
        return s.run(SUBGRAPH).data()


def build(rows):
    g = nx.DiGraph()
    for r in rows:
        g.add_node(r["adv"], kind="advisory", sev=r["sev"], title=r["title"])
        g.add_node(r["vc"], kind="vuln_crate")
        g.add_edge(r["adv"], r["vc"], rel="AFFECTS")
        if r["d1"]:
            if g.nodes.get(r["d1"], {}).get("kind") != "vuln_crate":
                g.add_node(r["d1"], kind="direct", downloads=r["dl1"] or 0)
            g.add_edge(r["d1"], r["vc"], rel="DEPENDS_ON", req=r["req1"], stuck=bool(r["stuck"]))
        if r["d2"]:
            if r["d2"] not in g:
                g.add_node(r["d2"], kind="transitive", downloads=r["dl2"] or 0)
            g.add_edge(r["d2"], r["d1"], rel="DEPENDS_ON", req=r["req2"], stuck=False)
    return g


def to_html(g, path):
    nodes, edges = [], []
    for n, d in g.nodes(data=True):
        if d["kind"] == "advisory":
            nodes.append({"id": n, "label": n.replace("RUSTSEC-", ""), "shape": "diamond", "size": 14,
                          "color": SEV_COLOR.get(d["sev"], "#9e9e9e"),
                          "title": f"{n} ({d['sev']})\n{d['title']}"})
        else:
            dl = d.get("downloads", 0) or 0
            nodes.append({"id": n, "label": n, "shape": "dot",
                          "size": 18 if d["kind"] == "vuln_crate" else 6 + min(14, len(str(dl))),
                          "color": COLORS[d["kind"]],
                          "title": f"{n}\n{d['kind'].replace('_', ' ')}" + (f"\n{dl:,} downloads" if dl else "")})
    for u, v, d in g.edges(data=True):
        if d["rel"] == "AFFECTS":
            edges.append({"from": u, "to": v, "color": "#b3001b", "dashes": True, "title": "AFFECTS"})
        else:
            edges.append({"from": u, "to": v, "arrows": "to", "title": f"DEPENDS_ON {d['req']}"
                          + ("\nnewest allowed version is STILL vulnerable" if d["stuck"] else ""),
                          "color": "#d62828" if d["stuck"] else "#bdbdbd", "width": 3 if d["stuck"] else 1})
    vis = open(os.path.join(ROOT, "scripts", "vendor", "vis-network.min.js")).read()
    stats = (f"{sum(1 for _, d in g.nodes(data=True) if d['kind']=='advisory')} advisories &middot; "
             f"{sum(1 for _, d in g.nodes(data=True) if d['kind']=='vuln_crate')} vulnerable crates &middot; "
             f"{sum(1 for _, d in g.nodes(data=True) if d['kind']=='direct')} directly exposed &middot; "
             f"{sum(1 for _, d in g.nodes(data=True) if d['kind']=='transitive')} transitively exposed")
    legend = "".join(f'<span><i style="background:{c}"></i>{t}</span>' for t, c in [
        ("Critical", SEV_COLOR["Critical"]), ("High", SEV_COLOR["High"]), ("Medium", SEV_COLOR["Medium"]),
        ("Severity unknown", SEV_COLOR["Unknown"]), ("Vulnerable crate (RustXec)", COLORS["vuln_crate"]),
        ("Directly exposed dependent", COLORS["direct"]), ("2-hop dependent", COLORS["transitive"])])
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RustXec Exposure Graph</title>
<style>
body{{margin:0;font:14px system-ui,sans-serif;background:#fafafa;color:#222}}
header{{padding:10px 16px;border-bottom:1px solid #ddd;background:#fff}}
h1{{font-size:18px;margin:0 0 4px}} .legend span{{margin-right:14px;white-space:nowrap}}
.legend i{{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:5px;vertical-align:-1px}}
#g{{height:calc(100vh - 92px)}} small{{color:#666}}
</style></head><body>
<header><h1>Who is exposed to RustXec vulnerabilities?</h1>
<div class="legend">{legend}<span><b style="color:#d62828">&#8212;</b> red edge = even the newest allowed version is vulnerable</span></div>
<input id="q" placeholder="Find a crate or advisory, press Enter" style="float:right;padding:4px 8px;width:260px">
<small>{stats}. Data: RustXec (MSR 2026), RustSec advisory-db, crates.io. Graph queried from Neo4j.</small></header>
<div id="g"></div>
<script>{vis}</script>
<script>
const nodes = new vis.DataSet({json.dumps(nodes)});
const edges = new vis.DataSet({json.dumps(edges)});
const net = new vis.Network(document.getElementById('g'), {{nodes, edges}}, {{
  physics: {{solver: 'forceAtlas2Based', forceAtlas2Based: {{gravitationalConstant: -40, springLength: 60}},
            stabilization: {{iterations: 300}}}},
  interaction: {{hover: true, tooltipDelay: 80}}, nodes: {{font: {{size: 11}}}}, edges: {{smooth: false}}
}});
document.getElementById('q').addEventListener('keydown', e => {{
  if (e.key !== 'Enter') return;
  const t = e.target.value.trim().toLowerCase();
  const hit = nodes.get().find(n => n.id.toLowerCase() === t) || nodes.get().find(n => n.id.toLowerCase().includes(t));
  if (hit) {{ net.selectNodes([hit.id]); net.focus(hit.id, {{scale: 1.6, animation: true}}); }}
}});
</script></body></html>"""
    open(path, "w").write(html)


def to_png(g, path, top=8):
    """Static figure: the vulnerable crates that have 'stuck' dependents (red edges),
    each drawn as its own small cluster in a grid so labels stay readable."""
    def stuck_in(n):
        return sum(1 for u in g.predecessors(n) if g.edges[u, n].get("stuck"))
    vcs = [n for n, d in g.nodes(data=True) if d["kind"] == "vuln_crate" and stuck_in(n)]
    vcs = sorted(vcs, key=lambda n: (stuck_in(n), g.in_degree(n)), reverse=True)[:top]
    cols = 4
    rows = (len(vcs) + cols - 1) // cols
    fig, axes = plt.subplots(rows, cols, figsize=(18, 5.2 * rows), dpi=130)
    axes = axes.flatten()
    for ax, vc in zip(axes, vcs):
        keep = {vc} | set(g.predecessors(vc))
        for d1 in list(g.predecessors(vc)):
            if g.nodes[d1]["kind"] != "advisory":
                keep |= set(list(g.predecessors(d1))[:4])
        h = g.subgraph(keep)
        pos = nx.spring_layout(h.to_undirected(), k=0.9, iterations=300, seed=3)
        col = [SEV_COLOR.get(d.get("sev"), "#9e9e9e") if d["kind"] == "advisory" else COLORS[d["kind"]]
               for _, d in h.nodes(data=True)]
        size = [900 if d["kind"] == "vuln_crate" else 260 if d["kind"] == "advisory" else 140
                for _, d in h.nodes(data=True)]
        stuck = [(u, v) for u, v, d in h.edges(data=True) if d.get("stuck")]
        nx.draw_networkx_edges(h, pos, ax=ax, edge_color="#c8c8c8", arrows=True, arrowsize=8, width=0.8)
        nx.draw_networkx_edges(h, pos, ax=ax, edgelist=stuck, edge_color="#d62828", width=2.2,
                               arrows=True, arrowsize=10)
        circles = [n for n, d in h.nodes(data=True) if d["kind"] != "advisory"]
        advs = [n for n, d in h.nodes(data=True) if d["kind"] == "advisory"]
        nx.draw_networkx_nodes(h, pos, ax=ax, nodelist=circles, node_size=[size[list(h).index(n)] for n in circles],
                               node_color=[col[list(h).index(n)] for n in circles], edgecolors="white")
        nx.draw_networkx_nodes(h, pos, ax=ax, nodelist=advs, node_shape="D", node_size=260,
                               node_color=[SEV_COLOR.get(h.nodes[n]["sev"], "#9e9e9e") for n in advs])
        labels = {n: (n.replace("RUSTSEC-", "") if d["kind"] == "advisory" else n)
                  for n, d in h.nodes(data=True)}
        nx.draw_networkx_labels(h, pos, labels, ax=ax, font_size=7)
        ax.set_title(f"{vc}: {stuck_in(vc)} dependent(s) stuck on a vulnerable version", fontsize=10)
        ax.margins(0.18)
        ax.axis("off")
    for ax in axes[len(vcs):]:
        ax.axis("off")
    from matplotlib.lines import Line2D
    handles = [Line2D([], [], marker="D", ls="", color=SEV_COLOR[s], label=f"Advisory ({s})")
               for s in ("Critical", "High", "Medium", "Unknown")]
    handles += [Line2D([], [], marker="o", ls="", color=COLORS[k], label=t, markersize=9) for k, t in
                [("vuln_crate", "Vulnerable crate (RustXec)"), ("direct", "Directly exposed dependent"),
                 ("transitive", "2-hop dependent")]]
    handles.append(Line2D([], [], color="#d62828", lw=2, label="DEPENDS_ON where even the newest allowed version is vulnerable"))
    fig.legend(handles=handles, loc="lower center", ncol=4, fontsize=9, frameon=False)
    fig.suptitle("RustXec in Neo4j: crates whose dependency requirement locks them onto a vulnerable release", fontsize=13)
    fig.tight_layout(rect=(0, 0.05, 1, 0.96))
    fig.savefig(path)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--uri", default="neo4j://localhost:7687")
    p.add_argument("--user", default="neo4j")
    p.add_argument("--password", default="")
    a = p.parse_args()
    g = build(fetch(a.uri, (a.user, a.password) if a.password else None))
    os.makedirs(OUT, exist_ok=True)
    to_html(g, os.path.join(OUT, "exposure_graph.html"))
    to_png(g, os.path.join(OUT, "exposure_graph.png"))
    print(f"graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges -> output/exposure_graph.html/.png")


if __name__ == "__main__":
    main()
