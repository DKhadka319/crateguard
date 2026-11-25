"""Step 3: load the graph into Neo4j over the official Python driver.

Runs cypher/01_schema.cypher, then cypher/02_load.cypher with each
`LOAD CSV ... FROM 'file:///X.csv' AS row` replaced by `UNWIND $rows AS row`
and the CSV rows sent as a parameter. That means the same Cypher works on
Neo4j Desktop, a local server, or Aura Free (which can't read local files).

Usage:
  pip install neo4j
  python scripts/load_neo4j.py --uri neo4j://localhost:7687 --user neo4j --password <pw>
  python scripts/load_neo4j.py --uri neo4j+s://xxxx.databases.neo4j.io --user neo4j --password <pw>
Add --wipe to delete everything in the database first.
"""
import argparse, csv, os, re
from neo4j import GraphDatabase

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOAD_RE = re.compile(r"LOAD CSV WITH HEADERS FROM 'file:///([\w.]+)' AS row")


def statements(path):
    text = "\n".join(l for l in open(path) if not l.strip().startswith("//"))
    return [s.strip() for s in text.split(";") if s.strip()]


def rows(name):
    with open(os.path.join(ROOT, "data", "neo4j_import", name)) as f:
        # LOAD CSV turns empty fields into null; do the same here
        return [{k: (v if v != "" else None) for k, v in r.items()} for r in csv.DictReader(f)]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--uri", default="neo4j://localhost:7687")
    p.add_argument("--user", default="neo4j")
    p.add_argument("--password", default="")
    p.add_argument("--database", default=None)
    p.add_argument("--wipe", action="store_true")
    a = p.parse_args()
    auth = (a.user, a.password) if a.password else None
    with GraphDatabase.driver(a.uri, auth=auth) as driver, driver.session(database=a.database) as s:
        if a.wipe:
            s.run("MATCH (n) DETACH DELETE n").consume()
        for st in statements(os.path.join(ROOT, "cypher", "01_schema.cypher")):
            s.run(st).consume()
        for st in statements(os.path.join(ROOT, "cypher", "02_load.cypher")):
            m = LOAD_RE.search(st)
            data = rows(m.group(1))
            st = LOAD_RE.sub("UNWIND $rows AS row", st)
            for i in range(0, len(data), 5000):
                s.run(st, rows=data[i:i + 5000]).consume()
            print(f"loaded {m.group(1):20s} {len(data):6d} rows")
        counts = s.run("MATCH (n) RETURN labels(n)[0] AS label, count(*) AS n ORDER BY n DESC").data()
        rels = s.run("MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS n ORDER BY n DESC").data()
    print("\nnodes:", ", ".join(f"{c['label']}={c['n']}" for c in counts))
    print("rels: ", ", ".join(f"{r['type']}={r['n']}" for r in rels))


if __name__ == "__main__":
    main()
