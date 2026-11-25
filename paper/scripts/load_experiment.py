"""Load experiment results (output/experiment/*.jsonl) into Neo4j.

  (:Model)-[:GAVE]->(:Answer {condition})-[:FOR]->(:Task)
  (:Answer)-[:SUGGESTS {req, verdict, installs, safe_version}]->(:Crate)
  (:Answer)-[:FLAGGED_BY]->(:Advisory)

Usage: python scripts/load_experiment.py output/experiment/*.jsonl  [--clear]
"""
import argparse, json
from neo4j import GraphDatabase

LOAD = """
UNWIND $rows AS row
MERGE (m:Model {name: row.model}) SET m.provider = row.provider
MERGE (t:Task {id: row.task_id}) SET t.category = row.category, t.text = row.task
CREATE (a:Answer {id: row.model + '|' + row.task_id + '|' + row.condition, condition: row.condition,
                  parsed: row.parsed, unchanged: coalesce(row.unchanged, false), reply: row.reply})
CREATE (m)-[:GAVE]->(a)-[:FOR]->(t)
WITH a, row
UNWIND row.results AS r
MERGE (c:Crate {name: r.crate})
  ON CREATE SET c.exists_on_cratesio = r.verdict <> 'HALLUCINATED'
CREATE (a)-[:SUGGESTS {req: r.req, verdict: r.verdict, installs: r.installs, safe_version: r.safe_version}]->(c)
WITH a, r
UNWIND r.advisories AS adv
MATCH (x:Advisory {id: adv.id})
MERGE (a)-[:FLAGGED_BY]->(x)
"""


def main():
    p = argparse.ArgumentParser()
    p.add_argument("files", nargs="+")
    p.add_argument("--clear", action="store_true", help="delete earlier Model/Task/Answer nodes first")
    p.add_argument("--uri", default="neo4j://localhost:7687")
    p.add_argument("--user", default="neo4j")
    p.add_argument("--password", default="")
    a = p.parse_args()
    auth = (a.user, a.password) if a.password else None
    with GraphDatabase.driver(a.uri, auth=auth) as drv, drv.session() as s:
        if a.clear:
            s.run("MATCH (n) WHERE n:Model OR n:Task OR n:Answer DETACH DELETE n").consume()
            s.run("MATCH (c:Crate) WHERE c.exists_on_cratesio = false AND NOT (c)--() DELETE c").consume()
        for path in a.files:
            rows = [json.loads(l) for l in open(path)]
            s.run(LOAD, rows=rows).consume()
            print(f"loaded {len(rows)} answers from {path}")


if __name__ == "__main__":
    main()
