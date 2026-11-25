"""The Neo4j side: load advisories and the mistake memory, and answer the guard's queries.

Graph model (subset of the research graph that the guard needs):
  (:Advisory {id, kind, title, severity, patched, unaffected, date, url})-[:AFFECTS]->(:Crate {name})
  (:Advisory)-[:ALSO_KNOWN_AS]->(:Alias {id})          CVE / GHSA ids
  (:Mistake {wrong, kind})-[:CORRECTED_TO]->(:Crate)   shared memory of AI mistakes and their fixes
"""
import json, os
from neo4j import GraphDatabase

SCHEMA = [
    "CREATE CONSTRAINT crate_name IF NOT EXISTS FOR (c:Crate) REQUIRE c.name IS UNIQUE",
    "CREATE CONSTRAINT advisory_id IF NOT EXISTS FOR (a:Advisory) REQUIRE a.id IS UNIQUE",
    "CREATE CONSTRAINT alias_id IF NOT EXISTS FOR (x:Alias) REQUIRE x.id IS UNIQUE",
    "CREATE CONSTRAINT mistake_wrong IF NOT EXISTS FOR (m:Mistake) REQUIRE m.wrong IS UNIQUE",
]
LOAD = """
UNWIND $rows AS row
MERGE (a:Advisory {id: row.id})
SET a.kind = row.kind, a.title = row.title, a.severity = row.severity, a.date = row.date,
    a.url = row.url, a.patched = row.patched, a.unaffected = row.unaffected
MERGE (c:Crate {name: row.crate})
MERGE (a)-[:AFFECTS]->(c)
WITH a, row UNWIND row.aliases AS al
MERGE (x:Alias {id: al})
MERGE (a)-[:ALSO_KNOWN_AS]->(x)
"""
ADVISORIES = """
MATCH (a:Advisory)-[:AFFECTS]->(:Crate {name: $name})
RETURN a.id AS id, a.kind AS kind, a.title AS title, a.severity AS severity,
       a.patched AS patched, a.unaffected AS unaffected
"""
MEMORY = "MATCH (m:Mistake)-[:CORRECTED_TO]->(c:Crate) RETURN m.wrong AS wrong, c.name AS right"


class Graph:
    def __init__(self, uri=None, user=None, password=None, database=None):
        uri = uri or os.environ.get("CRATEGUARD_NEO4J_URI", "bolt://localhost:7687")
        user = user or os.environ.get("CRATEGUARD_NEO4J_USER", "neo4j")
        password = password if password is not None else os.environ.get("CRATEGUARD_NEO4J_PASSWORD", "")
        self.driver = GraphDatabase.driver(uri, auth=(user, password) if password else None)
        self.database = database
        self._cache = {}

    def close(self):
        self.driver.close()

    def run(self, query, **params):
        with self.driver.session(database=self.database) as s:
            return s.run(query, **params).data()

    def load_advisories(self, advisories, wipe=False):
        if wipe:
            self.run("MATCH (n) WHERE n:Advisory OR n:Alias DETACH DELETE n")
        for q in SCHEMA:
            self.run(q)
        for i in range(0, len(advisories), 2000):
            self.run(LOAD, rows=advisories[i:i + 2000])
        return self.stats()

    def stats(self):
        return {r["label"]: r["n"] for r in self.run(
            "MATCH (n) WHERE n:Advisory OR n:Crate OR n:Mistake RETURN labels(n)[0] AS label, count(*) AS n")}

    def advisories(self, crate):
        if crate not in self._cache:
            self._cache[crate] = self.run(ADVISORIES, name=crate)
        return self._cache[crate]

    def memory(self):
        return {r["wrong"]: r["right"] for r in self.run(MEMORY)}

    def remember(self, pairs):
        """pairs: {wrong_name: right_name}. Adds to the shared mistake memory."""
        self.run("""UNWIND keys($p) AS w
                    MERGE (m:Mistake {wrong: w}) SET m.kind = 'invented_crate'
                    MERGE (c:Crate {name: $p[w]})
                    MERGE (m)-[:CORRECTED_TO]->(c)""", p=pairs)

    def export_memory(self, path):
        json.dump({"names": self.memory()}, open(path, "w"), indent=1, sort_keys=True)
