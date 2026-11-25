// ---------------------------------------------------------------
// 03_queries.cypher  -  analysis queries (paste one at a time into Neo4j Browser)
// scripts/run_queries.py runs all of them and saves output/query_results.md
// ---------------------------------------------------------------

// Q1: What kinds of vulnerabilities are in RustXec? (category x severity)
MATCH (a:Advisory {in_rustxec: true})-[:IN_CATEGORY]->(k:Category)
RETURN k.name AS category, count(a) AS advisories,
       sum(CASE WHEN a.severity IN ['Critical','High'] THEN 1 ELSE 0 END) AS critical_or_high
ORDER BY advisories DESC;

// Q2: Which advisories hit the most published releases?
MATCH (c:Crate)-[:HAS_VERSION]->(v:Version)-[:AFFECTED_BY]->(a:Advisory {in_rustxec: true})-[:AFFECTS]->(c)
WITH a, c, count(v) AS vulnerable_releases
MATCH (c)-[:HAS_VERSION]->(r:Version)
RETURN a.id AS advisory, c.name AS crate, a.severity AS severity,
       vulnerable_releases, count(r) AS total_releases,
       round(100.0 * vulnerable_releases / count(r), 1) AS pct_vulnerable
ORDER BY vulnerable_releases DESC LIMIT 10;

// Q3: How long was each vulnerability shipped before it was disclosed?
MATCH (v:Version)-[:AFFECTED_BY]->(a:Advisory)-[:AFFECTS]->(c:Crate)
WITH a, c, min(v.released) AS first_vulnerable_release
RETURN a.id AS advisory, c.name AS crate, first_vulnerable_release, a.date AS disclosed,
       duration.inDays(first_vulnerable_release, a.date).days AS days_exposed
ORDER BY days_exposed DESC LIMIT 10;

// Q4: Direct exposure. Popular crates whose current release still ALLOWS a vulnerable version
MATCH (dep:Crate)-[d:DEPENDS_ON {kind: 'normal'}]->(c:Crate {in_rustxec: true})
WHERE d.admits_vulnerable
RETURN dep.name AS dependent, d.from_version AS dependent_version, dep.downloads AS downloads,
       c.name AS vulnerable_crate, d.req AS requirement, d.resolves_to AS newest_allowed,
       d.resolves_vulnerable AS stuck_on_vulnerable
ORDER BY downloads DESC LIMIT 15;

// Q5: "Stuck" dependents. Even `cargo update` cannot reach a fixed version
MATCH (dep:Crate)-[d:DEPENDS_ON]->(c:Crate)<-[:AFFECTS]-(a:Advisory)
WHERE d.resolves_vulnerable
MATCH (:Version {id: c.name + '@' + d.resolves_to})-[:AFFECTED_BY]->(a)
RETURN dep.name AS dependent, d.kind AS kind, c.name AS vulnerable_crate, d.req AS requirement,
       d.resolves_to AS best_possible_version, collect(a.id) AS still_affected_by,
       dep.downloads AS downloads
ORDER BY downloads DESC LIMIT 15;

// Q6: Transitive exposure. Crates 2 hops away from a vulnerable crate
MATCH p = (top:Crate)-[d1:DEPENDS_ON {kind: 'normal'}]->(mid:Crate)
          -[d2:DEPENDS_ON {kind: 'normal'}]->(vc:Crate {in_rustxec: true})
WHERE d2.admits_vulnerable AND top <> vc AND NOT (top)-[:DEPENDS_ON]->(vc)
RETURN top.name AS crate, mid.name AS via, vc.name AS vulnerable_crate, top.downloads AS downloads
ORDER BY downloads DESC LIMIT 15;

// Q7: Blast radius. How many crates reach each vulnerable crate (1-3 hops)?
MATCH (vc:Crate {in_rustxec: true})<-[:DEPENDS_ON*1..3]-(x:Crate)
WITH vc, count(DISTINCT x) AS reachable_dependents
MATCH (a:Advisory {in_rustxec: true})-[:AFFECTS]->(vc)
RETURN vc.name AS vulnerable_crate, reachable_dependents, count(a) AS advisories,
       collect(DISTINCT a.severity) AS severities
ORDER BY reachable_dependents DESC LIMIT 10;

// Q8: Same weakness, different crates. CWEs that show up in more than one crate
MATCH (c:Crate)<-[:AFFECTS]-(a:Advisory {in_rustxec: true})-[:HAS_CWE]->(w:CWE)
WITH w, collect(DISTINCT c.name) AS crates, count(DISTINCT a) AS advisories
WHERE size(crates) > 1
RETURN w.id AS cwe, advisories, crates
ORDER BY advisories DESC;

// Q9: Look up one CVE: what it is, the vulnerable functions, and who depends on the crate
MATCH (x:Alias {id: 'CVE-2025-31130'})<-[:ALSO_KNOWN_AS]-(a:Advisory)-[:AFFECTS]->(c:Crate)
OPTIONAL MATCH (a)-[:VULNERABLE_FUNCTION]->(f:Function)
OPTIONAL MATCH (dep:Crate)-[d:DEPENDS_ON]->(c) WHERE d.admits_vulnerable
RETURN a.id AS advisory, a.title AS title, c.name AS crate, a.patched AS patched,
       collect(DISTINCT f.path) AS vulnerable_functions, collect(DISTINCT dep.name) AS exposed_dependents;

// ---------------------------------------------------------------
// Visualization queries: run these in Neo4j Browser and look at the Graph tab
// ---------------------------------------------------------------

// V1: One advisory in context (category, CWE, functions, and who depends on the crate)
// MATCH p = (a:Advisory {id: 'RUSTSEC-2025-0021'})-[:AFFECTS|IN_CATEGORY|HAS_CWE|ALSO_KNOWN_AS|VULNERABLE_FUNCTION]->() RETURN p
// UNION MATCH p = (:Advisory {id: 'RUSTSEC-2025-0021'})-[:AFFECTS]->(:Crate)<-[:DEPENDS_ON*1..2]-(:Crate) RETURN p

// V2: Exposure map. Every dependency edge that can pull in a vulnerable version
// MATCH p = (:Crate)-[d:DEPENDS_ON]->(c:Crate)<-[:AFFECTS]-(a:Advisory {in_rustxec: true}) WHERE d.admits_vulnerable AND a.severity IN ['Critical','High'] RETURN p LIMIT 150

// V3: Transitive chains into one vulnerable crate
// MATCH p = (:Crate)-[:DEPENDS_ON*1..2]->(c:Crate {name: 'openssl'}) RETURN p LIMIT 80
