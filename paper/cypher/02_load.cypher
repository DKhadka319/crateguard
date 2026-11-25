// ---------------------------------------------------------------
// 02_load.cypher  -  load the CSVs from data/neo4j_import/
// Neo4j Desktop: copy the CSVs into the DBMS "import" folder, then run this
// file in Neo4j Browser (each statement ends with ;).
// scripts/load_neo4j.py runs these same statements over the driver, which
// also works for Aura Free.
// ---------------------------------------------------------------

// Crates: RustXec crates, crates that depend on them, and every crate with a RustSec advisory
LOAD CSV WITH HEADERS FROM 'file:///crates.csv' AS row
MERGE (c:Crate {name: row.name})
SET c.in_rustxec = toBoolean(row.in_rustxec),
    c.has_advisory = toBoolean(row.has_advisory),
    c.downloads = toInteger(row.downloads),
    c.description = row.description,
    c.max_stable_version = row.max_stable_version;

// Advisories: the 102 RustXec vulnerabilities (in_rustxec = true) plus every other
// RustSec advisory (kind = vulnerability / unmaintained / unsound / notice)
LOAD CSV WITH HEADERS FROM 'file:///advisories.csv' AS row
MERGE (a:Advisory {id: row.id})
SET a.date = date(row.date), a.title = row.title, a.severity = row.severity,
    a.cvss_score = toFloat(row.cvss_score), a.cvss_vector = row.cvss_vector,
    a.url = row.url,
    a.patched = CASE WHEN row.patched IS NULL THEN [] ELSE split(row.patched, '|') END,
    a.unaffected = CASE WHEN row.unaffected IS NULL THEN [] ELSE split(row.unaffected, '|') END,
    a.keywords = CASE WHEN row.keywords IS NULL THEN [] ELSE split(row.keywords, '|') END,
    a.in_rustxec = toBoolean(row.in_rustxec), a.kind = row.kind
WITH a, row
MATCH (c:Crate {name: row.crate})
MERGE (a)-[:AFFECTS]->(c);

LOAD CSV WITH HEADERS FROM 'file:///categories.csv' AS row
MATCH (a:Advisory {id: row.advisory})
MERGE (k:Category {name: row.category})
MERGE (a)-[:IN_CATEGORY]->(k);

LOAD CSV WITH HEADERS FROM 'file:///cwes.csv' AS row
MATCH (a:Advisory {id: row.advisory})
MERGE (w:CWE {id: row.cwe})
MERGE (a)-[:HAS_CWE]->(w);

LOAD CSV WITH HEADERS FROM 'file:///aliases.csv' AS row
MATCH (a:Advisory {id: row.advisory})
MERGE (x:Alias {id: row.alias}) SET x.type = row.type
MERGE (a)-[:ALSO_KNOWN_AS]->(x);

// Vulnerable functions named in the advisory
LOAD CSV WITH HEADERS FROM 'file:///functions.csv' AS row
MATCH (a:Advisory {id: row.advisory}), (c:Crate {name: row.crate})
MERGE (f:Function {path: row.path})
MERGE (f)-[:DEFINED_IN]->(c)
MERGE (a)-[r:VULNERABLE_FUNCTION]->(f) SET r.ranges = split(row.ranges, '|');

// Every published version of each vulnerable crate
LOAD CSV WITH HEADERS FROM 'file:///versions.csv' AS row
MATCH (c:Crate {name: row.crate})
MERGE (v:Version {id: row.id})
SET v.crate = row.crate, v.num = row.num, v.yanked = toBoolean(row.yanked),
    v.prerelease = toBoolean(row.prerelease), v.released = date(row.released),
    v.vulnerable = toBoolean(row.vulnerable)
MERGE (c)-[:HAS_VERSION]->(v);

// Which versions each advisory hits (computed with Cargo semver rules)
LOAD CSV WITH HEADERS FROM 'file:///affected_by.csv' AS row
MATCH (v:Version {id: row.version}), (a:Advisory {id: row.advisory})
MERGE (v)-[:AFFECTED_BY]->(a);

// Dependency edges from crates.io (latest release of the dependent crate)
LOAD CSV WITH HEADERS FROM 'file:///depends_on.csv' AS row
MATCH (src:Crate {name: row.from}), (dst:Crate {name: row.to})
MERGE (src)-[d:DEPENDS_ON {kind: row.kind}]->(dst)
SET d.req = row.req, d.from_version = row.from_version,
    d.optional = toBoolean(row.optional),
    d.admits_vulnerable = toBoolean(row.admits_vulnerable),
    d.resolves_to = row.resolves_to,
    d.resolves_vulnerable = toBoolean(row.resolves_vulnerable);
