// ---------------------------------------------------------------
// 01_schema.cypher  -  uniqueness constraints (these also create indexes)
// Run once, before loading.
// ---------------------------------------------------------------
CREATE CONSTRAINT crate_name     IF NOT EXISTS FOR (c:Crate)    REQUIRE c.name IS UNIQUE;
CREATE CONSTRAINT version_id     IF NOT EXISTS FOR (v:Version)  REQUIRE v.id   IS UNIQUE;
CREATE CONSTRAINT advisory_id    IF NOT EXISTS FOR (a:Advisory) REQUIRE a.id   IS UNIQUE;
CREATE CONSTRAINT category_name  IF NOT EXISTS FOR (k:Category) REQUIRE k.name IS UNIQUE;
CREATE CONSTRAINT cwe_id         IF NOT EXISTS FOR (w:CWE)      REQUIRE w.id   IS UNIQUE;
CREATE CONSTRAINT alias_id       IF NOT EXISTS FOR (x:Alias)    REQUIRE x.id   IS UNIQUE;
CREATE CONSTRAINT function_path  IF NOT EXISTS FOR (f:Function) REQUIRE f.path IS UNIQUE;
CREATE INDEX advisory_severity   IF NOT EXISTS FOR (a:Advisory) ON (a.severity);
