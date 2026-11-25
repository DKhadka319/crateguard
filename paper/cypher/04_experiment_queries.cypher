// ---------------------------------------------------------------
// 04_experiment_queries.cypher  -  topic A: measure the AI suggestions
// Run after scripts/run_experiment.py and scripts/load_experiment.py
// ---------------------------------------------------------------

// E1 (RQ1, RQ2): How often does each model suggest a bad dependency, before and after the guard?
MATCH (m:Model)-[:GAVE]->(a:Answer)-[s:SUGGESTS]->(:Crate)
WITH m.name AS model, a.condition AS condition, count(s) AS deps,
     sum(CASE WHEN s.verdict = 'HALLUCINATED' THEN 1 ELSE 0 END) AS hallucinated,
     sum(CASE WHEN s.verdict = 'NO_SUCH_VERSION' THEN 1 ELSE 0 END) AS bad_version,
     sum(CASE WHEN s.verdict = 'VULNERABLE' THEN 1 ELSE 0 END) AS vulnerable,
     sum(CASE WHEN s.verdict = 'UNMAINTAINED' THEN 1 ELSE 0 END) AS unmaintained
RETURN model, condition, deps,
       round(100.0 * hallucinated / deps, 1) AS pct_hallucinated,
       round(100.0 * bad_version / deps, 1) AS pct_bad_version,
       round(100.0 * vulnerable / deps, 1) AS pct_vulnerable,
       round(100.0 * unmaintained / deps, 1) AS pct_unmaintained
ORDER BY model, condition;

// E2 (RQ1): Share of tasks where the answer has at least one serious problem
MATCH (m:Model)-[:GAVE]->(a:Answer)
OPTIONAL MATCH (a)-[s:SUGGESTS]->() WHERE s.verdict IN ['HALLUCINATED', 'NO_SUCH_VERSION', 'VULNERABLE']
WITH m.name AS model, a.condition AS condition, a, count(s) > 0 AS bad
RETURN model, condition, count(a) AS tasks, sum(CASE WHEN bad THEN 1 ELSE 0 END) AS tasks_with_problem,
       round(100.0 * sum(CASE WHEN bad THEN 1 ELSE 0 END) / count(a), 1) AS pct
ORDER BY model, condition;

// E3 (RQ2): Guard fix rate. Of the tasks with a problem at baseline, how many are clean after the guard?
MATCH (m:Model)-[:GAVE]->(b:Answer {condition: 'baseline'})-[:FOR]->(t:Task)<-[:FOR]-(g:Answer {condition: 'guarded'})<-[:GAVE]-(m)
WHERE EXISTS { (b)-[s:SUGGESTS]->() WHERE s.verdict IN ['HALLUCINATED', 'NO_SUCH_VERSION', 'VULNERABLE'] }
WITH m.name AS model, t, NOT EXISTS { (g)-[s2:SUGGESTS]->() WHERE s2.verdict IN ['HALLUCINATED', 'NO_SUCH_VERSION', 'VULNERABLE'] } AS fixed
RETURN model, count(t) AS tasks_with_problem, sum(CASE WHEN fixed THEN 1 ELSE 0 END) AS fixed_by_guard,
       round(100.0 * sum(CASE WHEN fixed THEN 1 ELSE 0 END) / count(t), 1) AS pct_fixed
ORDER BY model;

// E4 (RQ3): Invented crate names. Which fake names come up, and from how many models?
MATCH (m:Model)-[:GAVE]->(:Answer {condition: 'baseline'})-[:SUGGESTS {verdict: 'HALLUCINATED'}]->(c:Crate)
RETURN c.name AS invented_crate, count(DISTINCT m) AS models, collect(DISTINCT m.name) AS by_models
ORDER BY models DESC, invented_crate LIMIT 20;

// E5 (RQ3): Which vulnerable crates do the assistants suggest, and for which advisories?
MATCH (m:Model)-[:GAVE]->(a:Answer {condition: 'baseline'})-[s:SUGGESTS {verdict: 'VULNERABLE'}]->(c:Crate)
MATCH (a)-[:FLAGGED_BY]->(x:Advisory)-[:AFFECTS]->(c)
RETURN c.name AS crate, collect(DISTINCT s.req) AS suggested_reqs, collect(DISTINCT x.id) AS advisories,
       any(i IN collect(x.in_rustxec) WHERE i) AS has_rustxec_case, count(DISTINCT m) AS models
ORDER BY models DESC, crate;

// E6 (RQ3): Which task categories lead to the most problems?
MATCH (a:Answer {condition: 'baseline'})-[:FOR]->(t:Task)
OPTIONAL MATCH (a)-[s:SUGGESTS]->() WHERE s.verdict IN ['HALLUCINATED', 'NO_SUCH_VERSION', 'VULNERABLE']
WITH t.category AS category, a, count(s) > 0 AS bad
RETURN category, count(a) AS answers, round(100.0 * sum(CASE WHEN bad THEN 1 ELSE 0 END) / count(a), 1) AS pct_with_problem
ORDER BY pct_with_problem DESC;

// V4: Picture for the slides. One model's bad suggestions and the advisories behind them
// MATCH p = (:Model)-[:GAVE]->(a:Answer {condition: 'baseline'})-[s:SUGGESTS]->(c:Crate) WHERE s.verdict <> 'OK' OPTIONAL MATCH q = (a)-[:FLAGGED_BY]->(:Advisory) RETURN p, q LIMIT 100
