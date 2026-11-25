"""Guard v2: the guard gives the fix, re-checks the repair, auto-repairs what is left,
and keeps a shared memory of mistakes in Neo4j.

  1. Actionable feedback: every warning names a concrete fix (safe version, real crate name).
  2. Re-check: every repaired answer goes through guard.check again.
  3. Auto-fix: whatever is still serious is rewritten by the guard itself from Neo4j + crates.io.
  4. Mistake memory: invented names/versions seen before, and the fix that worked, stored as
     (:Mistake)-[:CORRECTED_TO]->(:Crate) in Neo4j and exported to data/mistake_memory.json.
"""
import difflib, json, os
import cargo_semver as sv
import guard

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERIOUS = {"HALLUCINATED", "NO_SUCH_VERSION", "VULNERABLE"}


def usable(name):
    rel = guard.releases(name) or []
    return [r["num"] for r in rel if not r["yanked"] and not sv.is_prerelease(r["num"])]


def latest_safe(session, name):
    """Newest non-yanked release with no vulnerability advisory, or None."""
    vers = usable(name)
    advs = [a for a in session.run(guard.ADVISORIES, name=name).data() if a["kind"] == "vulnerability"]
    safe = [v for v in vers if not any(guard.hits(v, a) for a in advs)]
    return max(safe, key=sv.key) if safe else None


def real_name(name, memory):
    """Did-you-mean for an invented crate: memory first, then the -/_ spelling swap."""
    for alt in (name.replace("_", "-"), name.replace("-", "_")):
        if alt != name and guard.releases(alt) is not None:
            return alt
    return memory.get("names", {}).get(name)


def feedback(session, results, memory):
    """Like guard.feedback, but each line says exactly what to use instead."""
    lines = []
    for r in results:
        v, c = r["verdict"], r["crate"]
        if v == "HALLUCINATED":
            alt = real_name(c, memory)
            lines.append(f"- `{c}` does not exist on crates.io." +
                         (f" Use `{alt} = \"{latest_safe(session, alt)}\"` instead." if alt else
                          " Replace it with a real, maintained crate, or remove it."))
        elif v in ("NO_SUCH_VERSION", "VULNERABLE", "OLD_FLOOR"):
            safe = latest_safe(session, c)
            why = {"NO_SUCH_VERSION": f"`{c} = \"{r['req']}\"` matches no published version.",
                   "VULNERABLE": f"`{c} = \"{r['req']}\"` installs {r['installs']}, which has known vulnerabilities "
                                 f"({', '.join(a['id'] for a in r['advisories'])}).",
                   "OLD_FLOOR": f"`{c} = \"{r['req']}\"` still allows vulnerable versions."}[v]
            lines.append(f"- {why} " + (f"Use `{c} = \"{safe}\"`." if safe else "No safe version exists; pick another crate."))
        elif v == "UNMAINTAINED":
            lines.append(f"- `{c}` is marked {r['advisories'][0]['kind']} by RustSec ({r['advisories'][0]['id']}); prefer a maintained alternative.")
    return "\n".join(lines)


def autofix(session, results, memory):
    """Rewrite every serious or OLD_FLOOR dependency. Returns (toml_text, removed_crates)."""
    out, removed = [], []
    for r in results:
        name, req = r["crate"], r["req"]
        if r["verdict"] == "HALLUCINATED":
            alt = real_name(name, memory)
            if not alt:
                removed.append(name); continue
            name, req = alt, latest_safe(session, alt) or "*"
        elif r["verdict"] in ("NO_SUCH_VERSION", "VULNERABLE", "OLD_FLOOR"):
            safe = latest_safe(session, name)
            if not safe:
                removed.append(name); continue
            req = safe
        out.append(f'{name} = "{req}"')
    return "```toml\n[dependencies]\n" + "\n".join(out) + "\n```", removed


def similar(a, b):
    a2, b2 = a.lower().replace("_", "-"), b.lower().replace("_", "-")
    return a2 in b2 or b2 in a2 or difflib.SequenceMatcher(None, a2, b2).ratio() >= 0.6


def learn(records):
    """Build mistake memory from v1 runs: (bad name -> name that the guarded answer used and passed).
    records: list of (baseline_results, guarded_results)."""
    names = {}
    for base, guarded in records:
        ok = {g["crate"] for g in guarded if g["verdict"] == "OK"}
        before = {b["crate"] for b in base}
        for b in base:
            if b["verdict"] == "HALLUCINATED":
                # the replacement is a crate that is new in the guarded answer and passed the guard
                # keep it only if the names look alike (a correction, not a different design choice)
                new = [n for n in sorted(ok - before) if similar(b["crate"], n)]
                if len(new) == 1:
                    names.setdefault(b["crate"], new[0])
    return {"names": names}


def save_memory(session, memory, path=os.path.join(ROOT, "data", "mistake_memory.json")):
    json.dump(memory, open(path, "w"), indent=1, sort_keys=True)
    session.run("MATCH (m:Mistake) DETACH DELETE m")
    session.run("""UNWIND $pairs AS p
                   MERGE (m:Mistake {wrong: p[0], kind: 'invented_crate'})
                   MERGE (c:Crate {name: p[1]})
                   MERGE (m)-[:CORRECTED_TO]->(c)""", pairs=list(memory["names"].items()))
    return path
