"""The Neo4j guard (topic A): check Rust dependencies that an AI assistant suggested.

For every suggested dependency (crate name + version requirement) it asks:
  1. Does the crate exist on crates.io?            (crates.io sparse index)
  2. Does the version requirement match a release?  (crates.io sparse index)
  3. Which version would Cargo install today?       (newest non-yanked match)
  4. Is that version hit by a RustSec advisory?      (Neo4j, plus Cargo semver rules)

Verdicts, worst first:
  HALLUCINATED    crate does not exist on crates.io (a name an attacker could register)
  NO_SUCH_VERSION crate exists but no release matches the requirement
  VULNERABLE      the version Cargo would install has a known vulnerability
  OLD_FLOOR       newest allowed version is fine, but the requirement still allows vulnerable ones
  UNMAINTAINED    RustSec marks the crate unmaintained (or unsound)
  OK              none of the above

Usage:
  python scripts/guard.py path/to/Cargo.toml
  python scripts/guard.py --dep openssl=0.10.55 --dep serde=1 --dep made-up-crate=0.1
Add --uri/--user/--password for a non-local Neo4j.
"""
import argparse, json, os, sys, tomllib, urllib.error, urllib.parse, urllib.request
from neo4j import GraphDatabase
import cargo_semver as sv

UA = "csci5304-neo4j-vuln-prototype (student research project)"
CACHE = os.environ.get("INDEX_CACHE", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "raw",
                                                     "index_cache"))
RANK = ["HALLUCINATED", "NO_SUCH_VERSION", "VULNERABLE", "OLD_FLOOR", "UNMAINTAINED", "OK"]

ADVISORIES = """
MATCH (a:Advisory)-[:AFFECTS]->(:Crate {name: $name})
RETURN a.id AS id, a.kind AS kind, a.title AS title, a.severity AS severity,
       a.patched AS patched, a.unaffected AS unaffected, a.in_rustxec AS in_rustxec
"""


def index_path(name):
    n = name.lower()
    if len(n) <= 2:
        return f"{len(n)}/{n}"
    if len(n) == 3:
        return f"3/{n[0]}/{n}"
    return f"{n[:2]}/{n[2:4]}/{n}"


def releases(name):
    """All releases of a crate from the crates.io sparse index, or None if it does not exist."""
    os.makedirs(CACHE, exist_ok=True)
    cache = os.path.join(CACHE, urllib.parse.quote(name.lower(), safe="") + ".json")
    if os.path.exists(cache):
        return json.load(open(cache))
    try:
        req = urllib.request.Request("https://index.crates.io/" + index_path(name), headers={"User-Agent": UA})
        lines = urllib.request.urlopen(req, timeout=30).read().decode().splitlines()
        data = [{"num": e["vers"], "yanked": e["yanked"]} for e in map(json.loads, lines) if e]
    except urllib.error.HTTPError as e:
        if e.code not in (403, 404):
            raise
        data = None
    json.dump(data, open(cache, "w"))
    return data


def hits(version, adv):
    return not sv.matches_any(version, adv["patched"] or []) and not sv.matches_any(version, adv["unaffected"] or [])


def check(session, name, req):
    """Return a dict describing one suggested dependency."""
    out = {"crate": name, "req": req, "verdict": "OK", "installs": None, "advisories": [], "safe_version": None}
    rel = releases(name)
    if rel is None:
        out["verdict"] = "HALLUCINATED"
        return out
    usable = [r["num"] for r in rel if not r["yanked"] and not sv.is_prerelease(r["num"])]
    try:
        allowed = [v for v in usable if sv.matches(v, req)]
    except ValueError:
        allowed = []
    if not allowed:
        out["verdict"] = "NO_SUCH_VERSION"
        return out
    installs = max(allowed, key=sv.key)
    out["installs"] = installs
    advs = session.run(ADVISORIES, name=name).data()
    vulns = [a for a in advs if a["kind"] == "vulnerability"]
    now = [a for a in vulns if hits(installs, a)]
    floor = [a for a in vulns if a not in now and any(hits(v, a) for v in allowed)]
    notes = [a for a in advs if a["kind"] in ("unmaintained", "unsound") and hits(installs, a)]
    if now:
        out["verdict"] = "VULNERABLE"
        safe = [v for v in usable if not any(hits(v, a) for a in vulns)]
        out["safe_version"] = max(safe, key=sv.key) if safe else None
    elif floor:
        out["verdict"] = "OLD_FLOOR"
    elif notes:
        out["verdict"] = "UNMAINTAINED"
    out["advisories"] = [{"id": a["id"], "kind": a["kind"], "severity": a["severity"], "title": a["title"],
                          "in_rustxec": a["in_rustxec"]} for a in (now or floor or notes)]
    return out


def deps_from_cargo_toml(text):
    """[dependencies] of a Cargo.toml (also dev/build) -> [(name, req)]."""
    data = tomllib.loads(text)
    out = []
    for table in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in data.get(table, {}).items():
            if isinstance(spec, str):
                out.append((name, spec))
            elif isinstance(spec, dict) and "version" in spec:
                out.append((spec.get("package", name), spec["version"]))
            elif isinstance(spec, dict):
                out.append((spec.get("package", name), "*"))
    return out


def feedback(results):
    """Plain-English warning for the AI, used in the 'guarded' experiment condition."""
    lines = []
    for r in results:
        if r["verdict"] == "HALLUCINATED":
            lines.append(f"- `{r['crate']}` does not exist on crates.io. Replace it with a real, maintained crate.")
        elif r["verdict"] == "NO_SUCH_VERSION":
            lines.append(f"- `{r['crate']} = \"{r['req']}\"` matches no published version.")
        elif r["verdict"] == "VULNERABLE":
            ids = ", ".join(a["id"] for a in r["advisories"])
            fix = f" Use version {r['safe_version']} or later." if r["safe_version"] else " No fixed version exists; pick another crate."
            lines.append(f"- `{r['crate']} = \"{r['req']}\"` installs {r['installs']}, affected by {ids}.{fix}")
        elif r["verdict"] == "OLD_FLOOR":
            lines.append(f"- `{r['crate']} = \"{r['req']}\"` still allows vulnerable versions; raise the minimum version.")
        elif r["verdict"] == "UNMAINTAINED":
            lines.append(f"- `{r['crate']}` is marked {r['advisories'][0]['kind']} by RustSec ({r['advisories'][0]['id']}).")
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("cargo_toml", nargs="?")
    p.add_argument("--dep", action="append", default=[], help="name=requirement, e.g. openssl=0.10.55")
    p.add_argument("--uri", default="neo4j://localhost:7687")
    p.add_argument("--user", default="neo4j")
    p.add_argument("--password", default="")
    p.add_argument("--json", action="store_true")
    a = p.parse_args()
    deps = deps_from_cargo_toml(open(a.cargo_toml).read()) if a.cargo_toml else []
    deps += [tuple(d.split("=", 1)) for d in a.dep]
    if not deps:
        p.error("give a Cargo.toml or at least one --dep")
    auth = (a.user, a.password) if a.password else None
    with GraphDatabase.driver(a.uri, auth=auth) as drv, drv.session() as s:
        results = [check(s, n, r) for n, r in deps]
    if a.json:
        print(json.dumps(results, indent=1))
        return
    for r in sorted(results, key=lambda r: RANK.index(r["verdict"])):
        adv = ", ".join(f"{x['id']} ({x['severity']})" for x in r["advisories"])
        line = f"{r['verdict']:15s} {r['crate']} = \"{r['req']}\""
        if r["installs"]:
            line += f" -> installs {r['installs']}"
        if adv:
            line += f"  [{adv}]"
        if r["safe_version"]:
            line += f"  fix: use >= {r['safe_version']}"
        print(line)
    bad = [r for r in results if r["verdict"] != "OK"]
    print(f"\n{len(bad)} of {len(results)} suggested dependencies need attention.")
    sys.exit(1 if any(r["verdict"] in RANK[:3] for r in results) else 0)


if __name__ == "__main__":
    main()
