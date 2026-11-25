"""Step 1: pull dependency data from crates.io for every crate in RustXec.

For each vulnerable crate we fetch
  * every published version (to know which releases are vulnerable), and
  * its top reverse dependencies (who depends on it = who may be exposed).
Then we go one more hop: the top dependents of the top dependents, so the
graph has real transitive chains (A -> B -> vulnerable crate).

crates.io asks for a User-Agent and at most ~1 request/second.
Responses are cached in data/raw/cratesio_cache/ so reruns are instant.
"""
import csv, json, os, sys, time, urllib.request, urllib.parse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw")
CACHE = os.environ.get("CRATES_CACHE", os.path.join(RAW, "cratesio_cache"))
os.makedirs(CACHE, exist_ok=True)
UA = "csci5304-neo4j-vuln-prototype (student research project)"

HOP1 = 10   # dependents kept per vulnerable crate
HOP2_PARENTS = 3  # how many of those get their own dependents fetched
HOP2 = 5    # dependents kept per hop-1 crate


def get(path):
    key = os.path.join(CACHE, urllib.parse.quote(path, safe="") + ".json")
    if os.path.exists(key):
        return json.load(open(key))
    url = "https://crates.io/api/v1/" + path
    for attempt in range(4):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            data = json.load(urllib.request.urlopen(req, timeout=30))
            break
        except urllib.error.HTTPError as e:
            if e.code == 404:
                data = {"error": 404}
                break
            time.sleep(2 ** attempt)
    else:
        data = {"error": "failed"}
    json.dump(data, open(key, "w"))
    time.sleep(1.0)
    return data


def reverse_deps(name, n):
    d = get(f"crates/{name}/reverse_dependencies?per_page={n}")
    if "dependencies" not in d:
        return []
    vers = {v["id"]: v for v in d.get("versions", [])}
    out = []
    for dep in d["dependencies"]:
        v = vers.get(dep["version_id"])
        if not v:
            continue
        out.append({
            "dependent": v["crate"], "dependent_version": v["num"],
            "dependent_downloads": v.get("downloads", 0),
            "dependency": name, "req": dep["req"], "kind": dep["kind"],
            "optional": dep["optional"],
        })
    return out


def main():
    rows = list(csv.DictReader(open(os.path.join(RAW, "rustxec_metadata.csv"))))
    vuln = sorted({r["package"] for r in rows})
    versions, crates, edges = {}, {}, []
    for i, name in enumerate(vuln, 1):
        print(f"[{i}/{len(vuln)}] {name}", file=sys.stderr)
        c = get(f"crates/{name}")
        if "crate" in c:
            crates[name] = {k: c["crate"].get(k) for k in
                            ("name", "downloads", "description", "repository", "max_stable_version")}
        v = get(f"crates/{name}/versions")
        versions[name] = [{"num": x["num"], "yanked": x["yanked"], "created_at": x["created_at"]}
                          for x in v.get("versions", [])]
        hop1 = reverse_deps(name, HOP1)
        edges += hop1
        for e in hop1[:HOP2_PARENTS]:
            edges += reverse_deps(e["dependent"], HOP2)
    json.dump({"crates": crates, "versions": versions, "edges": edges},
              open(os.path.join(RAW, "cratesio.json"), "w"), indent=1)
    print(f"done: {len(crates)} crates, {sum(map(len, versions.values()))} versions, {len(edges)} edges",
          file=sys.stderr)


if __name__ == "__main__":
    main()
